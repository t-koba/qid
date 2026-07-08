use qid_core::error::{QidError, QidResult};
use qid_core::models::AuditEvent;
use qid_crypto::{
    KeyProtector, PassphraseProtector, jwk::generate_eddsa, jwk::generate_es256,
    serialize_encrypted_key,
};
use qid_ops::{
    KeyRotationActionKind, KeyRotationPlan, KeyRotationPlanStatus, KeyRotationRequirement,
    KeyringInventoryRecord, plan_key_rotation,
};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use ulid::Ulid;
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRotationPlanningJobConfig {
    pub inventory: Vec<KeyringInventoryRecord>,
    pub requirements: Vec<KeyRotationRequirement>,
    pub now_epoch: u64,
    pub actor: String,
    pub reason: String,
    pub record_audit_event: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRotationPlanningJobReport {
    pub status: KeyRotationPlanningJobStatus,
    pub plans: Vec<KeyRotationPlan>,
    pub ready_count: usize,
    pub action_required_count: usize,
    pub rejected_count: usize,
    pub audit_event_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyRotationPlanningJobStatus {
    Ready,
    ActionRequired,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRotationExecutionJobConfig {
    pub plan: KeyRotationPlan,
    pub output_dir: PathBuf,
    pub algorithm: String,
    pub key_passphrase: Vec<u8>,
    pub now_epoch: u64,
    pub actor: String,
    pub reason: String,
    pub record_audit_event: bool,
    pub force: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRotationExecutionJobReport {
    pub status: KeyRotationExecutionJobStatus,
    pub executed: Vec<KeyRotationExecutedAction>,
    pub unsupported: Vec<KeyRotationUnsupportedAction>,
    pub audit_event_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyRotationExecutionJobStatus {
    Executed,
    UnsupportedActions,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRotationExecutedAction {
    pub action: KeyRotationActionKind,
    pub keyring_name: String,
    pub kid: String,
    pub encrypted_key_path: PathBuf,
    pub public_key_path: PathBuf,
    pub public_jwk_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRotationUnsupportedAction {
    pub action: KeyRotationActionKind,
    pub keyring_name: String,
    pub kid: Option<String>,
    pub reason: String,
}

pub async fn run_key_rotation_planning_job<R: Repository>(
    repo: &R,
    config: KeyRotationPlanningJobConfig,
) -> QidResult<KeyRotationPlanningJobReport> {
    if config.requirements.is_empty() {
        return Err(QidError::BadRequest {
            message: "key rotation planning requires at least one requirement".to_string(),
        });
    }
    if config.actor.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "key rotation planning actor must not be empty".to_string(),
        });
    }
    if config.reason.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "key rotation planning reason must not be empty".to_string(),
        });
    }

    let plans = plan_key_rotation(&config.inventory, &config.requirements, config.now_epoch);
    let ready_count = plans
        .iter()
        .filter(|plan| plan.status == KeyRotationPlanStatus::Ready)
        .count();
    let action_required_count = plans
        .iter()
        .filter(|plan| plan.status == KeyRotationPlanStatus::ActionRequired)
        .count();
    let rejected_count = plans
        .iter()
        .filter(|plan| plan.status == KeyRotationPlanStatus::Rejected)
        .count();
    let status = if rejected_count > 0 {
        KeyRotationPlanningJobStatus::Rejected
    } else if action_required_count > 0 {
        KeyRotationPlanningJobStatus::ActionRequired
    } else {
        KeyRotationPlanningJobStatus::Ready
    };
    let audit_event_id = if config.record_audit_event {
        let event_id = Ulid::new().to_string();
        repo.append_audit_event(&AuditEvent {
            id: event_id.clone(),
            realm_id: common_realm_id(&config.requirements),
            actor: config.actor,
            action: "key_rotation.plan".to_string(),
            target_type: "key_rotation".to_string(),
            target_id: "key_rotation_plan".to_string(),
            reason: config.reason,
            metadata_json: serde_json::json!({
                "status": status,
                "ready_count": ready_count,
                "action_required_count": action_required_count,
                "rejected_count": rejected_count,
                "plan_count": plans.len(),
                "now_epoch": config.now_epoch,
                "plans": plans.iter().map(|plan| serde_json::json!({
                    "realm_id": plan.realm_id,
                    "purpose": plan.purpose,
                    "status": plan.status,
                    "active_kid": plan.active_kid,
                    "successor_kid": plan.successor_kid,
                    "reasons": plan.reasons,
                })).collect::<Vec<_>>(),
            }),
            created_at: config.now_epoch,
            previous_hash: None,
            event_hash: None,
        })
        .await?;
        Some(event_id)
    } else {
        None
    };

    Ok(KeyRotationPlanningJobReport {
        status,
        plans,
        ready_count,
        action_required_count,
        rejected_count,
        audit_event_id,
    })
}

pub async fn run_key_rotation_execution_job<R: Repository>(
    repo: &R,
    config: KeyRotationExecutionJobConfig,
) -> QidResult<KeyRotationExecutionJobReport> {
    if config.actor.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "key rotation execution actor must not be empty".to_string(),
        });
    }
    if config.reason.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "key rotation execution reason must not be empty".to_string(),
        });
    }
    if config.key_passphrase.is_empty() {
        return Err(QidError::BadRequest {
            message: "key rotation execution requires a non-empty key passphrase".to_string(),
        });
    }
    if config.plan.status == KeyRotationPlanStatus::Rejected {
        return Ok(KeyRotationExecutionJobReport {
            status: KeyRotationExecutionJobStatus::Rejected,
            executed: Vec::new(),
            unsupported: config
                .plan
                .actions
                .iter()
                .map(|action| KeyRotationUnsupportedAction {
                    action: action.action.clone(),
                    keyring_name: action.keyring_name.clone(),
                    kid: action.kid.clone(),
                    reason: "rejected_plan_must_not_execute".to_string(),
                })
                .collect(),
            audit_event_id: None,
        });
    }

    std::fs::create_dir_all(&config.output_dir).map_err(|e| QidError::Internal {
        message: format!("failed to create key rotation output directory: {e}"),
    })?;
    let protector = PassphraseProtector::new(config.key_passphrase.clone())?;
    let mut executed = Vec::new();
    let mut unsupported = Vec::new();

    for action in &config.plan.actions {
        match action.action {
            KeyRotationActionKind::GenerateSuccessor => {
                let kid = action
                    .kid
                    .clone()
                    .unwrap_or_else(|| format!("{}-{}", action.keyring_name, Ulid::new()));
                let mut generated = generate_local_signing_key(&kid, &config.algorithm)?;
                let encrypted =
                    protector.seal(&generated.private_pem, &generated.kid, &config.algorithm)?;
                generated.private_pem.zeroize();
                let paths = rotation_key_paths(
                    &config.output_dir,
                    &action.keyring_name,
                    &config.algorithm,
                    &kid,
                );
                write_rotation_key_files(
                    &paths,
                    &serialize_encrypted_key(&encrypted)?,
                    &generated.public_pem,
                    &serde_json::to_string_pretty(&generated.public_jwk).map_err(|e| {
                        QidError::Internal {
                            message: format!("failed to serialize successor public JWK: {e}"),
                        }
                    })?,
                    config.force,
                )?;
                executed.push(KeyRotationExecutedAction {
                    action: action.action.clone(),
                    keyring_name: action.keyring_name.clone(),
                    kid,
                    encrypted_key_path: paths.0,
                    public_key_path: paths.1,
                    public_jwk_path: paths.2,
                });
            }
            KeyRotationActionKind::PromoteSuccessor
            | KeyRotationActionKind::RetireExpired
            | KeyRotationActionKind::RemoveRevoked => {
                unsupported.push(KeyRotationUnsupportedAction {
                    action: action.action.clone(),
                    keyring_name: action.keyring_name.clone(),
                    kid: action.kid.clone(),
                    reason: "persistent_keyring_state_transition_not_available".to_string(),
                });
            }
        }
    }

    let status = if !unsupported.is_empty() {
        KeyRotationExecutionJobStatus::UnsupportedActions
    } else {
        KeyRotationExecutionJobStatus::Executed
    };
    let audit_event_id = if config.record_audit_event {
        let event_id = Ulid::new().to_string();
        repo.append_audit_event(&AuditEvent {
            id: event_id.clone(),
            realm_id: Some(config.plan.realm_id.clone()),
            actor: config.actor,
            action: "key_rotation.execute".to_string(),
            target_type: "key_rotation".to_string(),
            target_id: format!("{}:{:?}", config.plan.realm_id, config.plan.purpose),
            reason: config.reason,
            metadata_json: serde_json::json!({
                "status": status,
                "algorithm": config.algorithm,
                "now_epoch": config.now_epoch,
                "executed": executed,
                "unsupported": unsupported,
            }),
            created_at: config.now_epoch,
            previous_hash: None,
            event_hash: None,
        })
        .await?;
        Some(event_id)
    } else {
        None
    };

    Ok(KeyRotationExecutionJobReport {
        status,
        executed,
        unsupported,
        audit_event_id,
    })
}

fn generate_local_signing_key(
    kid: &str,
    algorithm: &str,
) -> QidResult<qid_crypto::jwk::GeneratedKeyPair> {
    match algorithm {
        "ES256" => generate_es256(kid).map_err(|e| QidError::Crypto {
            message: format!("failed to generate ES256 successor key: {e}"),
        }),
        "EdDSA" => generate_eddsa(kid).map_err(|e| QidError::Crypto {
            message: format!("failed to generate EdDSA successor key: {e}"),
        }),
        other => Err(QidError::BadRequest {
            message: format!("local key rotation algorithm {other} is not supported"),
        }),
    }
}

fn rotation_key_paths(
    output_dir: &Path,
    keyring: &str,
    algorithm: &str,
    kid: &str,
) -> (PathBuf, PathBuf, PathBuf) {
    let keyring = safe_key_file_component(keyring);
    let algorithm = safe_key_file_component(algorithm);
    let kid = safe_key_file_component(kid);
    let base = format!("signing-key-{keyring}-{algorithm}-{kid}");
    (
        output_dir.join(format!("{base}.pem.enc")),
        output_dir.join(format!("{base}.pub.pem")),
        output_dir.join(format!("{base}.jwk.json")),
    )
}

fn write_rotation_key_files(
    paths: &(PathBuf, PathBuf, PathBuf),
    encrypted_key_json: &str,
    public_pem: &str,
    public_jwk_json: &str,
    force: bool,
) -> QidResult<()> {
    if !force {
        for path in [&paths.0, &paths.1, &paths.2] {
            if path.exists() {
                return Err(QidError::Conflict {
                    message: format!("rotation key output already exists: {}", path.display()),
                });
            }
        }
    }
    std::fs::write(&paths.0, encrypted_key_json).map_err(|e| QidError::Internal {
        message: format!("failed to write encrypted successor key: {e}"),
    })?;
    std::fs::write(&paths.1, public_pem).map_err(|e| QidError::Internal {
        message: format!("failed to write successor public key: {e}"),
    })?;
    std::fs::write(&paths.2, public_jwk_json).map_err(|e| QidError::Internal {
        message: format!("failed to write successor public JWK: {e}"),
    })?;
    Ok(())
}

fn safe_key_file_component(value: &str) -> String {
    let safe = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();
    if safe.is_empty() {
        "default".to_string()
    } else {
        safe
    }
}

fn common_realm_id(requirements: &[KeyRotationRequirement]) -> Option<String> {
    let first = requirements.first()?.realm_id.as_str();
    requirements
        .iter()
        .all(|requirement| requirement.realm_id == first)
        .then(|| first.to_string())
}
