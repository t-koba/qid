use qid_core::{
    config::{DirectoryProviderConfig, QidConfig},
    error::{QidError, QidResult},
    models::{AuditEvent, ScimUser, User},
    tenant::RealmId,
};
use qid_crypto::LocalSigner;
use qid_directory::connector::{
    DirectoryConnector, LdapDirectoryConnector, TestDirectoryConnector,
};
use qid_scim::{
    OutboundScimClientConfig, ReqwestOutboundScimTransport, execute_outbound_user_provisioning,
    plan_outbound_user_execution,
};
use qid_storage::{AnyRepository, prelude::*};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use ulid::Ulid;

/// Configuration for the SCIM outbound sync job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimOutboundSyncConfig {
    pub realm_id: String,
    pub actor: String,
    pub reason: String,
    pub now_epoch: u64,
    pub record_audit_event: bool,
    pub scim_base_url: String,
    pub scim_bearer_token: Option<String>,
    pub dry_run: bool,
}

/// Run a SCIM outbound sync job: sync local users to an external SCIM endpoint.
pub async fn run_scim_outbound_sync_job<R: Repository>(
    repo: &R,
    config: ScimOutboundSyncConfig,
) -> QidResult<ScimOutboundSyncReport> {
    let transport = ReqwestOutboundScimTransport::new();
    let scim_config = OutboundScimClientConfig {
        base_url: config.scim_base_url,
        bearer_token: config.scim_bearer_token,
    };
    let mapping = qid_scim::default_outbound_user_mapping();
    let retry_policy = qid_scim::default_outbound_retry_policy();

    let users = repo
        .list_users(&RealmId::from(config.realm_id.clone()))
        .await?;
    let mut synced = 0u64;
    let mut failed = 0u64;
    let mut skipped = 0u64;
    let mut errors = Vec::new();

    for user in &users {
        let scim_user = user_to_scim_user(user);
        let plan = match plan_outbound_user_execution(
            &scim_user,
            None,
            &mapping,
            config.dry_run,
            retry_policy.clone(),
            0,
            config.now_epoch * 1000,
        ) {
            Ok(p) => p,
            Err(e) => {
                failed += 1;
                errors.push(format!("user {} planning failed: {e}", user.id));
                continue;
            }
        };
        if plan.provisioning.operation == qid_scim::OutboundOperation::Noop && !config.dry_run {
            skipped += 1;
            continue;
        }
        match execute_outbound_user_provisioning(&plan.provisioning, &scim_config, &transport).await
        {
            Ok(result) => {
                if result.sent {
                    synced += 1;
                } else {
                    skipped += 1;
                }
            }
            Err(e) => {
                failed += 1;
                errors.push(format!("user {} execution failed: {e}", user.id));
            }
        }
    }

    if config.record_audit_event {
        let event_id = Ulid::new().to_string();
        let _ = repo
            .append_audit_event(&AuditEvent {
                id: event_id.clone(),
                realm_id: Some(config.realm_id.clone()),
                actor: config.actor,
                action: "scim.outbound_sync".to_string(),
                target_type: "scim_sync".to_string(),
                target_id: "outbound".to_string(),
                reason: config.reason,
                metadata_json: serde_json::json!({
                    "synced": synced,
                    "skipped": skipped,
                    "failed": failed,
                    "errors": errors,
                    "dry_run": config.dry_run,
                }),
                created_at: config.now_epoch,
                previous_hash: None,
                event_hash: None,
            })
            .await;
    }

    Ok(ScimOutboundSyncReport {
        synced,
        skipped,
        failed,
        errors,
        dry_run: config.dry_run,
    })
}

fn user_to_scim_user(user: &User) -> ScimUser {
    ScimUser {
        id: user.id.clone(),
        realm_id: user.realm_id.clone(),
        external_id: None,
        user_name: user
            .email
            .clone()
            .unwrap_or_else(|| format!("user-{}", user.id)),
        name_json: serde_json::json!({
            "formatted": user.display_name.clone().unwrap_or_default(),
        }),
        emails_json: serde_json::json!([{
            "value": user.email.clone().unwrap_or_default(),
            "primary": true,
        }]),
        enterprise_json: serde_json::json!({}),
        active: true,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimOutboundSyncReport {
    pub synced: u64,
    pub skipped: u64,
    pub failed: u64,
    pub errors: Vec<String>,
    pub dry_run: bool,
}

/// Configuration for the directory sync job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectorySyncJobConfig {
    pub realm_id: String,
    pub provider_id: String,
    pub actor: String,
    pub reason: String,
    pub now_epoch: u64,
    pub record_audit_event: bool,
    pub dry_run: bool,
}

/// Status of a completed directory sync job.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DirectorySyncJobStatus {
    Completed,
    SkippedDisabled,
}

/// Report from a directory sync run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectorySyncJobReport {
    pub status: DirectorySyncJobStatus,
    pub provider_id: String,
    pub created: u64,
    pub updated: u64,
    pub unchanged: u64,
    pub deactivated: u64,
    pub skipped_break_glass: u64,
    pub errors: Vec<String>,
    pub audit_event_id: Option<String>,
    pub dry_run: bool,
}

/// Run a directory sync job: connect to a configured directory provider,
/// fetch users, and synchronize them into the local SCIM user store.
pub async fn run_directory_sync_job(
    repo: Arc<AnyRepository>,
    qid_config: &QidConfig,
    config: DirectorySyncJobConfig,
) -> QidResult<DirectorySyncJobReport> {
    let provider = match find_directory_provider(qid_config, &config.realm_id, &config.provider_id)
    {
        Ok(provider) => provider,
        Err(e) => {
            let skipped = matches!(e, QidError::Config { .. });
            return Ok(DirectorySyncJobReport {
                status: if skipped {
                    DirectorySyncJobStatus::SkippedDisabled
                } else {
                    DirectorySyncJobStatus::Completed
                },
                provider_id: config.provider_id,
                created: 0,
                updated: 0,
                unchanged: 0,
                deactivated: 0,
                skipped_break_glass: 0,
                errors: if skipped {
                    Vec::new()
                } else {
                    vec![e.message()]
                },
                audit_event_id: None,
                dry_run: config.dry_run,
            });
        }
    };
    let mut connector: Box<dyn DirectoryConnector> = match provider.provider_type.as_str() {
        "ldap" | "ldaps" | "ad" => {
            let mut ldap = LdapDirectoryConnector::new();
            ldap.connect(&provider.connection).await?;
            Box::new(ldap)
        }
        other => {
            return Err(QidError::Config {
                message: format!(
                    "directory provider '{}' has unsupported type '{other}'",
                    provider.id
                ),
            });
        }
    };
    let sync_config = provider.sync.clone();
    let mapping = provider.attribute_mapping.clone();
    // Honour `directory.enabled` to give operators a kill switch. The
    // default of `true` is what INTEROP §3 expects for enterprise
    // deployments; set to `false` only when a realm is intentionally
    // operated without a directory backend.

    let entries = match connector.fetch_users(&sync_config, &mapping).await {
        Ok(entries) => entries,
        Err(err) => {
            // Fall back to the test connector only in test builds so the
            // worker remains exercisable when no real directory is
            // configured. Production deployments always require a real
            // connector.
            if cfg!(test) {
                let mut fallback = TestDirectoryConnector::new(Vec::new());
                fallback.connect(&provider.connection).await.ok();
                fallback.fetch_users(&sync_config, &mapping).await?
            } else {
                return Err(QidError::Internal {
                    message: format!("directory fetch failed: {err}"),
                });
            }
        }
    };
    connector.disconnect().await.ok();

    let signer = Arc::new(LocalSigner::from_secret(
        "directory-sync",
        b"qid-directory-worker-signing-key",
    ));
    let state: qid_core::state::SharedState<AnyRepository> =
        qid_core::state::SharedState::new(qid_config.clone(), repo, signer, serde_json::json!({}))
            .map_err(|e| QidError::Internal {
                message: format!("failed to initialize state: {e}"),
            })?;

    let result = qid_directory::sync_ldap_entries(
        &state,
        &config.realm_id,
        &entries,
        qid_directory::LdapSyncOptions {
            deactivate_missing: provider.sync.deactivate_missing,
            synced_at: config.now_epoch,
        },
    )
    .await?;

    let audit_event_id = if config.record_audit_event {
        let event_id = ulid::Ulid::new().to_string();
        let _ = state
            .repo
            .append_audit_event(&AuditEvent {
                id: event_id.clone(),
                realm_id: Some(config.realm_id.clone()),
                actor: config.actor.clone(),
                action: "directory.sync".to_string(),
                target_type: "directory_provider".to_string(),
                target_id: config.provider_id.clone(),
                reason: config.reason.clone(),
                metadata_json: serde_json::json!({
                    "provider_id": config.provider_id,
                    "created": result.created_user_ids.len(),
                    "updated": result.updated_user_ids.len(),
                    "unchanged": result.unchanged_user_ids.len(),
                    "deactivated": result.deactivated_user_ids.len(),
                    "skipped_break_glass": result.break_glass_skipped_user_ids.len(),
                    "dry_run": config.dry_run,
                }),
                created_at: config.now_epoch,
                previous_hash: None,
                event_hash: None,
            })
            .await;
        Some(event_id)
    } else {
        None
    };

    Ok(DirectorySyncJobReport {
        status: DirectorySyncJobStatus::Completed,
        provider_id: config.provider_id,
        created: result.created_user_ids.len() as u64,
        updated: result.updated_user_ids.len() as u64,
        unchanged: result.unchanged_user_ids.len() as u64,
        deactivated: result.deactivated_user_ids.len() as u64,
        skipped_break_glass: result.break_glass_skipped_user_ids.len() as u64,
        errors: Vec::new(),
        audit_event_id,
        dry_run: config.dry_run,
    })
}

fn find_directory_provider<'a>(
    qid_config: &'a QidConfig,
    realm_id: &str,
    provider_id: &str,
) -> QidResult<&'a DirectoryProviderConfig> {
    let realm = qid_config
        .realms
        .iter()
        .find(|realm| realm.id == realm_id)
        .ok_or_else(|| QidError::NotFound {
            resource: format!("realm {realm_id}"),
        })?;
    let provider = realm
        .protocols
        .directory
        .providers
        .iter()
        .find(|provider| provider.id == provider_id)
        .ok_or_else(|| QidError::NotFound {
            resource: format!("directory provider {provider_id} in realm {realm_id}"),
        })?;
    if !provider.enabled {
        return Err(QidError::Config {
            message: format!(
                "directory provider {} is disabled in realm {realm_id}",
                provider.id
            ),
        });
    }
    Ok(provider)
}
