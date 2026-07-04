use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    OidcToken,
    SamlAssertion,
    PepAssertion,
    AuditLog,
    BrowserSession,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyringInventoryRecord {
    pub realm_id: String,
    pub keyring_name: String,
    pub kid: String,
    pub purpose: KeyPurpose,
    pub signer_type: String,
    pub created_at_epoch: u64,
    pub not_before_epoch: u64,
    pub retire_after_epoch: u64,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRotationRequirement {
    pub realm_id: String,
    pub purpose: KeyPurpose,
    pub max_age_days: u64,
    pub overlap_days: u64,
    pub require_remote_signer: bool,
    pub require_dedicated_keyring: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRotationPlan {
    pub status: KeyRotationPlanStatus,
    pub realm_id: String,
    pub purpose: KeyPurpose,
    pub active_kid: Option<String>,
    pub successor_kid: Option<String>,
    pub actions: Vec<KeyRotationAction>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyRotationPlanStatus {
    Ready,
    ActionRequired,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRotationAction {
    pub action: KeyRotationActionKind,
    pub keyring_name: String,
    pub kid: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyRotationActionKind {
    GenerateSuccessor,
    PromoteSuccessor,
    RetireExpired,
    RemoveRevoked,
}

pub fn plan_key_rotation(
    inventory: &[KeyringInventoryRecord],
    requirements: &[KeyRotationRequirement],
    now_epoch: u64,
) -> Vec<KeyRotationPlan> {
    requirements
        .iter()
        .map(|requirement| plan_required_key_rotation(inventory, requirement, now_epoch))
        .collect()
}

fn plan_required_key_rotation(
    inventory: &[KeyringInventoryRecord],
    requirement: &KeyRotationRequirement,
    now_epoch: u64,
) -> KeyRotationPlan {
    let mut reasons = validate_key_rotation_requirement(requirement);
    let matching = inventory
        .iter()
        .filter(|record| {
            record.realm_id == requirement.realm_id && record.purpose == requirement.purpose
        })
        .collect::<Vec<_>>();

    let mut actions = matching
        .iter()
        .filter(|record| record.revoked)
        .map(|record| KeyRotationAction {
            action: KeyRotationActionKind::RemoveRevoked,
            keyring_name: record.keyring_name.clone(),
            kid: Some(record.kid.clone()),
            reason: "revoked_key_must_not_remain_in_active_inventory".to_string(),
        })
        .collect::<Vec<_>>();

    if requirement.require_dedicated_keyring {
        let active_shared_keyrings = matching
            .iter()
            .filter(|record| is_active_key(record, now_epoch))
            .filter(|record| {
                inventory.iter().any(|other| {
                    other.realm_id == record.realm_id
                        && other.keyring_name == record.keyring_name
                        && other.purpose != record.purpose
                        && is_active_key(other, now_epoch)
                })
            })
            .map(|record| record.keyring_name.clone())
            .collect::<BTreeSet<_>>();
        for keyring_name in active_shared_keyrings {
            reasons.push(format!("dedicated_keyring_required:{keyring_name}"));
        }
    }

    if requirement.require_remote_signer {
        for record in matching
            .iter()
            .filter(|record| is_active_key(record, now_epoch))
        {
            if !is_remote_signer(&record.signer_type) {
                reasons.push(format!("remote_signer_required:{}", record.keyring_name));
            }
        }
    }

    let active = matching
        .iter()
        .copied()
        .filter(|record| is_active_key(record, now_epoch))
        .max_by_key(|record| (record.created_at_epoch, record.kid.as_str()));
    let successor = matching
        .iter()
        .copied()
        .filter(|record| !record.revoked && record.not_before_epoch > now_epoch)
        .min_by_key(|record| (record.not_before_epoch, record.kid.as_str()));

    if let Some(active) = active {
        if active.retire_after_epoch <= now_epoch {
            actions.push(KeyRotationAction {
                action: KeyRotationActionKind::RetireExpired,
                keyring_name: active.keyring_name.clone(),
                kid: Some(active.kid.clone()),
                reason: "active_key_retired".to_string(),
            });
        }

        let max_age_seconds = days_to_seconds(requirement.max_age_days);
        let overlap_seconds = days_to_seconds(requirement.overlap_days);
        let rotate_after_epoch = active
            .created_at_epoch
            .saturating_add(max_age_seconds.saturating_sub(overlap_seconds));
        if now_epoch >= rotate_after_epoch && successor.is_none() {
            actions.push(KeyRotationAction {
                action: KeyRotationActionKind::GenerateSuccessor,
                keyring_name: active.keyring_name.clone(),
                kid: None,
                reason: "rotation_overlap_window_open".to_string(),
            });
        }
    } else if let Some(successor) = successor {
        actions.push(KeyRotationAction {
            action: KeyRotationActionKind::PromoteSuccessor,
            keyring_name: successor.keyring_name.clone(),
            kid: Some(successor.kid.clone()),
            reason: "no_active_key".to_string(),
        });
    } else {
        actions.push(KeyRotationAction {
            action: KeyRotationActionKind::GenerateSuccessor,
            keyring_name: default_keyring_name(requirement),
            kid: None,
            reason: "no_active_or_successor_key".to_string(),
        });
    }

    let status = if reasons.iter().any(|reason| {
        reason.starts_with("invalid_")
            || reason.starts_with("dedicated_keyring_required:")
            || reason.starts_with("remote_signer_required:")
    }) {
        KeyRotationPlanStatus::Rejected
    } else if actions.is_empty() {
        KeyRotationPlanStatus::Ready
    } else {
        KeyRotationPlanStatus::ActionRequired
    };

    KeyRotationPlan {
        status,
        realm_id: requirement.realm_id.clone(),
        purpose: requirement.purpose.clone(),
        active_kid: active.map(|record| record.kid.clone()),
        successor_kid: successor.map(|record| record.kid.clone()),
        actions,
        reasons,
    }
}

fn validate_key_rotation_requirement(requirement: &KeyRotationRequirement) -> Vec<String> {
    let mut reasons = Vec::new();
    if requirement.realm_id.trim().is_empty() {
        reasons.push("invalid_empty_realm_id".to_string());
    }
    if requirement.max_age_days == 0 {
        reasons.push("invalid_max_age_days_zero".to_string());
    }
    if requirement.overlap_days > requirement.max_age_days {
        reasons.push("invalid_overlap_exceeds_max_age".to_string());
    }
    reasons
}

fn is_active_key(record: &KeyringInventoryRecord, now_epoch: u64) -> bool {
    !record.revoked
        && record.not_before_epoch <= now_epoch
        && (record.retire_after_epoch == 0 || record.retire_after_epoch > now_epoch)
}

fn is_remote_signer(signer_type: &str) -> bool {
    matches!(signer_type, "kms" | "hsm" | "pkcs11")
}

fn default_keyring_name(requirement: &KeyRotationRequirement) -> String {
    format!(
        "{}-{}",
        requirement.realm_id,
        match &requirement.purpose {
            KeyPurpose::OidcToken => "oidc-token",
            KeyPurpose::SamlAssertion => "saml-assertion",
            KeyPurpose::PepAssertion => "pep-assertion",
            KeyPurpose::AuditLog => "audit-log",
            KeyPurpose::BrowserSession => "browser-session",
            KeyPurpose::Other(value) => value.as_str(),
        }
    )
}

fn days_to_seconds(days: u64) -> u64 {
    days.saturating_mul(24 * 60 * 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_record(
        keyring_name: &str,
        kid: &str,
        purpose: KeyPurpose,
        signer_type: &str,
        created_at_epoch: u64,
        not_before_epoch: u64,
        retire_after_epoch: u64,
    ) -> KeyringInventoryRecord {
        KeyringInventoryRecord {
            realm_id: "corp".to_string(),
            keyring_name: keyring_name.to_string(),
            kid: kid.to_string(),
            purpose,
            signer_type: signer_type.to_string(),
            created_at_epoch,
            not_before_epoch,
            retire_after_epoch,
            revoked: false,
        }
    }

    fn pep_rotation_requirement() -> KeyRotationRequirement {
        KeyRotationRequirement {
            realm_id: "corp".to_string(),
            purpose: KeyPurpose::PepAssertion,
            max_age_days: 90,
            overlap_days: 14,
            require_remote_signer: true,
            require_dedicated_keyring: true,
        }
    }

    #[test]
    fn key_rotation_requires_pep_assertion_dedicated_remote_keyring() {
        let inventory = vec![
            key_record(
                "corp-shared",
                "shared-1",
                KeyPurpose::PepAssertion,
                "local",
                100,
                100,
                10_000,
            ),
            key_record(
                "corp-shared",
                "shared-2",
                KeyPurpose::OidcToken,
                "local",
                100,
                100,
                10_000,
            ),
        ];

        let plans = plan_key_rotation(&inventory, &[pep_rotation_requirement()], 1_000);
        let plan = plans.first().expect("key rotation plan");

        assert_eq!(plan.status, KeyRotationPlanStatus::Rejected);
        assert!(
            plan.reasons
                .contains(&"dedicated_keyring_required:corp-shared".to_string())
        );
        assert!(
            plan.reasons
                .contains(&"remote_signer_required:corp-shared".to_string())
        );
    }

    #[test]
    fn key_rotation_generates_successor_inside_overlap_window() {
        let day = 24 * 60 * 60;
        let active = key_record(
            "corp-pep-assertion",
            "pep-1",
            KeyPurpose::PepAssertion,
            "kms",
            0,
            0,
            120 * day,
        );
        let plans = plan_key_rotation(&[active], &[pep_rotation_requirement()], 76 * day);
        let plan = plans.first().expect("key rotation plan");

        assert_eq!(plan.status, KeyRotationPlanStatus::ActionRequired);
        assert_eq!(plan.active_kid, Some("pep-1".to_string()));
        assert_eq!(
            plan.actions,
            vec![KeyRotationAction {
                action: KeyRotationActionKind::GenerateSuccessor,
                keyring_name: "corp-pep-assertion".to_string(),
                kid: None,
                reason: "rotation_overlap_window_open".to_string(),
            }]
        );
    }

    #[test]
    fn key_rotation_promotes_scheduled_successor_when_active_missing() {
        let successor = key_record(
            "corp-pep-assertion",
            "pep-2",
            KeyPurpose::PepAssertion,
            "hsm",
            1_000,
            2_000,
            10_000,
        );
        let plans = plan_key_rotation(&[successor], &[pep_rotation_requirement()], 1_500);
        let plan = plans.first().expect("key rotation plan");

        assert_eq!(plan.status, KeyRotationPlanStatus::ActionRequired);
        assert_eq!(plan.successor_kid, Some("pep-2".to_string()));
        assert_eq!(
            plan.actions[0].action,
            KeyRotationActionKind::PromoteSuccessor
        );
        assert_eq!(plan.actions[0].kid, Some("pep-2".to_string()));
    }
}
