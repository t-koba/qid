use qid_core::error::{QidError, QidResult};
use qid_core::models::AuditEvent;
use qid_ops::{
    KeyRotationPlan, KeyRotationPlanStatus, KeyRotationRequirement, KeyringInventoryRecord,
    plan_key_rotation,
};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

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

fn common_realm_id(requirements: &[KeyRotationRequirement]) -> Option<String> {
    let first = requirements.first()?.realm_id.as_str();
    requirements
        .iter()
        .all(|requirement| requirement.realm_id == first)
        .then(|| first.to_string())
}
