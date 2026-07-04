//! Audit event primitives.

use qid_core::models::AuditEvent as CoreAuditEvent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub r#type: String,
    pub time: String,
    pub tenant: Option<String>,
    pub realm: Option<String>,
    pub subject: Option<String>,
    pub decision: Option<String>,
    pub decision_id: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditOpenTelemetryCorrelation {
    pub traceparent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditSiemCorrelation {
    pub audit_correlation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditExportRecord {
    pub schema_version: String,
    pub id: String,
    pub realm_id: Option<String>,
    pub actor: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub reason: String,
    pub metadata: serde_json::Value,
    pub created_at: u64,
    pub previous_hash: Option<String>,
    pub event_hash: Option<String>,
    pub otel: Option<AuditOpenTelemetryCorrelation>,
    pub siem: Option<AuditSiemCorrelation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditExportOptions {
    pub include_metadata: bool,
    pub traceparent: Option<String>,
    pub audit_correlation_id: Option<String>,
}

impl Default for AuditExportOptions {
    fn default() -> Self {
        Self {
            include_metadata: true,
            traceparent: None,
            audit_correlation_id: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditRetentionPolicy {
    pub retention_days: u64,
    pub legal_hold: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRetentionPlan {
    pub legal_hold: bool,
    pub cutoff_epoch: Option<u64>,
    pub retained_ids: Vec<String>,
    pub expired_ids: Vec<String>,
}

pub fn export_record(event: &CoreAuditEvent, options: &AuditExportOptions) -> AuditExportRecord {
    AuditExportRecord {
        schema_version: "qid.audit.v1".to_string(),
        id: event.id.clone(),
        realm_id: event.realm_id.clone(),
        actor: event.actor.clone(),
        action: event.action.clone(),
        target_type: event.target_type.clone(),
        target_id: event.target_id.clone(),
        reason: event.reason.clone(),
        metadata: if options.include_metadata {
            event.metadata_json.clone()
        } else {
            serde_json::json!({})
        },
        created_at: event.created_at,
        previous_hash: event.previous_hash.clone(),
        event_hash: event.event_hash.clone(),
        otel: options
            .traceparent
            .clone()
            .map(|traceparent| AuditOpenTelemetryCorrelation {
                traceparent: Some(traceparent),
            }),
        siem: options
            .audit_correlation_id
            .clone()
            .map(|audit_correlation_id| AuditSiemCorrelation {
                audit_correlation_id,
            }),
    }
}

pub fn export_jsonl(
    events: &[CoreAuditEvent],
    options: &AuditExportOptions,
) -> serde_json::Result<String> {
    let mut out = String::new();
    for event in events {
        let record = export_record(event, options);
        out.push_str(&serde_json::to_string(&record)?);
        out.push('\n');
    }
    Ok(out)
}

pub fn siem_webhook_payload(
    events: &[CoreAuditEvent],
    options: &AuditExportOptions,
    delivered_at: u64,
) -> serde_json::Value {
    let records: Vec<AuditExportRecord> = events
        .iter()
        .map(|event| export_record(event, options))
        .collect();
    serde_json::json!({
        "schema_version": "qid.audit.webhook.v1",
        "event_count": records.len(),
        "delivered_at": delivered_at,
        "events": records,
    })
}

pub fn plan_retention(
    events: &[CoreAuditEvent],
    now_epoch: u64,
    policy: AuditRetentionPolicy,
) -> AuditRetentionPlan {
    if policy.legal_hold {
        return AuditRetentionPlan {
            legal_hold: true,
            cutoff_epoch: None,
            retained_ids: events.iter().map(|event| event.id.clone()).collect(),
            expired_ids: Vec::new(),
        };
    }

    let retention_seconds = policy.retention_days.saturating_mul(24 * 60 * 60);
    let cutoff_epoch = now_epoch.saturating_sub(retention_seconds);
    let mut retained_ids = Vec::new();
    let mut expired_ids = Vec::new();

    for event in events {
        if event.created_at < cutoff_epoch {
            expired_ids.push(event.id.clone());
        } else {
            retained_ids.push(event.id.clone());
        }
    }

    AuditRetentionPlan {
        legal_hold: false,
        cutoff_epoch: Some(cutoff_epoch),
        retained_ids,
        expired_ids,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core_event(id: &str, created_at: u64) -> CoreAuditEvent {
        CoreAuditEvent {
            id: id.to_string(),
            realm_id: Some("corp".to_string()),
            actor: "admin@example.com".to_string(),
            action: "user.create".to_string(),
            target_type: "user".to_string(),
            target_id: "usr_1".to_string(),
            reason: "ticket-123".to_string(),
            metadata_json: serde_json::json!({ "email": "user@example.com" }),
            created_at,
            previous_hash: None,
            event_hash: None,
        }
    }

    #[test]
    fn jsonl_export_includes_correlation_and_metadata() {
        let options = AuditExportOptions {
            traceparent: Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00".into()),
            audit_correlation_id: Some("corr-1".into()),
            ..AuditExportOptions::default()
        };
        let jsonl = export_jsonl(&[core_event("evt-1", 100)], &options).unwrap();
        let line = jsonl.trim_end();
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(value["schema_version"], "qid.audit.v1");
        assert_eq!(value["metadata"]["email"], "user@example.com");
        assert_eq!(value["otel"]["traceparent"], options.traceparent.unwrap());
        assert_eq!(value["siem"]["audit_correlation_id"], "corr-1");
    }

    #[test]
    fn jsonl_export_can_redact_metadata() {
        let options = AuditExportOptions {
            include_metadata: false,
            ..AuditExportOptions::default()
        };
        let jsonl = export_jsonl(&[core_event("evt-1", 100)], &options).unwrap();
        let value: serde_json::Value = serde_json::from_str(jsonl.trim_end()).unwrap();
        assert_eq!(value["metadata"], serde_json::json!({}));
    }

    #[test]
    fn siem_payload_wraps_records() {
        let payload = siem_webhook_payload(
            &[core_event("evt-1", 100), core_event("evt-2", 200)],
            &AuditExportOptions::default(),
            1700000000,
        );
        assert_eq!(payload["schema_version"], "qid.audit.webhook.v1");
        assert_eq!(payload["event_count"], 2);
        assert_eq!(payload["delivered_at"], 1700000000);
        assert_eq!(payload["events"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn retention_plan_respects_legal_hold() {
        let events = vec![core_event("old", 10), core_event("new", 200)];
        let plan = plan_retention(
            &events,
            200,
            AuditRetentionPolicy {
                retention_days: 0,
                legal_hold: true,
            },
        );
        assert!(plan.legal_hold);
        assert_eq!(plan.expired_ids, Vec::<String>::new());
        assert_eq!(plan.retained_ids, vec!["old", "new"]);
    }

    #[test]
    fn retention_plan_separates_expired_events() {
        let events = vec![core_event("old", 10), core_event("new", 200)];
        let plan = plan_retention(
            &events,
            200,
            AuditRetentionPolicy {
                retention_days: 0,
                legal_hold: false,
            },
        );
        assert_eq!(plan.cutoff_epoch, Some(200));
        assert_eq!(plan.expired_ids, vec!["old"]);
        assert_eq!(plan.retained_ids, vec!["new"]);
    }
}
