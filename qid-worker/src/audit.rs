use qid_core::{
    error::{QidError, QidResult},
    models::{
        AuditChainVerification, AuditEvent, AuditRetentionEnforcementPlan, ComplianceEvidencePack,
    },
    tenant::RealmId,
};
use qid_observability::audit::{
    AuditExportOptions, AuditExportRecord, export_jsonl, siem_webhook_payload,
};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use ulid::Ulid;

use crate::hex_sha256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRetentionJobConfig {
    pub realm_id: Option<String>,
    pub actor: String,
    pub reason: String,
    pub now_epoch: u64,
    pub record_audit_event: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRetentionJobReport {
    pub status: AuditRetentionJobStatus,
    pub realm_id: Option<String>,
    pub chain_verification: AuditChainVerification,
    pub plan: Option<AuditRetentionEnforcementPlan>,
    pub audit_event_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditRetentionJobStatus {
    Evaluated,
    SkippedNoPolicy,
    SkippedChainInvalid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditSiemDeliveryConfig {
    pub realm_id: Option<String>,
    pub endpoint_url: String,
    pub limit: usize,
    pub now_epoch: u64,
    pub traceparent: Option<String>,
    pub audit_correlation_id: Option<String>,
    pub include_metadata: bool,
    pub actor: String,
    pub reason: String,
    pub record_audit_event: bool,
    pub completed_attempts: u32,
    pub retry_policy: AuditSiemRetryPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditSiemRedriveConfig {
    pub delivery_id: String,
    pub now_epoch: u64,
    pub actor: String,
    pub reason: String,
    pub record_audit_event: bool,
    pub retry_policy: AuditSiemRetryPolicy,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditSiemRetryPolicy {
    pub max_attempts: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
}

impl Default for AuditSiemRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base_delay_ms: 1_000,
            max_delay_ms: 60_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditSiemRetryDecision {
    pub retry: bool,
    pub attempt: u32,
    pub delay_ms: Option<u64>,
    /// First error message preserved across retries to avoid overwriting
    /// the original failure context.
    pub first_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditSiemHttpRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditSiemHttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditSiemDeliveryReport {
    pub status: AuditSiemDeliveryStatus,
    pub delivery_id: Option<String>,
    pub realm_id: Option<String>,
    pub event_count: usize,
    pub endpoint_url: String,
    pub http_status: Option<u16>,
    pub retry: AuditSiemRetryDecision,
    pub audit_event_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditSiemDeliveryStatus {
    Delivered,
    FailedRetryable,
    FailedPermanent,
    SkippedNoEvents,
}

pub trait SiemWebhookTransport {
    fn send(&self, request: AuditSiemHttpRequest) -> Result<AuditSiemHttpResponse, String>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditWormArchiveConfig {
    pub realm_id: Option<String>,
    pub limit: usize,
    pub now_epoch: u64,
    pub include_metadata: bool,
    pub actor: String,
    pub reason: String,
    pub record_audit_event: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRetentionExecutionConfig {
    pub realm_id: Option<String>,
    pub now_epoch: u64,
    pub actor: String,
    pub reason: String,
    pub archive_required: bool,
    pub include_metadata_in_archive: bool,
    pub record_audit_event: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditWormObject {
    pub key: String,
    pub content_type: String,
    pub body: Vec<u8>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditWormPutResult {
    pub key: String,
    pub version_id: Option<String>,
    pub location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvidenceManifest {
    pub schema_version: String,
    pub realm_id: Option<String>,
    pub generated_at: u64,
    pub event_count: usize,
    pub first_event_id: Option<String>,
    pub last_event_id: Option<String>,
    pub first_event_hash: Option<String>,
    pub last_event_hash: Option<String>,
    pub body_sha256: String,
    pub body_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvidenceVerificationReport {
    pub valid: bool,
    pub event_count: usize,
    pub body_sha256: String,
    pub expected_body_sha256: String,
    pub first_event_id: Option<String>,
    pub last_event_id: Option<String>,
    pub first_event_hash: Option<String>,
    pub last_event_hash: Option<String>,
    pub broken_event_id: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditWormArchiveReport {
    pub status: AuditWormArchiveStatus,
    pub realm_id: Option<String>,
    pub event_count: usize,
    pub manifest: Option<AuditEvidenceManifest>,
    pub body_object: Option<AuditWormPutResult>,
    pub manifest_object: Option<AuditWormPutResult>,
    pub audit_event_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRetentionExecutionReport {
    pub status: AuditRetentionExecutionStatus,
    pub realm_id: Option<String>,
    pub chain_verification: AuditChainVerification,
    pub retention_plan: Option<AuditRetentionEnforcementPlan>,
    pub archive_report: Option<AuditWormArchiveReport>,
    pub purge_event_ids: Vec<String>,
    pub audit_event_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditWormArchiveStatus {
    Archived,
    SkippedNoEvents,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditRetentionExecutionStatus {
    Ready,
    SkippedNoPolicy,
    SkippedChainInvalid,
    SkippedLegalHold,
    SkippedNoExpiredEvents,
    SkippedArchiveRequired,
}

pub trait WormArchiveTransport {
    fn put_once(&self, object: AuditWormObject) -> Result<AuditWormPutResult, String>;
}

pub fn compliance_evidence_pack_from_audit_archive(
    tenant_id: &str,
    controls: Vec<String>,
    period_start: u64,
    period_end: u64,
    report: &AuditWormArchiveReport,
) -> QidResult<ComplianceEvidencePack> {
    if report.status != AuditWormArchiveStatus::Archived {
        return Err(QidError::BadRequest {
            message: "audit archive report must be archived before evidence packaging".to_string(),
        });
    }
    let manifest = report
        .manifest
        .as_ref()
        .ok_or_else(|| QidError::BadRequest {
            message: "audit archive report is missing manifest".to_string(),
        })?;
    let body_object = report
        .body_object
        .as_ref()
        .ok_or_else(|| QidError::BadRequest {
            message: "audit archive report is missing body object".to_string(),
        })?;
    if report.event_count == 0 || manifest.event_count == 0 {
        return Err(QidError::BadRequest {
            message: "audit evidence package requires archived events".to_string(),
        });
    }

    let tenant_id = tenant_id.trim();
    let pack = ComplianceEvidencePack {
        id: format!(
            "audit-evidence-{tenant_id}-{}-{}",
            manifest.generated_at,
            &manifest.body_sha256[..16]
        ),
        tenant_id: tenant_id.to_string(),
        period_start,
        period_end,
        controls,
        object_uri: body_object.location.clone(),
        sha256_hex: manifest.body_sha256.clone(),
        generated_at: manifest.generated_at,
    };
    pack.validate()?;
    Ok(pack)
}

pub fn verify_audit_evidence_archive(
    manifest: &AuditEvidenceManifest,
    body: &[u8],
) -> AuditEvidenceVerificationReport {
    let body_sha256 = hex_sha256(body);
    if body_sha256 != manifest.body_sha256 {
        return invalid_evidence_report(
            manifest,
            body_sha256,
            0,
            None,
            Some("body_sha256 mismatch".to_string()),
        );
    }

    let records = match parse_audit_export_jsonl(body) {
        Ok(records) => records,
        Err(error) => {
            return invalid_evidence_report(manifest, body_sha256, 0, None, Some(error));
        }
    };
    if records.len() != manifest.event_count {
        return invalid_evidence_report(
            manifest,
            body_sha256,
            records.len(),
            None,
            Some("event_count mismatch".to_string()),
        );
    }

    let Some((first, last)) = linked_export_bounds(&records) else {
        let broken_event_id = records.first().map(|record| record.id.clone());
        return invalid_evidence_report(
            manifest,
            body_sha256,
            records.len(),
            broken_event_id,
            Some("audit export chain is not contiguous".to_string()),
        );
    };

    let first_event_id = Some(first.id.clone());
    let last_event_id = Some(last.id.clone());
    let first_event_hash = first.event_hash.clone();
    let last_event_hash = last.event_hash.clone();
    if first_event_id != manifest.first_event_id
        || last_event_id != manifest.last_event_id
        || first_event_hash != manifest.first_event_hash
        || last_event_hash != manifest.last_event_hash
    {
        return AuditEvidenceVerificationReport {
            valid: false,
            event_count: records.len(),
            body_sha256,
            expected_body_sha256: manifest.body_sha256.clone(),
            first_event_id,
            last_event_id,
            first_event_hash,
            last_event_hash,
            broken_event_id: None,
            error: Some("manifest chain boundary mismatch".to_string()),
        };
    }

    AuditEvidenceVerificationReport {
        valid: true,
        event_count: records.len(),
        body_sha256: body_sha256.clone(),
        expected_body_sha256: manifest.body_sha256.clone(),
        first_event_id,
        last_event_id,
        first_event_hash,
        last_event_hash,
        broken_event_id: None,
        error: None,
    }
}

pub async fn run_audit_retention_job<R: Repository>(
    repo: &R,
    config: AuditRetentionJobConfig,
) -> QidResult<AuditRetentionJobReport> {
    let realm = config.realm_id.as_ref().map(|id| RealmId(id.clone()));
    let realm_ref = realm.as_ref();
    let chain_verification = repo.verify_audit_chain(realm_ref).await?;
    if !chain_verification.valid {
        return Ok(AuditRetentionJobReport {
            status: AuditRetentionJobStatus::SkippedChainInvalid,
            realm_id: config.realm_id,
            chain_verification,
            plan: None,
            audit_event_id: None,
        });
    }

    let Some(plan) = repo
        .plan_audit_retention(realm_ref, config.now_epoch)
        .await?
    else {
        return Ok(AuditRetentionJobReport {
            status: AuditRetentionJobStatus::SkippedNoPolicy,
            realm_id: config.realm_id,
            chain_verification,
            plan: None,
            audit_event_id: None,
        });
    };

    let audit_event_id = if config.record_audit_event {
        let event_id = Ulid::new().to_string();
        repo.append_audit_event(&AuditEvent {
            id: event_id.clone(),
            realm_id: config.realm_id.clone(),
            actor: config.actor,
            action: "audit_retention.evaluate".to_string(),
            target_type: "audit_retention".to_string(),
            target_id: config
                .realm_id
                .as_deref()
                .unwrap_or("__global__")
                .to_string(),
            reason: config.reason,
            metadata_json: serde_json::json!({
                "retention_days": plan.retention_days,
                "legal_hold": plan.legal_hold,
                "cutoff_epoch": plan.cutoff_epoch,
                "checked_events": plan.checked_events,
                "expired_count": plan.expired_event_ids.len(),
                "retained_count": plan.retained_event_ids.len(),
                "expired_event_ids": plan.expired_event_ids,
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

    Ok(AuditRetentionJobReport {
        status: AuditRetentionJobStatus::Evaluated,
        realm_id: config.realm_id,
        chain_verification,
        plan: Some(plan),
        audit_event_id,
    })
}

pub async fn run_audit_siem_delivery_job<R, T>(
    repo: &R,
    transport: &T,
    config: AuditSiemDeliveryConfig,
) -> QidResult<AuditSiemDeliveryReport>
where
    R: Repository,
    T: SiemWebhookTransport,
{
    if !config.endpoint_url.starts_with("https://") {
        return Err(QidError::Config {
            message: format!(
                "SIEM webhook endpoint_url must use https:// scheme, got: {}",
                config.endpoint_url
            ),
        });
    }
    let realm = config.realm_id.as_ref().map(|id| RealmId(id.clone()));
    let events = repo.list_audit_events(realm.as_ref(), config.limit).await?;
    if events.is_empty() {
        return Ok(AuditSiemDeliveryReport {
            status: AuditSiemDeliveryStatus::SkippedNoEvents,
            delivery_id: None,
            realm_id: config.realm_id,
            event_count: 0,
            endpoint_url: config.endpoint_url,
            http_status: None,
            retry: AuditSiemRetryDecision {
                retry: false,
                attempt: config.completed_attempts + 1,
                delay_ms: None,
                first_error: None,
            },
            audit_event_id: None,
        });
    }

    let export_options = AuditExportOptions {
        include_metadata: config.include_metadata,
        traceparent: config.traceparent.clone(),
        audit_correlation_id: config.audit_correlation_id.clone(),
    };
    let payload = siem_webhook_payload(&events, &export_options, config.now_epoch);
    let delivery_id = format!(
        "siem-{}",
        qid_core::util::sha256_base64url(
            format!(
                "{}|{}|{}|{}",
                config.realm_id.as_deref().unwrap_or("global"),
                config.endpoint_url,
                config.now_epoch,
                payload["event_count"].as_u64().unwrap_or_default()
            )
            .as_bytes()
        )
    );
    repo.upsert_siem_delivery(&SiemDeliveryRecord {
        id: delivery_id.clone(),
        realm_id: config.realm_id.clone(),
        endpoint_url: config.endpoint_url.clone(),
        payload_json: payload.clone(),
        attempts: config.completed_attempts,
        next_retry_at: Some(config.now_epoch),
        status: SiemDeliveryStatus::Pending,
        last_error: None,
        created_at: config.now_epoch,
        updated_at: config.now_epoch,
    })
    .await?;
    let body = serde_json::to_vec(&payload).map_err(|e| qid_core::error::QidError::Internal {
        message: e.to_string(),
    })?;
    let response = transport.send(AuditSiemHttpRequest {
        method: "POST".to_string(),
        url: config.endpoint_url.clone(),
        headers: siem_delivery_headers(&config, body.len()),
        body,
    });

    let (status, http_status, retry) = match response {
        Ok(response) if (200..300).contains(&response.status) => (
            AuditSiemDeliveryStatus::Delivered,
            Some(response.status),
            AuditSiemRetryDecision {
                retry: false,
                attempt: config.completed_attempts + 1,
                delay_ms: None,
                first_error: None,
            },
        ),
        Ok(response) => {
            let retry = plan_siem_retry(
                config.retry_policy,
                config.completed_attempts,
                response.status,
            );
            let status = if retry.retry {
                AuditSiemDeliveryStatus::FailedRetryable
            } else {
                AuditSiemDeliveryStatus::FailedPermanent
            };
            (status, Some(response.status), retry)
        }
        Err(e) => {
            let first_error = Some(e.to_string());
            let mut retry = plan_siem_retry(config.retry_policy, config.completed_attempts, 503);
            retry.first_error = first_error;
            let status = if retry.retry {
                AuditSiemDeliveryStatus::FailedRetryable
            } else {
                AuditSiemDeliveryStatus::FailedPermanent
            };
            (status, None, retry)
        }
    };
    let queue_status = match status {
        AuditSiemDeliveryStatus::Delivered => SiemDeliveryStatus::Delivered,
        AuditSiemDeliveryStatus::FailedRetryable => SiemDeliveryStatus::Pending,
        AuditSiemDeliveryStatus::FailedPermanent => SiemDeliveryStatus::Dead,
        AuditSiemDeliveryStatus::SkippedNoEvents => SiemDeliveryStatus::Pending,
    };
    let next_retry_at = retry
        .delay_ms
        .map(|delay_ms| config.now_epoch.saturating_add(delay_ms.div_ceil(1_000)));
    repo.mark_siem_delivery_status(
        &delivery_id,
        queue_status,
        retry.attempt,
        next_retry_at,
        retry.first_error.as_deref(),
        config.now_epoch,
    )
    .await?;

    let event_count = events.len();
    let audit_event_id = if config.record_audit_event {
        let event_id = Ulid::new().to_string();
        repo.append_audit_event(&AuditEvent {
            id: event_id.clone(),
            realm_id: config.realm_id.clone(),
            actor: config.actor,
            action: "audit_siem.deliver".to_string(),
            target_type: "audit_siem".to_string(),
            target_id: config.endpoint_url.clone(),
            reason: config.reason,
            metadata_json: serde_json::json!({
                "status": status,
                "delivery_id": delivery_id,
                "event_count": event_count,
                "http_status": http_status,
                "retry": retry,
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

    Ok(AuditSiemDeliveryReport {
        status,
        delivery_id: Some(delivery_id),
        realm_id: config.realm_id,
        event_count,
        endpoint_url: config.endpoint_url,
        http_status,
        retry,
        audit_event_id,
    })
}

pub async fn run_audit_siem_redrive_job<R, T>(
    repo: &R,
    transport: &T,
    config: AuditSiemRedriveConfig,
) -> QidResult<AuditSiemDeliveryReport>
where
    R: Repository,
    T: SiemWebhookTransport,
{
    let delivery = repo
        .get_siem_delivery(&config.delivery_id)
        .await?
        .ok_or_else(|| QidError::NotFound {
            resource: format!("siem delivery {}", config.delivery_id),
        })?;
    if delivery.endpoint_url.is_empty() || !delivery.endpoint_url.starts_with("https://") {
        return Err(QidError::Config {
            message: format!(
                "SIEM webhook endpoint_url must use https:// scheme, got: {}",
                delivery.endpoint_url
            ),
        });
    }
    let body = serde_json::to_vec(&delivery.payload_json).map_err(|e| QidError::Internal {
        message: e.to_string(),
    })?;
    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("content-length".to_string(), body.len().to_string());
    headers.insert(
        "x-qid-event-type".to_string(),
        "qid.audit.webhook.v1".to_string(),
    );
    let response = transport.send(AuditSiemHttpRequest {
        method: "POST".to_string(),
        url: delivery.endpoint_url.clone(),
        headers,
        body,
    });
    let (status, http_status, retry) = match response {
        Ok(response) if (200..300).contains(&response.status) => (
            AuditSiemDeliveryStatus::Delivered,
            Some(response.status),
            AuditSiemRetryDecision {
                retry: false,
                attempt: delivery.attempts + 1,
                delay_ms: None,
                first_error: None,
            },
        ),
        Ok(response) => {
            let retry = plan_siem_retry(config.retry_policy, delivery.attempts, response.status);
            let status = if retry.retry {
                AuditSiemDeliveryStatus::FailedRetryable
            } else {
                AuditSiemDeliveryStatus::FailedPermanent
            };
            (status, Some(response.status), retry)
        }
        Err(e) => {
            let mut retry = plan_siem_retry(config.retry_policy, delivery.attempts, 503);
            retry.first_error = Some(e);
            let status = if retry.retry {
                AuditSiemDeliveryStatus::FailedRetryable
            } else {
                AuditSiemDeliveryStatus::FailedPermanent
            };
            (status, None, retry)
        }
    };
    let queue_status = match status {
        AuditSiemDeliveryStatus::Delivered => SiemDeliveryStatus::Delivered,
        AuditSiemDeliveryStatus::FailedRetryable => SiemDeliveryStatus::Pending,
        AuditSiemDeliveryStatus::FailedPermanent => SiemDeliveryStatus::Dead,
        AuditSiemDeliveryStatus::SkippedNoEvents => SiemDeliveryStatus::Pending,
    };
    let next_retry_at = retry
        .delay_ms
        .map(|delay_ms| config.now_epoch.saturating_add(delay_ms.div_ceil(1_000)));
    repo.mark_siem_delivery_status(
        &delivery.id,
        queue_status,
        retry.attempt,
        next_retry_at,
        retry.first_error.as_deref(),
        config.now_epoch,
    )
    .await?;
    let event_count = delivery
        .payload_json
        .get("event_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default() as usize;
    let audit_event_id = if config.record_audit_event {
        let event_id = Ulid::new().to_string();
        repo.append_audit_event(&AuditEvent {
            id: event_id.clone(),
            realm_id: delivery.realm_id.clone(),
            actor: config.actor,
            action: "audit_siem.redrive".to_string(),
            target_type: "audit_siem".to_string(),
            target_id: delivery.id.clone(),
            reason: config.reason,
            metadata_json: serde_json::json!({
                "status": status,
                "delivery_id": delivery.id.clone(),
                "event_count": event_count,
                "http_status": http_status,
                "retry": retry,
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

    Ok(AuditSiemDeliveryReport {
        status,
        delivery_id: Some(config.delivery_id),
        realm_id: delivery.realm_id,
        event_count,
        endpoint_url: delivery.endpoint_url,
        http_status,
        retry,
        audit_event_id,
    })
}

pub async fn run_audit_worm_archive_job<R, T>(
    repo: &R,
    transport: &T,
    config: AuditWormArchiveConfig,
) -> QidResult<AuditWormArchiveReport>
where
    R: Repository,
    T: WormArchiveTransport,
{
    let realm = config.realm_id.as_ref().map(|id| RealmId(id.clone()));
    let events = repo.list_audit_events(realm.as_ref(), config.limit).await?;
    if events.is_empty() {
        return Ok(AuditWormArchiveReport {
            status: AuditWormArchiveStatus::SkippedNoEvents,
            realm_id: config.realm_id,
            event_count: 0,
            manifest: None,
            body_object: None,
            manifest_object: None,
            audit_event_id: None,
        });
    }

    let export_options = AuditExportOptions {
        include_metadata: config.include_metadata,
        traceparent: None,
        audit_correlation_id: None,
    };
    let body = export_jsonl(&events, &export_options)
        .map_err(|e| QidError::Internal {
            message: e.to_string(),
        })?
        .into_bytes();
    let archive_id = Ulid::new().to_string();
    let stream = config.realm_id.as_deref().unwrap_or("__global__");
    let body_key = format!("audit/{stream}/{}/{}.jsonl", config.now_epoch, archive_id);
    let manifest_key = format!(
        "audit/{stream}/{}/{}.manifest.json",
        config.now_epoch, archive_id
    );
    let manifest = AuditEvidenceManifest {
        schema_version: "qid.audit.evidence.v1".to_string(),
        realm_id: config.realm_id.clone(),
        generated_at: config.now_epoch,
        event_count: events.len(),
        first_event_id: events.last().map(|event| event.id.clone()),
        last_event_id: events.first().map(|event| event.id.clone()),
        first_event_hash: events.last().and_then(|event| event.event_hash.clone()),
        last_event_hash: events.first().and_then(|event| event.event_hash.clone()),
        body_sha256: hex_sha256(&body),
        body_key: body_key.clone(),
    };

    let body_object = transport
        .put_once(AuditWormObject {
            key: body_key.clone(),
            content_type: "application/x-ndjson".to_string(),
            body,
            metadata: archive_metadata(&config, "body"),
        })
        .map_err(|e| QidError::Storage { message: e })?;
    let manifest_body = serde_json::to_vec(&manifest).map_err(|e| QidError::Internal {
        message: e.to_string(),
    })?;
    let manifest_object = transport
        .put_once(AuditWormObject {
            key: manifest_key,
            content_type: "application/json".to_string(),
            body: manifest_body,
            metadata: archive_metadata(&config, "manifest"),
        })
        .map_err(|e| QidError::Storage { message: e })?;

    let audit_event_id = if config.record_audit_event {
        let event_id = Ulid::new().to_string();
        repo.append_audit_event(&AuditEvent {
            id: event_id.clone(),
            realm_id: config.realm_id.clone(),
            actor: config.actor,
            action: "audit_worm.archive".to_string(),
            target_type: "audit_worm".to_string(),
            target_id: body_key,
            reason: config.reason,
            metadata_json: serde_json::json!({
                "event_count": manifest.event_count,
                "body_sha256": manifest.body_sha256,
                "body_location": body_object.location,
                "manifest_location": manifest_object.location,
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

    Ok(AuditWormArchiveReport {
        status: AuditWormArchiveStatus::Archived,
        realm_id: config.realm_id,
        event_count: manifest.event_count,
        manifest: Some(manifest),
        body_object: Some(body_object),
        manifest_object: Some(manifest_object),
        audit_event_id,
    })
}

pub async fn run_audit_retention_execution_job<R, T>(
    repo: &R,
    archive_transport: &T,
    config: AuditRetentionExecutionConfig,
) -> QidResult<AuditRetentionExecutionReport>
where
    R: Repository,
    T: WormArchiveTransport,
{
    let realm = config.realm_id.as_ref().map(|id| RealmId(id.clone()));
    let realm_ref = realm.as_ref();
    let chain_verification = repo.verify_audit_chain(realm_ref).await?;
    if !chain_verification.valid {
        return Ok(AuditRetentionExecutionReport {
            status: AuditRetentionExecutionStatus::SkippedChainInvalid,
            realm_id: config.realm_id,
            chain_verification,
            retention_plan: None,
            archive_report: None,
            purge_event_ids: Vec::new(),
            audit_event_id: None,
        });
    }

    let Some(retention_plan) = repo
        .plan_audit_retention(realm_ref, config.now_epoch)
        .await?
    else {
        return Ok(AuditRetentionExecutionReport {
            status: AuditRetentionExecutionStatus::SkippedNoPolicy,
            realm_id: config.realm_id,
            chain_verification,
            retention_plan: None,
            archive_report: None,
            purge_event_ids: Vec::new(),
            audit_event_id: None,
        });
    };

    if retention_plan.legal_hold {
        return Ok(AuditRetentionExecutionReport {
            status: AuditRetentionExecutionStatus::SkippedLegalHold,
            realm_id: config.realm_id,
            chain_verification,
            retention_plan: Some(retention_plan),
            archive_report: None,
            purge_event_ids: Vec::new(),
            audit_event_id: None,
        });
    }

    if retention_plan.expired_event_ids.is_empty() {
        return Ok(AuditRetentionExecutionReport {
            status: AuditRetentionExecutionStatus::SkippedNoExpiredEvents,
            realm_id: config.realm_id,
            chain_verification,
            retention_plan: Some(retention_plan),
            archive_report: None,
            purge_event_ids: Vec::new(),
            audit_event_id: None,
        });
    }

    let archive_report = if config.archive_required {
        let archive_report = run_audit_worm_archive_job(
            repo,
            archive_transport,
            AuditWormArchiveConfig {
                realm_id: config.realm_id.clone(),
                limit: retention_plan.checked_events,
                now_epoch: config.now_epoch,
                include_metadata: config.include_metadata_in_archive,
                actor: config.actor.clone(),
                reason: config.reason.clone(),
                record_audit_event: true,
            },
        )
        .await?;
        if archive_report.status != AuditWormArchiveStatus::Archived {
            return Ok(AuditRetentionExecutionReport {
                status: AuditRetentionExecutionStatus::SkippedArchiveRequired,
                realm_id: config.realm_id,
                chain_verification,
                retention_plan: Some(retention_plan),
                archive_report: Some(archive_report),
                purge_event_ids: Vec::new(),
                audit_event_id: None,
            });
        }
        Some(archive_report)
    } else {
        None
    };

    let purge_event_ids = retention_plan.expired_event_ids.clone();
    let audit_event_id = if config.record_audit_event {
        let event_id = Ulid::new().to_string();
        repo.append_audit_event(&AuditEvent {
            id: event_id.clone(),
            realm_id: config.realm_id.clone(),
            actor: config.actor,
            action: "audit_retention.ready".to_string(),
            target_type: "audit_retention".to_string(),
            target_id: config
                .realm_id
                .as_deref()
                .unwrap_or("__global__")
                .to_string(),
            reason: config.reason,
            metadata_json: serde_json::json!({
                "purge_event_ids": purge_event_ids,
                "purge_count": purge_event_ids.len(),
                "archive_required": config.archive_required,
                "archive_body_location": archive_report
                    .as_ref()
                    .and_then(|report| report.body_object.as_ref())
                    .map(|object| object.location.clone()),
                "archive_manifest_location": archive_report
                    .as_ref()
                    .and_then(|report| report.manifest_object.as_ref())
                    .map(|object| object.location.clone()),
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

    Ok(AuditRetentionExecutionReport {
        status: AuditRetentionExecutionStatus::Ready,
        realm_id: config.realm_id,
        chain_verification,
        retention_plan: Some(retention_plan),
        archive_report,
        purge_event_ids,
        audit_event_id,
    })
}

pub fn plan_siem_retry(
    policy: AuditSiemRetryPolicy,
    completed_attempts: u32,
    status: u16,
) -> AuditSiemRetryDecision {
    let attempt = completed_attempts + 1;
    let retryable_status = status == 429 || (500..600).contains(&status);
    if !retryable_status || attempt >= policy.max_attempts {
        return AuditSiemRetryDecision {
            retry: false,
            attempt,
            delay_ms: None,
            first_error: None,
        };
    }

    let multiplier = 1_u64.checked_shl(completed_attempts).unwrap_or(u64::MAX);
    let delay_ms = policy
        .base_delay_ms
        .saturating_mul(multiplier)
        .min(policy.max_delay_ms);
    AuditSiemRetryDecision {
        retry: true,
        attempt,
        delay_ms: Some(delay_ms),
        first_error: None,
    }
}

fn siem_delivery_headers(
    config: &AuditSiemDeliveryConfig,
    content_length: usize,
) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("content-length".to_string(), content_length.to_string());
    headers.insert(
        "x-qid-event-type".to_string(),
        "qid.audit.webhook.v1".to_string(),
    );
    if let Some(traceparent) = &config.traceparent {
        headers.insert("traceparent".to_string(), traceparent.clone());
    }
    if let Some(correlation_id) = &config.audit_correlation_id {
        headers.insert(
            "x-qid-audit-correlation-id".to_string(),
            correlation_id.clone(),
        );
    }
    headers
}

fn archive_metadata(config: &AuditWormArchiveConfig, kind: &str) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert("qid-object-kind".to_string(), kind.to_string());
    metadata.insert("qid-generated-at".to_string(), config.now_epoch.to_string());
    metadata.insert(
        "qid-realm-id".to_string(),
        config
            .realm_id
            .clone()
            .unwrap_or_else(|| "__global__".to_string()),
    );
    metadata
}

fn parse_audit_export_jsonl(body: &[u8]) -> Result<Vec<AuditExportRecord>, String> {
    let raw = std::str::from_utf8(body).map_err(|e| format!("audit body is not UTF-8: {e}"))?;
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<AuditExportRecord>(line)
                .map_err(|e| format!("invalid audit export record: {e}"))
        })
        .collect()
}

fn linked_export_bounds(
    records: &[AuditExportRecord],
) -> Option<(&AuditExportRecord, &AuditExportRecord)> {
    if records.is_empty() {
        return None;
    }
    let mut by_previous_hash: BTreeMap<Option<String>, &AuditExportRecord> = BTreeMap::new();
    for record in records {
        record.event_hash.as_ref()?;
        if by_previous_hash
            .insert(record.previous_hash.clone(), record)
            .is_some()
        {
            return None;
        }
    }
    let first = by_previous_hash.get(&None).copied()?;
    let mut current = first;
    let mut checked = 1;
    while let Some(current_hash) = current.event_hash.clone() {
        let Some(next) = by_previous_hash.get(&Some(current_hash)).copied() else {
            break;
        };
        current = next;
        checked += 1;
    }
    (checked == records.len()).then_some((first, current))
}

fn invalid_evidence_report(
    manifest: &AuditEvidenceManifest,
    body_sha256: String,
    event_count: usize,
    broken_event_id: Option<String>,
    error: Option<String>,
) -> AuditEvidenceVerificationReport {
    AuditEvidenceVerificationReport {
        valid: false,
        event_count,
        body_sha256,
        expected_body_sha256: manifest.body_sha256.clone(),
        first_event_id: None,
        last_event_id: None,
        first_event_hash: None,
        last_event_hash: None,
        broken_event_id,
        error,
    }
}
