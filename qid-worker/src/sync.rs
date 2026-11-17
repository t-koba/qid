use qid_core::{
    config::{DIRECTORY_SYNC_PROVIDER_TYPES, DirectoryProviderConfig, QidConfig},
    error::{QidError, QidResult},
    models::AuditEvent,
};
use qid_directory::connector::{DirectoryConnector, LdapDirectoryConnector};
use qid_storage::{AnyRepository, prelude::*};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub use crate::outbound::*;

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
    Failed,
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

/// The error a directory sync reports for a failed fetch. The connector's
/// own kind is kept, so an operator configuration fault stays a
/// configuration fault, and the fetch context is added to every kind.
pub(crate) fn directory_fetch_error(err: QidError) -> QidError {
    let message = format!("directory fetch failed: {err}");
    match err {
        QidError::Config { .. } => QidError::Config { message },
        QidError::Crypto { .. } => QidError::Crypto { message },
        QidError::Storage { .. } => QidError::Storage { message },
        QidError::NotFound { .. } => QidError::NotFound { resource: message },
        QidError::Unauthorized { .. } => QidError::Unauthorized { message },
        QidError::BadRequest { .. } => QidError::BadRequest { message },
        QidError::Internal { .. } => QidError::Internal { message },
        QidError::TooManyRequests { .. } => QidError::TooManyRequests { message },
        QidError::AttemptBudgetSpent { .. } => QidError::AttemptBudgetSpent { message },
        QidError::Conflict { .. } => QidError::Conflict { message },
        QidError::DpopNonce { .. } => QidError::DpopNonce { message },
    }
}

/// Whether a worker command report describes a failure that must abort the
/// process. Delivery jobs use `failed_retryable` and `failed_permanent`, so
/// only an exact `failed` comparison would let an authoritative delivery
/// failure exit successfully.
pub fn sync_failed(result: &serde_json::Value) -> bool {
    result["report"]["status"]
        .as_str()
        .is_some_and(|status| status == "failed" || status.starts_with("failed_"))
        || result["report"]["failed"].as_u64().is_some_and(|n| n > 0)
        || result["report"]["errors"]
            .as_array()
            .is_some_and(|errors| !errors.is_empty())
}

/// The connector a directory sync job fetches through.
///
/// Production uses the LDAP connector. A caller injects its own so the
/// fetch and its fault classification are the same code in every build.
pub(crate) type DirectoryConnectorFactory =
    Box<dyn Fn() -> Box<dyn DirectoryConnector> + Send + Sync>;

/// Run a directory sync job against a configured directory provider.
pub async fn run_directory_sync_job(
    repo: Arc<AnyRepository>,
    qid_config: &QidConfig,
    config: DirectorySyncJobConfig,
) -> QidResult<DirectorySyncJobReport> {
    run_directory_sync_job_with_connector(
        repo,
        qid_config,
        config,
        Box::new(|| Box::new(LdapDirectoryConnector::new()) as Box<dyn DirectoryConnector>),
    )
    .await
}

/// Run a directory sync job against a configured directory provider with an
/// injected connector.
///
/// The fetch, the fault classification, and the sync are the production
/// ones; only the connector differs.
pub(crate) async fn run_directory_sync_job_with_connector(
    repo: Arc<AnyRepository>,
    qid_config: &QidConfig,
    config: DirectorySyncJobConfig,
    connector_factory: DirectoryConnectorFactory,
) -> QidResult<DirectorySyncJobReport> {
    if config.dry_run {
        return Err(QidError::BadRequest {
            message: "directory sync dry-run is not supported; refusing to run because sync can mutate user state".to_string(),
        });
    }

    let provider = match find_directory_provider(qid_config, &config.realm_id, &config.provider_id)
    {
        Ok(provider) => provider,
        Err(e) => {
            let skipped = matches!(e, QidError::Config { .. });
            return Ok(DirectorySyncJobReport {
                status: if skipped {
                    DirectorySyncJobStatus::SkippedDisabled
                } else {
                    DirectorySyncJobStatus::Failed
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
    if !DIRECTORY_SYNC_PROVIDER_TYPES.contains(&provider.provider_type.as_str()) {
        return Err(QidError::Config {
            message: format!(
                "directory provider '{}' has unsupported type '{}'",
                provider.id, provider.provider_type
            ),
        });
    }
    if provider.provider_type == "csv" {
        return run_csv_directory_sync_job(repo, qid_config, &config, provider).await;
    }
    let mut connector = connector_factory();
    connector.connect(&provider.connection).await?;
    let sync_config = provider.sync.clone();
    let mapping = provider.attribute_mapping.clone();

    let entries = connector
        .fetch_users(&sync_config, &mapping)
        .await
        .map_err(directory_fetch_error)?;
    connector.disconnect().await.ok();

    // The directory job issues no token, so it holds no signing key: a key
    // in the source is a credential every reader of the source holds.
    let signer = Arc::new(qid_core::jwt::NoSigningKey);
    let state: qid_core::state::SharedState<AnyRepository> =
        qid_core::state::SharedState::new(qid_config.clone(), repo, signer, serde_json::json!({}))
            .map_err(|e| QidError::Internal {
                message: format!("failed to initialize state: {e}"),
            })?;

    let result = qid_directory::sync_ldap_entries(
        &state,
        &config.realm_id,
        &provider.id,
        &entries,
        qid_directory::LdapSyncOptions {
            deactivate_missing: provider.sync.deactivate_missing.unwrap_or(true),
            synced_at: config.now_epoch,
        },
    )
    .await?;

    let (audit_event_id, audit_error) = record_directory_sync_audit(
        &state.repo,
        &config,
        result.created_user_ids.len() as u64,
        result.updated_user_ids.len() as u64,
        result.unchanged_user_ids.len() as u64,
        result.deactivated_user_ids.len() as u64,
        result.break_glass_skipped_user_ids.len() as u64,
    )
    .await;

    Ok(DirectorySyncJobReport {
        status: DirectorySyncJobStatus::Completed,
        provider_id: config.provider_id,
        created: result.created_user_ids.len() as u64,
        updated: result.updated_user_ids.len() as u64,
        unchanged: result.unchanged_user_ids.len() as u64,
        deactivated: result.deactivated_user_ids.len() as u64,
        skipped_break_glass: result.break_glass_skipped_user_ids.len() as u64,
        errors: audit_error.into_iter().collect(),
        audit_event_id,
        dry_run: config.dry_run,
    })
}

/// Run a directory sync job for a CSV HR provider: the whole configured file
/// is parsed before any write, then the HR lifecycle importer owns the
/// joiner/mover/leaver semantics. `deactivate_missing` is an LDAP snapshot
/// semantic and does not apply to an HR event batch.
async fn run_csv_directory_sync_job(
    repo: Arc<AnyRepository>,
    qid_config: &QidConfig,
    config: &DirectorySyncJobConfig,
    provider: &DirectoryProviderConfig,
) -> QidResult<DirectorySyncJobReport> {
    let records = qid_directory::csv::read_csv_hr_records(
        provider.connection.url.trim(),
        provider.connection.max_entries,
    )
    .await
    .map_err(directory_fetch_error)?;

    // The directory job issues no token, so it holds no signing key: a key
    // in the source is a credential every reader of the source holds.
    let signer = Arc::new(qid_core::jwt::NoSigningKey);
    let state: qid_core::state::SharedState<AnyRepository> =
        qid_core::state::SharedState::new(qid_config.clone(), repo, signer, serde_json::json!({}))
            .map_err(|e| QidError::Internal {
                message: format!("failed to initialize state: {e}"),
            })?;

    let results = qid_directory::import_hr_records(&state, &config.realm_id, records).await?;
    let count = |action: qid_directory::HrImportAction| {
        results.iter().filter(|r| r.action == action).count() as u64
    };
    let created = count(qid_directory::HrImportAction::Created);
    let updated = count(qid_directory::HrImportAction::Updated);
    let deactivated = count(qid_directory::HrImportAction::Deprovisioned);
    let (audit_event_id, audit_error) =
        record_directory_sync_audit(&state.repo, config, created, updated, 0, deactivated, 0).await;

    Ok(DirectorySyncJobReport {
        status: DirectorySyncJobStatus::Completed,
        provider_id: config.provider_id.clone(),
        created,
        updated,
        unchanged: 0,
        deactivated,
        skipped_break_glass: 0,
        errors: audit_error.into_iter().collect(),
        audit_event_id,
        dry_run: config.dry_run,
    })
}

/// Persist the `directory.sync` audit event with the job counters, so LDAP
/// and CSV providers report identically. A failed append still reports that
/// the sync mutations may already have occurred.
async fn record_directory_sync_audit(
    repo: &AnyRepository,
    config: &DirectorySyncJobConfig,
    created: u64,
    updated: u64,
    unchanged: u64,
    deactivated: u64,
    skipped_break_glass: u64,
) -> (Option<String>, Option<String>) {
    if !config.record_audit_event {
        return (None, None);
    }
    let event_id = ulid::Ulid::new().to_string();
    match repo
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
                "created": created,
                "updated": updated,
                "unchanged": unchanged,
                "deactivated": deactivated,
                "skipped_break_glass": skipped_break_glass,
                "dry_run": config.dry_run,
            }),
            created_at: config.now_epoch,
            previous_hash: None,
            event_hash: None,
        })
        .await
    {
        Ok(()) => (Some(event_id), None),
        Err(e) => (
            None,
            Some(format!(
                "failed to persist directory sync audit event: {e}; directory sync mutations may already have occurred"
            )),
        ),
    }
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
    // Realm-level kill switch: when `directory.enabled` is false, report
    // `SkippedDisabled` before any provider connection, fetch, sync, or audit.
    if !realm.protocols.directory.enabled {
        return Err(QidError::Config {
            message: format!("directory sync is disabled in realm {realm_id}"),
        });
    }
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
