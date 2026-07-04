use anyhow::{Context, ensure};
use clap::{Parser, Subcommand};
use qid_core::{config::QidConfig, util::now_seconds};
use qid_ops::{KeyPurpose, KeyRotationRequirement, KeyringInventoryRecord};
use qid_storage::AnyRepository;
use qid_worker::{
    AuditRetentionExecutionConfig, AuditRetentionJobConfig, AuditSiemDeliveryConfig,
    AuditSiemHttpRequest, AuditSiemHttpResponse, AuditSiemRetryPolicy, AuditWormArchiveConfig,
    AuditWormObject, AuditWormPutResult, DirectorySyncJobConfig, KeyRotationPlanningJobConfig,
    NotificationChannel, NotificationDeliveryConfig, NotificationRequest, NotificationResponse,
    NotificationRetryPolicy, NotificationTransport, SiemWebhookTransport, WormArchiveTransport,
    run_audit_retention_execution_job, run_audit_retention_job, run_audit_siem_delivery_job,
    run_audit_worm_archive_job, run_directory_sync_job, run_key_rotation_planning_job,
    run_notification_delivery_job,
};
use std::{
    cell::RefCell,
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

#[derive(Parser)]
#[command(name = "qid-worker")]
#[command(about = "qid asynchronous job worker")]
pub(crate) struct Args {
    #[arg(short, long, global = true, default_value = "/etc/qid/qid.yaml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Evaluate audit retention policy and optionally record an audit event.
    #[command(name = "audit-retention-evaluate")]
    RetentionEvaluate {
        #[arg(long)]
        realm: Option<String>,
        #[arg(long, default_value = "qid-worker")]
        actor: String,
        #[arg(long, default_value = "scheduled retention evaluation")]
        reason: String,
        #[arg(long)]
        now: Option<u64>,
        #[arg(long, default_value_t = true)]
        record_audit_event: bool,
    },
    /// Evaluate retention, archive when required, and report purge-ready ids.
    #[command(name = "audit-retention-execute")]
    RetentionExecute {
        #[arg(long)]
        realm: Option<String>,
        #[arg(long)]
        archive_dir: PathBuf,
        #[arg(long, default_value = "qid-worker")]
        actor: String,
        #[arg(long, default_value = "scheduled retention execution")]
        reason: String,
        #[arg(long)]
        now: Option<u64>,
        #[arg(long, default_value_t = true)]
        archive_required: bool,
        #[arg(long, default_value_t = true)]
        include_metadata_in_archive: bool,
        #[arg(long, default_value_t = true)]
        record_audit_event: bool,
    },
    /// Export recent audit events to an append-only local WORM archive directory.
    #[command(name = "audit-worm-archive")]
    WormArchive {
        #[arg(long)]
        realm: Option<String>,
        #[arg(long)]
        archive_dir: PathBuf,
        #[arg(long, default_value_t = 1000)]
        limit: usize,
        #[arg(long, default_value = "qid-worker")]
        actor: String,
        #[arg(long, default_value = "scheduled audit archive")]
        reason: String,
        #[arg(long)]
        now: Option<u64>,
        #[arg(long, default_value_t = true)]
        include_metadata: bool,
        #[arg(long, default_value_t = true)]
        record_audit_event: bool,
    },
    /// Build and deliver a SIEM webhook payload through a deterministic local transport.
    #[command(name = "audit-siem-deliver")]
    SiemDeliver {
        #[arg(long)]
        realm: Option<String>,
        #[arg(long)]
        endpoint_url: String,
        #[arg(long)]
        request_output: Option<PathBuf>,
        #[arg(long, default_value_t = 202)]
        dry_run_status: u16,
        #[arg(long, default_value_t = 1000)]
        limit: usize,
        #[arg(long)]
        now: Option<u64>,
        #[arg(long)]
        traceparent: Option<String>,
        #[arg(long)]
        audit_correlation_id: Option<String>,
        #[arg(long, default_value_t = true)]
        include_metadata: bool,
        #[arg(long, default_value = "qid-worker")]
        actor: String,
        #[arg(long, default_value = "scheduled siem delivery")]
        reason: String,
        #[arg(long, default_value_t = true)]
        record_audit_event: bool,
        #[arg(long, default_value_t = 0)]
        completed_attempts: u32,
        #[arg(long, default_value_t = 5)]
        max_attempts: u32,
        #[arg(long, default_value_t = 1000)]
        base_delay_ms: u64,
        #[arg(long, default_value_t = 60000)]
        max_delay_ms: u64,
    },
    /// Deliver an email or push notification through a deterministic local transport.
    #[command(name = "notification-deliver")]
    NotificationDeliver {
        #[arg(long)]
        realm: Option<String>,
        #[arg(long)]
        channel: String,
        #[arg(long)]
        provider: String,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        subject: Option<String>,
        #[arg(long)]
        body: String,
        #[arg(long)]
        template_id: Option<String>,
        #[arg(long, default_value = "{}")]
        data_json: String,
        #[arg(long)]
        request_output: Option<PathBuf>,
        #[arg(long, default_value_t = 202)]
        dry_run_status: u16,
        #[arg(long)]
        now: Option<u64>,
        #[arg(long, default_value = "qid-worker")]
        actor: String,
        #[arg(long, default_value = "scheduled notification delivery")]
        reason: String,
        #[arg(long, default_value_t = true)]
        record_audit_event: bool,
        #[arg(long, default_value_t = 0)]
        completed_attempts: u32,
        #[arg(long, default_value_t = 5)]
        max_attempts: u32,
        #[arg(long, default_value_t = 1000)]
        base_delay_ms: u64,
        #[arg(long, default_value_t = 60000)]
        max_delay_ms: u64,
    },
    /// Synchronize a directory provider (LDAP/AD/SCIM) into the local user store.
    #[command(name = "directory-sync")]
    DirectorySync {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        provider_id: String,
        #[arg(long, default_value = "qid-worker")]
        actor: String,
        #[arg(long, default_value = "scheduled directory sync")]
        reason: String,
        #[arg(long)]
        now: Option<u64>,
        #[arg(long, default_value_t = true)]
        record_audit_event: bool,
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Plan key rotation actions and record an operational audit event.
    #[command(name = "key-rotation-plan")]
    KeyRotationPlan {
        /// Inventory record: realm,keyring,kid,purpose,signer_type,created,not_before,retire_after[,revoked].
        #[arg(long = "inventory", required = true)]
        inventory: Vec<String>,
        /// Requirement: realm,purpose,max_age_days,overlap_days,require_remote,require_dedicated.
        #[arg(long = "requirement", required = true)]
        requirement: Vec<String>,
        #[arg(long, default_value = "qid-worker")]
        actor: String,
        #[arg(long, default_value = "scheduled key rotation planning")]
        reason: String,
        #[arg(long)]
        now: Option<u64>,
        #[arg(long, default_value_t = true)]
        record_audit_event: bool,
    },
}

pub(crate) async fn run(args: Args) -> anyhow::Result<serde_json::Value> {
    let repo = open_repo(&args.config).await?;
    match args.command {
        Command::RetentionEvaluate {
            realm,
            actor,
            reason,
            now,
            record_audit_event,
        } => {
            let report = run_audit_retention_job(
                repo.as_ref(),
                AuditRetentionJobConfig {
                    realm_id: realm,
                    actor,
                    reason,
                    now_epoch: now.unwrap_or_else(now_seconds),
                    record_audit_event,
                },
            )
            .await?;
            Ok(serde_json::json!({
                "command": "audit_retention_evaluate",
                "report": report,
            }))
        }
        Command::RetentionExecute {
            realm,
            archive_dir,
            actor,
            reason,
            now,
            archive_required,
            include_metadata_in_archive,
            record_audit_event,
        } => {
            let archive = LocalWormArchive::new(archive_dir)?;
            let report = run_audit_retention_execution_job(
                repo.as_ref(),
                &archive,
                AuditRetentionExecutionConfig {
                    realm_id: realm,
                    now_epoch: now.unwrap_or_else(now_seconds),
                    actor,
                    reason,
                    archive_required,
                    include_metadata_in_archive,
                    record_audit_event,
                },
            )
            .await?;
            Ok(serde_json::json!({
                "command": "audit_retention_execute",
                "report": report,
            }))
        }
        Command::WormArchive {
            realm,
            archive_dir,
            limit,
            actor,
            reason,
            now,
            include_metadata,
            record_audit_event,
        } => {
            ensure!(limit > 0, "limit must be greater than zero");
            let archive = LocalWormArchive::new(archive_dir)?;
            let report = run_audit_worm_archive_job(
                repo.as_ref(),
                &archive,
                AuditWormArchiveConfig {
                    realm_id: realm,
                    limit,
                    now_epoch: now.unwrap_or_else(now_seconds),
                    include_metadata,
                    actor,
                    reason,
                    record_audit_event,
                },
            )
            .await?;
            Ok(serde_json::json!({
                "command": "audit_worm_archive",
                "report": report,
            }))
        }
        Command::SiemDeliver {
            realm,
            endpoint_url,
            request_output,
            dry_run_status,
            limit,
            now,
            traceparent,
            audit_correlation_id,
            include_metadata,
            actor,
            reason,
            record_audit_event,
            completed_attempts,
            max_attempts,
            base_delay_ms,
            max_delay_ms,
        } => {
            ensure!(limit > 0, "limit must be greater than zero");
            ensure!(
                (100..=599).contains(&dry_run_status),
                "dry_run_status must be an HTTP status code"
            );
            let transport = DryRunSiemTransport::new(dry_run_status, request_output);
            let report = run_audit_siem_delivery_job(
                repo.as_ref(),
                &transport,
                AuditSiemDeliveryConfig {
                    realm_id: realm,
                    endpoint_url,
                    limit,
                    now_epoch: now.unwrap_or_else(now_seconds),
                    traceparent,
                    audit_correlation_id,
                    include_metadata,
                    actor,
                    reason,
                    record_audit_event,
                    completed_attempts,
                    retry_policy: AuditSiemRetryPolicy {
                        max_attempts,
                        base_delay_ms,
                        max_delay_ms,
                    },
                },
            )
            .await?;
            Ok(serde_json::json!({
                "command": "audit_siem_deliver",
                "request_output": transport.output_path(),
                "report": report,
            }))
        }
        Command::NotificationDeliver {
            realm,
            channel,
            provider,
            recipient,
            subject,
            body,
            template_id,
            data_json,
            request_output,
            dry_run_status,
            now,
            actor,
            reason,
            record_audit_event,
            completed_attempts,
            max_attempts,
            base_delay_ms,
            max_delay_ms,
        } => {
            ensure!(
                (100..=599).contains(&dry_run_status),
                "dry_run_status must be an HTTP status code"
            );
            let data_json = serde_json::from_str(&data_json).context("invalid data_json")?;
            let transport = DryRunNotificationTransport::new(dry_run_status, request_output);
            let report = run_notification_delivery_job(
                repo.as_ref(),
                &transport,
                NotificationDeliveryConfig {
                    realm_id: realm,
                    channel: parse_notification_channel(&channel)?,
                    provider,
                    recipient,
                    subject,
                    body,
                    template_id,
                    data_json,
                    now_epoch: now.unwrap_or_else(now_seconds),
                    actor,
                    reason,
                    record_audit_event,
                    completed_attempts,
                    retry_policy: NotificationRetryPolicy {
                        max_attempts,
                        base_delay_ms,
                        max_delay_ms,
                    },
                },
            )
            .await?;
            Ok(serde_json::json!({
                "command": "notification_deliver",
                "request_output": transport.output_path(),
                "report": report,
            }))
        }
        Command::DirectorySync {
            realm,
            provider_id,
            actor,
            reason,
            now,
            record_audit_event,
            dry_run,
        } => {
            let qid_config = open_config(&args.config)?;
            let report = run_directory_sync_job(
                repo.clone(),
                &qid_config,
                DirectorySyncJobConfig {
                    realm_id: realm,
                    provider_id,
                    actor,
                    reason,
                    now_epoch: now.unwrap_or_else(now_seconds),
                    record_audit_event,
                    dry_run,
                },
            )
            .await?;
            Ok(serde_json::json!({
                "command": "directory_sync",
                "report": report,
            }))
        }
        Command::KeyRotationPlan {
            inventory,
            requirement,
            actor,
            reason,
            now,
            record_audit_event,
        } => {
            let inventory = inventory
                .iter()
                .map(|raw| parse_keyring_inventory_record(raw))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let requirements = requirement
                .iter()
                .map(|raw| parse_key_rotation_requirement(raw))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let report = run_key_rotation_planning_job(
                repo.as_ref(),
                KeyRotationPlanningJobConfig {
                    inventory,
                    requirements,
                    now_epoch: now.unwrap_or_else(now_seconds),
                    actor,
                    reason,
                    record_audit_event,
                },
            )
            .await?;
            Ok(serde_json::json!({
                "command": "key_rotation_plan",
                "report": report,
            }))
        }
    }
}

fn open_config(config_path: &Path) -> anyhow::Result<QidConfig> {
    QidConfig::from_file(config_path.to_str().context("invalid config path")?)
        .context("failed to load config")
}

async fn open_repo(config_path: &Path) -> anyhow::Result<Arc<AnyRepository>> {
    let config = open_config(config_path)?;
    let storage_url = config.storage.primary.resolve_url_or("qid-store.json");
    Ok(Arc::new(
        AnyRepository::connect(&storage_url)
            .await
            .context("failed to connect to storage")?,
    ))
}

struct DryRunSiemTransport {
    status: u16,
    request_output: Option<PathBuf>,
}

impl DryRunSiemTransport {
    fn new(status: u16, request_output: Option<PathBuf>) -> Self {
        Self {
            status,
            request_output,
        }
    }

    fn output_path(&self) -> Option<&Path> {
        self.request_output.as_deref()
    }
}

impl SiemWebhookTransport for DryRunSiemTransport {
    fn send(&self, request: AuditSiemHttpRequest) -> Result<AuditSiemHttpResponse, String> {
        if let Some(path) = &self.request_output {
            let body_json: serde_json::Value =
                serde_json::from_slice(&request.body).map_err(|e| e.to_string())?;
            let captured = serde_json::json!({
                "method": request.method,
                "url": request.url,
                "headers": request.headers,
                "body": body_json,
            });
            let raw = serde_json::to_vec_pretty(&captured).map_err(|e| e.to_string())?;
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            fs::write(path, raw).map_err(|e| e.to_string())?;
        }
        Ok(AuditSiemHttpResponse {
            status: self.status,
            body: Vec::new(),
        })
    }
}

struct DryRunNotificationTransport {
    status: u16,
    request_output: Option<PathBuf>,
}

impl DryRunNotificationTransport {
    fn new(status: u16, request_output: Option<PathBuf>) -> Self {
        Self {
            status,
            request_output,
        }
    }

    fn output_path(&self) -> Option<&Path> {
        self.request_output.as_deref()
    }
}

impl NotificationTransport for DryRunNotificationTransport {
    fn send(&self, request: NotificationRequest) -> Result<NotificationResponse, String> {
        if let Some(path) = &self.request_output {
            let raw = serde_json::to_vec_pretty(&request).map_err(|e| e.to_string())?;
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            fs::write(path, raw).map_err(|e| e.to_string())?;
        }
        Ok(NotificationResponse {
            status: self.status,
            provider_message_id: Some(format!("dry-run-{}", request.channel.as_str())),
        })
    }
}

fn parse_notification_channel(raw: &str) -> anyhow::Result<NotificationChannel> {
    match raw {
        "email" => Ok(NotificationChannel::Email),
        "push" => Ok(NotificationChannel::Push),
        other => anyhow::bail!("unsupported notification channel: {other}"),
    }
}

fn parse_keyring_inventory_record(raw: &str) -> anyhow::Result<KeyringInventoryRecord> {
    let fields = split_csv_fields(raw);
    if !(fields.len() == 8 || fields.len() == 9) {
        anyhow::bail!(
            "key inventory must have 8 or 9 fields: realm,keyring,kid,purpose,signer_type,created,not_before,retire_after[,revoked]"
        );
    }
    Ok(KeyringInventoryRecord {
        realm_id: non_empty_field(&fields, 0, "realm")?.to_string(),
        keyring_name: non_empty_field(&fields, 1, "keyring")?.to_string(),
        kid: non_empty_field(&fields, 2, "kid")?.to_string(),
        purpose: parse_key_purpose(non_empty_field(&fields, 3, "purpose")?)?,
        signer_type: non_empty_field(&fields, 4, "signer_type")?.to_string(),
        created_at_epoch: parse_u64_field(&fields, 5, "created")?,
        not_before_epoch: parse_u64_field(&fields, 6, "not_before")?,
        retire_after_epoch: parse_u64_field(&fields, 7, "retire_after")?,
        revoked: fields
            .get(8)
            .map(|value| parse_bool_field(value, "revoked"))
            .transpose()?
            .unwrap_or(false),
    })
}

fn parse_key_rotation_requirement(raw: &str) -> anyhow::Result<KeyRotationRequirement> {
    let fields = split_csv_fields(raw);
    if fields.len() != 6 {
        anyhow::bail!(
            "key rotation requirement must have 6 fields: realm,purpose,max_age_days,overlap_days,require_remote,require_dedicated"
        );
    }
    Ok(KeyRotationRequirement {
        realm_id: non_empty_field(&fields, 0, "realm")?.to_string(),
        purpose: parse_key_purpose(non_empty_field(&fields, 1, "purpose")?)?,
        max_age_days: parse_u64_field(&fields, 2, "max_age_days")?,
        overlap_days: parse_u64_field(&fields, 3, "overlap_days")?,
        require_remote_signer: parse_bool_field(
            non_empty_field(&fields, 4, "require_remote")?,
            "require_remote",
        )?,
        require_dedicated_keyring: parse_bool_field(
            non_empty_field(&fields, 5, "require_dedicated")?,
            "require_dedicated",
        )?,
    })
}

fn split_csv_fields(raw: &str) -> Vec<String> {
    raw.split(',').map(|part| part.trim().to_string()).collect()
}

fn non_empty_field<'a>(fields: &'a [String], index: usize, name: &str) -> anyhow::Result<&'a str> {
    fields
        .get(index)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("{name} must not be empty"))
}

fn parse_u64_field(fields: &[String], index: usize, name: &str) -> anyhow::Result<u64> {
    non_empty_field(fields, index, name)?
        .parse::<u64>()
        .with_context(|| format!("{name} must be an unsigned integer"))
}

fn parse_bool_field(value: &str, name: &str) -> anyhow::Result<bool> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => anyhow::bail!("{name} must be true or false"),
    }
}

fn parse_key_purpose(value: &str) -> anyhow::Result<KeyPurpose> {
    Ok(match value {
        "oidc_token" => KeyPurpose::OidcToken,
        "saml_assertion" => KeyPurpose::SamlAssertion,
        "pep_assertion" => KeyPurpose::PepAssertion,
        "audit_log" => KeyPurpose::AuditLog,
        "browser_session" => KeyPurpose::BrowserSession,
        other if other.starts_with("other:") && other.len() > "other:".len() => {
            KeyPurpose::Other(other["other:".len()..].to_string())
        }
        other => anyhow::bail!("unsupported key purpose: {other}"),
    })
}

struct LocalWormArchive {
    root: PathBuf,
    written: RefCell<Vec<AuditWormPutResult>>,
}

impl LocalWormArchive {
    fn new(root: PathBuf) -> anyhow::Result<Self> {
        fs::create_dir_all(&root)
            .with_context(|| format!("failed to create archive dir {}", root.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&root).with_context(|| {
                format!("failed to read archive dir metadata {}", root.display())
            })?;
            let mode = metadata.permissions().mode() & 0o777;
            if mode != 0o700 {
                anyhow::bail!(
                    "archive directory {} has permissions {:#o}, expected 0o700 (owner-only)",
                    root.display(),
                    mode,
                );
            }
        }
        Ok(Self {
            root,
            written: RefCell::new(Vec::new()),
        })
    }

    fn object_path(&self, key: &str) -> Result<PathBuf, String> {
        let path = Path::new(key);
        if path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return Err("archive object key must be relative and stay inside archive root".into());
        }
        Ok(self.root.join(path))
    }
}

impl WormArchiveTransport for LocalWormArchive {
    fn put_once(&self, object: AuditWormObject) -> Result<AuditWormPutResult, String> {
        let path = self.object_path(&object.key)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|e| e.to_string())?;
        file.write_all(&object.body).map_err(|e| e.to_string())?;
        let result = AuditWormPutResult {
            key: object.key,
            version_id: None,
            location: format!("file://{}", path.display()),
        };
        self.written.borrow_mut().push(result.clone());
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qid_core::{
        models::{AuditEvent, AuditRetentionConfig},
        tenant::RealmId,
    };
    use qid_storage::prelude::*;

    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("qid-worker-cli-{name}-{}", ulid::Ulid::new()))
    }

    fn write_config(dir: &Path) -> (PathBuf, PathBuf) {
        let store = dir.join("qid-store.json");
        let config = dir.join("qid.yaml");
        let store_url =
            serde_json::to_string(&store.to_string_lossy()).expect("store path should serialize");
        std::fs::write(
            &config,
            format!(
                r#"
server:
  listen: "127.0.0.1:0"
  public_base_url: "https://id.example.com"
storage:
  primary:
    url: {store_url}
realms:
  - id: corp
    issuer: "https://id.example.com/realms/corp"
"#
            ),
        )
        .expect("config file");
        (config, store)
    }

    async fn append_audit_event(repo: &AnyRepository, id: &str, created_at: u64) {
        repo.append_audit_event(&AuditEvent {
            id: id.to_string(),
            realm_id: Some("corp".to_string()),
            actor: "admin@example.com".to_string(),
            action: "audit.test".to_string(),
            target_type: "audit".to_string(),
            target_id: id.to_string(),
            reason: "test".to_string(),
            metadata_json: serde_json::json!({ "id": id }),
            created_at,
            previous_hash: None,
            event_hash: None,
        })
        .await
        .expect("audit event");
    }

    #[tokio::test]
    async fn retention_evaluate_command_uses_real_storage() {
        let dir = temp_dir("retention");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let (config, store) = write_config(&dir);
        let repo = AnyRepository::connect(store.to_str().expect("store path"))
            .await
            .expect("repository");
        append_audit_event(&repo, "old", 10).await;
        append_audit_event(&repo, "new", 200).await;
        repo.set_audit_retention_config(&AuditRetentionConfig {
            realm_id: Some("corp".to_string()),
            retention_days: 0,
            legal_hold: false,
            updated_by: "admin@example.com".to_string(),
            reason: "ticket-1".to_string(),
            updated_at: 199,
        })
        .await
        .expect("retention config");

        let result = run(Args {
            config,
            command: Command::RetentionEvaluate {
                realm: Some("corp".to_string()),
                actor: "qid-worker".to_string(),
                reason: "scheduled retention evaluation".to_string(),
                now: Some(200),
                record_audit_event: true,
            },
        })
        .await
        .expect("retention evaluate");

        assert_eq!(result["command"], "audit_retention_evaluate");
        assert_eq!(result["report"]["status"], "evaluated");
        assert_eq!(result["report"]["plan"]["expired_event_ids"][0], "old");
        let refreshed = AnyRepository::connect(store.to_str().expect("store path"))
            .await
            .expect("repository");
        assert_eq!(
            refreshed
                .list_audit_events(Some(&RealmId::from("corp".to_string())), 10)
                .await
                .expect("audit events")
                .len(),
            3
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn worm_archive_command_writes_append_only_files() {
        let dir = temp_dir("archive");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let (config, store) = write_config(&dir);
        let repo = AnyRepository::connect(store.to_str().expect("store path"))
            .await
            .expect("repository");
        append_audit_event(&repo, "event-1", 100).await;
        let archive_dir = dir.join("archive");
        std::fs::create_dir_all(&archive_dir).expect("create archive dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&archive_dir, std::fs::Permissions::from_mode(0o700))
                .expect("set archive dir permissions");
        }

        let result = run(Args {
            config,
            command: Command::WormArchive {
                realm: Some("corp".to_string()),
                archive_dir: archive_dir.clone(),
                limit: 10,
                actor: "qid-worker".to_string(),
                reason: "scheduled audit archive".to_string(),
                now: Some(300),
                include_metadata: true,
                record_audit_event: true,
            },
        })
        .await
        .expect("worm archive");

        assert_eq!(result["command"], "audit_worm_archive");
        assert_eq!(result["report"]["status"], "archived");
        let body_location = result["report"]["body_object"]["location"]
            .as_str()
            .expect("body location");
        let body_path = body_location
            .strip_prefix("file://")
            .expect("file location");
        assert!(Path::new(body_path).exists());
        assert!(archive_dir.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn siem_deliver_command_captures_request_without_network() {
        let dir = temp_dir("siem");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let (config, store) = write_config(&dir);
        let repo = AnyRepository::connect(store.to_str().expect("store path"))
            .await
            .expect("repository");
        append_audit_event(&repo, "event-1", 100).await;
        let request_output = dir.join("siem-request.json");

        let result = run(Args {
            config,
            command: Command::SiemDeliver {
                realm: Some("corp".to_string()),
                endpoint_url: "https://siem.example.com/audit".to_string(),
                request_output: Some(request_output.clone()),
                dry_run_status: 202,
                limit: 10,
                now: Some(200),
                traceparent: None,
                audit_correlation_id: Some("corr-1".to_string()),
                include_metadata: true,
                actor: "qid-worker".to_string(),
                reason: "scheduled siem delivery".to_string(),
                record_audit_event: false,
                completed_attempts: 0,
                max_attempts: 5,
                base_delay_ms: 1000,
                max_delay_ms: 60000,
            },
        })
        .await
        .expect("siem deliver");

        assert_eq!(result["command"], "audit_siem_deliver");
        assert_eq!(result["report"]["status"], "delivered");
        let captured: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(request_output).expect("captured request"),
        )
        .expect("captured request JSON");
        assert_eq!(captured["method"], "POST");
        assert_eq!(captured["body"]["event_count"], 1);
        assert_eq!(captured["body"]["events"][0]["id"], "event-1");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn notification_deliver_command_writes_request_and_audit() {
        let dir = temp_dir("notification");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let (config, store) = write_config(&dir);
        let request_output = dir.join("notification-request.json");

        let result = run(Args {
            config,
            command: Command::NotificationDeliver {
                realm: Some("corp".to_string()),
                channel: "email".to_string(),
                provider: "smtp://mail.example.com".to_string(),
                recipient: "alice@example.com".to_string(),
                subject: Some("Verify your email".to_string()),
                body: "Use code 123456".to_string(),
                template_id: Some("email.verify".to_string()),
                data_json: r#"{"code":"123456"}"#.to_string(),
                request_output: Some(request_output.clone()),
                dry_run_status: 202,
                now: Some(300),
                actor: "qid-worker".to_string(),
                reason: "scheduled notification delivery".to_string(),
                record_audit_event: true,
                completed_attempts: 0,
                max_attempts: 5,
                base_delay_ms: 1000,
                max_delay_ms: 60000,
            },
        })
        .await
        .expect("notification deliver");

        assert_eq!(result["command"], "notification_deliver");
        assert_eq!(result["report"]["status"], "delivered");
        assert_eq!(result["report"]["channel"], "email");
        let captured: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(request_output).expect("captured request"),
        )
        .expect("captured request JSON");
        assert_eq!(captured["channel"], "email");
        assert_eq!(captured["recipient"], "alice@example.com");
        assert_eq!(captured["template_id"], "email.verify");

        let refreshed = AnyRepository::connect(store.to_str().expect("store path"))
            .await
            .expect("repository");
        let events = refreshed
            .list_audit_events(Some(&RealmId::from("corp".to_string())), 10)
            .await
            .expect("audit events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "notification.deliver");
        assert_eq!(
            events[0].target_id,
            result["report"]["recipient_hash"]
                .as_str()
                .expect("recipient hash")
        );
        assert!(
            !events[0]
                .metadata_json
                .to_string()
                .contains("alice@example.com")
        );
        assert!(!events[0].metadata_json.to_string().contains("Use code"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn key_rotation_plan_command_uses_real_storage_and_records_audit() {
        let dir = temp_dir("key-rotation");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let (config, store) = write_config(&dir);

        let result = run(Args {
            config,
            command: Command::KeyRotationPlan {
                inventory: vec![
                    "corp,corp-shared,shared-1,pep_assertion,local,100,100,10000".to_string(),
                    "corp,corp-shared,shared-2,oidc_token,local,100,100,10000".to_string(),
                ],
                requirement: vec!["corp,pep_assertion,90,14,true,true".to_string()],
                actor: "qid-worker".to_string(),
                reason: "scheduled key rotation planning".to_string(),
                now: Some(1_000),
                record_audit_event: true,
            },
        })
        .await
        .expect("key rotation plan");

        assert_eq!(result["command"], "key_rotation_plan");
        assert_eq!(result["report"]["status"], "rejected");
        assert_eq!(result["report"]["rejected_count"], 1);
        assert_eq!(
            result["report"]["plans"][0]["reasons"][0],
            "dedicated_keyring_required:corp-shared"
        );
        let refreshed = AnyRepository::connect(store.to_str().expect("store path"))
            .await
            .expect("repository");
        let events = refreshed
            .list_audit_events(Some(&RealmId::from("corp".to_string())), 10)
            .await
            .expect("audit events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "key_rotation.plan");
        std::fs::remove_dir_all(&dir).ok();
    }
}
