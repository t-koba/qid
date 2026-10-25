use anyhow::{Context, ensure};
use clap::{Parser, Subcommand};
use qid_core::{config::QidConfig, util::now_seconds};
use qid_ops::{KeyPurpose, KeyRotationPlan, KeyRotationRequirement, KeyringInventoryRecord};
use qid_storage::AnyRepository;
use qid_worker::{
    AuditRetentionExecutionConfig, AuditRetentionJobConfig, AuditSiemDeliveryConfig,
    AuditSiemRedriveConfig, AuditSiemRetryPolicy, AuditTimestampConfig, AuditWormArchiveConfig,
    AuditWormObject, AuditWormPutResult, DeliveryTransport, DirectorySyncJobConfig,
    KeyRotationExecutionJobConfig, KeyRotationPlanningJobConfig, NotificationChannel,
    NotificationDeliveryConfig, NotificationRetryPolicy, WormArchiveTransport,
    run_audit_retention_execution_job, run_audit_retention_job, run_audit_siem_delivery_job,
    run_audit_siem_redrive_job, run_audit_worm_archive_job, run_directory_sync_job,
    run_key_rotation_execution_job, run_key_rotation_planning_job, run_notification_delivery_job,
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
    /// Delete one bounded batch of expired push records outside quota retention.
    /// Schedule repeated invocations externally; never deletes authenticator tombstones.
    PushCleanup {
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=1000))]
        limit: u32,
    },
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
        #[arg(long)]
        tsa_url: Option<String>,
        #[arg(long = "tsa-ca")]
        tsa_ca: Vec<PathBuf>,
        #[arg(long, default_value_t = 10)]
        tsa_timeout_seconds: u64,
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
        #[arg(long)]
        tsa_url: Option<String>,
        #[arg(long = "tsa-ca")]
        tsa_ca: Vec<PathBuf>,
        #[arg(long, default_value_t = 10)]
        tsa_timeout_seconds: u64,
    },
    /// Send a SIEM webhook over HTTPS; --dry-run records without sending.
    #[command(name = "audit-siem-deliver")]
    SiemDeliver {
        #[arg(long)]
        realm: Option<String>,
        #[arg(long)]
        endpoint_url: String,
        #[arg(long)]
        request_output: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        #[arg(long, default_value_t = 10)]
        timeout_seconds: u64,
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
    /// Redrive a persistent SIEM delivery queue entry.
    #[command(name = "audit-siem-redrive")]
    SiemRedrive {
        #[arg(long)]
        id: String,
        #[arg(long)]
        request_output: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        #[arg(long, default_value_t = 10)]
        timeout_seconds: u64,
        #[arg(long)]
        now: Option<u64>,
        #[arg(long, default_value = "qid-worker")]
        actor: String,
        #[arg(long, default_value = "scheduled siem redrive")]
        reason: String,
        #[arg(long, default_value_t = true)]
        record_audit_event: bool,
        #[arg(long, default_value_t = 5)]
        max_attempts: u32,
        #[arg(long, default_value_t = 1000)]
        base_delay_ms: u64,
        #[arg(long, default_value_t = 60000)]
        max_delay_ms: u64,
    },
    /// Send an email or push notification; HTTPS providers receive JSON, smtp(s) providers send email.
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
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        #[arg(long, default_value_t = 10)]
        timeout_seconds: u64,
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
    /// Synchronize a directory provider (LDAP/AD) into the local user store.
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
        #[arg(
            long,
            default_value_t = false,
            help = "Refuse execution; non-mutating directory sync plans are not supported"
        )]
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
    /// Execute supported key rotation actions from a plan JSON file.
    #[command(name = "key-rotation-execute")]
    KeyRotationExecute {
        #[arg(long)]
        plan_json: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value = "ES256")]
        algorithm: String,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long, default_value = "qid-worker")]
        actor: String,
        #[arg(long, default_value = "scheduled key rotation execution")]
        reason: String,
        #[arg(long)]
        now: Option<u64>,
        #[arg(long, default_value_t = true)]
        record_audit_event: bool,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

pub(crate) async fn run(args: Args) -> anyhow::Result<serde_json::Value> {
    let repo = open_repo(&args.config).await?;
    match args.command {
        Command::PushCleanup { limit } => {
            use qid_storage::{OidcContinuationRepository, PushRepository};
            let now = now_seconds();
            let push_deleted = repo.cleanup_expired_push_records(now, limit).await?;
            let oidc_continuations_deleted =
                repo.cleanup_expired_oidc_continuations(now, limit).await?;
            Ok(serde_json::json!({
                "command": "push_cleanup",
                "deleted": push_deleted + oidc_continuations_deleted,
                "push_deleted": push_deleted,
                "oidc_continuations_deleted": oidc_continuations_deleted
            }))
        }
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
            tsa_url,
            tsa_ca,
            tsa_timeout_seconds,
        } => {
            let archive = LocalWormArchive::new(archive_dir)?;
            let timestamp = load_timestamp_config(tsa_url, tsa_ca, tsa_timeout_seconds)?;
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
                    timestamp,
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
            tsa_url,
            tsa_ca,
            tsa_timeout_seconds,
        } => {
            ensure!(limit > 0, "limit must be greater than zero");
            let archive = LocalWormArchive::new(archive_dir)?;
            let timestamp = load_timestamp_config(tsa_url, tsa_ca, tsa_timeout_seconds)?;
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
                    timestamp,
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
            dry_run,
            timeout_seconds,
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
            let transport = if dry_run {
                DeliveryTransport::dry_run(request_output)
            } else {
                DeliveryTransport::https(timeout_seconds, request_output)
                    .map_err(anyhow::Error::msg)?
            };
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
            dry_run,
            timeout_seconds,
            now,
            actor,
            reason,
            record_audit_event,
            completed_attempts,
            max_attempts,
            base_delay_ms,
            max_delay_ms,
        } => {
            let config = NotificationDeliveryConfig {
                realm_id: realm,
                channel: parse_notification_channel(&channel)?,
                provider,
                recipient,
                subject,
                body,
                template_id,
                data_json: serde_json::from_str(&data_json).context("invalid data_json")?,
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
            };
            let report = if dry_run {
                let transport = DeliveryTransport::dry_run(request_output.clone());
                run_notification_delivery_job(repo.as_ref(), &transport, config).await?
            } else if qid_worker::is_smtp_provider(config.provider.as_str()) {
                deliver_notification_via_smtp(repo.as_ref(), config, timeout_seconds).await?
            } else {
                let transport = DeliveryTransport::https(timeout_seconds, request_output.clone())
                    .map_err(anyhow::Error::msg)?;
                run_notification_delivery_job(repo.as_ref(), &transport, config).await?
            };
            Ok(serde_json::json!({
                "command": "notification_deliver",
                "request_output": request_output,
                "report": report,
            }))
        }
        Command::SiemRedrive {
            id,
            request_output,
            dry_run,
            timeout_seconds,
            now,
            actor,
            reason,
            record_audit_event,
            max_attempts,
            base_delay_ms,
            max_delay_ms,
        } => {
            let transport = if dry_run {
                DeliveryTransport::dry_run(request_output)
            } else {
                DeliveryTransport::https(timeout_seconds, request_output)
                    .map_err(anyhow::Error::msg)?
            };
            let report = run_audit_siem_redrive_job(
                repo.as_ref(),
                &transport,
                AuditSiemRedriveConfig {
                    delivery_id: id,
                    now_epoch: now.unwrap_or_else(now_seconds),
                    actor,
                    reason,
                    record_audit_event,
                    retry_policy: AuditSiemRetryPolicy {
                        max_attempts,
                        base_delay_ms,
                        max_delay_ms,
                    },
                },
            )
            .await?;
            Ok(serde_json::json!({
                "command": "audit_siem_redrive",
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
        Command::KeyRotationExecute {
            plan_json,
            output_dir,
            algorithm,
            passphrase_file,
            actor,
            reason,
            now,
            record_audit_event,
            force,
        } => {
            let plan = read_key_rotation_plan(&plan_json)?;
            let key_passphrase = read_key_passphrase(passphrase_file.as_deref())?;
            let report = run_key_rotation_execution_job(
                repo.as_ref(),
                KeyRotationExecutionJobConfig {
                    plan,
                    output_dir,
                    algorithm,
                    key_passphrase,
                    now_epoch: now.unwrap_or_else(now_seconds),
                    actor,
                    reason,
                    record_audit_event,
                    force,
                },
            )
            .await?;
            Ok(serde_json::json!({
                "command": "key_rotation_execute",
                "report": report,
            }))
        }
    }
}

fn open_config(config_path: &Path) -> anyhow::Result<QidConfig> {
    QidConfig::from_file(config_path.to_str().context("invalid config path")?)
        .context("failed to load config")
}

fn load_timestamp_config(
    url: Option<String>,
    ca_paths: Vec<PathBuf>,
    timeout_seconds: u64,
) -> anyhow::Result<Option<AuditTimestampConfig>> {
    match (url.as_ref(), ca_paths.is_empty()) {
        (None, true) => return Ok(None),
        (None, false) => anyhow::bail!("--tsa-ca requires --tsa-url"),
        (Some(_), true) => anyhow::bail!("--tsa-url requires at least one --tsa-ca"),
        (Some(_), false) => {}
    }
    ensure!(
        timeout_seconds > 0,
        "--tsa-timeout-seconds must be greater than zero"
    );
    let url = url.context("--tsa-url is required")?;
    let parsed = reqwest::Url::parse(&url).context("--tsa-url is invalid")?;
    ensure!(
        parsed.scheme() == "https" && parsed.host_str().is_some(),
        "--tsa-url must be an absolute https:// URL"
    );
    ensure!(
        parsed.username().is_empty() && parsed.password().is_none(),
        "--tsa-url must not contain user information"
    );

    let mut trusted_roots_der = Vec::new();
    for path in ca_paths {
        let bytes = fs::read(&path)
            .with_context(|| format!("failed to read TSA CA bundle {}", path.display()))?;
        let certificates = rustls_pemfile::certs(&mut bytes.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("failed to parse TSA CA bundle {}", path.display()))?;
        ensure!(
            !certificates.is_empty(),
            "TSA CA bundle contains no certificates: {}",
            path.display()
        );
        trusted_roots_der.extend(
            certificates
                .into_iter()
                .map(|certificate| certificate.as_ref().to_vec()),
        );
    }
    Ok(Some(AuditTimestampConfig {
        url,
        trusted_roots_der,
        timeout_seconds,
    }))
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

async fn deliver_notification_via_smtp(
    repo: &AnyRepository,
    config: NotificationDeliveryConfig,
    timeout_seconds: u64,
) -> anyhow::Result<qid_worker::NotificationDeliveryReport> {
    #[cfg(feature = "smtp-transport")]
    {
        let transport =
            qid_worker::SmtpTransport::from_env(config.provider.as_str(), timeout_seconds)
                .map_err(anyhow::Error::msg)?;
        Ok(run_notification_delivery_job(repo, &transport, config).await?)
    }
    #[cfg(not(feature = "smtp-transport"))]
    {
        let _ = (repo, config, timeout_seconds);
        anyhow::bail!(
            "SMTP notification provider requires qid-worker built with --features smtp-transport"
        )
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

fn read_key_rotation_plan(path: &Path) -> anyhow::Result<KeyRotationPlan> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read key rotation plan {}", path.display()))?;
    serde_json::from_str(&body)
        .with_context(|| format!("failed to parse key rotation plan {}", path.display()))
}

fn read_key_passphrase(path: Option<&Path>) -> anyhow::Result<Vec<u8>> {
    if let Some(path) = path {
        let passphrase = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read passphrase file {}", path.display()))?;
        return Ok(passphrase
            .trim_end_matches(['\r', '\n'])
            .as_bytes()
            .to_vec());
    }
    let passphrase = std::env::var("QID_KEY_PASSPHRASE")
        .context("QID_KEY_PASSPHRASE or --passphrase-file is required")?;
    Ok(passphrase.into_bytes())
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
        models::{AuditEvent, AuditRetentionConfig, ScimUser},
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

    #[tokio::test]
    async fn push_cleanup_command_is_bounded_and_independent_of_audit() {
        use clap::Parser;
        for limit in ["0", "1001"] {
            assert!(
                Args::try_parse_from(["qid-worker", "push-cleanup", "--limit", limit]).is_err()
            );
        }
        let dir = temp_dir("push-cleanup");
        std::fs::create_dir_all(&dir).unwrap();
        let (config, store) = write_config(&dir);
        let repo = AnyRepository::connect(store.to_str().unwrap())
            .await
            .unwrap();
        append_audit_event(&repo, "must-remain", 1).await;
        drop(repo);
        let args = Args::try_parse_from([
            "qid-worker",
            "--config",
            config.to_str().unwrap(),
            "push-cleanup",
        ])
        .unwrap();
        let result = run(args).await.unwrap();
        assert_eq!(result["command"], "push_cleanup");
        assert_eq!(result["deleted"], 0);
        let repo = AnyRepository::connect(store.to_str().unwrap())
            .await
            .unwrap();
        assert!(
            repo.list_audit_events(None, 10)
                .await
                .unwrap()
                .iter()
                .any(|event| event.id == "must-remain")
        );
        drop(repo);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn directory_sync_dry_run_is_rejected_without_changing_users_or_audit() {
        let dir = temp_dir("directory-sync-dry-run");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let (config, store) = write_config(&dir);
        let initial_user = ScimUser {
            id: "user-before-dry-run".to_string(),
            realm_id: "corp".to_string(),
            external_id: Some("uid=existing,dc=example,dc=com".to_string()),
            user_name: "before@example.com".to_string(),
            name_json: serde_json::json!({"givenName": "Before"}),
            emails_json: serde_json::json!([{"value": "before@example.com"}]),
            enterprise_json: serde_json::json!({}),
            directory_provider_id: None,
            deprovisioned_at: None,
            active: true,
        };
        let repo = AnyRepository::connect(store.to_str().expect("store path"))
            .await
            .expect("repository");
        repo.create_scim_user(&initial_user)
            .await
            .expect("seed user");
        drop(repo);

        let result = run(Args {
            config,
            command: Command::DirectorySync {
                realm: "corp".to_string(),
                provider_id: "missing-provider".to_string(),
                actor: "qid-worker".to_string(),
                reason: "dry-run safety regression".to_string(),
                now: Some(100),
                record_audit_event: true,
                dry_run: true,
            },
        })
        .await;
        let error = result.expect_err("dry-run must be rejected before directory lookup");
        assert!(
            error
                .to_string()
                .contains("directory sync dry-run is not supported")
        );

        let refreshed = AnyRepository::connect(store.to_str().expect("store path"))
            .await
            .expect("repository");
        let users = refreshed
            .list_scim_users(&RealmId::from("corp".to_string()))
            .await
            .expect("SCIM users");
        assert_eq!(
            serde_json::to_value(users).expect("serialize SCIM users"),
            serde_json::to_value(vec![initial_user]).expect("serialize initial user")
        );
        assert!(
            refreshed
                .list_audit_events(Some(&RealmId::from("corp".to_string())), 10)
                .await
                .expect("audit events")
                .is_empty()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn directory_sync_honors_realm_level_kill_switch_before_connect() {
        let dir = temp_dir("directory-sync-disabled");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let (config, store) = write_config(&dir);
        let base_config = std::fs::read_to_string(&config).expect("base config");
        let disabled_directory_config = base_config.replace(
            "    issuer: \"https://id.example.com/realms/corp\"\n",
            "    issuer: \"https://id.example.com/realms/corp\"\n    protocols:\n      directory:\n        enabled: false\n        providers:\n          - id: corp-ldap\n            type: ldap\n            enabled: true\n            connection:\n              url: \"ldap://dir.invalid\"\n",
        );
        std::fs::write(&config, disabled_directory_config).expect("disabled directory config");

        let initial_user = ScimUser {
            id: "user-before-disabled-sync".to_string(),
            realm_id: "corp".to_string(),
            external_id: Some("uid=keep,dc=example,dc=com".to_string()),
            user_name: "keep@example.com".to_string(),
            name_json: serde_json::json!({"givenName": "Keep"}),
            emails_json: serde_json::json!([{"value": "keep@example.com"}]),
            enterprise_json: serde_json::json!({}),
            directory_provider_id: Some("corp-ldap".to_string()),
            deprovisioned_at: None,
            active: true,
        };
        let repo = AnyRepository::connect(store.to_str().expect("store path"))
            .await
            .expect("repository");
        repo.create_scim_user(&initial_user)
            .await
            .expect("seed user");
        drop(repo);

        let result = run(Args {
            config,
            command: Command::DirectorySync {
                realm: "corp".to_string(),
                provider_id: "corp-ldap".to_string(),
                actor: "qid-worker".to_string(),
                reason: "disabled kill-switch regression".to_string(),
                now: Some(100),
                record_audit_event: true,
                dry_run: false,
            },
        })
        .await
        .expect("disabled directory sync should report instead of failing");
        assert_eq!(result["command"], "directory_sync");
        assert_eq!(result["report"]["status"], "skipped_disabled");
        assert_eq!(result["report"]["provider_id"], "corp-ldap");
        assert!(result["report"]["audit_event_id"].is_null());

        let refreshed = AnyRepository::connect(store.to_str().expect("store path"))
            .await
            .expect("repository");
        let users = refreshed
            .list_scim_users(&RealmId::from("corp".to_string()))
            .await
            .expect("SCIM users");
        assert_eq!(
            serde_json::to_value(users).expect("serialize SCIM users"),
            serde_json::to_value(vec![initial_user]).expect("serialize initial user")
        );
        assert!(
            refreshed
                .list_audit_events(Some(&RealmId::from("corp".to_string())), 10)
                .await
                .expect("audit events")
                .is_empty()
        );
        std::fs::remove_dir_all(&dir).ok();
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
        drop(repo);

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
        drop(repo);
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
                tsa_url: None,
                tsa_ca: Vec::new(),
                tsa_timeout_seconds: 10,
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
        drop(repo);
        let request_output = dir.join("siem-request.json");

        let result = run(Args {
            config,
            command: Command::SiemDeliver {
                realm: Some("corp".to_string()),
                endpoint_url: "https://siem.example.com/audit".to_string(),
                request_output: Some(request_output.clone()),
                dry_run: true,
                timeout_seconds: 10,
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
        assert_eq!(result["report"]["status"], "skipped_dry_run");
        let repo = AnyRepository::connect(store.to_str().expect("store path"))
            .await
            .expect("repository");
        let delivery_id = result["report"]["delivery_id"]
            .as_str()
            .expect("delivery id");
        let queued = repo
            .get_siem_delivery(delivery_id)
            .await
            .expect("queue lookup")
            .expect("queue row");
        assert_eq!(
            queued.status,
            qid_storage::prelude::SiemDeliveryStatus::Pending
        );
        assert_eq!(queued.attempts, 0);
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
                provider: "https://mail.example.com/send".to_string(),
                recipient: "alice@example.com".to_string(),
                subject: Some("Verify your email".to_string()),
                body: "Use code 123456".to_string(),
                template_id: Some("email.verify".to_string()),
                data_json: r#"{"code":"123456"}"#.to_string(),
                request_output: Some(request_output.clone()),
                dry_run: true,
                timeout_seconds: 10,
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
        assert_eq!(result["report"]["status"], "skipped_dry_run");
        assert_eq!(result["report"]["channel"], "email");
        let captured: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(request_output).expect("captured request"),
        )
        .expect("captured request JSON");
        assert_eq!(captured["body"]["channel"], "email");
        assert_eq!(captured["body"]["recipient"], "alice@example.com");
        assert_eq!(captured["body"]["template_id"], "email.verify");

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

    #[tokio::test]
    async fn key_rotation_execute_command_writes_successor_key_and_records_audit() {
        let dir = temp_dir("key-rotation-execute");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let (config, store) = write_config(&dir);
        let plan_json = dir.join("plan.json");
        std::fs::write(
            &plan_json,
            serde_json::to_string(&KeyRotationPlan {
                status: qid_ops::KeyRotationPlanStatus::ActionRequired,
                realm_id: "corp".to_string(),
                purpose: qid_ops::KeyPurpose::OidcToken,
                active_kid: Some("old".to_string()),
                successor_kid: None,
                actions: vec![qid_ops::KeyRotationAction {
                    action: qid_ops::KeyRotationActionKind::GenerateSuccessor,
                    keyring_name: "corp-main".to_string(),
                    kid: Some("next".to_string()),
                    reason: "rotation_overlap_window_open".to_string(),
                }],
                reasons: Vec::new(),
            })
            .expect("serialize plan"),
        )
        .expect("write plan");
        let passphrase_file = dir.join("passphrase");
        std::fs::write(&passphrase_file, "test-passphrase\n").expect("write passphrase");
        let output_dir = dir.join("keys");

        let result = run(Args {
            config,
            command: Command::KeyRotationExecute {
                plan_json,
                output_dir: output_dir.clone(),
                algorithm: "ES256".to_string(),
                passphrase_file: Some(passphrase_file),
                actor: "qid-worker".to_string(),
                reason: "scheduled key rotation execution".to_string(),
                now: Some(123),
                record_audit_event: true,
                force: false,
            },
        })
        .await
        .expect("key rotation execute");

        assert_eq!(result["command"], "key_rotation_execute");
        assert_eq!(result["report"]["status"], "executed");
        let encrypted_path = output_dir.join("signing-key-corp-main-ES256-next.pem.enc");
        let public_key_path = output_dir.join("signing-key-corp-main-ES256-next.pub.pem");
        let public_jwk_path = output_dir.join("signing-key-corp-main-ES256-next.jwk.json");
        assert!(encrypted_path.exists());
        assert!(public_key_path.exists());
        assert!(public_jwk_path.exists());
        assert!(
            !std::fs::read_to_string(&encrypted_path)
                .expect("encrypted key")
                .contains("PRIVATE KEY")
        );
        let refreshed = AnyRepository::connect(store.to_str().expect("store path"))
            .await
            .expect("repository");
        let events = refreshed
            .list_audit_events(Some(&RealmId::from("corp".to_string())), 10)
            .await
            .expect("audit events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "key_rotation.execute");
        assert_eq!(events[0].metadata_json["executed"][0]["kid"], "next");
        std::fs::remove_dir_all(&dir).ok();
    }
}
