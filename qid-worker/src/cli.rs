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
    /// Reconcile a realm SCIM registry to an external endpoint (read-only unless --apply).
    ScimOutboundSync {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        token_file: PathBuf,
        #[arg(long)]
        apply: bool,
        #[arg(long, value_enum, default_value = "none")]
        orphan_action: ScimOrphanAction,
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..))]
        page_size: u32,
        #[arg(long, default_value_t = 10_000, value_parser = clap::value_parser!(u32).range(1..))]
        max_resources: u32,
        #[arg(long, default_value = "qid-worker")]
        actor: String,
        #[arg(long, default_value = "scheduled SCIM outbound sync")]
        reason: String,
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

#[derive(Clone, clap::ValueEnum)]
pub(crate) enum ScimOrphanAction {
    None,
    Deactivate,
    Delete,
}

fn scim_token(endpoint: &str, path: &Path) -> anyhow::Result<String> {
    let url =
        reqwest::Url::parse(endpoint).map_err(|_| anyhow::anyhow!("invalid SCIM endpoint"))?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "SCIM endpoint must be HTTPS without credentials, query or fragment"
    );
    let token =
        fs::read_to_string(path).map_err(|_| anyhow::anyhow!("cannot read SCIM token file"))?;
    let token = token.trim();
    ensure!(
        !token.is_empty() && !token.chars().any(char::is_whitespace) && token.is_ascii(),
        "invalid SCIM token file"
    );
    Ok(token.to_string())
}

pub(crate) async fn run(args: Args) -> anyhow::Result<serde_json::Value> {
    let repo = open_repo(&args.config).await?;
    match args.command {
        Command::ScimOutboundSync {
            realm,
            endpoint,
            token_file,
            apply,
            orphan_action,
            page_size,
            max_resources,
            actor,
            reason,
        } => {
            let token = scim_token(&endpoint, &token_file)?;
            let report = qid_worker::run_scim_outbound_sync_job_with_options(
                repo.as_ref(),
                qid_worker::ScimOutboundSyncConfig {
                    realm_id: realm,
                    actor,
                    reason,
                    now_epoch: now_seconds(),
                    record_audit_event: true,
                    scim_base_url: endpoint,
                    scim_bearer_token: Some(token),
                    dry_run: !apply,
                },
                qid_worker::ScimOutboundSyncOptions {
                    inventory: qid_scim::OutboundInventoryLimits {
                        page_size: page_size as usize,
                        max_resources: max_resources as usize,
                    },
                    orphan_action: match orphan_action {
                        ScimOrphanAction::None => None,
                        ScimOrphanAction::Deactivate => {
                            Some(qid_scim::OutboundOrphanAction::Deactivate)
                        }
                        ScimOrphanAction::Delete => Some(qid_scim::OutboundOrphanAction::Delete),
                    },
                },
            )
            .await?;
            Ok(serde_json::json!({"command": "scim_outbound_sync", "report": report}))
        }
        Command::PushCleanup { limit } => {
            use qid_storage::{AdminRepository, OidcContinuationRepository, PushRepository};
            let now = now_seconds();
            let push_deleted = repo.cleanup_expired_push_records(now, limit).await?;
            let oidc_continuations_deleted =
                repo.cleanup_expired_oidc_continuations(now, limit).await?;
            let admin_elevations_deleted =
                repo.cleanup_expired_admin_elevations(now, limit).await?;
            Ok(serde_json::json!({
                "command": "push_cleanup",
                "deleted": push_deleted + oidc_continuations_deleted + admin_elevations_deleted,
                "push_deleted": push_deleted,
                "oidc_continuations_deleted": oidc_continuations_deleted,
                "admin_elevations_deleted": admin_elevations_deleted
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
#[path = "cli_tests.rs"]
mod tests;
