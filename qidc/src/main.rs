use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use qid_core::{
    config::QidConfig,
    models::{Client, ClientType, PasswordCredential, Session, TotpCredential, User},
    state::PasswordCredentials,
    tenant::{RealmId, TenantId},
};
use qid_crypto::{
    ARGON2ID_ALGORITHM, CredentialContext, KeyProtector, PassphraseProtector,
    jwk::{GeneratedKeyPair, generate_eddsa, generate_es256},
    parse_encrypted_key, serialize_encrypted_key,
    totp::TotpVerifier,
};
use qid_diagnostics::{build_check_report, check_storage_saas};
use qid_ops::{
    CacheKey, RestoreExecutionConfig, build_backup_manifest, plan_key_rotation,
    plan_restore as ops_plan_restore, run_restore_execution,
};
use qid_policy::{NativePolicyEngine, PolicyContext, PolicyEngine};
use qid_risk::{
    DestinationReputation, DeviceTrustState, PepSignal, RiskInput, TokenSignal, evaluate_risk,
};
use qid_storage::{AnyRepository, prelude::*};
use qid_storage::{SiemDeliveryStatus, traits::SiemDeliveryRecord};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

mod explain;
mod ops;

use explain::*;
use ops::*;

mod cli;
use cli::*;

fn primary_config_path(config_paths: &[PathBuf]) -> anyhow::Result<&Path> {
    config_paths
        .last()
        .map(PathBuf::as_path)
        .context("at least one config path is required")
}

fn load_config(config_paths: &[PathBuf]) -> anyhow::Result<QidConfig> {
    QidConfig::from_files(config_paths).context("failed to load config")
}

fn encrypted_key_path(input: &Path) -> PathBuf {
    let mut path = input.as_os_str().to_os_string();
    path.push(".enc");
    PathBuf::from(path)
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

fn rotation_key_paths(
    output_dir: &Path,
    keyring: &str,
    alg: &str,
    kid: &str,
) -> (PathBuf, PathBuf, PathBuf) {
    let keyring = safe_key_file_component(keyring);
    let alg = safe_key_file_component(alg);
    let kid = safe_key_file_component(kid);
    let base = format!("signing-key-{keyring}-{alg}-{kid}");
    (
        output_dir.join(format!("{base}.pem.enc")),
        output_dir.join(format!("{base}.pub.pem")),
        output_dir.join(format!("{base}.jwk.json")),
    )
}

fn generate_local_signing_key(kid: &str, alg: &str) -> anyhow::Result<GeneratedKeyPair> {
    match alg {
        "ES256" => generate_es256(kid).context("failed to generate ES256 key"),
        "EdDSA" => generate_eddsa(kid).context("failed to generate EdDSA key"),
        other => anyhow::bail!("local key rotation algorithm {other} is not supported"),
    }
}

fn parse_siem_delivery_status(value: &str) -> anyhow::Result<SiemDeliveryStatus> {
    match value {
        "pending" => Ok(SiemDeliveryStatus::Pending),
        "delivered" => Ok(SiemDeliveryStatus::Delivered),
        "dead" => Ok(SiemDeliveryStatus::Dead),
        other => anyhow::bail!("unsupported SIEM delivery status: {other}"),
    }
}

fn summarize_siem_delivery(record: &SiemDeliveryRecord) -> serde_json::Value {
    serde_json::json!({
        "id": record.id,
        "realm_id": record.realm_id,
        "endpoint_url": record.endpoint_url,
        "attempts": record.attempts,
        "next_retry_at": record.next_retry_at,
        "status": record.status,
        "last_error": record.last_error,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "payload_event_count": record.payload_json.get("event_count").cloned().unwrap_or(serde_json::Value::Null),
    })
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();
    let config_paths = args.config.clone();

    match args.command {
        Command::Check => {
            let config = load_config(&config_paths).context("config validation failed")?;
            let plan = qid_core::plan::RuntimePlan::from_config(&config)
                .context("runtime plan validation failed")?;
            let report = build_check_report(&config, &plan, primary_config_path(&config_paths)?);
            let mut report = report;
            report.extend_checks(check_storage_saas(&config).await);
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Plan => {
            let config = load_config(&config_paths).context("failed to load config")?;
            let plan = qid_core::plan::RuntimePlan::from_config(&config)
                .context("failed to build runtime plan")?;
            println!("{plan:#?}");
        }
        Command::Keys { command } => match command {
            KeysCommand::Encrypt(key_args) => {
                let output = key_args
                    .output
                    .unwrap_or_else(|| encrypted_key_path(&key_args.input));
                if output.exists() && !key_args.force {
                    anyhow::bail!(
                        "output encrypted key already exists: {} (use --force to overwrite)",
                        output.display()
                    );
                }
                let passphrase = read_key_passphrase(key_args.passphrase_file.as_deref())?;
                let protector = PassphraseProtector::new(passphrase)?;
                let mut plaintext = std::fs::read_to_string(&key_args.input)
                    .with_context(|| format!("failed to read key {}", key_args.input.display()))?;
                let encrypted = protector
                    .seal(&plaintext, &key_args.kid, &key_args.alg)
                    .context("failed to encrypt key")?;
                plaintext.zeroize();
                std::fs::write(&output, serialize_encrypted_key(&encrypted)?).with_context(
                    || format!("failed to write encrypted key {}", output.display()),
                )?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "encrypted",
                        "input": key_args.input,
                        "output": output,
                        "kid": encrypted.kid,
                        "alg": encrypted.alg,
                        "version": encrypted.version,
                    }))?
                );
            }
            KeysCommand::Status(key_args) => {
                let content = std::fs::read_to_string(&key_args.key)
                    .with_context(|| format!("failed to read key {}", key_args.key.display()))?;
                let status = match parse_encrypted_key(&content) {
                    Ok(encrypted) => serde_json::json!({
                        "encrypted": true,
                        "path": key_args.key,
                        "version": encrypted.version,
                        "kid": encrypted.kid,
                        "alg": encrypted.alg,
                        "created_at": encrypted.created_at,
                    }),
                    Err(_) => serde_json::json!({
                        "encrypted": false,
                        "path": key_args.key,
                        "contains_private_key_pem": content.contains("PRIVATE KEY"),
                    }),
                };
                println!("{}", serde_json::to_string_pretty(&status)?);
            }
            KeysCommand::Rotate(key_args) => {
                let kid = key_args
                    .kid
                    .unwrap_or_else(|| format!("{}-{}", key_args.keyring, ulid::Ulid::new()));
                std::fs::create_dir_all(&key_args.output_dir).with_context(|| {
                    format!(
                        "failed to create key output directory {}",
                        key_args.output_dir.display()
                    )
                })?;
                let (encrypted_path, public_path, jwk_path) = rotation_key_paths(
                    &key_args.output_dir,
                    &key_args.keyring,
                    &key_args.alg,
                    &kid,
                );
                if !key_args.force {
                    for path in [&encrypted_path, &public_path, &jwk_path] {
                        if path.exists() {
                            anyhow::bail!(
                                "rotation key output already exists: {} (use --force to overwrite)",
                                path.display()
                            );
                        }
                    }
                }

                let passphrase = read_key_passphrase(key_args.passphrase_file.as_deref())?;
                let protector = PassphraseProtector::new(passphrase)?;
                let mut generated = generate_local_signing_key(&kid, &key_args.alg)?;
                let encrypted = protector
                    .seal(&generated.private_pem, &generated.kid, &key_args.alg)
                    .context("failed to encrypt successor key")?;
                generated.private_pem.zeroize();

                std::fs::write(&encrypted_path, serialize_encrypted_key(&encrypted)?)
                    .with_context(|| {
                        format!("failed to write encrypted key {}", encrypted_path.display())
                    })?;
                std::fs::write(&public_path, generated.public_pem.as_bytes()).with_context(
                    || format!("failed to write public key {}", public_path.display()),
                )?;
                std::fs::write(
                    &jwk_path,
                    serde_json::to_string_pretty(&generated.public_jwk)?,
                )
                .with_context(|| format!("failed to write public JWK {}", jwk_path.display()))?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "successor_generated",
                        "keyring": key_args.keyring,
                        "kid": encrypted.kid,
                        "alg": encrypted.alg,
                        "encrypted_key": encrypted_path,
                        "public_key": public_path,
                        "public_jwk": jwk_path,
                    }))?
                );
            }
        },
        Command::Ops { command } => match command {
            OpsCommand::Check => {
                let config = load_config(&config_paths).context("failed to load config")?;
                let cache = cache_backend_config_from_qid(&config)?;
                cache.validate().context("ops cache validation failed")?;
                let checks = serde_json::json!({
                    "cache": {
                        "kind": cache.kind,
                        "endpoints": cache.endpoints,
                        "key_prefix": cache.key_prefix,
                        "ttl_seconds": cache.ttl_seconds,
                        "source": "storage.cache",
                    },
                    "cluster": {
                        "cluster_id": config.ops.cluster.cluster_id,
                        "region": config.ops.cluster.region,
                        "node_id": config.ops.cluster.node_id,
                        "leader_lease_ttl_seconds": config.ops.cluster.leader_lease_ttl_seconds,
                        "multi_region_active_active": config.ops.cluster.multi_region_active_active,
                    },
                    "backup": {
                        "enabled": config.ops.backup.enabled,
                        "object_store_uri": config.ops.backup.object_store_uri,
                        "migration_version": config.ops.backup.migration_version,
                    },
                    "emergency": {
                        "read_only": config.ops.emergency.read_only,
                    },
                    "status": "ok",
                });
                println!("{}", serde_json::to_string_pretty(&checks)?);
            }
            OpsCommand::BackupManifest(backup_args) => {
                let config = load_config(&config_paths).context("failed to load config")?;
                let source_cluster_id = backup_args
                    .source_cluster_id
                    .or(config.ops.cluster.cluster_id)
                    .context("source cluster id is required")?;
                let migration_version = backup_args
                    .migration_version
                    .or(config.ops.backup.migration_version)
                    .context("migration version is required")?;
                let objects = backup_args
                    .object
                    .iter()
                    .map(|raw| parse_backup_object(raw))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                let manifest = build_backup_manifest(
                    &source_cluster_id,
                    &migration_version,
                    qid_core::util::now_seconds(),
                    objects,
                )?;
                println!("{}", serde_json::to_string_pretty(&manifest)?);
            }
            OpsCommand::RestorePlan(restore_args) => {
                let config = load_config(&config_paths).context("failed to load config")?;
                let manifest = read_backup_manifest(&restore_args.manifest)?;
                let current_migration_version = restore_args
                    .current_migration_version
                    .or(config.ops.backup.migration_version)
                    .context("current migration version is required")?;
                let read_only = restore_args.read_only || config.ops.emergency.read_only;
                let plan = ops_plan_restore(
                    &manifest,
                    &restore_args.target_cluster_id,
                    &current_migration_version,
                    read_only,
                );
                println!("{}", serde_json::to_string_pretty(&plan)?);
            }
            OpsCommand::RestoreExecute(restore_args) => {
                let config = load_config(&config_paths).context("failed to load config")?;
                let manifest = read_backup_manifest(&restore_args.manifest)?;
                let current_migration_version = restore_args
                    .current_migration_version
                    .or(config.ops.backup.migration_version)
                    .context("current migration version is required")?;
                let read_only = restore_args.read_only || config.ops.emergency.read_only;
                let mut store =
                    LocalRestoreStore::new(restore_args.source_dir, restore_args.target_dir);
                let report = run_restore_execution(
                    &mut store,
                    &manifest,
                    RestoreExecutionConfig {
                        target_cluster_id: restore_args.target_cluster_id,
                        current_migration_version,
                        read_only_enabled: read_only,
                        allow_overwrite: restore_args.allow_overwrite,
                        dry_run: restore_args.dry_run,
                    },
                )?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            OpsCommand::CacheKey(cache_args) => {
                let config = load_config(&config_paths).context("failed to load config")?;
                let cache_config = cache_backend_config_from_qid(&config)?;
                let cache_key = CacheKey::new(cache_args.namespace, cache_args.material)?;
                let rendered = cache_key.render(&cache_config)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "key": rendered,
                        "digest": cache_key.digest,
                    }))?
                );
            }
            OpsCommand::KeyRotationPlan(rotation_args) => {
                let inventory = rotation_args
                    .inventory
                    .iter()
                    .map(|raw| parse_keyring_inventory_record(raw))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                let requirements = rotation_args
                    .requirement
                    .iter()
                    .map(|raw| parse_key_rotation_requirement(raw))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                let now = rotation_args
                    .now
                    .unwrap_or_else(qid_core::util::now_seconds);
                let plans = plan_key_rotation(&inventory, &requirements, now);
                println!("{}", serde_json::to_string_pretty(&plans)?);
            }
            OpsCommand::KeyRotationCheck => {
                let config = load_config(&config_paths)?;
                let state_dir = primary_config_path(&config_paths)?
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join("qid-state");
                let now = qid_core::util::now_seconds();
                let mut all_plans = Vec::new();
                for keyring in &config.crypto.keyrings {
                    let max_age_days = keyring.rotation.max_age_days;
                    let overlap_days = keyring.rotation.overlap_days;
                    let require_remote = matches!(keyring.signer.r#type.as_str(), "kms" | "remote");
                    let require_dedicated = keyring.purposes.len() <= 1;
                    for purpose in &keyring.purposes {
                        let key_purpose = parse_key_purpose(purpose)?;
                        let (private_path, _public_path) =
                            if keyring.name == "default" && config.crypto.default_alg == "ES256" {
                                (
                                    state_dir.join("signing-key.pem"),
                                    state_dir.join("signing-key.pub.pem"),
                                )
                            } else {
                                (
                                    state_dir.join(format!("{}-private.pem", keyring.name)),
                                    state_dir.join(format!("{}-public.pem", keyring.name)),
                                )
                            };
                        let created_at_epoch = if private_path.exists() {
                            private_path
                                .metadata()
                                .ok()
                                .and_then(|m| m.modified().ok())
                                .and_then(|t| {
                                    t.duration_since(std::time::UNIX_EPOCH)
                                        .ok()
                                        .map(|d| d.as_secs())
                                })
                                .unwrap_or(0)
                        } else {
                            0
                        };
                        let inventory = vec![qid_ops::KeyringInventoryRecord {
                            realm_id: keyring
                                .realm_id
                                .clone()
                                .unwrap_or_else(|| "default".to_string()),
                            keyring_name: keyring.name.clone(),
                            kid: keyring.name.clone(),
                            purpose: key_purpose.clone(),
                            signer_type: keyring.signer.r#type.clone(),
                            created_at_epoch,
                            not_before_epoch: created_at_epoch,
                            retire_after_epoch: created_at_epoch + max_age_days * 86400,
                            revoked: false,
                        }];
                        let requirements = vec![qid_ops::KeyRotationRequirement {
                            realm_id: keyring
                                .realm_id
                                .clone()
                                .unwrap_or_else(|| "default".to_string()),
                            purpose: key_purpose,
                            max_age_days,
                            overlap_days,
                            require_remote_signer: require_remote,
                            require_dedicated_keyring: require_dedicated,
                        }];
                        let plans = plan_key_rotation(&inventory, &requirements, now);
                        all_plans.extend(plans);
                    }
                }
                let needs_rotation = !all_plans.is_empty();
                println!("{}", serde_json::to_string_pretty(&all_plans)?);
                if needs_rotation {
                    eprintln!("WARNING: key rotation overdue");
                    std::process::exit(1);
                }
            }
            OpsCommand::SiemDlqList(dlq_args) => {
                if dlq_args.limit == 0 {
                    anyhow::bail!("limit must be greater than zero");
                }
                let config = load_config(&config_paths).context("failed to load config")?;
                let repo = open_repo(&config).await?;
                let status = dlq_args
                    .status
                    .as_deref()
                    .map(parse_siem_delivery_status)
                    .transpose()?;
                let records = repo
                    .list_siem_deliveries(dlq_args.realm.as_deref(), status, dlq_args.limit)
                    .await?;
                let records = records
                    .iter()
                    .map(summarize_siem_delivery)
                    .collect::<Vec<_>>();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "command": "siem_dlq_list",
                        "count": records.len(),
                        "deliveries": records,
                    }))?
                );
            }
            OpsCommand::SiemDlqRedrive(redrive_args) => {
                let config = load_config(&config_paths).context("failed to load config")?;
                let repo = open_repo(&config).await?;
                let now = redrive_args.now.unwrap_or_else(qid_core::util::now_seconds);
                let record = repo
                    .get_siem_delivery(&redrive_args.id)
                    .await?
                    .with_context(|| format!("SIEM delivery {} not found", redrive_args.id))?;
                repo.mark_siem_delivery_status(
                    &record.id,
                    SiemDeliveryStatus::Pending,
                    0,
                    Some(now),
                    None,
                    now,
                )
                .await?;
                let updated = repo
                    .get_siem_delivery(&record.id)
                    .await?
                    .context("redriven SIEM delivery not found")?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "command": "siem_dlq_redrive",
                        "delivery": summarize_siem_delivery(&updated),
                    }))?
                );
            }
        },
        Command::Realm { command } => {
            let config = load_config(&config_paths).context("failed to load config")?;
            let repo = open_repo(&config).await?;
            match command {
                RealmCommand::Create(args) => {
                    // The configuration owns a realm it declares: the
                    // daemon serves that realm with the issuer the
                    // configuration names and refuses to start when the
                    // stored issuer differs, so the command writes the
                    // configured issuer and refuses a different one.
                    if let Some(declared) = declared_realm(&config, &args.id) {
                        if let Some(message) =
                            realm_issuer_conflict(&config, &args.id, &args.issuer)
                        {
                            bail!("{message}");
                        }
                        ensure_realm_row(&repo, &config, &args.id).await?;
                        println!(
                            "realm {} is declared in the configuration with issuer {}",
                            args.id, declared.issuer
                        );
                    } else {
                        // A realm the configuration does not declare lives
                        // in the repository only, and the stored issuer of
                        // such a realm is not changed by the command.
                        if let Some(stored) = repo
                            .get_realm_issuer(&RealmId::from(args.id.clone()))
                            .await?
                        {
                            bail!(
                                "realm {} already exists with issuer {stored}; the issuer of a stored \
                                 realm is not changed by the CLI",
                                args.id
                            );
                        }
                        repo.create_realm(
                            &TenantId::from("default"),
                            &RealmId::from(args.id.clone()),
                            &args.issuer,
                            args.display_name.as_deref(),
                        )
                        .await?;
                        println!("realm created: {}", args.id);
                        if let Some(note) = realm_declaration_note(&config, &args.id) {
                            println!("{note}");
                        }
                    }
                }
                RealmCommand::List => {
                    let realms = repo.list_realms().await?;
                    if realms.is_empty() {
                        println!("no realms found");
                    } else {
                        for (id, issuer) in &realms {
                            println!("{id}  {issuer}");
                        }
                    }
                }
                RealmCommand::Get(args) => {
                    let issuer = repo
                        .get_realm_issuer(&RealmId::from(args.id.clone()))
                        .await?;
                    match issuer {
                        Some(issuer) => println!("{}  {}", args.id, issuer),
                        None => println!("realm not found: {}", args.id),
                    }
                }
                RealmCommand::Delete(args) => {
                    repo.delete_realm(&RealmId::from(args.id.clone())).await?;
                    println!("realm deleted: {}", args.id);
                }
            }
        }
        Command::Client { command } => {
            let config = load_config(&config_paths).context("failed to load config")?;
            let repo = open_repo(&config).await?;
            match command {
                ClientCommand::Create(args) => {
                    // The realm the client belongs to must be in the
                    // repository, and a client id the configuration
                    // declares belongs to the configuration: the daemon
                    // serves that client from the configuration and
                    // refuses to start when the stored record differs.
                    ensure_realm_row(&repo, &config, &args.realm).await?;
                    if let Some(message) =
                        configured_client_conflict(&config, &args.realm, &args.client_id)
                    {
                        bail!("{message}");
                    }
                    if repo
                        .get_client_by_client_id(
                            &RealmId::from(args.realm.clone()),
                            &args.client_id,
                        )
                        .await?
                        .is_some()
                    {
                        bail!(
                            "client {} already exists in realm {}",
                            args.client_id,
                            args.realm
                        );
                    }
                    // A client id names one client among the realms the
                    // deployment serves, so the command refuses an id
                    // another of them holds.
                    let served_realm_ids: Vec<RealmId> = config
                        .realms
                        .iter()
                        .map(|realm| RealmId::from(realm.id.clone()))
                        .collect();
                    qid_storage::ensure_client_id_unambiguous(
                        &repo,
                        &served_realm_ids,
                        &args.client_id,
                        &RealmId::from(args.realm.clone()),
                    )
                    .await?;
                    let id = new_id();
                    let client_type = match args.client_type {
                        CliClientType::Confidential => ClientType::Confidential,
                        CliClientType::Public => ClientType::Public,
                    };
                    let token_endpoint_auth_method = match client_type {
                        ClientType::Public => "none".to_string(),
                        ClientType::Confidential => {
                            qid_core::models::default_token_endpoint_auth_method()
                        }
                    };
                    let grant_types = vec!["authorization_code".to_string()];
                    let raw_secret = (client_type == ClientType::Confidential).then(|| {
                        args.secret
                            .clone()
                            .unwrap_or_else(|| format!("secret_{}", ulid::Ulid::new()))
                    });
                    repo.create_client(&Client {
                        id,
                        realm_id: args.realm.clone(),
                        client_id: args.client_id.clone(),
                        client_type,
                        token_endpoint_auth_method,
                        client_secret_hash: raw_secret
                            .as_deref()
                            .map(qid_core::util::client_secret_hash),
                        mtls_certificate_thumbprints: Vec::new(),
                        jwks: qid_core::models::default_client_jwks(),
                        redirect_uris: vec![args.redirect_uri],
                        grant_types,
                        client_name: None,
                        client_uri: None,
                        logo_uri: None,
                        contacts: Vec::new(),
                        post_logout_redirect_uris: Vec::new(),
                        default_max_age: None,
                        require_auth_time: false,
                        sector_identifier_uri: None,
                        subject_type: None,
                        backchannel_logout_uri: None,
                        frontchannel_logout_uri: None,
                        backchannel_client_notification_endpoint: None,
                        require_pushed_authorization_requests: false,
                    })
                    .await?;
                    if let Some(secret) = raw_secret {
                        println!("client created: {} (secret: {secret})", args.client_id);
                    } else {
                        println!("client created: {}", args.client_id);
                    }
                }
                ClientCommand::List(args) => {
                    let clients = repo
                        .list_clients(&RealmId::from(args.realm.clone()))
                        .await?;
                    if clients.is_empty() {
                        println!("no clients found");
                    } else {
                        for c in &clients {
                            println!("{}  {}  {:?}", c.id, c.client_id, c.client_type);
                        }
                    }
                }
                ClientCommand::Delete(args) => {
                    repo.delete_client(&RealmId::from(args.realm.clone()), &args.id)
                        .await?;
                    println!("client deleted: {}", args.id);
                }
            }
        }
        Command::User { command } => {
            let config = load_config(&config_paths).context("failed to load config")?;
            let repo = open_repo(&config).await?;
            match command {
                UserCommand::Create(args) => {
                    // The realm's own Argon2id cost, so a credential the
                    // product creates carries the deployment's calibration.
                    // The realm is resolved before the user is written so a
                    // rejected realm leaves no half-created account behind.
                    let context = realm_password_context(&config, &args.realm)?;
                    // The realm the user belongs to must be in the
                    // repository, so the write names the realm that
                    // holds the user.
                    ensure_realm_row(&repo, &config, &args.realm).await?;
                    let hash = context.hash(&args.password)?;
                    let id = new_id();
                    repo.create_user(&User {
                        id: id.clone(),
                        realm_id: args.realm.clone(),
                        email: Some(args.email.clone()),
                        email_verified: false,
                        display_name: args.display_name.clone(),
                        failed_login_attempts: 0,
                        locked_until: None,
                        org: None,
                    })
                    .await?;
                    repo.store_password_credential(&PasswordCredential {
                        user_id: id.clone(),
                        hash,
                        algorithm: ARGON2ID_ALGORITHM.to_string(),
                    })
                    .await?;
                    println!("user created: {id} ({})", args.email);
                }
                UserCommand::List(args) => {
                    let users = repo.list_users(&RealmId::from(args.realm.clone())).await?;
                    if users.is_empty() {
                        println!("no users found");
                    } else {
                        for u in &users {
                            let email = u.email.as_deref().unwrap_or("-");
                            let name = u.display_name.as_deref().unwrap_or("-");
                            println!("{}  {email}  {name}", u.id);
                        }
                    }
                }
                UserCommand::Get(args) => {
                    let user = repo.get_user_by_id(&args.id).await?;
                    match user {
                        Some(u) => {
                            let email = u.email.as_deref().unwrap_or("-");
                            let name = u.display_name.as_deref().unwrap_or("-");
                            println!("id: {}", u.id);
                            println!("realm_id: {}", u.realm_id);
                            println!("email: {email}");
                            println!("email_verified: {}", u.email_verified);
                            println!("display_name: {name}");
                        }
                        None => println!("user not found: {}", args.id),
                    }
                }
                UserCommand::Delete(args) => {
                    repo.delete_user(&args.id, None).await?;
                    println!("user deleted: {}", args.id);
                }
            }
        }
        Command::Session { command } => {
            let config = load_config(&config_paths).context("failed to load config")?;
            let repo = open_repo(&config).await?;
            match command {
                SessionCommand::Create(args) => {
                    let now = qid_core::util::now_seconds();
                    let session = Session {
                        id: new_id(),
                        realm_id: args.realm.clone(),
                        user_id: args.user_id.clone(),
                        auth_time: now,
                        acr: None,
                        amr: vec!["password".to_string()],
                        idle_expires_at: now + args.idle_minutes * 60,
                        absolute_expires_at: now + args.absolute_hours * 3600,
                        revoked: false,
                        created_at: now,
                        cnf: None,
                    };
                    repo.create_session(&session).await?;
                    println!("session created: {}", session.id);
                }
                SessionCommand::Revoke(args) => {
                    repo.revoke_session(&args.session_id, None).await?;
                    println!("session revoked: {}", args.session_id);
                }
            }
        }
        Command::Explain {
            realm,
            subject,
            resource_host,
            action,
            pep_registration,
            destination_category,
            destination_reputation,
            device_trust,
            anonymous_network,
            high_risk_asn,
            phishing_resistant_mfa,
            sender_constrained_token,
            token_age_seconds,
            auth_age_seconds,
            acr,
            amr,
            format,
        } => {
            let config = load_config(&config_paths).context("failed to load config")?;
            let realm_config = config.realms.iter().find(|r| r.id == realm);
            let repo = open_repo(&config).await?;
            let bundle = repo
                .get_active_policy_bundle(&RealmId::from(realm.clone()))
                .await?;
            let mut engine = NativePolicyEngine::new();
            if let Some(ref b) = bundle {
                let pb: qid_policy::PolicyBundle = serde_json::from_value(b.compiled_json.clone())
                    .with_context(|| format!("invalid policy bundle: {}", b.name))?;
                engine.load(pb, b.name.clone());
            }
            let risk_input = RiskInput {
                subject: Some(subject.clone()),
                high_risk_asn,
                anonymous_network,
                destination_reputation: destination_reputation.into(),
                phishing_resistant_mfa_satisfied: phishing_resistant_mfa,
                device_trust: device_trust.into(),
                pep: Some(PepSignal {
                    edge_name: pep_registration.clone(),
                    host: resource_host.clone(),
                    destination_category: destination_category.clone(),
                    destination_reputation: Some(destination_reputation.into()),
                    ..PepSignal::default()
                }),
                token: Some(TokenSignal {
                    sender_constrained: sender_constrained_token,
                    token_age_seconds,
                    auth_time_age_seconds: auth_age_seconds,
                    acr: acr.clone(),
                    amr: amr.clone(),
                }),
                ..RiskInput::default()
            };
            let risk_evaluation = evaluate_risk(&risk_input);
            let ctx = PolicyContext {
                subject_id: Some(subject.clone()),
                groups: vec![],
                roles: vec![],
                entitlements: vec![],
                device_id: None,
                posture: vec![],
                acr: acr.clone(),
                auth_age_seconds,
                risk_score: Some(risk_evaluation.score),
                resource_host: resource_host.clone(),
                resource_action: Some(action.clone()),
                pep_registration: pep_registration.clone(),
            };
            let result = engine.explain(&ctx).await;
            match format.as_str() {
                "json" => {
                    let explanation = build_explain_json(
                        config.profile,
                        realm_config,
                        &ctx,
                        &result,
                        bundle.as_ref().map(|b| b.name.as_str()),
                        Some(&risk_evaluation),
                    );
                    println!("{}", serde_json::to_string_pretty(&explanation)?)
                }
                _ => println!("{:#?}", result),
            }
        }
        Command::Totp { command } => {
            let config = load_config(&config_paths).context("failed to load config")?;
            let repo = open_repo(&config).await?;
            match command {
                TotpCommand::Enroll(args) => {
                    let plan = qid_core::plan::RuntimePlan::from_config(&config)?;
                    let user = repo
                        .get_user_by_id(&args.user_id)
                        .await?
                        .context("no such user")?;
                    ensure_totp_offered(&plan, &user.realm_id)?;
                    let id = new_id();
                    let secret = TotpVerifier::generate_secret();
                    let now = qid_core::util::now_seconds();
                    let cred = TotpCredential {
                        id: id.clone(),
                        user_id: args.user_id.clone(),
                        secret: secret.clone(),
                        algorithm: "SHA1".to_string(),
                        digits: 6,
                        period: 30,
                        enabled: true,
                        last_used_step: None,
                        created_at: now,
                    };
                    repo.store_totp_credential(&cred).await?;
                    let qr_url = format!(
                        "otpauth://totp/qid:{}?secret={}&issuer=qid&algorithm=SHA1&digits=6&period=30",
                        args.user_id, secret
                    );
                    println!("TOTP enrolled: id={id} secret={secret}");
                    println!("QR URL: {qr_url}");
                }
            }
        }
    }

    Ok(())
}

async fn open_repo(config: &QidConfig) -> anyhow::Result<AnyRepository> {
    let storage_url = config.storage.primary.resolve_url_or("qid-store.json");
    let repo = AnyRepository::connect(&storage_url)
        .await
        .context("failed to connect to storage")?;
    Ok(repo)
}

/// A realm that does not offer the TOTP factor refuses every enrolment,
/// whatever performs it.
fn ensure_totp_offered(plan: &qid_core::plan::RuntimePlan, realm_id: &str) -> anyhow::Result<()> {
    let realm = plan
        .realm(realm_id)
        .context("the user's realm is not configured")?;
    if !realm.accepts_totp() {
        anyhow::bail!("TOTP is not enabled for realm {}", realm.id);
    }
    Ok(())
}

fn new_id() -> String {
    ulid::Ulid::new().to_string()
}

/// The Argon2id calibration a realm's password credentials are hashed with.
///
/// The realm's own cost is the deployment's calibration, so a credential the
/// product creates carries it. A realm the configuration does not declare has
/// no cost the product may apply, and the product does not choose one on the
/// operator's behalf, so the realm is named as missing rather than the
/// credential being hashed with a fallback cost.
fn realm_password_context(config: &QidConfig, realm_id: &str) -> anyhow::Result<CredentialContext> {
    let realm = config
        .realms
        .iter()
        .find(|candidate| candidate.id == realm_id)
        .with_context(|| {
            format!(
                "realm {realm_id} is not declared in the configuration; the credential is hashed \
                 with that realm's Argon2id calibration, so declare the realm in the \
                 configuration file"
            )
        })?;
    Ok(CredentialContext::resolve(&realm.authentication.password)?)
}

/// The realm the configuration declares, if it declares one.
fn declared_realm<'a>(
    config: &'a QidConfig,
    realm_id: &str,
) -> Option<&'a qid_core::config::RealmConfig> {
    config.realms.iter().find(|realm| realm.id == realm_id)
}

/// Why a realm the configuration declares refuses the issuer the operator
/// named, if it refuses it.
///
/// The daemon serves a declared realm with the issuer the configuration
/// names and refuses to start when the stored issuer differs, so the CLI
/// refuses an issuer that would break the next start.
fn realm_issuer_conflict(config: &QidConfig, realm_id: &str, issuer: &str) -> Option<String> {
    let declared = declared_realm(config, realm_id)?;
    if declared.issuer == issuer {
        return None;
    }
    Some(format!(
        "realm {realm_id} is declared in the configuration with issuer {}; the daemon serves that \
         realm with the configured issuer",
        declared.issuer
    ))
}

/// Why a client id the configuration declares refuses the CLI's client, if
/// it refuses it.
///
/// The daemon serves a declared client from the configuration and refuses
/// to start when the stored record differs, so the CLI refuses a client id
/// the configuration owns.
fn configured_client_conflict(
    config: &QidConfig,
    realm_id: &str,
    client_id: &str,
) -> Option<String> {
    let declared = declared_realm(config, realm_id)?;
    if !declared
        .clients
        .iter()
        .any(|client| client.client_id == client_id)
    {
        return None;
    }
    Some(format!(
        "client {client_id} is declared in the configuration for realm {realm_id}; the daemon serves \
         that client from the configuration"
    ))
}

/// Make sure the repository holds the realm a write belongs to.
///
/// The daemon seeds the realms the configuration declares at startup and
/// refuses to start when a stored issuer differs from the configured one,
/// and the SQL backend's foreign keys require the realm row before a user
/// or a client can be written. The command therefore writes the realm the
/// configuration describes and refuses a realm that differs from it, so
/// the two backends answer the same way.
async fn ensure_realm_row(
    repo: &AnyRepository,
    config: &QidConfig,
    realm_id: &str,
) -> anyhow::Result<()> {
    let realm = RealmId::from(realm_id.to_string());
    let stored = repo.get_realm_issuer(&realm).await?;
    let Some(declared) = declared_realm(config, realm_id) else {
        if stored.is_none() {
            bail!(
                "realm {realm_id} is not in the repository; create it with `qidc realm create` \
                 or declare it in the configuration file"
            );
        }
        return Ok(());
    };
    match stored {
        Some(issuer) if issuer == declared.issuer => Ok(()),
        Some(issuer) => bail!(
            "realm {realm_id} is stored with issuer {issuer} but the configuration declares {}; \
             the daemon refuses to start when the two differ",
            declared.issuer
        ),
        None => {
            // The tenant is the one the daemon seeds a configured realm
            // with, so the row is the same whoever writes it.
            repo.create_realm(
                &TenantId::from("default"),
                &realm,
                &declared.issuer,
                declared.display_name.as_deref(),
            )
            .await?;
            Ok(())
        }
    }
}

/// What the operator must know about a realm the CLI created in the
/// repository: the product serves the realms the configuration declares, so a
/// realm that only the repository knows is not served and holds no user the
/// CLI can create.
fn realm_declaration_note(config: &QidConfig, realm_id: &str) -> Option<String> {
    if config.realms.iter().any(|realm| realm.id == realm_id) {
        return None;
    }
    Some(format!(
        "realm {realm_id} is stored in the repository only; declare it in the configuration file \
         to serve it and to create users in it"
    ))
}

#[cfg(test)]
mod tests;
