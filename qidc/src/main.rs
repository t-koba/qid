use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use qid_core::{
    config::QidConfig,
    models::{Client, ClientType, PasswordCredential, Session, TotpCredential, User},
    tenant::{RealmId, TenantId},
};
use qid_crypto::{password, totp::TotpVerifier};
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
use std::path::{Path, PathBuf};

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
        },
        Command::Realm { command } => {
            let repo = open_repo(&config_paths).await?;
            match command {
                RealmCommand::Create(args) => {
                    repo.create_realm(
                        &TenantId::from("default"),
                        &RealmId::from(args.id.clone()),
                        &args.issuer,
                        args.display_name.as_deref(),
                    )
                    .await?;
                    println!("realm created: {}", args.id);
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
            let repo = open_repo(&config_paths).await?;
            match command {
                ClientCommand::Create(args) => {
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
                    repo.delete_client(&args.id).await?;
                    println!("client deleted: {}", args.id);
                }
            }
        }
        Command::User { command } => {
            let repo = open_repo(&config_paths).await?;
            match command {
                UserCommand::Create(args) => {
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
                    let hash = password::hash_password(&args.password)?;
                    repo.store_password_credential(&PasswordCredential {
                        user_id: id.clone(),
                        hash,
                        algorithm: "argon2id".to_string(),
                        pepper_ref: None,
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
                    repo.delete_user(&args.id).await?;
                    println!("user deleted: {}", args.id);
                }
            }
        }
        Command::Session { command } => {
            let repo = open_repo(&config_paths).await?;
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
                    repo.revoke_session(&args.session_id).await?;
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
            let repo = open_repo(&config_paths).await?;
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
            let repo = open_repo(&config_paths).await?;
            match command {
                TotpCommand::Enroll(args) => {
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

async fn open_repo(config_paths: &[PathBuf]) -> anyhow::Result<AnyRepository> {
    let config = QidConfig::from_files(config_paths).context("failed to load config")?;
    let storage_url = config.storage.primary.resolve_url_or("qid-store.json");
    let repo = AnyRepository::connect(&storage_url)
        .await
        .context("failed to connect to storage")?;
    Ok(repo)
}

fn new_id() -> String {
    ulid::Ulid::new().to_string()
}

#[cfg(test)]
mod tests;
