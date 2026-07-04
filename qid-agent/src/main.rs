use anyhow::{Context, bail, ensure};
use clap::Parser;
use qid_core::{
    config::QidConfig,
    models::{Device, WorkloadIdentity},
    tenant::RealmId,
    util::now_seconds,
};
use qid_storage::{AnyRepository, prelude::*};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Parser)]
#[command(name = "qid-agent")]
#[command(about = "qid endpoint posture and workload identity agent")]
struct Args {
    #[arg(short, long, global = true, default_value = "/etc/qid/qid.yaml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Register or update endpoint posture for a user device.
    DeviceRegister {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        user_id: String,
        #[arg(long)]
        device_name: Option<String>,
        #[arg(long, default_value = "endpoint")]
        device_type: String,
        #[arg(long = "posture")]
        posture: Vec<String>,
        #[arg(long)]
        observed_at: Option<u64>,
    },
    /// Update the last-seen timestamp for an existing device.
    DeviceHeartbeat {
        #[arg(long)]
        device_id: String,
        #[arg(long)]
        last_seen_at: Option<u64>,
    },
    /// List registered devices for a user.
    Devices {
        #[arg(long)]
        user_id: String,
    },
    /// Register a workload identity for SPIFFE-aware agents.
    WorkloadRegister {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        spiffe_id: String,
        #[arg(long)]
        trust_domain: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long, default_value = "{}")]
        authorities_json: String,
    },
    /// List workload identities for a realm.
    Workloads {
        #[arg(long)]
        realm: String,
    },
    /// Delete a workload identity by id.
    WorkloadDelete {
        #[arg(long)]
        id: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let result = run(args).await?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

async fn run(args: Args) -> anyhow::Result<serde_json::Value> {
    let repo = open_repo(&args.config).await?;
    match args.command {
        Command::DeviceRegister {
            realm,
            user_id,
            device_name,
            device_type,
            posture,
            observed_at,
        } => {
            ensure!(!realm.trim().is_empty(), "realm must not be empty");
            ensure!(!user_id.trim().is_empty(), "user_id must not be empty");
            ensure!(
                !device_type.trim().is_empty(),
                "device_type must not be empty"
            );
            let observed_at = observed_at.unwrap_or_else(now_seconds);
            let user = repo
                .get_user_by_id(&user_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("user not found: {user_id}"))?;
            ensure!(
                user.realm_id == realm,
                "user {user_id} does not belong to realm {realm}"
            );
            let device = Device {
                id: ulid::Ulid::new().to_string(),
                user_id,
                realm_id: realm.clone(),
                device_name,
                device_type,
                posture: normalize_posture(posture)?,
                registered_at: observed_at,
                last_seen_at: observed_at,
            };
            repo.register_device(&device).await?;
            Ok(serde_json::json!({
                "command": "device_register",
                "realm": realm,
                "device": device,
            }))
        }
        Command::DeviceHeartbeat {
            device_id,
            last_seen_at,
        } => {
            let Some(mut device) = repo.get_device(&device_id).await? else {
                bail!("device not found: {device_id}");
            };
            let last_seen_at = last_seen_at.unwrap_or_else(now_seconds);
            repo.update_device_last_seen(&device_id, last_seen_at)
                .await?;
            device.last_seen_at = last_seen_at;
            Ok(serde_json::json!({
                "command": "device_heartbeat",
                "device": device,
            }))
        }
        Command::Devices { user_id } => {
            ensure!(!user_id.trim().is_empty(), "user_id must not be empty");
            let devices = repo.get_user_devices(&user_id).await?;
            Ok(serde_json::json!({
                "command": "devices",
                "user_id": user_id,
                "devices": devices,
            }))
        }
        Command::WorkloadRegister {
            realm,
            spiffe_id,
            trust_domain,
            description,
            authorities_json,
        } => {
            ensure!(!realm.trim().is_empty(), "realm must not be empty");
            ensure_spiffe_trust_domain(&spiffe_id, &trust_domain)?;
            let realm_id = RealmId::from(realm.clone());
            if repo
                .get_workload_identity_by_spiffe(&realm_id, &spiffe_id)
                .await?
                .is_some()
            {
                bail!("workload identity already exists for SPIFFE id: {spiffe_id}");
            }
            let authorities_json: serde_json::Value = serde_json::from_str(&authorities_json)
                .context("authorities_json must be valid JSON")?;
            let identity = WorkloadIdentity {
                id: ulid::Ulid::new().to_string(),
                realm_id: realm.clone(),
                spiffe_id,
                description,
                trust_domain,
                authorities_json,
            };
            repo.create_workload_identity(&identity).await?;
            Ok(serde_json::json!({
                "command": "workload_register",
                "realm": realm,
                "workload_identity": identity,
            }))
        }
        Command::Workloads { realm } => {
            ensure!(!realm.trim().is_empty(), "realm must not be empty");
            let realm_id = RealmId::from(realm.clone());
            let identities = repo.list_workload_identities(&realm_id).await?;
            Ok(serde_json::json!({
                "command": "workloads",
                "realm": realm,
                "workload_identities": identities,
            }))
        }
        Command::WorkloadDelete { id } => {
            ensure!(!id.trim().is_empty(), "id must not be empty");
            repo.delete_workload_identity(&id).await?;
            Ok(serde_json::json!({
                "command": "workload_delete",
                "id": id,
                "deleted": true,
            }))
        }
    }
}

async fn open_repo(config_path: &Path) -> anyhow::Result<Arc<AnyRepository>> {
    let config = QidConfig::from_file(config_path.to_str().context("invalid config path")?)
        .context("failed to load config")?;
    let storage_url = config.storage.primary.resolve_url_or("qid-store.json");
    Ok(Arc::new(
        AnyRepository::connect(&storage_url)
            .await
            .context("failed to connect to storage")?,
    ))
}

fn normalize_posture(values: Vec<String>) -> anyhow::Result<Vec<String>> {
    let mut normalized = Vec::new();
    for item in values {
        for part in item.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if !normalized.iter().any(|existing| existing == part) {
                normalized.push(part.to_string());
            }
        }
    }
    ensure!(
        !normalized.is_empty(),
        "at least one posture signal is required"
    );
    Ok(normalized)
}

fn ensure_spiffe_trust_domain(spiffe_id: &str, trust_domain: &str) -> anyhow::Result<()> {
    ensure!(
        !trust_domain.trim().is_empty(),
        "trust_domain must not be empty"
    );
    let Some(rest) = spiffe_id.strip_prefix("spiffe://") else {
        bail!("spiffe_id must start with spiffe://");
    };
    let observed = rest
        .split('/')
        .next()
        .filter(|domain| !domain.is_empty())
        .context("spiffe_id must contain a trust domain")?;
    ensure!(
        observed == trust_domain,
        "spiffe_id trust domain does not match trust_domain"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("qid-agent-{name}-{}", ulid::Ulid::new()))
    }

    fn write_config(dir: &std::path::Path) -> (PathBuf, PathBuf) {
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
    authentication:
      password:
        enabled: true
"#
            ),
        )
        .expect("config file");
        (config, store)
    }

    #[test]
    fn posture_parser_splits_trims_and_deduplicates() {
        let posture = normalize_posture(vec![
            "disk_encrypted, firewall_enabled".to_string(),
            "disk_encrypted".to_string(),
            "os_updated".to_string(),
        ])
        .expect("posture");
        assert_eq!(
            posture,
            vec!["disk_encrypted", "firewall_enabled", "os_updated"]
        );
    }

    #[test]
    fn spiffe_validation_rejects_mismatched_trust_domain() {
        let err = ensure_spiffe_trust_domain("spiffe://prod.example/ns/default/sa/api", "corp")
            .expect_err("trust domain mismatch");
        assert!(
            err.to_string()
                .contains("spiffe_id trust domain does not match trust_domain")
        );
    }

    #[tokio::test]
    async fn device_register_and_heartbeat_use_real_storage() {
        let dir = temp_dir("device");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let (config, store) = write_config(&dir);

        let repo = AnyRepository::connect(store.to_str().expect("utf-8 store"))
            .await
            .expect("repository");
        repo.create_user(&qid_core::models::User {
            id: "user-1".to_string(),
            realm_id: "corp".to_string(),
            email: None,
            email_verified: false,
            display_name: None,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .expect("create user");

        let result = run(Args {
            config: config.clone(),
            command: Command::DeviceRegister {
                realm: "corp".to_string(),
                user_id: "user-1".to_string(),
                device_name: Some("laptop".to_string()),
                device_type: "macos".to_string(),
                posture: vec![
                    "disk_encrypted,firewall_enabled".to_string(),
                    "os_updated".to_string(),
                ],
                observed_at: Some(100),
            },
        })
        .await
        .expect("device register");

        let device_id = result["device"]["id"]
            .as_str()
            .expect("device id")
            .to_string();
        let lookup_repo = AnyRepository::connect(store.to_str().expect("utf-8 store"))
            .await
            .expect("repository");
        let device = lookup_repo
            .get_device(&device_id)
            .await
            .expect("device lookup")
            .expect("device");
        assert_eq!(
            device.posture,
            vec!["disk_encrypted", "firewall_enabled", "os_updated"]
        );
        assert_eq!(device.last_seen_at, 100);

        let heartbeat = run(Args {
            config,
            command: Command::DeviceHeartbeat {
                device_id: device_id.clone(),
                last_seen_at: Some(250),
            },
        })
        .await
        .expect("device heartbeat");
        assert_eq!(heartbeat["command"], "device_heartbeat");

        let refreshed_repo = AnyRepository::connect(store.to_str().expect("utf-8 store"))
            .await
            .expect("refreshed repository");
        let updated = refreshed_repo
            .get_device(&device_id)
            .await
            .expect("updated device lookup")
            .expect("updated device");
        assert_eq!(updated.last_seen_at, 250);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn workload_register_enforces_spiffe_and_persists_identity() {
        let dir = temp_dir("workload");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let (config, store) = write_config(&dir);

        let result = run(Args {
            config,
            command: Command::WorkloadRegister {
                realm: "corp".to_string(),
                spiffe_id: "spiffe://prod.example/ns/default/sa/api".to_string(),
                trust_domain: "prod.example".to_string(),
                description: Some("API workload".to_string()),
                authorities_json: r#"{"bundle":"prod"}"#.to_string(),
            },
        })
        .await
        .expect("workload register");
        assert_eq!(result["command"], "workload_register");

        let repo = AnyRepository::connect(store.to_str().expect("utf-8 store"))
            .await
            .expect("repository");
        let identity = repo
            .get_workload_identity_by_spiffe(
                &RealmId::from("corp".to_string()),
                "spiffe://prod.example/ns/default/sa/api",
            )
            .await
            .expect("workload lookup")
            .expect("workload");
        assert_eq!(identity.trust_domain, "prod.example");
        assert_eq!(identity.authorities_json["bundle"], "prod");
        std::fs::remove_dir_all(&dir).ok();
    }
}
