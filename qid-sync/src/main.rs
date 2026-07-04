use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use qid_core::{config::QidConfig, state::SharedState};
use qid_crypto::LocalSigner;
use qid_directory::{
    DeprovisionEvent, DynamicGroupRule, HrRecord, LdapDirectoryEntry, LdapSyncOptions,
    audit_deprovision_sla, expand_nested_group_members, import_hr_records, resolve_manager_chain,
    sync_dynamic_group_members, sync_ldap_entries,
};
use qid_storage::AnyRepository;
use serde::de::DeserializeOwned;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Parser)]
#[command(name = "qid-sync")]
#[command(about = "qid directory lifecycle synchronization worker")]
struct Args {
    #[arg(short, long, global = true, default_value = "/etc/qid/qid.yaml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Import HR joiner/mover/leaver records from JSON.
    HrImport {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        input: PathBuf,
    },
    /// Synchronize LDAP/AD directory entries from JSON.
    LdapSync {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        deactivate_missing: bool,
        #[arg(long)]
        synced_at: Option<u64>,
    },
    /// Audit leaver deprovisioning SLA from JSON events.
    DeprovisionSla {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        sla_seconds: u64,
        #[arg(long)]
        now: Option<u64>,
    },
    /// Synchronize a dynamic group from a JSON rule.
    DynamicGroupSync {
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        rule: PathBuf,
    },
    /// Expand nested SCIM group membership.
    ExpandGroup {
        #[arg(long)]
        group_id: String,
    },
    /// Resolve a user's manager chain.
    ManagerChain {
        #[arg(long)]
        user_id: String,
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
    let state = open_state(&args.config).await?;
    match args.command {
        Command::HrImport { realm, input } => {
            let records = read_json_file::<Vec<HrRecord>>(&input)?;
            let results = import_hr_records(&state, &realm, records).await?;
            Ok(serde_json::json!({
                "command": "hr_import",
                "realm": realm,
                "results": results,
            }))
        }
        Command::LdapSync {
            realm,
            input,
            deactivate_missing,
            synced_at,
        } => {
            let entries = read_json_file::<Vec<LdapDirectoryEntry>>(&input)?;
            let result = sync_ldap_entries(
                &state,
                &realm,
                &entries,
                LdapSyncOptions {
                    deactivate_missing,
                    synced_at: synced_at.unwrap_or_else(qid_core::util::now_seconds),
                },
            )
            .await?;
            Ok(serde_json::json!({
                "command": "ldap_sync",
                "realm": realm,
                "result": result,
            }))
        }
        Command::DeprovisionSla {
            realm,
            input,
            sla_seconds,
            now,
        } => {
            let events = read_json_file::<Vec<DeprovisionEvent>>(&input)?;
            let findings = audit_deprovision_sla(
                &state,
                &realm,
                &events,
                sla_seconds,
                now.unwrap_or_else(qid_core::util::now_seconds),
            )
            .await?;
            Ok(serde_json::json!({
                "command": "deprovision_sla",
                "realm": realm,
                "findings": findings,
            }))
        }
        Command::DynamicGroupSync { group_id, rule } => {
            let rule = read_json_file::<DynamicGroupRule>(&rule)?;
            let result = sync_dynamic_group_members(&state, &group_id, &rule).await?;
            Ok(serde_json::json!({
                "command": "dynamic_group_sync",
                "result": result,
            }))
        }
        Command::ExpandGroup { group_id } => {
            let result = expand_nested_group_members(&state, &group_id).await?;
            Ok(serde_json::json!({
                "command": "expand_group",
                "result": result,
            }))
        }
        Command::ManagerChain { user_id } => {
            let result = resolve_manager_chain(&state, &user_id).await?;
            Ok(serde_json::json!({
                "command": "manager_chain",
                "result": result,
            }))
        }
    }
}

async fn open_state(config_path: &Path) -> anyhow::Result<Arc<SharedState<AnyRepository>>> {
    let config = QidConfig::from_file(config_path.to_str().context("invalid config path")?)
        .context("failed to load config")?;
    let storage_url = config.storage.primary.resolve_url_or("qid-store.json");
    let repo = Arc::new(
        AnyRepository::connect(&storage_url)
            .await
            .context("failed to connect to storage")?,
    );
    let signer = Arc::new(LocalSigner::from_secret(
        "qid-sync",
        b"qid-sync-directory-worker-signing-key",
    ));
    let jwks = serde_json::json!({
        "keys": []
    });
    Ok(Arc::new(SharedState::new(config, repo, signer, jwks)?))
}

fn read_json_file<T: DeserializeOwned>(path: &PathBuf) -> anyhow::Result<T> {
    if path.as_os_str() == "-" {
        bail!("stdin input is not supported by path-based qid-sync commands");
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("invalid JSON in {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use qid_storage::prelude::ScimRepository;

    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("qid-sync-{name}-{}", ulid::Ulid::new()))
    }

    #[tokio::test]
    async fn hr_import_command_uses_real_storage_and_directory_import() {
        let dir = temp_dir("hr-import");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let store = dir.join("qid-store.json");
        let config = dir.join("qid.yaml");
        std::fs::write(
            &config,
            format!(
                r#"
server:
  listen: "127.0.0.1:0"
  public_base_url: "https://id.example.com"
storage:
  primary:
    url: "{}"
realms:
  - id: corp
    issuer: "https://id.example.com/realms/corp"
"#,
                store.display()
            ),
        )
        .expect("config file");
        let input = dir.join("hr.json");
        std::fs::write(
            &input,
            r#"[{
                "external_id": "hr-1",
                "user_name": "alice@example.com",
                "email": "alice@example.com",
                "display_name": "Alice Example",
                "department": "Engineering",
                "manager_external_id": null,
                "event": "joiner"
            }]"#,
        )
        .expect("hr input");

        let result = run(Args {
            config: config.clone(),
            command: Command::HrImport {
                realm: "corp".to_string(),
                input,
            },
        })
        .await
        .expect("qid-sync run");

        assert_eq!(result["command"], "hr_import");
        assert_eq!(result["results"][0]["action"], "created");
        let repo = AnyRepository::connect(store.to_str().expect("utf-8 store"))
            .await
            .expect("repository");
        let users = repo
            .list_scim_users(&qid_core::tenant::RealmId::from("corp".to_string()))
            .await
            .expect("SCIM users");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].external_id.as_deref(), Some("hr-1"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
