use anyhow::{Context, bail, ensure};
use clap::{Parser, Subcommand};
use qid_core::{
    config::QidConfig,
    models::{PasswordCredential, User},
    tenant::{RealmId, TenantId},
};
use qid_crypto::password;
use qid_storage::{AnyRepository, prelude::*};
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    sync::Arc,
};

#[derive(Parser)]
#[command(name = "qid-dev")]
#[command(about = "qid local development and integration smoke helper")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a runnable local development configuration with test users and qpx smoke assets.
    DevInit {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "dev")]
        realm: String,
        #[arg(long, default_value = "127.0.0.1:8443")]
        listen: String,
        #[arg(long)]
        issuer: Option<String>,
        #[arg(long, default_value = "https://id.example.com")]
        public_base_url: String,
        #[arg(long)]
        force: bool,
    },
    /// Seed test users from a JSON file into the configured storage.
    SeedUsers {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        realm: Option<String>,
        #[arg(long)]
        replace_password: bool,
    },
    /// Run the qpx integration smoke test script.
    QpxSmoke {
        #[arg(long, default_value = "examples/qpx-e2e")]
        example_dir: PathBuf,
        #[arg(long)]
        qpxd_bin: Option<PathBuf>,
        #[arg(long)]
        skip_qpxd: bool,
    },
}

#[derive(Debug, Deserialize)]
struct SeedUser {
    email: String,
    password: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    email_verified: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let result = run(args).await?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

async fn run(args: Args) -> anyhow::Result<serde_json::Value> {
    match args.command {
        Command::DevInit {
            output,
            realm,
            listen,
            issuer,
            public_base_url,
            force,
        } => {
            let dev = DevSpec::new(output, realm, listen, issuer, public_base_url)?;
            dev.write(force)?;
            Ok(serde_json::json!({
                "command": "dev_init",
                "output": dev.output,
                "config": dev.output.join("qid.yaml"),
                "policy": dev.output.join("policy.json"),
                "qpx": dev.output.join("qpx.yaml"),
                "users": dev.output.join("users.seed.json"),
                "realm": dev.realm,
                "issuer": dev.issuer,
            }))
        }
        Command::SeedUsers {
            config,
            input,
            realm,
            replace_password,
        } => {
            let result = seed_users(&config, &input, realm.as_deref(), replace_password).await?;
            Ok(serde_json::json!({
                "command": "seed_users",
                "config": config,
                "input": input,
                "result": result,
            }))
        }
        Command::QpxSmoke {
            example_dir,
            qpxd_bin,
            skip_qpxd,
        } => {
            run_qpx_smoke(&example_dir, qpxd_bin.as_deref(), skip_qpxd)?;
            Ok(serde_json::json!({
                "command": "qpx_smoke",
                "example_dir": example_dir,
                "passed": true,
            }))
        }
    }
}

struct DevSpec {
    output: PathBuf,
    realm: String,
    listen: String,
    issuer: String,
    public_base_url: String,
    client_secret: String,
}

impl DevSpec {
    fn new(
        output: PathBuf,
        realm: String,
        listen: String,
        issuer: Option<String>,
        public_base_url: String,
    ) -> anyhow::Result<Self> {
        ensure!(!realm.trim().is_empty(), "realm must not be empty");
        ensure!(!listen.trim().is_empty(), "listen must not be empty");
        ensure!(
            !public_base_url.trim().is_empty(),
            "public_base_url must not be empty"
        );
        let issuer = issuer.unwrap_or_else(|| {
            format!("{}/realms/{}", public_base_url.trim_end_matches('/'), realm)
        });
        Ok(Self {
            output,
            realm,
            listen,
            issuer,
            public_base_url,
            client_secret: format!("qid-dev-{}", ulid::Ulid::new()),
        })
    }

    fn write(&self, force: bool) -> anyhow::Result<()> {
        ensure_dev_dir(&self.output, force)?;
        write_new_file(&self.output.join("qid.yaml"), self.qid_yaml().as_bytes())?;
        write_new_file(
            &self.output.join("policy.json"),
            self.policy_json().as_bytes(),
        )?;
        write_new_file(&self.output.join("qpx.yaml"), self.qpx_yaml().as_bytes())?;
        write_new_file(
            &self.output.join("users.seed.json"),
            self.users_seed_json().as_bytes(),
        )?;
        write_new_file(&self.output.join("README.md"), self.readme().as_bytes())?;
        QidConfig::from_file(
            self.output
                .join("qid.yaml")
                .to_str()
                .context("invalid generated config path")?,
        )
        .context("generated qid.yaml is invalid")?;
        Ok(())
    }

    fn qid_yaml(&self) -> String {
        format!(
            r#"server:
  listen: {listen}
  public_base_url: {public_base_url}

storage:
  primary:
    type: file
    url: {storage_url}

crypto:
  default_alg: ES256
  keyrings:
    - name: dev-main
      realm_id: {realm}
      purposes:
        - oidc_token
        - saml_assertion
      signer:
        type: local
      rotation:
        overlap_days: 14
        max_age_days: 90
    - name: dev-pep-assertion
      realm_id: {realm}
      purposes:
        - pep_assertion
      signer:
        type: local
      rotation:
        overlap_days: 14
        max_age_days: 90

realms:
  - id: {realm}
    issuer: {issuer}
    display_name: "qid Local Development"
    clients:
      - client_id: "qid-dev-cli"
        id: "client-qid-dev-cli"
        client_type: confidential
        token_endpoint_auth_method: client_secret_post
        client_secret: {client_secret}
        grant_types:
          - client_credentials
      - client_id: "qpx-smoke"
        id: "client-qpx-smoke"
        client_type: confidential
        token_endpoint_auth_method: client_secret_post
        client_secret: {client_secret}
        grant_types:
          - client_credentials
    protocols:
      oidc:
        enabled: true
        authorization_code:
          enabled: true
          pkce_required: true
        implicit:
          enabled: false
        ropc:
          enabled: false
        logout:
          backchannel: true
          frontchannel: true
      oauth:
        introspection: true
        revocation: true
        dynamic_client_registration: false
        resource_servers:
          - audience: "qpx"
            resources:
              - "urn:qid:pep:qpx:edge/dev-egress"
            scopes:
              - api
            introspection_client_ids:
              - pep-edge-dev-main
            require_sender_constraint: false
    authentication:
      passkeys:
        enabled: false
      password:
        enabled: true
        hash: argon2id
    sessions:
      browser:
        cookie_name: "__Host-qid"
        same_site: Lax
        idle_timeout_minutes: 30
        absolute_timeout_hours: 12
    pep_registrations:
      enabled: true
      registrations:
        - name: dev-egress
          audience: "qpx"
          assertion:
            header: "x-qid-assertion"
            ttl_seconds: 60
            alg: ES256
          decision:
            endpoint: "/pep/decision/v1/evaluate"
            fail_policy: deny
    policy:
      bundles:
        - name: qid-dev-authenticated
          source: policy.json
          mode: enforce
      default_decision: deny

observability:
  logs:
    format: json
  metrics:
    listen: "127.0.0.1:9464"
"#,
            listen = yaml_string(&self.listen),
            public_base_url = yaml_string(&self.public_base_url),
            storage_url = yaml_string(&self.output.join("qid-dev-store.json").to_string_lossy()),
            realm = yaml_string(&self.realm),
            issuer = yaml_string(&self.issuer),
            client_secret = yaml_string(&self.client_secret),
        )
    }

    fn policy_json(&self) -> String {
        serde_json::to_string_pretty(&serde_json::json!({
            "version": "1",
            "default_decision": "deny",
            "rules": [
                {
                    "name": "allow-qid-dev-authenticated",
                    "type": "allow",
                    "action": "forward.direct",
                    "resource_host": "*",
                    "inject_headers": {
                        "x-qid-policy": "allow-qid-dev-authenticated"
                    },
                    "pep": {
                        "force_tunnel": true,
                        "cache_bypass": true
                    }
                }
            ]
        }))
        .expect("policy JSON")
    }

    fn qpx_yaml(&self) -> String {
        format!(
            r#"state_dir: "${{QPX_STATE_DIR:-./qpx-state}}"
identity:
  proxy_name: qpx-dev
security:
  identity_sources:
  - name: qid-signed-assertion
    type: signed_assertion
    assertion:
      header: x-qid-assertion
      algorithms:
      - ES256
      issuer: {issuer}
      audience: qpx
      public_key_env: QPX_ASSERTION_PUBLIC_KEY
      claims:
        user_from_sub: true
        groups: groups
        tenant: tenant
        auth_strength: acr
        idp: iss
        groups_separator: ","
  decisions:
    decision:
    - name: qid-central-policy
      endpoint: http://127.0.0.1:8443/pep/decision/v1/evaluate
      timeout_ms: 300
      send:
        request: true
        identity: true
      on_error: deny
edges:
- kind: forward
  name: dev-egress
  listen: 127.0.0.1:18088
  default_action:
    type: block
  rules:
  - name: allow-authenticated
    match:
      host:
      - "*"
      identity:
        user:
        - "*"
    action:
      type: direct
  policy_context:
    identity_sources:
    - qid-signed-assertion
    decision: qid-central-policy
"#,
            issuer = yaml_string(&self.issuer)
        )
    }

    fn users_seed_json(&self) -> String {
        serde_json::to_string_pretty(&serde_json::json!([
            {
                "email": "alice@example.com",
                "password": "qid-dev-alice-password",
                "display_name": "Alice Dev",
                "email_verified": true
            },
            {
                "email": "bob@example.com",
                "password": "qid-dev-bob-password",
                "display_name": "Bob Dev",
                "email_verified": true
            }
        ]))
        .expect("users seed JSON")
    }

    fn readme(&self) -> String {
        r#"# qid local development

Start qidd:

```sh
cargo run --bin qidd -- -c qid.yaml
```

Seed test users:

```sh
cargo run --bin qid-dev -- seed-users -c qid.yaml --input users.seed.json
```

Run qpx smoke from the repository root:

```sh
cargo run --bin qid-dev -- qpx-smoke
```

The generated files are for local development only.
"#
        .to_string()
    }
}

async fn seed_users(
    config_path: &Path,
    input: &Path,
    realm_override: Option<&str>,
    replace_password: bool,
) -> anyhow::Result<serde_json::Value> {
    let config = QidConfig::from_file(config_path.to_str().context("invalid config path")?)
        .context("failed to load config")?;
    let realm_config = match realm_override {
        Some(realm_id) => config
            .realms
            .iter()
            .find(|realm| realm.id == realm_id)
            .with_context(|| format!("realm not found in config: {realm_id}"))?,
        None => config
            .realms
            .first()
            .context("config must contain at least one realm")?,
    };
    let users: Vec<SeedUser> = read_json(input)?;
    ensure!(
        !users.is_empty(),
        "seed input must contain at least one user"
    );
    let repo = open_repo(&config).await?;
    ensure_realm(&repo, realm_config).await?;

    let mut created = Vec::new();
    let mut existing = Vec::new();
    let mut updated_password = Vec::new();
    for seed in users {
        ensure!(
            !seed.email.trim().is_empty(),
            "seed user email must not be empty"
        );
        ensure!(
            !seed.password.is_empty(),
            "seed user password must not be empty"
        );
        let realm_id = RealmId::from(realm_config.id.clone());
        if let Some(user) = repo.get_user_by_email(&realm_id, &seed.email).await? {
            existing.push(seed.email.clone());
            if replace_password {
                store_password(&repo, &user.id, &seed.password).await?;
                updated_password.push(seed.email);
            }
            continue;
        }

        let id = ulid::Ulid::new().to_string();
        repo.create_user(&User {
            id: id.clone(),
            realm_id: realm_config.id.clone(),
            email: Some(seed.email.clone()),
            email_verified: seed.email_verified,
            display_name: seed.display_name,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await?;
        store_password(&repo, &id, &seed.password).await?;
        created.push(seed.email);
    }

    Ok(serde_json::json!({
        "realm": realm_config.id,
        "created": created,
        "existing": existing,
        "updated_password": updated_password,
    }))
}

async fn ensure_realm(
    repo: &Arc<AnyRepository>,
    realm: &qid_core::config::RealmConfig,
) -> anyhow::Result<()> {
    let realm_id = RealmId::from(realm.id.clone());
    match repo.get_realm_tenant(&realm_id).await? {
        Some(_) => Ok(()),
        None => repo
            .create_realm(
                &TenantId::from("default"),
                &realm_id,
                &realm.issuer,
                realm.display_name.as_deref(),
            )
            .await
            .map_err(Into::into),
    }
}

async fn store_password(
    repo: &Arc<AnyRepository>,
    user_id: &str,
    plaintext: &str,
) -> anyhow::Result<()> {
    let hash = password::hash_password(plaintext)?;
    repo.store_password_credential(&PasswordCredential {
        user_id: user_id.to_string(),
        hash,
        algorithm: "argon2id".to_string(),
        pepper_ref: None,
    })
    .await?;
    Ok(())
}

async fn open_repo(config: &QidConfig) -> anyhow::Result<Arc<AnyRepository>> {
    let storage_url = config.storage.primary.resolve_url_or("qid-dev.db");
    Ok(Arc::new(
        AnyRepository::connect(&storage_url)
            .await
            .context("failed to connect to storage")?,
    ))
}

fn run_qpx_smoke(
    example_dir: &Path,
    qpxd_bin: Option<&Path>,
    skip_qpxd: bool,
) -> anyhow::Result<()> {
    let script = example_dir.join("run.sh");
    ensure!(
        script.exists(),
        "qpx smoke script not found: {}",
        script.display()
    );
    let mut command = ProcessCommand::new("bash");
    command.arg(&script).current_dir(example_dir);
    if let Some(qpxd_bin) = qpxd_bin {
        command.env("QPXD_BIN", qpxd_bin);
    }
    if skip_qpxd {
        command.env("QPXD_BIN", example_dir.join(".qid-dev-skip-qpxd"));
    }
    let status = command.status().context("failed to run qpx smoke script")?;
    ensure!(status.success(), "qpx smoke script failed with {status}");
    Ok(())
}

fn ensure_dev_dir(output: &Path, force: bool) -> anyhow::Result<()> {
    if output.exists() {
        ensure!(output.is_dir(), "{} is not a directory", output.display());
        if !force && output.read_dir()?.next().is_some() {
            bail!(
                "{} already exists and is not empty; pass --force to overwrite development files",
                output.display()
            );
        }
    } else {
        fs::create_dir_all(output)
            .with_context(|| format!("failed to create {}", output.display()))?;
    }
    Ok(())
}

fn write_new_file(path: &Path, body: &[u8]) -> anyhow::Result<()> {
    fs::write(path, body).with_context(|| format!("failed to write {}", path.display()))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> anyhow::Result<T> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("invalid JSON in {}", path.display()))
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).expect("JSON string")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("qid-dev-{name}-{}", ulid::Ulid::new()))
    }

    #[tokio::test]
    async fn dev_init_writes_valid_local_assets() {
        let dir = temp_dir("dev-init");
        let result = run(Args {
            command: Command::DevInit {
                output: dir.clone(),
                realm: "dev".to_string(),
                listen: "127.0.0.1:0".to_string(),
                issuer: None,
                public_base_url: "https://id.example.com".to_string(),
                force: false,
            },
        })
        .await
        .expect("dev init");

        assert_eq!(result["command"], "dev_init");
        assert!(dir.join("qid.yaml").exists());
        assert!(dir.join("policy.json").exists());
        assert!(dir.join("qpx.yaml").exists());
        assert!(dir.join("users.seed.json").exists());

        let config = QidConfig::from_file(dir.join("qid.yaml").to_str().expect("config path"))
            .expect("generated config");
        assert_eq!(config.realms[0].id, "dev");
        assert_eq!(config.realms[0].clients.len(), 2);
        assert_eq!(config.realms[0].policy.default_decision, "deny");
        assert_eq!(config.crypto.keyrings.len(), 2);
        assert_eq!(config.crypto.keyrings[0].name, "dev-main");
        assert_eq!(
            config.crypto.keyrings[0].purposes,
            vec!["oidc_token".to_string(), "saml_assertion".to_string()]
        );
        assert_eq!(config.crypto.keyrings[1].name, "dev-pep-assertion");
        assert_eq!(config.crypto.keyrings[1].realm_id.as_deref(), Some("dev"));
        assert_eq!(
            config.crypto.keyrings[1].purposes,
            vec!["pep_assertion".to_string()]
        );

        let users: Vec<SeedUser> = read_json(&dir.join("users.seed.json")).expect("seed users");
        assert_eq!(users.len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn seed_users_uses_real_storage_and_hashes_passwords() {
        let dir = temp_dir("seed-users");
        run(Args {
            command: Command::DevInit {
                output: dir.clone(),
                realm: "dev".to_string(),
                listen: "127.0.0.1:0".to_string(),
                issuer: None,
                public_base_url: "https://id.example.com".to_string(),
                force: false,
            },
        })
        .await
        .expect("dev init");

        let config = dir.join("qid.yaml");
        let users = dir.join("users.seed.json");
        let result = run(Args {
            command: Command::SeedUsers {
                config: config.clone(),
                input: users,
                realm: Some("dev".to_string()),
                replace_password: false,
            },
        })
        .await
        .expect("seed users");
        assert_eq!(
            result["result"]["created"]
                .as_array()
                .expect("created")
                .len(),
            2
        );
        assert!(dir.join("qid-dev-store.json").exists());

        let loaded = QidConfig::from_file(config.to_str().expect("config path")).expect("config");
        let repo = open_repo(&loaded).await.expect("repository");
        let alice = repo
            .get_user_by_email(&RealmId::from("dev".to_string()), "alice@example.com")
            .await
            .expect("alice lookup")
            .expect("alice");
        assert!(alice.email_verified);
        let cred = repo
            .get_password_credential(&alice.id)
            .await
            .expect("password lookup")
            .expect("password");
        assert!(cred.hash.starts_with("$argon2id$"));
        assert!(password::verify_password("qid-dev-alice-password", &cred.hash).expect("verify"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn dev_init_requires_force_for_non_empty_directory() {
        let dir = temp_dir("force");
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join("existing.txt"), "existing").expect("existing file");

        let err = run(Args {
            command: Command::DevInit {
                output: dir.clone(),
                realm: "dev".to_string(),
                listen: "127.0.0.1:0".to_string(),
                issuer: None,
                public_base_url: "https://id.example.com".to_string(),
                force: false,
            },
        })
        .await
        .expect_err("non-empty directory requires force");
        assert!(err.to_string().contains("pass --force"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
