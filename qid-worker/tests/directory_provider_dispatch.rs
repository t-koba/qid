use qid_core::config::QidConfig;
use qid_storage::AnyRepository;
use qid_worker::{DirectorySyncJobConfig, run_directory_sync_job};
use std::sync::Arc;

#[tokio::test]
async fn active_directory_provider_dispatches_to_ldap_connector() {
    let dir = std::env::temp_dir().join(format!("qid-worker-ad-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let store = dir.join("qid-store.json");
    let config_path = dir.join("qid.yaml");
    let store_url = serde_json::to_string(&store.to_string_lossy()).expect("store path");
    std::fs::write(
        &config_path,
        format!(
            r#"server:
  listen: "127.0.0.1:0"
  public_base_url: "https://id.example.com"
storage:
  primary:
    url: {store_url}
realms:
  - id: corp
    issuer: "https://id.example.com/realms/corp"
    protocols:
      directory:
        enabled: true
        providers:
          - id: corp-ad
            type: active-directory
            enabled: true
            connection:
              url: "ldap://dir.invalid"
"#
        ),
    )
    .expect("config file");

    let config = QidConfig::from_file(config_path.to_str().expect("config path"))
        .expect("canonical active-directory config validates");
    let repo = Arc::new(
        AnyRepository::connect(store.to_str().expect("store path"))
            .await
            .expect("repository"),
    );
    // The LDAP-specific connect error proves dispatch reached that connector.
    let error = run_directory_sync_job(
        repo,
        &config,
        DirectorySyncJobConfig {
            realm_id: "corp".to_string(),
            provider_id: "corp-ad".to_string(),
            actor: "qid-worker".to_string(),
            reason: "active-directory dispatch regression".to_string(),
            now_epoch: 100,
            record_audit_event: false,
            dry_run: false,
        },
    )
    .await
    .expect_err("malformed LDAP URL should fail in the selected connector")
    .to_string();

    assert!(
        error.contains("LDAP connect to"),
        "unexpected error: {error}"
    );
    assert!(
        error.starts_with("internal error:"),
        "an unreachable directory is a transport fault: {error}"
    );
    assert!(
        !error.contains("unsupported type"),
        "canonical active-directory type was rejected: {error}"
    );
    std::fs::remove_dir_all(&dir).ok();
}
