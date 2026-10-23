use qid_core::config::{DirectoryAttributeMapping, DirectoryConnectionConfig, DirectorySyncConfig};
use qid_core::error::{QidError, QidResult};
use qid_directory::LdapDirectoryEntry;
use qid_directory::connector::DirectoryConnector;
use qid_storage::{AnyRepository, AuditRepository, RealmRepository, ScimRepository, SqlRepository};
use std::sync::Arc;

/// A directory connector for the sync regressions: it returns fixed entries,
/// or fails with a fixed fault.
struct StubDirectoryConnector {
    entries: Vec<LdapDirectoryEntry>,
    fault: Option<QidError>,
}

impl StubDirectoryConnector {
    fn returning(entries: Vec<LdapDirectoryEntry>) -> Self {
        Self {
            entries,
            fault: None,
        }
    }

    fn failing(fault: QidError) -> Self {
        Self {
            entries: Vec::new(),
            fault: Some(fault),
        }
    }
}

#[async_trait::async_trait]
impl DirectoryConnector for StubDirectoryConnector {
    async fn connect(&mut self, _config: &DirectoryConnectionConfig) -> QidResult<()> {
        Ok(())
    }

    async fn fetch_users(
        &self,
        _sync: &DirectorySyncConfig,
        _mapping: &DirectoryAttributeMapping,
    ) -> QidResult<Vec<LdapDirectoryEntry>> {
        match &self.fault {
            Some(fault) => Err(fault.clone()),
            None => Ok(self.entries.clone()),
        }
    }

    async fn disconnect(&mut self) -> QidResult<()> {
        Ok(())
    }
}

/// A repository and configuration with one enabled directory provider, so
/// a sync job reaches its fetch.
async fn sync_fixture() -> (
    Arc<AnyRepository>,
    qid_core::config::QidConfig,
    std::path::PathBuf,
) {
    let dir = std::env::temp_dir().join(format!("qid-sync-fixture-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let db_path = dir.join("sync.db");
    let db_url = format!("sqlite:{}", db_path.display());
    let repo = SqlRepository::connect(&db_url).await.expect("connect");
    repo.migrate().await.expect("migrate");
    repo.create_realm(
        &"default".into(),
        &"corp".into(),
        "https://id.example.com/realms/corp",
        None,
    )
    .await
    .expect("create realm");
    let cfg_path = dir.join("qid.yaml");
    std::fs::write(&cfg_path, format!("server:\n  listen: \"127.0.0.1:0\"\n  public_base_url: \"https://id.example.com\"\nstorage:\n  primary:\n    url: {}\nrealms:\n  - id: corp\n    issuer: \"https://id.example.com/realms/corp\"\n    protocols:\n      directory:\n        enabled: true\n        providers:\n          - id: corp-ldap\n            type: ldap\n            enabled: true\n            connection:\n              url: \"ldap://dir.invalid\"\n            sync:\n              deactivate_missing: true\n", serde_json::to_string(&db_path.to_string_lossy()).expect("store url"))).expect("write config");
    let config = qid_core::config::QidConfig::from_file(cfg_path.to_str().expect("cfg path"))
        .expect("config");
    (Arc::new(AnyRepository::Sql(repo)), config, dir)
}

fn sync_job_config() -> crate::DirectorySyncJobConfig {
    crate::DirectorySyncJobConfig {
        realm_id: "corp".to_string(),
        provider_id: "corp-ldap".to_string(),
        actor: "qid-worker".to_string(),
        reason: "connector injection regression".to_string(),
        now_epoch: 100,
        record_audit_event: false,
        dry_run: false,
    }
}
#[tokio::test]
async fn directory_sync_reports_failed_audit_without_losing_deactivation() {
    let dir = std::env::temp_dir().join(format!("qid-sync-audit-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let db_path = dir.join("sync.db");
    let db_url = format!("sqlite:{}", db_path.display());
    let repo = SqlRepository::connect(&db_url).await.expect("connect");
    repo.migrate().await.expect("migrate");
    repo.create_realm(
        &"default".into(),
        &"corp".into(),
        "https://id.example.com/realms/corp",
        None,
    )
    .await
    .expect("create realm");
    let trigger_url = format!("sqlite:{}?mode=rwc", db_path.display());
    let pool = sqlx::sqlite::SqlitePool::connect(&trigger_url)
        .await
        .expect("trigger pool");
    sqlx::query("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;").execute(&pool).await.expect("create trigger");
    pool.close().await;
    repo.create_scim_user(&qid_core::models::ScimUser {
        id: "user-1".to_string(),
        realm_id: "corp".to_string(),
        external_id: Some("cn=alice,dc=example,dc=com".to_string()),
        user_name: "alice".to_string(),
        name_json: serde_json::json!({}),
        emails_json: serde_json::json!([]),
        enterprise_json: serde_json::json!({}),
        directory_provider_id: Some("corp-ldap".to_string()),
        deprovisioned_at: None,
        active: true,
    })
    .await
    .expect("seed user");
    let cfg_path = dir.join("qid.yaml");
    std::fs::write(&cfg_path, format!("server:\n  listen: \"127.0.0.1:0\"\n  public_base_url: \"https://id.example.com\"\nstorage:\n  primary:\n    url: {}\nrealms:\n  - id: corp\n    issuer: \"https://id.example.com/realms/corp\"\n    protocols:\n      directory:\n        enabled: true\n        providers:\n          - id: corp-ldap\n            type: ldap\n            enabled: true\n            connection:\n              url: \"ldap://dir.invalid\"\n            sync:\n              deactivate_missing: true\n", serde_json::to_string(&db_path.to_string_lossy()).expect("store url"))).expect("write config");
    let config = qid_core::config::QidConfig::from_file(cfg_path.to_str().expect("cfg path"))
        .expect("config");
    let any = Arc::new(AnyRepository::Sql(repo));
    let report = crate::sync::run_directory_sync_job_with_connector(
        any.clone(),
        &config,
        crate::DirectorySyncJobConfig {
            realm_id: "corp".to_string(),
            provider_id: "corp-ldap".to_string(),
            actor: "qid-worker".to_string(),
            reason: "audit failure regression".to_string(),
            now_epoch: 100,
            record_audit_event: true,
            dry_run: false,
        },
        Box::new(|| Box::new(StubDirectoryConnector::returning(Vec::new()))),
    )
    .await
    .expect("sync job");
    assert_eq!(report.status, crate::DirectorySyncJobStatus::Completed);
    assert_eq!(report.deactivated, 1);
    assert!(report.audit_event_id.is_none());
    assert_eq!(report.errors.len(), 1);
    let msg = report.errors.join("\n").to_lowercase();
    assert!(
        msg.contains("audit") && msg.contains("persist"),
        "missing audit persistence: {}",
        report.errors.join(";")
    );
    assert!(
        msg.contains("may already have occurred"),
        "missing prior-mutation caveat: {}",
        report.errors.join(";")
    );
    let user = any
        .get_scim_user("user-1")
        .await
        .expect("get user")
        .expect("user exists");
    assert!(
        !user.active,
        "seeded user must be deactivated before audit failure"
    );
    let events = any
        .list_audit_events(
            Some(&qid_core::tenant::RealmId::from("corp".to_string())),
            10,
        )
        .await
        .expect("list audit");
    assert!(events.is_empty(), "no audit event must persist");
    let any = Arc::try_unwrap(any).unwrap_or_else(|_| panic!("single owner"));
    match any {
        AnyRepository::Sql(r) => r.close().await,
        _ => panic!("expected sql repository"),
    }
    std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
}

#[tokio::test]
async fn a_directory_fetch_fault_is_reported_instead_of_swallowed() {
    // A test build used to fall back to an empty test connector, so a fetch
    // fault completed the sync and deactivated every user instead of
    // reporting the fault.
    let (any, config, dir) = sync_fixture().await;
    let error = crate::sync::run_directory_sync_job_with_connector(
        any.clone(),
        &config,
        sync_job_config(),
        Box::new(|| {
            Box::new(StubDirectoryConnector::failing(QidError::Config {
                message: "bind DN and bind password must both be set".to_string(),
            }))
        }),
    )
    .await
    .expect_err("the fetch fault is reported");

    assert!(
        matches!(error, QidError::Config { .. }),
        "a configuration fault stays a configuration fault: {error:?}"
    );
    assert!(
        error.message().contains("directory fetch failed"),
        "the fault carries the fetch context: {error:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn a_directory_sync_applies_the_entries_the_connector_returns() {
    let (any, config, dir) = sync_fixture().await;
    let report = crate::sync::run_directory_sync_job_with_connector(
        any.clone(),
        &config,
        sync_job_config(),
        Box::new(|| {
            Box::new(StubDirectoryConnector::returning(vec![
                LdapDirectoryEntry {
                    dn: "uid=alice,ou=people,dc=example,dc=com".to_string(),
                    uid: "alice".to_string(),
                    mail: Some("alice@example.com".to_string()),
                    display_name: Some("Alice Example".to_string()),
                    department: Some("Engineering".to_string()),
                    manager_dn: None,
                    enabled: true,
                },
            ]))
        }),
    )
    .await
    .expect("sync job");

    assert_eq!(report.status, crate::DirectorySyncJobStatus::Completed);
    assert_eq!(report.created, 1);
    let users = any
        .list_scim_users(&qid_core::tenant::RealmId::from("corp".to_string()))
        .await
        .expect("list users");
    let user = users
        .iter()
        .find(|user| user.user_name == "alice")
        .expect("the directory entry became a user");
    assert_eq!(user.directory_provider_id.as_deref(), Some("corp-ldap"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_directory_fetch_fault_keeps_its_kind() {
    use qid_core::error::QidError;
    // The classification is outside the production-only branch, so the kind
    // a connector reports is the kind the operator sees.
    let config = QidError::Config {
        message: "bind DN and bind password must both be set".to_string(),
    };
    let error = crate::sync::directory_fetch_error(config);
    assert!(
        matches!(error, QidError::Config { .. }),
        "a configuration fault stays a configuration fault"
    );
    assert!(error.message().contains("directory fetch failed"));
    let internal = QidError::Internal {
        message: "the directory is unreachable".to_string(),
    };
    let error = crate::sync::directory_fetch_error(internal);
    assert!(
        matches!(error, QidError::Internal { .. }),
        "a transport fault stays a server fault"
    );
}

#[test]
fn a_directory_fetch_fault_keeps_every_kind() {
    use qid_core::error::QidError;
    // The third arm passes every other kind through unchanged.
    let storage = QidError::Storage {
        message: "the store is unavailable".to_string(),
    };
    let error = crate::sync::directory_fetch_error(storage);
    assert!(
        matches!(error, QidError::Storage { .. }),
        "a storage fault keeps its kind"
    );
}

#[test]
fn a_failed_directory_sync_makes_the_command_exit_nonzero() {
    let status =
        serde_json::to_value(crate::DirectorySyncJobStatus::Failed).expect("the status serializes");
    assert_eq!(status, "failed");
    let failed = serde_json::json!({
        "command": "directory_sync",
        "report": {"status": status, "errors": ["provider missing-provider not found"]}
    });
    assert!(crate::sync::sync_failed(&failed));
    let skipped = serde_json::json!({
        "command": "directory_sync",
        "report": {"status": "skipped_disabled", "errors": []}
    });
    assert!(!crate::sync::sync_failed(&skipped));
    let other = serde_json::json!({"command": "audit_retention_evaluate"});
    assert!(!crate::sync::sync_failed(&other));
}

/// A repository and configuration with one enabled CSV HR provider backed by
/// a real temp file, so a sync job reads the file end to end.
async fn csv_sync_fixture(
    initial_csv: &str,
) -> (
    Arc<AnyRepository>,
    qid_core::config::QidConfig,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let dir = std::env::temp_dir().join(format!("qid-csv-fixture-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let db_path = dir.join("sync.db");
    let db_url = format!("sqlite:{}", db_path.display());
    let repo = SqlRepository::connect(&db_url).await.expect("connect");
    repo.migrate().await.expect("migrate");
    repo.create_realm(
        &"default".into(),
        &"corp".into(),
        "https://id.example.com/realms/corp",
        None,
    )
    .await
    .expect("create realm");
    let csv_path = dir.join("workforce.csv");
    std::fs::write(&csv_path, initial_csv).expect("write csv");
    let cfg_path = dir.join("qid.yaml");
    std::fs::write(&cfg_path, format!("server:\n  listen: \"127.0.0.1:0\"\n  public_base_url: \"https://id.example.com\"\nstorage:\n  primary:\n    url: {}\nrealms:\n  - id: corp\n    issuer: \"https://id.example.com/realms/corp\"\n    protocols:\n      directory:\n        enabled: true\n        providers:\n          - id: hr-csv\n            type: csv\n            enabled: true\n            connection:\n              url: {}\n            sync:\n              deactivate_missing: false\n", serde_json::to_string(&db_path.to_string_lossy()).expect("store url"), serde_json::to_string(&format!("  {}  ", csv_path.to_string_lossy())).expect("csv url"))).expect("write config");
    let config = qid_core::config::QidConfig::from_file(cfg_path.to_str().expect("cfg path"))
        .expect("config");
    (Arc::new(AnyRepository::Sql(repo)), config, dir, csv_path)
}

fn csv_job_config(record_audit_event: bool) -> crate::DirectorySyncJobConfig {
    crate::DirectorySyncJobConfig {
        realm_id: "corp".to_string(),
        provider_id: "hr-csv".to_string(),
        actor: "qid-worker".to_string(),
        reason: "csv hr regression".to_string(),
        now_epoch: 100,
        record_audit_event,
        dry_run: false,
    }
}

#[tokio::test]
async fn csv_directory_sync_creates_updates_and_deprovisions_through_the_job() {
    let (any, config, dir, csv_path) = csv_sync_fixture(
        "external_id,email,display_name,department,manager_external_id,event\nhr-1,hr-1@example.com,HR One,Research,,joiner\nhr-2,hr-2@example.com,HR Two,Sales,,joiner\n",
    )
    .await;
    let report = crate::sync::run_directory_sync_job(any.clone(), &config, csv_job_config(true))
        .await
        .expect("csv sync job");
    assert_eq!(report.status, crate::DirectorySyncJobStatus::Completed);
    assert_eq!(report.created, 2);
    assert_eq!(report.updated, 0);
    assert_eq!(report.deactivated, 0);
    assert!(report.audit_event_id.is_some());

    let users = any
        .list_scim_users(&qid_core::tenant::RealmId::from("corp".to_string()))
        .await
        .expect("list users");
    assert_eq!(users.len(), 2);
    let hr1 = users
        .iter()
        .find(|u| u.user_name == "hr-1")
        .expect("hr-1 created");
    assert_eq!(
        hr1.enterprise_json["department"],
        serde_json::json!("Research")
    );

    std::fs::write(
        &csv_path,
        "external_id,email,display_name,department,manager_external_id,event\nhr-1,hr-1@example.com,HR One,Platform,,mover\nhr-2,,,,,leaver\n",
    )
    .expect("rewrite csv");
    let report = crate::sync::run_directory_sync_job(any.clone(), &config, csv_job_config(true))
        .await
        .expect("csv resync job");
    assert_eq!(report.status, crate::DirectorySyncJobStatus::Completed);
    assert_eq!(report.created, 0);
    assert_eq!(report.updated, 1);
    assert_eq!(report.deactivated, 1);

    let users = any
        .list_scim_users(&qid_core::tenant::RealmId::from("corp".to_string()))
        .await
        .expect("list users");
    let hr1 = users
        .iter()
        .find(|u| u.user_name == "hr-1")
        .expect("hr-1 kept");
    assert_eq!(
        hr1.enterprise_json["department"],
        serde_json::json!("Platform")
    );
    assert!(hr1.active);
    let hr2 = users
        .iter()
        .find(|u| u.user_name == "hr-2")
        .expect("hr-2 kept");
    assert!(!hr2.active, "the leaver is deprovisioned");

    let events = any
        .list_audit_events(
            Some(&qid_core::tenant::RealmId::from("corp".to_string())),
            10,
        )
        .await
        .expect("list audit");
    assert!(
        events.iter().all(|e| e.action == "directory.sync"),
        "csv syncs audit like ldap syncs"
    );
    assert_eq!(events.len(), 2);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn csv_directory_sync_rejects_a_bad_batch_before_any_write() {
    let (any, config, dir, csv_path) = csv_sync_fixture(
        "external_id,email,display_name,department,manager_external_id,event\nhr-1,hr-1@example.com,HR One,Research,,joiner\n",
    )
    .await;
    crate::sync::run_directory_sync_job(any.clone(), &config, csv_job_config(false))
        .await
        .expect("seed sync");

    for (row, expected) in [
        ("hr-3,,,,,not-an-event", "event"),
        ("hr-3,,un\"quoted,,,joiner", "malformed quoted field"),
        ("hr-3,,\"closed\"text,,,joiner", "malformed quoted field"),
    ] {
        std::fs::write(
            &csv_path,
            format!("external_id,email,display_name,department,manager_external_id,event\nhr-2,hr-2@example.com,HR Two,Sales,,joiner\n{row}\n"),
        )
        .expect("rewrite csv");
        let err = crate::sync::run_directory_sync_job(any.clone(), &config, csv_job_config(false))
            .await
            .expect_err("a bad row fails the whole batch");
        assert!(
            err.message().contains(expected),
            "the failure names the bad row: {err:?}"
        );
    }

    let users = any
        .list_scim_users(&qid_core::tenant::RealmId::from("corp".to_string()))
        .await
        .expect("list users");
    assert_eq!(users.len(), 1, "no prefix of the rejected batch is written");
    assert_eq!(users[0].user_name, "hr-1");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn csv_directory_sync_ignores_the_injected_ldap_connector() {
    // The CSV path parses the configured file and never touches the LDAP
    // connector factory, so LDAP dispatch keeps its own path.
    let (any, config, dir, _csv_path) = csv_sync_fixture(
        "external_id,email,display_name,department,manager_external_id,event\nhr-1,,,,,joiner\n",
    )
    .await;
    let report = crate::sync::run_directory_sync_job_with_connector(
        any.clone(),
        &config,
        csv_job_config(false),
        Box::new(|| {
            Box::new(StubDirectoryConnector::failing(QidError::Config {
                message: "the csv path must not connect".to_string(),
            })) as Box<dyn DirectoryConnector>
        }),
    )
    .await
    .expect("csv sync without a usable connector");
    assert_eq!(report.status, crate::DirectorySyncJobStatus::Completed);
    assert_eq!(report.created, 1);
    std::fs::remove_dir_all(&dir).ok();
}
