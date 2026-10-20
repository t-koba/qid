use qid_storage::{AnyRepository, AuditRepository, RealmRepository, ScimRepository, SqlRepository};
use std::sync::Arc;
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
    let report = crate::run_directory_sync_job(
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
    let failed = serde_json::json!({
        "command": "directory_sync",
        "report": {"status": "failed", "errors": ["provider missing-provider not found"]}
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
