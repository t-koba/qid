use qid_core::models::{AuditEvent, AuthorizationCode, Session, TokenFamily, User};
use qid_core::tenant::{RealmId, TenantId};
use qid_storage::{
    FileFlushMode, FileRepository, SiemDeliveryRecord, SiemDeliveryStatus, prelude::*,
};
use std::sync::Arc;
use std::time::Duration;

async fn setup() -> Arc<FileRepository> {
    let path = std::env::temp_dir().join(format!("qid_file_test_{}.json", ulid::Ulid::new()));
    setup_at(path).await
}

async fn setup_at(path: std::path::PathBuf) -> Arc<FileRepository> {
    let repo = Arc::new(FileRepository::new(path.to_str().unwrap()).await.unwrap());
    repo.migrate().await.unwrap();
    qid_storage::RealmRepository::create_realm(
        repo.as_ref(),
        &TenantId::from("tenant-1"),
        &RealmId::from("test"),
        "https://id.example.com",
        Some("Test Realm"),
    )
    .await
    .unwrap();
    repo
}

#[tokio::test]
async fn file_session_crud() {
    let repo = setup().await;
    let now = qid_core::util::now_seconds();
    let session = Session {
        id: "session-1".to_string(),
        realm_id: "test".to_string(),
        user_id: "user-1".to_string(),
        auth_time: now,
        acr: None,
        amr: Vec::new(),
        absolute_expires_at: now + 3600,
        idle_expires_at: now + 900,
        revoked: false,
        created_at: now,
        cnf: None,
    };
    repo.create_session(&session).await.unwrap();
    let loaded = repo.get_session("session-1").await.unwrap().unwrap();
    assert_eq!(loaded.user_id, "user-1");
    assert!(!loaded.revoked);
    repo.revoke_session("session-1").await.unwrap();
    let after_revoke = repo.get_session("session-1").await.unwrap().unwrap();
    assert!(after_revoke.revoked);
}

#[tokio::test]
async fn file_authorization_code_single_use() {
    let repo = setup().await;
    let now = qid_core::util::now_seconds();
    let code = AuthorizationCode {
        code_hash: "code-hash-1".to_string(),
        client_id: "client-1".to_string(),
        user_id: "user-1".to_string(),
        realm_id: "test".to_string(),
        redirect_uri: "https://example.com/cb".to_string(),
        state: None,
        nonce: None,
        auth_time: None,
        acr: None,
        amr: Vec::new(),
        code_challenge: None,
        code_challenge_method: None,
        scopes: vec!["openid".to_string()],
        resource: Vec::new(),
        authorization_details: None,
        expires_at: now + 3600,
        used: false,
        created_at: now,
    };
    repo.create_authorization_code(&code).await.unwrap();
    let loaded = repo
        .get_authorization_code("code-hash-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.client_id, "client-1");
    repo.mark_authorization_code_used("code-hash-1")
        .await
        .unwrap();
    let second_use = repo.mark_authorization_code_used("code-hash-1").await;
    assert!(second_use.is_err(), "second use must be rejected");
}

#[tokio::test]
async fn file_token_family_reuse_detected() {
    let repo = setup().await;
    let now = qid_core::util::now_seconds();
    let family = TokenFamily {
        id: "tf-1".to_string(),
        user_id: "user-1".to_string(),
        client_id: "client-1".to_string(),
        realm_id: "test".to_string(),
        current_refresh_hash: "hash-v1".to_string(),
        audience: Vec::new(),
        resource: Vec::new(),
        authorization_details: None,
        sender_constraint: None,
        issued_at: now,
        revoked: false,
    };
    repo.create_token_family(&family).await.unwrap();
    // Same hash presented twice must be detected
    let result = repo
        .update_token_family_refresh_hash("tf-1", "hash-v1")
        .await;
    assert!(
        result.is_err(),
        "same hash reuse must be rejected as replay"
    );
}

#[tokio::test]
async fn file_audit_chain_hash_integrity() {
    let repo = setup().await;
    let now = qid_core::util::now_seconds();

    let event1 = AuditEvent {
        id: "evt-1".to_string(),
        realm_id: Some("test".to_string()),
        actor: "admin".to_string(),
        action: "user.create".to_string(),
        target_type: "User".to_string(),
        target_id: "user-1".to_string(),
        reason: "test".to_string(),
        metadata_json: serde_json::json!({}),
        created_at: now,
        previous_hash: None,
        event_hash: None,
    }
    .with_chain_hashes(None);
    let event1_hash = event1.event_hash.clone();
    repo.append_audit_event(&event1).await.unwrap();

    let event2 = AuditEvent {
        id: "evt-2".to_string(),
        realm_id: Some("test".to_string()),
        actor: "admin".to_string(),
        action: "user.delete".to_string(),
        target_type: "User".to_string(),
        target_id: "user-1".to_string(),
        reason: "cleanup".to_string(),
        metadata_json: serde_json::json!({}),
        created_at: now + 1,
        previous_hash: event1_hash,
        event_hash: None,
    }
    .with_chain_hashes(event1.event_hash);
    repo.append_audit_event(&event2).await.unwrap();

    // Verify chain integrity via the repository's verification method
    let realm_verification = repo.verify_audit_chain(Some(&"test".into())).await.unwrap();
    assert!(realm_verification.valid, "audit chain must be valid");
    assert_eq!(
        realm_verification.checked_events, 2,
        "must verify both events"
    );
    assert_eq!(
        realm_verification.last_event_id,
        Some("evt-2".to_string()),
        "last event id must be the most recent"
    );
}

#[tokio::test]
async fn file_concurrent_user_writes_survive_reload() {
    let path = std::env::temp_dir().join(format!("qid_file_concurrent_{}.json", ulid::Ulid::new()));
    {
        let repo = setup_at(path.clone()).await;
        let mut tasks = Vec::new();
        for i in 0..100 {
            let repo = Arc::clone(&repo);
            tasks.push(tokio::spawn(async move {
                let user = User {
                    id: format!("user-{i:03}"),
                    realm_id: "test".to_string(),
                    email: Some(format!("user-{i:03}@example.com")),
                    email_verified: true,
                    display_name: Some(format!("User {i:03}")),
                    failed_login_attempts: 0,
                    locked_until: None,
                    org: None,
                };
                repo.create_user(&user).await
            }));
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
    }

    let reloaded = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    let users = reloaded.list_users(&RealmId::from("test")).await.unwrap();
    assert_eq!(users.len(), 100, "all concurrent writes must be durable");
}

#[tokio::test]
async fn file_user_pages_are_stable() {
    let repo = setup().await;
    for id in ["user-c", "user-a", "user-b"] {
        repo.create_user(&User {
            id: id.to_string(),
            realm_id: "test".to_string(),
            email: Some(format!("{id}@example.com")),
            email_verified: true,
            display_name: None,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .unwrap();
    }

    let page = repo
        .list_users_page(&RealmId::from("test"), 1, 1)
        .await
        .unwrap();

    assert_eq!(page.len(), 1);
    assert_eq!(page[0].id, "user-b");
}

#[tokio::test]
async fn file_interval_flush_defers_disk_write_until_flush() {
    let path = std::env::temp_dir().join(format!("qid_file_flush_{}.json", ulid::Ulid::new()));
    let repo = FileRepository::new_with_flush_mode(
        path.to_str().unwrap(),
        FileFlushMode::Interval(Duration::from_secs(60)),
    )
    .await
    .unwrap();
    repo.migrate().await.unwrap();
    qid_storage::RealmRepository::create_realm(
        &repo,
        &TenantId::from("tenant-1"),
        &RealmId::from("test"),
        "https://id.example.com",
        Some("Test Realm"),
    )
    .await
    .unwrap();
    let before_flush = tokio::fs::read_to_string(&path).await.unwrap();

    repo.create_user(&User {
        id: "user-interval".to_string(),
        realm_id: "test".to_string(),
        email: Some("interval@example.com".to_string()),
        email_verified: true,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();

    let dirty_content = tokio::fs::read_to_string(&path).await.unwrap();
    assert_eq!(dirty_content, before_flush);

    repo.flush().await.unwrap();
    let flushed_content = tokio::fs::read_to_string(&path).await.unwrap();
    assert!(
        flushed_content.contains("user-interval"),
        "manual flush must persist dirty store"
    );
}

#[tokio::test]
async fn file_repository_rejects_second_process_lock_holder() {
    let path = std::env::temp_dir().join(format!("qid_file_lock_{}.json", ulid::Ulid::new()));
    let first = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    let second = FileRepository::new(path.to_str().unwrap()).await;

    let error = second.expect_err("second repository must not acquire the same file lock");
    assert!(
        format!("{error:?}").contains("file storage is already locked"),
        "error must clearly explain the process lock failure: {error:?}"
    );

    drop(first);
    let reopened = FileRepository::new(path.to_str().unwrap()).await;
    assert!(
        reopened.is_ok(),
        "lock must be released when the first repository is dropped"
    );
}

#[tokio::test]
async fn file_siem_delivery_queue_survives_reload() {
    let path = std::env::temp_dir().join(format!("qid_file_siem_{}.json", ulid::Ulid::new()));
    {
        let repo = setup_at(path.clone()).await;
        repo.upsert_siem_delivery(&SiemDeliveryRecord {
            id: "delivery-1".to_string(),
            realm_id: Some("test".to_string()),
            endpoint_url: "https://siem.example.com/audit".to_string(),
            payload_json: serde_json::json!({"event_count": 1}),
            attempts: 2,
            next_retry_at: Some(300),
            status: SiemDeliveryStatus::Pending,
            last_error: Some("temporary failure".to_string()),
            created_at: 100,
            updated_at: 200,
        })
        .await
        .unwrap();
    }

    let reloaded = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    let deliveries = reloaded
        .list_siem_deliveries(Some("test"), Some(SiemDeliveryStatus::Pending), 10)
        .await
        .unwrap();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries[0].id, "delivery-1");
    assert_eq!(deliveries[0].attempts, 2);
}
