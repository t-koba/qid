use qid_core::models::{AuditEvent, AuthorizationCode, Session, TokenFamily};
use qid_core::tenant::{RealmId, TenantId};
use qid_storage::{FileRepository, prelude::*};
use std::sync::Arc;

async fn setup() -> Arc<FileRepository> {
    let path = std::env::temp_dir().join(format!("qid_file_test_{}.json", ulid::Ulid::new()));
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
