use qid_core::models::{
    AuditEvent, AuthorizationCode, CiamVerificationChallengeRecord, Client, ClientType, Session,
    TokenFamily, User, default_client_jwks,
};
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
    repo.revoke_session("session-1", None).await.unwrap();
    let after_revoke = repo.get_session("session-1").await.unwrap().unwrap();
    assert!(after_revoke.revoked);
}

#[tokio::test]
async fn file_ciam_verification_attempts_survive_reopen_and_legacy_rows_default_zero() {
    let path =
        std::env::temp_dir().join(format!("qid_file_ciam_attempts_{}.json", ulid::Ulid::new()));
    let repo = setup_at(path.clone()).await;
    let challenge = CiamVerificationChallengeRecord {
        id: "verify-persist".to_string(),
        realm_id: "test".to_string(),
        user_id: "user-1".to_string(),
        channel: "email".to_string(),
        address: "persist@example.com".to_string(),
        purpose: "email_verification".to_string(),
        code_hash: "persisted-code-hash".to_string(),
        attempt_count: 0,
        expires_at_epoch_seconds: 1_800_000_600,
        consumed_at_epoch_seconds: None,
        created_at_epoch_seconds: 1_800_000_000,
    };
    repo.store_ciam_verification_challenge(&challenge)
        .await
        .unwrap();
    repo.attempt_ciam_verification_challenge(
        &RealmId::from("test"),
        &challenge.id,
        &challenge.code_hash,
        false,
        1_800_000_010,
        5,
    )
    .await
    .unwrap();
    drop(repo);

    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    let loaded = repo
        .get_ciam_verification_challenge(&RealmId::from("test"), &challenge.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.attempt_count, 1);
    drop(repo);

    let mut stored: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    stored["ciam_verification_challenges"][&challenge.id]
        .as_object_mut()
        .unwrap()
        .remove("attempt_count");
    std::fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    let legacy = repo
        .get_ciam_verification_challenge(&RealmId::from("test"), &challenge.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(legacy.attempt_count, 0);
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
        session_id: None,
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

fn test_family(id: &str, hash: &str, issued_at: u64, deadline: Option<u64>) -> TokenFamily {
    TokenFamily {
        id: id.to_string(),
        user_id: "user-1".to_string(),
        client_id: "client-1".to_string(),
        realm_id: "test".to_string(),
        current_refresh_hash: hash.to_string(),
        scopes: Vec::new(),
        auth_time: None,
        acr: None,
        amr: Vec::new(),
        audience: Vec::new(),
        resource: Vec::new(),
        authorization_details: None,
        sender_constraint: None,
        issued_at,
        refresh_expires_at: deadline,
        session_id: None,
        revoked: false,
    }
}

#[tokio::test]
async fn file_token_family_reuse_detected() {
    let repo = setup().await;
    let now = qid_core::util::now_seconds();
    let family = test_family("tf-1", "hash-v1", now, Some(now + 86_400));
    repo.create_token_family(&family).await.unwrap();
    let fetched = repo.get_token_family("tf-1").await.unwrap().unwrap();
    assert_eq!(fetched.refresh_expires_at, family.refresh_expires_at);
    // Same hash presented twice must be detected
    let result = repo
        .update_token_family_refresh_hash("tf-1", "hash-v1", "hash-v1", 7200)
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

#[tokio::test]
async fn file_refresh_rotation_single_winner() {
    let repo = setup().await;
    let now = qid_core::util::now_seconds();
    let family = test_family("tf-race", "hash-v0", now, None);
    repo.create_token_family(&family).await.unwrap();
    // Both requests read "hash-v0" before either update (barrier after read).
    let r1 = repo.update_token_family_refresh_hash("tf-race", "hash-v0", "hash-v1", 7000);
    let r2 = repo.update_token_family_refresh_hash("tf-race", "hash-v0", "hash-v2", 7000);
    let (r1, r2) = tokio::join!(r1, r2);
    assert!(
        r1.is_ok() ^ r2.is_ok(),
        "exactly one overlapping rotation must win, got {r1:?} / {r2:?}"
    );
    let current = repo
        .get_token_family("tf-race")
        .await
        .unwrap()
        .unwrap()
        .current_refresh_hash;
    assert!(
        current == "hash-v1" || current == "hash-v2",
        "winner hash must be stored, got {current}"
    );
    let stored = repo.get_token_family("tf-race").await.unwrap().unwrap();
    assert_eq!(
        stored.refresh_expires_at,
        Some(7000),
        "rotation must pin the deadline"
    );
    // Stale expected hash must not rotate again.
    let stale = repo
        .update_token_family_refresh_hash("tf-race", "hash-v0", "hash-v3", 7000)
        .await;
    assert!(stale.is_err(), "stale expected hash must be rejected");
}

#[tokio::test]
async fn file_refresh_rotation_revoked_stays_revoked() {
    let repo = setup().await;
    let now = qid_core::util::now_seconds();
    let family = test_family("tf-revoked", "hash-v0", now, None);
    repo.create_token_family(&family).await.unwrap();
    repo.revoke_token_family("tf-revoked", &family.realm_id)
        .await
        .unwrap();
    let result = repo
        .update_token_family_refresh_hash("tf-revoked", "hash-v0", "hash-v1", 7000)
        .await;
    assert!(
        result.is_err(),
        "no successful consumption after revocation"
    );
}

#[tokio::test]
async fn file_interval_flush_retries_after_transient_failure() {
    let path = std::env::temp_dir().join(format!("qid_file_retry_{}.json", ulid::Ulid::new()));
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

    repo.create_user(&User {
        id: "user-retry".to_string(),
        realm_id: "test".to_string(),
        email: Some("retry@example.com".to_string()),
        email_verified: true,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();

    let tmp_path = path.with_extension("tmp");
    // Ensure a clean slate, then block the atomic write by making tmp a directory.
    let _ = tokio::fs::remove_file(&tmp_path).await;
    let _ = tokio::fs::remove_dir(&tmp_path).await;
    tokio::fs::create_dir(&tmp_path).await.unwrap();

    let first = repo.flush().await;
    assert!(
        first.is_err(),
        "transient storage failure must be reported, got {first:?}"
    );

    tokio::fs::remove_dir(&tmp_path).await.unwrap();

    // No further mutation: retry must persist the outstanding write.
    repo.flush().await.unwrap();
    let flushed = tokio::fs::read_to_string(&path).await.unwrap();
    assert!(
        flushed.contains("user-retry"),
        "retry flush must persist outstanding write without another mutation"
    );
}

fn sample_client(id: &str, realm_id: &str, client_id: &str) -> Client {
    Client {
        id: id.to_string(),
        realm_id: realm_id.to_string(),
        client_id: client_id.to_string(),
        client_type: ClientType::Public,
        token_endpoint_auth_method: "none".to_string(),
        client_secret_hash: None,
        mtls_certificate_thumbprints: Vec::new(),
        jwks: default_client_jwks(),
        redirect_uris: vec!["https://app.example.com/callback".to_string()],
        grant_types: vec!["authorization_code".to_string()],
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
    }
}

/// A client id is answered in one read over the named realms.
#[tokio::test]
async fn file_client_lookup_across_realms_reads_only_the_named_realms() {
    let repo = setup().await;
    qid_storage::RealmRepository::create_realm(
        repo.as_ref(),
        &TenantId::from("tenant-1"),
        &RealmId::from("other"),
        "https://id.example.com/other",
        Some("Other Realm"),
    )
    .await
    .unwrap();
    repo.create_client(&sample_client("client-a", "test", "shared-app"))
        .await
        .unwrap();
    repo.create_client(&sample_client("client-b", "other", "shared-app"))
        .await
        .unwrap();
    repo.create_client(&sample_client("client-c", "test", "other-app"))
        .await
        .unwrap();

    let both = repo
        .find_clients_by_client_id(
            &[RealmId::from("test"), RealmId::from("other")],
            "shared-app",
        )
        .await
        .unwrap();
    assert_eq!(both.len(), 2);

    let one = repo
        .find_clients_by_client_id(&[RealmId::from("test")], "shared-app")
        .await
        .unwrap();
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].realm_id, "test");

    let unnamed = repo
        .find_clients_by_client_id(&[RealmId::from("other")], "other-app")
        .await
        .unwrap();
    assert!(unnamed.is_empty());

    let none = repo
        .find_clients_by_client_id(&[], "shared-app")
        .await
        .unwrap();
    assert!(none.is_empty());
}

#[tokio::test]
async fn file_client_require_par_round_trip() {
    let repo = setup().await;
    let mut flagged = sample_client("client-par", "test", "par-required-app");
    flagged.require_pushed_authorization_requests = true;
    repo.create_client(&flagged).await.unwrap();
    let loaded = repo
        .get_client_by_client_id(&RealmId::from("test"), "par-required-app")
        .await
        .unwrap()
        .expect("flagged client must be found");
    assert!(
        loaded.require_pushed_authorization_requests,
        "the RFC 9126 PAR flag must survive file persistence"
    );

    let mut cleared = loaded.clone();
    cleared.require_pushed_authorization_requests = false;
    repo.update_client(&cleared).await.unwrap();
    let reloaded = repo
        .get_client_by_client_id(&RealmId::from("test"), "par-required-app")
        .await
        .unwrap()
        .expect("updated client must be found");
    assert!(
        !reloaded.require_pushed_authorization_requests,
        "clearing the PAR flag must survive file persistence"
    );

    // A record written before the flag existed carries no key, so the
    // serde default keeps it opt-in rather than locking the client out.
    let legacy: Client = serde_json::from_value(serde_json::json!({
        "id": "client-legacy",
        "realm_id": "test",
        "client_id": "legacy-app",
        "client_type": "public",
        "redirect_uris": [],
        "grant_types": ["authorization_code"],
    }))
    .expect("a client record without the PAR flag must still parse");
    assert!(
        !legacy.require_pushed_authorization_requests,
        "the PAR flag defaults to false for legacy records"
    );
}

#[tokio::test]
async fn file_polling_grant_targets_survive_reopen_and_legacy_records_default_empty() {
    use qid_core::models::{BackchannelAuthenticationGrant, DeviceAuthorizationGrant};
    let path = std::env::temp_dir().join(format!("qid_grant_targets_{}.json", ulid::Ulid::new()));
    let repo = setup_at(path.clone()).await;
    let mut device: DeviceAuthorizationGrant = serde_json::from_value(serde_json::json!({
        "device_code_hash": "device", "user_code": "user-code", "client_id": "client", "realm_id": "test",
        "scopes": ["read"], "user_id": null, "expires_at": 3000, "approved_at": null, "consumed": false, "created_at": 1
    })).unwrap();
    let mut ciba: BackchannelAuthenticationGrant = serde_json::from_value(serde_json::json!({
        "auth_req_id_hash": "ciba", "client_id": "client", "realm_id": "test", "login_hint": "user@example.com",
        "binding_message": null, "scopes": ["read"], "user_id": null, "expires_at": 3000,
        "approved_at": null, "consumed": false, "created_at": 1
    })).unwrap();
    assert!(device.resource.is_empty() && device.audience.is_empty());
    assert!(ciba.resource.is_empty() && ciba.audience.is_empty());
    device.resource = vec!["https://api.example.com/bound".into()];
    device.audience = vec!["api://bound".into()];
    ciba.resource = device.resource.clone();
    ciba.audience = device.audience.clone();
    repo.store_device_authorization_grant(&device)
        .await
        .unwrap();
    repo.store_backchannel_authentication_grant(&ciba)
        .await
        .unwrap();
    drop(repo);
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    let loaded = repo
        .get_device_authorization_grant("device")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.resource, device.resource);
    assert_eq!(loaded.audience, device.audience);
    let loaded = repo
        .get_backchannel_authentication_grant("ciba")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.resource, ciba.resource);
    assert_eq!(loaded.audience, ciba.audience);
    drop(repo);
    let mut stored: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for (table, key) in [
        ("device_authorization_grants", "device"),
        ("backchannel_authentication_grants", "ciba"),
    ] {
        let row = stored[table][key].as_object_mut().unwrap();
        row.remove("resource");
        row.remove("audience");
    }
    std::fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    let legacy = repo
        .get_device_authorization_grant("device")
        .await
        .unwrap()
        .unwrap();
    assert!(legacy.resource.is_empty() && legacy.audience.is_empty());
    let legacy = repo
        .get_backchannel_authentication_grant("ciba")
        .await
        .unwrap()
        .unwrap();
    assert!(legacy.resource.is_empty() && legacy.audience.is_empty());
    drop(repo);
    std::fs::remove_file(path).unwrap();
}
