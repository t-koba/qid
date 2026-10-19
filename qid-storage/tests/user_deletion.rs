use qid_core::{models::*, tenant::RealmId};
use qid_storage::{FileRepository, SqlRepository, prelude::*};
use serde_json::json;

async fn seed(repo: &impl Repository) {
    repo.create_realm(
        &"tenant".into(),
        &"realm".into(),
        "https://id.example.com",
        None,
    )
    .await
    .unwrap();
    for id in ["target", "survivor"] {
        repo.create_user(&User {
            id: id.into(),
            realm_id: "realm".into(),
            email: None,
            email_verified: false,
            display_name: None,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .unwrap();
        repo.store_password_credential(&PasswordCredential {
            user_id: id.into(),
            hash: "test-hash".into(),
            algorithm: "argon2id".into(),
            pepper_ref: None,
        })
        .await
        .unwrap();
        repo.create_session(&Session {
            id: id.into(),
            realm_id: "realm".into(),
            user_id: id.into(),
            auth_time: 100,
            acr: None,
            amr: vec!["pwd".into()],
            idle_expires_at: 1000,
            absolute_expires_at: 1000,
            revoked: false,
            created_at: 100,
            cnf: None,
        })
        .await
        .unwrap();
        repo.store_webauthn_credential(&WebAuthnCredential {
            id: id.into(),
            user_id: id.into(),
            credential_id: vec![1],
            public_key: vec![2],
            counter: 1,
            aaguid: vec![0; 16],
            device_name: None,
            created_at: 100,
        })
        .await
        .unwrap();
        repo.store_totp_credential(&TotpCredential {
            id: id.into(),
            user_id: id.into(),
            secret: "test-secret".into(),
            algorithm: "SHA1".into(),
            digits: 6,
            period: 30,
            enabled: true,
            last_used_step: None,
            created_at: 100,
        })
        .await
        .unwrap();
        repo.register_device(&Device {
            id: id.into(),
            user_id: id.into(),
            realm_id: "realm".into(),
            device_name: None,
            device_type: "unknown".into(),
            posture: vec![],
            registered_at: 100,
            last_seen_at: 100,
        })
        .await
        .unwrap();
        repo.append_audit_event(&AuditEvent {
            id: id.into(),
            realm_id: Some("realm".into()),
            actor: id.into(),
            action: "login".into(),
            target_type: "user".into(),
            target_id: id.into(),
            reason: "test".into(),
            metadata_json: json!({}),
            created_at: 100,
            previous_hash: None,
            event_hash: None,
        })
        .await
        .unwrap();
    }
    // Direct ownership and session ownership are independent cleanup paths.
    for (id, owner, session) in [
        ("direct", "target", None),
        ("session-linked", "survivor", Some("target")),
        ("survivor", "survivor", Some("survivor")),
    ] {
        repo.create_authorization_code(&AuthorizationCode {
            code_hash: id.into(),
            client_id: "client".into(),
            user_id: owner.into(),
            realm_id: "realm".into(),
            redirect_uri: "https://app.example.com/cb".into(),
            state: Some("state".into()),
            nonce: Some("nonce".into()),
            auth_time: Some(100),
            acr: None,
            amr: vec!["pwd".into()],
            code_challenge: None,
            code_challenge_method: None,
            scopes: vec!["openid".into()],
            resource: vec![],
            authorization_details: None,
            expires_at: 1000,
            used: false,
            created_at: 100,
            session_id: session.map(Into::into),
        })
        .await
        .unwrap();
        repo.create_token_family(&TokenFamily {
            id: id.into(),
            user_id: owner.into(),
            client_id: "client".into(),
            realm_id: "realm".into(),
            current_refresh_hash: format!("refresh-{id}"),
            scopes: vec!["openid".into()],
            auth_time: Some(100),
            acr: None,
            amr: vec![],
            audience: vec![],
            resource: vec![],
            authorization_details: None,
            sender_constraint: None,
            issued_at: 100,
            refresh_expires_at: Some(1000),
            session_id: session.map(Into::into),
            revoked: false,
        })
        .await
        .unwrap();
    }
    for (id, owner, family) in [
        ("direct", "target", None),
        ("direct-other-family", "target", Some("survivor")),
        ("family-linked", "survivor", Some("direct")),
        (
            "session-family-linked",
            "service-account",
            Some("session-linked"),
        ),
        ("survivor", "survivor", Some("survivor")),
        ("non-user", "service-account", None),
        ("unowned", "", None),
    ] {
        repo.create_access_token(&AccessToken {
            jti: id.into(),
            family_id: family.map(Into::into),
            user_id: owner.into(),
            client_id: "client".into(),
            realm_id: "realm".into(),
            scopes: vec![],
            audience: vec![],
            resource: vec![],
            authorization_details: None,
            cnf: None,
            auth_time: None,
            acr: None,
            amr: vec![],
            nonce: None,
            sender_constraint: None,
            token_format: TokenFormat::Jwt,
            expires_at: 1000,
            revoked: false,
            issued_at: 100,
        })
        .await
        .unwrap();
    }
    for owner in [Some("target"), Some("survivor"), None] {
        let id = owner.unwrap_or("pending");
        repo.store_device_authorization_grant(&DeviceAuthorizationGrant {
            device_code_hash: id.into(),
            user_code: id.into(),
            client_id: "client".into(),
            realm_id: "realm".into(),
            scopes: vec!["openid".into()],
            user_id: owner.map(Into::into),
            expires_at: 1000,
            approved_at: owner.map(|_| 100),
            consumed: false,
            last_poll_at: None,
            poll_interval_seconds: 5,
            created_at: 100,
        })
        .await
        .unwrap();
        repo.store_backchannel_authentication_grant(&BackchannelAuthenticationGrant {
            auth_req_id_hash: id.into(),
            client_id: "client".into(),
            realm_id: "realm".into(),
            // A hint naming the deleted user is not ownership of an unapproved grant.
            login_hint: "target".into(),
            binding_message: None,
            scopes: vec!["openid".into()],
            user_id: owner.map(Into::into),
            expires_at: 1000,
            approved_at: owner.map(|_| 100),
            consumed: false,
            last_poll_at: None,
            poll_interval_seconds: 5,
            created_at: 100,
        })
        .await
        .unwrap();
    }
}

async fn assert_deleted(repo: &impl Repository) {
    for (id, exists) in [("target", false), ("survivor", true)] {
        assert_eq!(repo.get_user_by_id(id).await.unwrap().is_some(), exists);
        assert_eq!(
            repo.get_password_credential(id).await.unwrap().is_some(),
            exists
        );
        assert_eq!(repo.get_session(id).await.unwrap().is_some(), exists);
        assert_eq!(
            repo.get_webauthn_credentials(id).await.unwrap().len(),
            usize::from(exists)
        );
        assert_eq!(
            repo.get_totp_credential(id).await.unwrap().is_some(),
            exists
        );
        assert_eq!(repo.get_device(id).await.unwrap().is_some(), exists);
    }
    for (id, exists) in [
        ("direct", false),
        ("session-linked", false),
        ("survivor", true),
    ] {
        assert_eq!(
            repo.get_authorization_code(id).await.unwrap().is_some(),
            exists,
            "code {id}"
        );
        assert_eq!(
            repo.get_token_family(id).await.unwrap().is_some(),
            exists,
            "family {id}"
        );
    }
    for (id, exists) in [
        ("direct", false),
        ("direct-other-family", false),
        ("family-linked", false),
        ("session-family-linked", false),
        ("survivor", true),
        ("non-user", true),
        ("unowned", true),
    ] {
        assert_eq!(
            repo.get_access_token(id).await.unwrap().is_some(),
            exists,
            "token {id}"
        );
    }
    for (id, exists) in [("target", false), ("survivor", true), ("pending", true)] {
        assert_eq!(
            repo.get_device_authorization_grant(id)
                .await
                .unwrap()
                .is_some(),
            exists
        );
        assert_eq!(
            repo.get_device_authorization_grant_by_user_code(id)
                .await
                .unwrap()
                .is_some(),
            exists
        );
        assert_eq!(
            repo.get_backchannel_authentication_grant(id)
                .await
                .unwrap()
                .is_some(),
            exists
        );
    }
    let audit = repo
        .list_audit_events(Some(&RealmId::from("realm")), 10)
        .await
        .unwrap();
    assert_eq!(audit.len(), 2);
    assert!(
        audit
            .iter()
            .any(|event| event.actor == "target" && event.target_id == "target")
    );
    assert!(
        repo.verify_audit_chain(Some(&"realm".into()))
            .await
            .unwrap()
            .valid
    );
}

#[tokio::test]
async fn sql_user_deletion_cleans_only_owned_authentication_state() {
    let path = std::env::temp_dir().join(format!("qid-user-deletion-{}.db", ulid::Ulid::new()));
    let repo = SqlRepository::connect(&format!("sqlite:{}", path.display()))
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    seed(&repo).await;
    let audit = repo.list_audit_events(None, 10).await.unwrap();
    repo.delete_user("target").await.unwrap();
    assert_deleted(&repo).await;
    assert_eq!(
        serde_json::to_value(repo.list_audit_events(None, 10).await.unwrap()).unwrap(),
        serde_json::to_value(audit).unwrap()
    );
    repo.delete_user("target").await.unwrap();
    assert_deleted(&repo).await;
    repo.close().await;
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn file_user_deletion_persists_only_owned_authentication_cleanup() {
    let path = std::env::temp_dir().join(format!("qid-user-deletion-{}.json", ulid::Ulid::new()));
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    seed(&repo).await;
    let audit = repo.list_audit_events(None, 10).await.unwrap();
    repo.delete_user("target").await.unwrap();
    assert_deleted(&repo).await;
    drop(repo);
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    assert_deleted(&repo).await;
    assert_eq!(
        serde_json::to_value(repo.list_audit_events(None, 10).await.unwrap()).unwrap(),
        serde_json::to_value(audit).unwrap()
    );
    repo.delete_user("target").await.unwrap();
    assert_deleted(&repo).await;
    drop(repo);
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn sql_authentication_ownership_migration_drops_orphans_and_preserves_live_context() {
    let path = std::env::temp_dir().join(format!("qid-auth-migration-{}.db", ulid::Ulid::new()));
    let url = format!("sqlite:{}", path.display());
    let repo = SqlRepository::connect(&url).await.unwrap();
    let pool = sqlx::AnyPool::connect(&url).await.unwrap();
    for sql in [
        include_str!("../migrations/20250101000001_initial_schema.sql"),
        include_str!("../migrations/20250618000003_authorization_details.sql"),
        include_str!("../migrations/20250618000009_authorization_code_context.sql"),
        include_str!("../migrations/20250618000025_device_authorization_polling.sql"),
        include_str!("../migrations/20250618000026_ciba_polling.sql"),
        include_str!("../migrations/20250630000006_authorization_code_session.sql"),
    ] {
        sqlx::raw_sql(sql).execute(&pool).await.unwrap();
    }
    sqlx::raw_sql("INSERT INTO realms (id, tenant_id, issuer) VALUES ('realm', 'tenant', 'https://id.example.com');
        INSERT INTO users (id, realm_id) VALUES ('live', 'realm');
        INSERT INTO authorization_codes (code_hash, client_id, user_id, realm_id, redirect_uri, code_challenge, code_challenge_method, scopes, expires_at, used, created_at, state, nonce, auth_time, acr, amr, resource, authorization_details, session_id) VALUES
            ('live', 'client', 'live', 'realm', 'https://app.example.com/cb', 'challenge', 'S256', '[\"openid\"]', 1000, 0, 100, 'state', 'nonce', 100, 'acr', '[\"pwd\"]', '[\"resource\"]', '[{\"type\":\"example\"}]', 'session'),
            ('orphan', 'client', 'missing', 'realm', 'https://app.example.com/cb', NULL, NULL, '[]', 1000, 0, 100, NULL, NULL, NULL, NULL, '[]', '[]', NULL, NULL);
        INSERT INTO device_authorization_grants VALUES
            ('live', 'live', 'client', 'realm', '[\"openid\"]', 'live', 1000, 150, 0, 100, 120, 10),
            ('orphan', 'orphan', 'client', 'realm', '[]', 'missing', 1000, 150, 0, 100, NULL, 5),
            ('pending', 'pending', 'client', 'realm', '[]', NULL, 1000, NULL, 0, 100, 120, 10);
        INSERT INTO backchannel_authentication_grants VALUES
            ('live', 'client', 'realm', 'hint', 'binding', '[\"openid\"]', 'live', 1000, 150, 0, 100, 120, 10),
            ('orphan', 'client', 'realm', 'hint', NULL, '[]', 'missing', 1000, 150, 0, 100, NULL, 5),
            ('pending', 'client', 'realm', 'hint', NULL, '[]', NULL, 1000, NULL, 0, 100, 120, 10);")
        .execute(&pool).await.unwrap();
    let code = serde_json::to_value(repo.get_authorization_code("live").await.unwrap()).unwrap();
    let mut grants = vec![];
    for id in ["live", "pending"] {
        grants.push((
            serde_json::to_value(repo.get_device_authorization_grant(id).await.unwrap()).unwrap(),
            serde_json::to_value(repo.get_backchannel_authentication_grant(id).await.unwrap())
                .unwrap(),
        ));
    }
    let mut tx = pool.begin().await.unwrap();
    sqlx::raw_sql(include_str!(
        "../migrations/20250630000012_user_authentication_lifecycle.sql"
    ))
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        serde_json::to_value(repo.get_authorization_code("live").await.unwrap()).unwrap(),
        code
    );
    assert!(
        repo.get_authorization_code("orphan")
            .await
            .unwrap()
            .is_none()
    );
    for (i, id) in ["live", "pending"].iter().enumerate() {
        assert_eq!(
            serde_json::to_value(repo.get_device_authorization_grant(id).await.unwrap()).unwrap(),
            grants[i].0
        );
        assert_eq!(
            serde_json::to_value(repo.get_backchannel_authentication_grant(id).await.unwrap())
                .unwrap(),
            grants[i].1
        );
    }
    assert!(
        repo.get_device_authorization_grant("orphan")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.get_backchannel_authentication_grant("orphan")
            .await
            .unwrap()
            .is_none()
    );
    let index_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name IN ('idx_auth_codes_client', 'idx_auth_codes_user', 'idx_auth_codes_realm_expires', 'idx_device_auth_user_code', 'idx_device_auth_expires', 'idx_ciba_grants_expires', 'idx_ciba_grants_client')")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(index_count, 7);
    // The DB must reject dangling owners both at code issuance and grant approval.
    assert!(
        sqlx::query("UPDATE authorization_codes SET user_id = 'missing' WHERE code_hash = 'live'")
            .execute(&pool)
            .await
            .is_err()
    );
    assert!(
        repo.approve_device_authorization_grant("pending", "missing", 200)
            .await
            .is_err()
    );
    assert!(
        repo.approve_backchannel_authentication_grant("pending", "missing", 200)
            .await
            .is_err()
    );
    sqlx::query("DELETE FROM users WHERE id = 'live'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(repo.get_authorization_code("live").await.unwrap().is_none());
    for id in ["live", "pending"] {
        assert_eq!(
            repo.get_device_authorization_grant(id)
                .await
                .unwrap()
                .is_some(),
            id == "pending"
        );
        assert_eq!(
            repo.get_backchannel_authentication_grant(id)
                .await
                .unwrap()
                .is_some(),
            id == "pending"
        );
    }
    pool.close().await;
    repo.close().await;
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn sql_failed_user_deletion_rolls_back_authentication_cleanup() {
    let path = std::env::temp_dir().join(format!("qid-auth-rollback-{}.db", ulid::Ulid::new()));
    let url = format!("sqlite:{}", path.display());
    let repo = SqlRepository::connect(&url).await.unwrap();
    repo.migrate().await.unwrap();
    seed(&repo).await;
    let pool = sqlx::AnyPool::connect(&url).await.unwrap();
    sqlx::raw_sql("CREATE TRIGGER block_deletion BEFORE DELETE ON users BEGIN SELECT RAISE(ABORT, 'test failure'); END;")
        .execute(&pool).await.unwrap();
    assert!(repo.delete_user("target").await.is_err());
    assert!(repo.get_user_by_id("target").await.unwrap().is_some());
    assert!(repo.get_session("target").await.unwrap().is_some());
    for id in ["direct", "session-linked", "survivor"] {
        assert!(repo.get_authorization_code(id).await.unwrap().is_some());
        assert!(repo.get_token_family(id).await.unwrap().is_some());
    }
    for id in [
        "direct",
        "direct-other-family",
        "family-linked",
        "session-family-linked",
        "survivor",
        "non-user",
        "unowned",
    ] {
        assert!(repo.get_access_token(id).await.unwrap().is_some());
    }
    for id in ["target", "survivor", "pending"] {
        assert!(
            repo.get_device_authorization_grant(id)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            repo.get_backchannel_authentication_grant(id)
                .await
                .unwrap()
                .is_some()
        );
    }
    assert_eq!(
        repo.get_webauthn_credentials("target").await.unwrap().len(),
        1
    );
    assert!(repo.get_totp_credential("target").await.unwrap().is_some());
    assert!(repo.get_device("target").await.unwrap().is_some());
    pool.close().await;
    repo.close().await;
    std::fs::remove_file(path).unwrap();
}
