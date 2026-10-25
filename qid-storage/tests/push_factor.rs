//! Public issuance uses the real server clock. Deterministic lifecycle and
//! cleanup parity fixtures live in the private push_tests unit module.
use qid_core::{models::*, util::now_seconds};
use qid_storage::{FileRepository, SqlRepository, prelude::*};
async fn admission(repo: &impl Repository) {
    repo.create_realm(
        &"tenant".into(),
        &"realm".into(),
        "https://id.example.com",
        None,
    )
    .await
    .unwrap();
    repo.create_user(&User {
        id: "owner".into(),
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
    let now = now_seconds();
    let mut c = PushRegistrationChallenge {
        authenticator: PushAuthenticator {
            id: "device".into(),
            realm_id: "realm".into(),
            user_id: "owner".into(),
            destination: "opaque".into(),
            device_name: "Test Phone".into(),
            device_platform: "android".into(),
            public_jwk: PushPublicJwk::OKP {
                crv: "Ed25519".into(),
                x: "public".into(),
            },
            created_at: now - 2,
            revoked_at: None,
        },
        nonce_verifier: "a".repeat(64),
        expires_at: now + 3600,
        max_attempts: 2,
        attempt_count: 0,
    };
    assert!(
        repo.try_issue_push_registration(&c, 1, 86400)
            .await
            .unwrap()
    );
    assert!(
        repo.attempt_push_registration(&c, true, now_seconds())
            .await
            .unwrap()
    );
    let at = now_seconds();
    let mut login = PushLoginChallenge {
        id: "login".into(),
        realm_id: "realm".into(),
        user_id: "owner".into(),
        authenticator_id: "device".into(),
        purpose: PushPurpose::PasswordLogin,
        nonce_verifier: "b".repeat(64),
        browser_binding_verifier: "c".repeat(64),
        resend_admitted_at: Vec::new(),
        created_at: at,
        expires_at: at + 600,
        max_attempts: 2,
        attempt_count: 0,
        decision: None,
        decided_at: None,
        consumed_at: None,
    };
    assert!(repo.try_issue_push_login(&login, 1, 86400).await.unwrap());
    login.id = "second-login".into();
    assert!(!repo.try_issue_push_login(&login, 1, 86400).await.unwrap());
    c.authenticator.id = "second".into();
    assert!(
        !repo
            .try_issue_push_registration(&c, 1, 86400)
            .await
            .unwrap()
    );
    c.authenticator.id = "expired".into();
    c.expires_at = now - 1;
    assert!(
        repo.try_issue_push_registration(&c, 10, 86400)
            .await
            .is_err()
    );
    c.authenticator.id = "future".into();
    c.authenticator.created_at = now + 1800;
    c.expires_at = now + 3600;
    assert!(
        repo.try_issue_push_registration(&c, 10, 86400)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn file_uses_server_admission_time() {
    let dir = std::env::temp_dir().join(format!("qid-push-clock-{}", ulid::Ulid::new()));
    let repo = FileRepository::new(dir.join("store.json").to_str().unwrap())
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    admission(&repo).await;
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}
#[tokio::test]
async fn sql_uses_server_admission_time() {
    let dir = std::env::temp_dir().join(format!("qid-push-clock-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let repo = SqlRepository::connect(&format!("sqlite:{}", dir.join("store.db").display()))
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    admission(&repo).await;
    repo.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}
async fn device_metadata_roundtrip(repo: &impl Repository) {
    repo.create_realm(
        &"tenant".into(),
        &"realm".into(),
        "https://id.example.com",
        None,
    )
    .await
    .unwrap();
    repo.create_user(&User {
        id: "owner".into(),
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
    let now = now_seconds();
    let c = PushRegistrationChallenge {
        authenticator: PushAuthenticator {
            id: "device".into(),
            realm_id: "realm".into(),
            user_id: "owner".into(),
            destination: "opaque".into(),
            device_name: "Test Phone".into(),
            device_platform: "android".into(),
            public_jwk: PushPublicJwk::OKP {
                crv: "Ed25519".into(),
                x: "public".into(),
            },
            created_at: now - 2,
            revoked_at: None,
        },
        nonce_verifier: "a".repeat(64),
        expires_at: now + 600,
        max_attempts: 2,
        attempt_count: 0,
    };
    assert!(
        repo.try_issue_push_registration(&c, 10, 86400)
            .await
            .unwrap()
    );
    assert!(
        repo.attempt_push_registration(&c, true, now_seconds())
            .await
            .unwrap()
    );
    let listed = repo
        .list_push_authenticators(&"realm".into(), "owner")
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].device_name, "Test Phone");
    assert_eq!(listed[0].device_platform, "android");
    // Blank, control-containing and over-long metadata is refused at issuance.
    for (name, platform) in [
        ("".to_string(), "android".to_string()),
        ("   ".to_string(), "android".to_string()),
        ("bad\nname".to_string(), "android".to_string()),
        (" Test Phone".to_string(), "android".to_string()),
        ("ok".to_string(), "".to_string()),
        ("ok".to_string(), "x".repeat(65)),
    ] {
        let mut bad = c.clone();
        bad.authenticator.id = format!("bad-{}", name.len() + platform.len());
        bad.authenticator.device_name = name;
        bad.authenticator.device_platform = platform;
        assert!(
            repo.try_issue_push_registration(&bad, 10, 86400)
                .await
                .is_err()
        );
    }
    // A revoked tombstone keeps its display metadata for account management.
    assert!(
        repo.revoke_push_authenticator(&"realm".into(), "owner", "device", now_seconds())
            .await
            .unwrap()
    );
    let listed = repo
        .list_push_authenticators(&"realm".into(), "owner")
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].device_name, "Test Phone");
    assert!(listed[0].revoked_at.is_some());
    // A foreign owner sees nothing of this realm/user.
    assert!(
        repo.list_push_authenticators(&"realm".into(), "peer")
            .await
            .unwrap()
            .is_empty()
    );
}
#[tokio::test]
async fn file_persists_device_metadata() {
    let dir = std::env::temp_dir().join(format!("qid-push-meta-{}", ulid::Ulid::new()));
    let repo = FileRepository::new(dir.join("store.json").to_str().unwrap())
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    device_metadata_roundtrip(&repo).await;
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}
#[tokio::test]
async fn sql_persists_device_metadata() {
    let dir = std::env::temp_dir().join(format!("qid-push-meta-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let repo = SqlRepository::connect(&format!("sqlite:{}", dir.join("store.db").display()))
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    device_metadata_roundtrip(&repo).await;
    repo.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}
