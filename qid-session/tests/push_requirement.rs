use qid_core::{
    models::{PushAuthenticator, PushPublicJwk, PushRegistrationChallenge, User},
    tenant::RealmId,
    util,
};
use qid_session::auth::push_factor_satisfied;
use qid_storage::{FileRepository, prelude::*};

#[tokio::test]
async fn push_requirement_tracks_current_registration_and_trusted_amr() {
    let path = std::env::temp_dir().join(format!(
        "qid-session-push-requirement-{}.json",
        ulid::Ulid::new()
    ));
    let repo = FileRepository::new(path.to_str().expect("test path is not UTF-8"))
        .await
        .expect("file repository creation failed");
    repo.migrate()
        .await
        .expect("file repository migration failed");
    repo.create_realm(
        &"tenant-1".into(),
        &"corp".into(),
        "https://login.example.com",
        Some("Test realm"),
    )
    .await
    .expect("realm creation failed");
    repo.create_user(&User {
        id: "user-1".into(),
        realm_id: "corp".into(),
        email: Some("alice@example.com".into()),
        email_verified: true,
        display_name: Some("Alice".into()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .expect("user creation failed");
    let realm = RealmId::from("corp");
    let password_amr = vec!["pwd".to_string()];
    assert!(
        push_factor_satisfied(&repo, &realm, "user-1", &password_amr)
            .await
            .unwrap()
    );

    let now = util::now_seconds();
    let registration = PushRegistrationChallenge {
        authenticator: PushAuthenticator {
            id: "push-device".into(),
            realm_id: realm.as_str().to_string(),
            user_id: "user-1".into(),
            destination: "opaque-test-destination".into(),
            device_name: "Test Phone".into(),
            device_platform: "android".into(),
            public_jwk: PushPublicJwk::EC {
                crv: "P-256".into(),
                x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                y: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            },
            created_at: now,
            revoked_at: None,
        },
        nonce_verifier: "a".repeat(64),
        expires_at: now + 300,
        max_attempts: 3,
        attempt_count: 0,
    };
    assert!(
        repo.try_issue_push_registration(&registration, 10, 86_400)
            .await
            .unwrap()
    );
    assert!(
        repo.attempt_push_registration(&registration, true, util::now_seconds())
            .await
            .unwrap()
    );
    assert!(
        !push_factor_satisfied(&repo, &realm, "user-1", &password_amr)
            .await
            .unwrap()
    );
    assert!(
        push_factor_satisfied(
            &repo,
            &RealmId::from("other-realm"),
            "user-1",
            &password_amr
        )
        .await
        .unwrap()
    );
    assert!(
        push_factor_satisfied(&repo, &realm, "other-user", &password_amr)
            .await
            .unwrap()
    );
    for factor in ["webauthn", "totp", "push"] {
        let amr = vec!["pwd".to_string(), factor.to_string()];
        assert!(
            push_factor_satisfied(&repo, &realm, "user-1", &amr)
                .await
                .unwrap(),
            "existing {factor} proof should satisfy an enrolled push requirement"
        );
    }
    let email_amr = vec!["email".to_string()];
    assert!(
        push_factor_satisfied(&repo, &realm, "user-1", &email_amr)
            .await
            .unwrap(),
        "email magic-link keeps its separate behavior and is not a password-only session"
    );
    let password_amr = vec!["password".to_string()];
    assert!(
        !push_factor_satisfied(&repo, &realm, "user-1", &password_amr)
            .await
            .unwrap(),
        "a password-only session must require push when a device is enrolled"
    );

    assert!(
        repo.revoke_push_authenticator(&realm, "user-1", "push-device", util::now_seconds())
            .await
            .unwrap()
    );
    assert!(
        push_factor_satisfied(&repo, &realm, "user-1", &password_amr)
            .await
            .unwrap()
    );
    drop(repo);
    let _ = std::fs::remove_file(path);
}
