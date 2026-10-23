//! The live password route migrates persistent credentials with the realm owner.
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use qid_core::{
    config::{Argon2idCostConfig, PasswordPepperConfig, PasswordSecretSource, QidConfig},
    models::{PasswordCredential, User},
    state::SharedState,
    test_helpers,
};
use qid_crypto::{
    ARGON2ID_ALGORITHM, Argon2idParams, LocalSigner, hash_password_with_params,
    resolve_password_contexts,
};
use qid_storage::{AnyRepository, prelude::*};
use std::{path::Path, sync::Arc};
use tower::ServiceExt;

fn config(dir: &Path, active: &str, keys: &[&str]) -> QidConfig {
    let mut config = test_helpers::test_config();
    let password = &mut config.realms[0].authentication.password;
    password.argon2id = Argon2idCostConfig {
        memory_kib: 8,
        time_cost: 1,
        parallelism: 1,
    };
    password.pepper = Some(PasswordPepperConfig {
        active: active.into(),
        keys: keys
            .iter()
            .map(|id| {
                (
                    id.to_string(),
                    PasswordSecretSource::File {
                        file: dir.join(id).to_string_lossy().into_owned(),
                    },
                )
            })
            .collect(),
    });
    config
}

fn state(
    config: QidConfig,
    repo: Arc<AnyRepository>,
) -> anyhow::Result<SharedState<AnyRepository>> {
    let contexts = resolve_password_contexts(&config)?;
    let mut state = SharedState::new(
        config,
        repo,
        Arc::new(LocalSigner::from_secret("test", b"test-only-signing-key")),
        serde_json::json!({"keys":[]}),
    )?;
    state.password_credentials = contexts;
    Ok(state)
}

async fn login(state: SharedState<AnyRepository>, password: &str) -> anyhow::Result<StatusCode> {
    let app: Router = qid_session::auth_routes(&state.paths).with_state(Arc::new(state));
    Ok(app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/test/auth/password")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email":"pepper@example.com", "password":password})
                        .to_string(),
                ))?,
        )
        .await?
        .status())
}

async fn close(repo: Arc<AnyRepository>) -> anyhow::Result<()> {
    repo.flush().await?;
    match Arc::try_unwrap(repo).map_err(|_| anyhow::anyhow!("API owners not released"))? {
        AnyRepository::Sql(repo) => repo.close().await,
        AnyRepository::File(repo) => drop(repo),
    }
    Ok(())
}

#[tokio::test]
async fn password_route_persists_pepper_migration_and_rotation_in_file_and_sqlite() {
    for sql in [false, true] {
        let dir = std::env::temp_dir().join(format!("qid-password-pepper-{}", ulid::Ulid::new()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("old"), b"test-only-old-pepper").unwrap();
        std::fs::write(dir.join("new"), b"test-only-new-pepper").unwrap();
        let path = dir.join(if sql { "store.db" } else { "store.json" });
        let url = if sql {
            format!("sqlite:{}", path.display())
        } else {
            path.to_str().unwrap().into()
        };
        let repo = Arc::new(AnyRepository::connect(&url).await.unwrap());
        repo.create_realm(
            &"tenant-1".into(),
            &"test".into(),
            "https://id.example.com",
            None,
        )
        .await
        .unwrap();
        repo.create_user(&User {
            id: "user-pepper".into(),
            realm_id: "test".into(),
            email: Some("pepper@example.com".into()),
            email_verified: true,
            display_name: None,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .unwrap();
        repo.store_password_credential(&PasswordCredential {
            user_id: "user-pepper".into(),
            algorithm: ARGON2ID_ALGORITHM.into(),
            hash: hash_password_with_params("test-password", &Argon2idParams::new(8, 1, 1))
                .unwrap(),
        })
        .await
        .unwrap();
        let old = config(&dir, "old", &["old"]);
        let policy =
            qid_session::auth::PasswordPolicy::from_config(&old.realms[0].authentication.password);
        let service = qid_session::auth::Authenticator::new(
            repo.clone(),
            policy,
            Arc::new(qid_core::throttle::FailureBudget::new()),
        );
        assert!(
            service
                .authenticate_password(&"test".into(), "pepper@example.com", "test-password")
                .await
                .is_err()
        );
        drop(service);
        let mut unresolved = state(old.clone(), repo.clone()).unwrap();
        unresolved.password_credentials.clear();
        assert_eq!(
            login(unresolved, "test-password").await.unwrap(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert!(
            !repo
                .get_password_credential("user-pepper")
                .await
                .unwrap()
                .unwrap()
                .hash
                .contains("keyid=")
        );

        assert_eq!(
            login(state(old.clone(), repo.clone()).unwrap(), "test-password")
                .await
                .unwrap(),
            StatusCode::OK
        );
        let tagged = repo
            .get_password_credential("user-pepper")
            .await
            .unwrap()
            .unwrap();
        assert!(tagged.hash.contains("keyid=b2xk"));
        assert!(!tagged.hash.contains("test-only-old-pepper"));
        close(repo).await.unwrap();
        let repo = Arc::new(AnyRepository::connect(&url).await.unwrap());
        assert_eq!(
            repo.get_password_credential("user-pepper")
                .await
                .unwrap()
                .unwrap()
                .hash,
            tagged.hash
        );
        // Wrong key bytes under the same ID, unknown key, and config removal
        // all fail; no failed verification can rewrite or downgrade the hash.
        std::fs::write(dir.join("old"), b"wrong-realm-pepper").unwrap();
        assert_eq!(
            login(state(old.clone(), repo.clone()).unwrap(), "test-password")
                .await
                .unwrap(),
            StatusCode::UNAUTHORIZED
        );
        let new_only = config(&dir, "new", &["new"]);
        assert_eq!(
            login(
                state(new_only.clone(), repo.clone()).unwrap(),
                "test-password"
            )
            .await
            .unwrap(),
            StatusCode::UNAUTHORIZED
        );
        let mut disabled = old.clone();
        disabled.realms[0].authentication.password.pepper = None;
        assert_eq!(
            login(state(disabled, repo.clone()).unwrap(), "test-password")
                .await
                .unwrap(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            repo.get_password_credential("user-pepper")
                .await
                .unwrap()
                .unwrap()
                .hash,
            tagged.hash
        );
        std::fs::write(dir.join("old"), b"test-only-old-pepper").unwrap();
        let rotated = config(&dir, "new", &["old", "new"]);
        let resolved = state(rotated, repo.clone()).unwrap();
        // One startup snapshot: removing a source after resolution is not hot rotation.
        std::fs::remove_file(dir.join("old")).unwrap();
        assert_eq!(
            login(resolved, "test-password").await.unwrap(),
            StatusCode::OK
        );
        let current = repo
            .get_password_credential("user-pepper")
            .await
            .unwrap()
            .unwrap();
        assert!(current.hash.contains("keyid=bmV3"));
        close(repo).await.unwrap();
        let repo = Arc::new(AnyRepository::connect(&url).await.unwrap());
        assert_eq!(
            repo.get_password_credential("user-pepper")
                .await
                .unwrap()
                .unwrap()
                .hash,
            current.hash
        );
        assert_eq!(
            login(state(new_only, repo.clone()).unwrap(), "test-password")
                .await
                .unwrap(),
            StatusCode::OK
        );
        close(repo).await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}
