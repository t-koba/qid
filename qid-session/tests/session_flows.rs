#[path = "support/admin_assurance.rs"]
mod admin_assurance;

use anyhow::Context;
use qid_core::{
    cache::{MemoryCache, SharedCache},
    config::{
        AdminConfig, AuthenticationConfig, CorsConfig, CryptoConfig, DeploymentProfile,
        ObservabilityConfig, OpsConfig, PepRegistrationsConfig, PolicyConfig, ProtocolConfig,
        QidConfig, RealmConfig, ServerConfig, ServerPaths, SessionConfig, StorageConfig,
    },
    jwt::{JwtClaims, Signer, TokenData},
    models::{PasswordCredential, User},
    tenant::RealmId,
    throttle::FailureBudget,
};
use qid_crypto::{ARGON2ID_ALGORITHM, Argon2idParams, hash_password_with_params};
use qid_session::{
    auth::{Authenticator, PasswordPolicy},
    browser::{SessionManager, session_cache_put},
};
use qid_storage::{FileRepository, prelude::*};
use serde_json::json;
use std::sync::Arc;

struct TestSigner;

impl Signer for TestSigner {
    fn sign(&self, _claims: &JwtClaims) -> anyhow::Result<String> {
        Ok("test-token".to_string())
    }

    fn sign_with_typ(&self, _claims: &JwtClaims, _typ: &str) -> anyhow::Result<String> {
        Ok("test-token".to_string())
    }

    fn decode_signature_only(&self, _token: &str) -> anyhow::Result<TokenData<JwtClaims>> {
        anyhow::bail!("test signer does not decode tokens")
    }

    fn decode_with_aud(
        &self,
        _token: &str,
        _expected_audience: &str,
    ) -> anyhow::Result<TokenData<JwtClaims>> {
        anyhow::bail!("test signer does not decode tokens")
    }

    fn algorithm(&self) -> &'static str {
        "HS256"
    }
}

fn config() -> QidConfig {
    QidConfig {
        include: Vec::new(),
        profile: DeploymentProfile::Oidc,
        server: ServerConfig {
            listen: "127.0.0.1:0".to_string(),
            public_base_url: "https://id.example.com".to_string(),
            tls: None,
            http_message_signatures: Default::default(),
            cors: CorsConfig::default(),
            paths: ServerPaths::default(),
            hsts: Default::default(),
            notification: None,
            quic: Default::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig::default(),
        realms: vec![RealmConfig {
            id: "corp".to_string(),
            issuer: "https://id.example.com/realms/corp".to_string(),
            display_name: None,
            tenant_id: None,
            clients: Vec::new(),
            protocols: ProtocolConfig::default(),
            authentication: AuthenticationConfig::default(),
            sessions: SessionConfig::default(),
            pep_registrations: PepRegistrationsConfig::default(),
            policy: PolicyConfig::default(),
        }],
        observability: ObservabilityConfig::default(),
        ops: OpsConfig::default(),
    }
}

#[tokio::test]
async fn password_login_session_and_revoke_propagate_through_shared_cache() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir().context("failed to create temp dir")?;
    let store = tmp.path().join("qid-session.json");
    let repo = Arc::new(
        FileRepository::new(store.to_str().context("store path must be UTF-8")?)
            .await
            .context("failed to create file repository")?,
    );
    repo.migrate()
        .await
        .context("failed to migrate repository")?;

    let user = User {
        id: "user-123".to_string(),
        realm_id: "corp".to_string(),
        email: Some("alice@example.com".to_string()),
        email_verified: true,
        display_name: Some("Alice Example".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: Some("tenant-a".to_string()),
    };
    repo.create_user(&user)
        .await
        .context("failed to create user")?;
    repo.store_password_credential(&PasswordCredential {
        user_id: user.id.clone(),
        hash: hash_password_with_params(
            "correct horse battery staple",
            &Argon2idParams::new(8, 1, 1),
        )
        .context("failed to hash password")?,
        algorithm: ARGON2ID_ALGORITHM.to_string(),
    })
    .await
    .context("failed to store password credential")?;

    // This session-cache test does not measure Argon2 cost; password-policy tests cover the default.
    let mut authentication = AuthenticationConfig::default();
    authentication.password.argon2id.memory_kib = 8;
    authentication.password.argon2id.time_cost = 1;
    authentication.password.argon2id.parallelism = 1;
    let auth = Authenticator::new(
        Arc::clone(&repo),
        PasswordPolicy::from_config(&authentication.password),
        Arc::new(FailureBudget::new()),
    );
    let authn = auth
        .authenticate_password(
            &RealmId::from("corp"),
            "alice@example.com",
            "correct horse battery staple",
        )
        .await
        .context("password authentication failed")?;
    assert_eq!(authn.user.id, "user-123");
    assert_eq!(authn.acr, "urn:qid:acr:password");
    assert_eq!(authn.amr, vec!["pwd"]);

    let sessions = SessionManager::new(Arc::clone(&repo), 30, 8);
    let session = sessions
        .create("corp", &authn.user.id, &authn.acr, &authn.amr)
        .await
        .context("failed to create browser session")?;
    assert!(sessions.get(&session.id).await?.is_some());
    admin_assurance::assert_admin_assurance(&session, false, false);

    let shared_cache: Arc<dyn SharedCache> = Arc::new(MemoryCache::new());
    let first = qid_core::state::SharedState::new(
        config(),
        Arc::clone(&repo),
        Arc::new(TestSigner),
        json!({"keys": []}),
    )?
    .with_shared_cache(Arc::clone(&shared_cache));
    let second = qid_core::state::SharedState::new(
        config(),
        Arc::clone(&repo),
        Arc::new(TestSigner),
        json!({"keys": []}),
    )?
    .with_shared_cache(shared_cache);

    let cache_put = session_cache_put(&session, qid_core::util::now_seconds())?
        .context("active session should produce cache entry")?;
    first.session_cache_put(
        session.id.clone(),
        cache_put.value.clone(),
        cache_put.ttl_seconds,
    );
    assert_eq!(
        second.session_cache_get(&session.id),
        Some(cache_put.value.clone())
    );

    sessions
        .revoke(&session.id, None)
        .await
        .context("failed to revoke browser session")?;
    first.session_cache_delete(&session.id);

    assert!(sessions.get(&session.id).await?.is_none());
    assert_eq!(second.session_cache_get(&session.id), None);

    Ok(())
}

async fn session_owner_fixture() -> anyhow::Result<(tempfile::TempDir, Arc<FileRepository>)> {
    let tmp = tempfile::tempdir()?;
    let repo = Arc::new(
        FileRepository::new(
            tmp.path()
                .join("sessions.json")
                .to_str()
                .context("store path must be UTF-8")?,
        )
        .await?,
    );
    repo.migrate().await?;
    for realm in ["corp", "other"] {
        repo.create_realm(
            &"tenant".into(),
            &realm.into(),
            &format!("https://id.example.com/realms/{realm}"),
            None,
        )
        .await?;
        repo.create_user(&User {
            id: format!("user-{realm}"),
            realm_id: realm.into(),
            email: None,
            email_verified: false,
            display_name: None,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await?;
    }
    Ok((tmp, repo))
}

#[tokio::test]
async fn regeneration_revokes_only_old_sessions_in_the_login_realm() -> anyhow::Result<()> {
    let (_tmp, repo) = session_owner_fixture().await?;
    let manager = SessionManager::new(repo.clone(), 30, 8);
    let amr = vec!["pwd".into()];
    let foreign = manager
        .create("other", "user-other", "password", &amr)
        .await?;
    let fresh = manager
        .create_with_regeneration("corp", "user-corp", "password", &amr, Some(&foreign.id))
        .await?;
    assert_ne!(fresh.id, foreign.id);
    assert_eq!(fresh.realm_id, "corp");
    assert_eq!(fresh.user_id, "user-corp");
    assert!(!fresh.revoked);
    assert_eq!(
        serde_json::to_value(repo.get_session(&foreign.id).await?.unwrap())?,
        serde_json::to_value(&foreign)?
    );
    assert!(manager.get(&fresh.id).await?.is_some());

    // Same-realm regeneration still prevents fixation.
    let replacement = manager
        .create_with_regeneration("corp", "user-corp", "password", &amr, Some(&fresh.id))
        .await?;
    assert_ne!(replacement.id, fresh.id);
    assert_ne!(replacement.id, foreign.id);
    assert_eq!(replacement.realm_id, "corp");
    assert_eq!(replacement.user_id, "user-corp");
    assert!(repo.get_session(&fresh.id).await?.unwrap().revoked);
    assert!(manager.get(&fresh.id).await?.is_none());
    assert!(manager.get(&replacement.id).await?.is_some());
    Ok(())
}

#[tokio::test]
async fn session_routes_preserve_foreign_rows_cookies_and_cache() -> anyhow::Result<()> {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use qid_core::state::SharedState;
    use tower::ServiceExt;

    let (_tmp, repo) = session_owner_fixture().await?;
    let mut cfg = config();
    let mut other = cfg.realms[0].clone();
    other.id = "other".into();
    other.issuer = "https://id.example.com/realms/other".into();
    cfg.realms.push(other);
    let state = Arc::new(
        SharedState::new(cfg, repo.clone(), Arc::new(TestSigner), json!({"keys": []}))?
            .with_shared_cache(Arc::new(MemoryCache::new())),
    );
    let manager = SessionManager::new(repo.clone(), 5, 8);
    let session = manager
        .create("other", "user-other", "password", &["pwd".into()])
        .await?;
    let cache = session_cache_put(&session, qid_core::util::now_seconds())?.unwrap();
    state.session_cache_put(session.id.clone(), cache.value.clone(), cache.ttl_seconds);
    let app = qid_session::auth_routes(&state.paths).with_state(state.clone());
    let cookie = format!(
        "{}={}",
        state.realm("other").unwrap().browser_session.cookie_name,
        session.id
    );
    assert_eq!(
        state.realm("corp").unwrap().browser_session.cookie_name,
        state.realm("other").unwrap().browser_session.cookie_name
    );

    for operation in ["refresh", "revoke"] {
        for cookie_value in [cookie.as_str(), "__Host-qid=missing"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/api/v1/corp/auth/session/{operation}"))
                        .header("cookie", cookie_value)
                        .body(Body::empty())?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert!(!response.headers().contains_key("set-cookie"));
            assert_eq!(
                serde_json::to_value(repo.get_session(&session.id).await?.unwrap())?,
                serde_json::to_value(&session)?
            );
            assert_eq!(
                state.session_cache_get(&session.id),
                Some(cache.value.clone())
            );
        }
    }

    let mut expected = session.clone();
    for operation in ["refresh", "revoke"] {
        // Successful same-realm writes, unlike the refusals above, evict stale cache.
        state.session_cache_put(session.id.clone(), cache.value.clone(), cache.ttl_seconds);
        let before = qid_core::util::now_seconds();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/other/auth/session/{operation}"))
                    .header("cookie", &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(state.session_cache_get(&session.id), None);
        let stored = repo.get_session(&session.id).await?.unwrap();
        if operation == "refresh" {
            let timeout = state
                .realm("other")
                .unwrap()
                .browser_session
                .idle_timeout_minutes
                * 60;
            assert!(stored.idle_expires_at >= before + timeout);
            assert!(stored.idle_expires_at <= qid_core::util::now_seconds() + timeout);
            assert_ne!(stored.idle_expires_at, session.idle_expires_at);
            expected.idle_expires_at = stored.idle_expires_at;
            assert!(!response.headers().contains_key("set-cookie"));
        } else {
            expected.revoked = true;
            assert!(
                response
                    .headers()
                    .get("set-cookie")
                    .unwrap()
                    .to_str()?
                    .contains("Max-Age=0")
            );
        }
        assert_eq!(
            serde_json::to_value(stored)?,
            serde_json::to_value(&expected)?
        );
    }
    Ok(())
}
