#![allow(clippy::expect_used, clippy::unwrap_used)]

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
};
use qid_crypto::{ARGON2ID_ALGORITHM, hash_password};
use qid_session::{
    auth::Authenticator,
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
        hash: hash_password("correct horse battery staple").context("failed to hash password")?,
        algorithm: ARGON2ID_ALGORITHM.to_string(),
        pepper_ref: None,
    })
    .await
    .context("failed to store password credential")?;

    let auth = Authenticator::new(Arc::clone(&repo));
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
        .revoke(&session.id)
        .await
        .context("failed to revoke browser session")?;
    first.session_cache_delete(&session.id);

    assert!(sessions.get(&session.id).await?.is_none());
    assert_eq!(second.session_cache_get(&session.id), None);

    Ok(())
}
