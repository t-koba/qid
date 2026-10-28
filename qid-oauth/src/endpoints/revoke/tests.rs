//! Observe arguments at the real OAuth route's write; backend tests cover atomicity.
use super::*;
use axum::{body::Body, http::Request};
use qid_core::{
    models::{AccessToken, TokenFamily, TokenFormat},
    test_helpers::test_config,
};
use qid_crypto::LocalSigner;
use qid_storage::{AnyRepository, FileRepository};
use tower::ServiceExt;

thread_local! {
    static REVOKES: std::cell::RefCell<Vec<(String, String)>> =
        const { std::cell::RefCell::new(Vec::new()) };
    static FAMILY_REVOKES: std::cell::RefCell<Vec<(String, String)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

pub(super) struct ObservedTokens<'a, R>(pub &'a R);
impl<R: TokenRepository> ObservedTokens<'_, R> {
    pub async fn revoke_access_token(&self, jti: &str, realm: &str) -> QidResult<()> {
        REVOKES.with(|calls| calls.borrow_mut().push((jti.into(), realm.into())));
        self.0.revoke_access_token(jti, realm).await
    }

    pub async fn revoke_token_family(&self, id: &str, realm: &str) -> QidResult<()> {
        FAMILY_REVOKES.with(|calls| calls.borrow_mut().push((id.into(), realm.into())));
        self.0.revoke_token_family(id, realm).await
    }
}

fn take_revokes() -> Vec<(String, String)> {
    REVOKES.with(|calls| std::mem::take(&mut *calls.borrow_mut()))
}

fn take_family_revokes() -> Vec<(String, String)> {
    FAMILY_REVOKES.with(|calls| std::mem::take(&mut *calls.borrow_mut()))
}

struct TestFile(std::path::PathBuf);
impl Drop for TestFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn client() -> Client {
    Client {
        id: "client-record".into(),
        realm_id: "test".into(),
        client_id: "client".into(),
        client_type: ClientType::Public,
        token_endpoint_auth_method: "none".into(),
        client_secret_hash: None,
        mtls_certificate_thumbprints: vec![],
        jwks: qid_core::models::default_client_jwks(),
        redirect_uris: vec![],
        grant_types: vec!["authorization_code".into()],
        client_name: None,
        client_uri: None,
        logo_uri: None,
        contacts: vec![],
        post_logout_redirect_uris: vec![],
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

async fn snapshot(repo: &impl TokenRepository) -> serde_json::Value {
    let mut tokens = Vec::new();
    for id in ["opaque", "jwt", "foreign-realm", "foreign-client"] {
        tokens.push(repo.get_access_token(id).await.unwrap().unwrap());
    }
    serde_json::to_value(tokens).unwrap()
}

// Current-thread runtimes keep observation isolated; a unique file per fixture.
async fn fixture() -> (TestFile, Arc<SharedState<AnyRepository>>) {
    let file = TestFile(
        std::env::temp_dir().join(format!("qid-oauth-access-scope-{}.json", ulid::Ulid::new())),
    );
    // Exercise runtime backend forwarding as well as the Arc receiver used by OAuth.
    let repo = Arc::new(AnyRepository::File(
        FileRepository::new(file.0.to_str().unwrap()).await.unwrap(),
    ));
    repo.migrate().await.unwrap();
    for realm in ["test", "foreign"] {
        repo.create_realm(
            &"tenant".into(),
            &realm.into(),
            &format!("https://id.example.com/{realm}"),
            None,
        )
        .await
        .unwrap();
    }
    repo.create_client(&client()).await.unwrap();
    let state = Arc::new(
        SharedState::new(
            test_config(),
            repo.clone(),
            Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests")),
            serde_json::json!({}),
        )
        .unwrap(),
    );
    for (jti, realm, client_id) in [
        ("opaque", "test", "client"),
        ("jwt", "test", "client"),
        ("foreign-realm", "foreign", "client"),
        ("foreign-client", "test", "other-client"),
    ] {
        repo.create_access_token(&AccessToken {
            jti: jti.into(),
            family_id: None,
            realm_id: realm.into(),
            client_id: client_id.into(),
            user_id: "user".into(),
            scopes: vec!["read".into()],
            audience: vec!["api".into()],
            resource: vec![],
            authorization_details: None,
            cnf: None,
            auth_time: Some(100),
            acr: None,
            amr: vec!["pwd".into()],
            nonce: None,
            sender_constraint: None,
            token_format: TokenFormat::Jwt,
            expires_at: qid_core::util::now_seconds() + 600,
            issued_at: 100,
            revoked: false,
        })
        .await
        .unwrap();
    }
    (file, state)
}

#[tokio::test]
async fn revoke_route_passes_authenticated_realm_to_storage() {
    assert!(take_revokes().is_empty());
    let (_file, state) = fixture().await;
    let repo = state.repo.clone();
    let app = crate::routes(&state.paths).with_state(state.clone());
    let before = snapshot(&*repo).await;
    // Every refused/unknown request is the same empty RFC 7009 success, with no write.
    for id in ["missing", "foreign-realm", "foreign-client"] {
        let token = super::super::encode_opaque_access_token(id);
        let response = app
            .clone()
            .oneshot(request(&state.paths.revoke, &token))
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert!(
            axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(take_revokes().is_empty());
        assert_eq!(snapshot(&*repo).await, before);
    }
    for id in ["opaque", "jwt"] {
        let token = if id == "opaque" {
            super::super::encode_opaque_access_token(id)
        } else {
            state
                .signer
                .sign(&JwtClaims {
                    iss: Some("https://id.example.com".into()),
                    sub: Some("user".into()),
                    aud: None,
                    exp: Some((qid_core::util::now_seconds() + 600) as usize),
                    nbf: None,
                    iat: Some(100),
                    jti: Some(id.into()),
                    extra: Default::default(),
                })
                .unwrap()
        };
        for _ in 0..2 {
            let mut expected = snapshot(&*repo).await;
            let index = usize::from(id == "jwt");
            expected[index]["revoked"] = true.into();
            let response = app
                .clone()
                .oneshot(request(&state.paths.revoke, &token))
                .await
                .unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::OK);
            assert!(
                axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(take_revokes(), vec![(id.into(), "test".into())]);
            assert_eq!(snapshot(&*repo).await, expected);
        }
    }
}

fn request(path: &str, token: &str) -> Request<Body> {
    request_with_hint(path, token, Some("access_token"))
}

fn request_with_hint(path: &str, token: &str, hint: Option<&str>) -> Request<Body> {
    let hint = hint
        .map(|hint| format!("&token_type_hint={hint}"))
        .unwrap_or_default();
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(format!("client_id=client&token={token}{hint}")))
        .unwrap()
}

async fn seed_families(repo: &impl TokenRepository) {
    for (id, realm, client_id) in [
        ("family", "test", "client"),
        ("foreign-realm", "foreign", "client"),
        ("foreign-client", "test", "other-client"),
    ] {
        repo.create_token_family(&TokenFamily {
            id: id.into(),
            user_id: "user".into(),
            client_id: client_id.into(),
            realm_id: realm.into(),
            current_refresh_hash: qid_core::util::sha256_base64url("refresh-jti"),
            scopes: vec!["read".into()],
            auth_time: Some(100),
            acr: None,
            amr: vec!["pwd".into()],
            audience: vec!["api".into()],
            resource: vec![],
            authorization_details: None,
            sender_constraint: None,
            issued_at: 100,
            refresh_expires_at: Some(qid_core::util::now_seconds() + 600),
            session_id: None,
            revoked: false,
        })
        .await
        .unwrap();
    }
}

async fn full_snapshot(repo: &impl TokenRepository) -> serde_json::Value {
    let mut families = Vec::new();
    for id in ["family", "foreign-realm", "foreign-client"] {
        families.push(repo.get_token_family(id).await.unwrap().unwrap());
    }
    serde_json::json!({"tokens": snapshot(repo).await, "families": families})
}

fn signed_token(
    state: &SharedState<AnyRepository>,
    jti: &str,
    family: Option<&str>,
    aud: &str,
) -> String {
    let mut extra = std::collections::HashMap::new();
    if let Some(family) = family {
        extra.insert("family_id".into(), family.into());
    }
    state
        .signer
        .sign(&JwtClaims {
            iss: Some("https://id.example.com".into()),
            sub: Some("user".into()),
            aud: Some(qid_crypto::Audience::Single(aud.into())),
            exp: Some((qid_core::util::now_seconds() + 600) as usize),
            nbf: None,
            iat: Some(100),
            jti: Some(jti.into()),
            extra,
        })
        .unwrap()
}

#[tokio::test]
async fn revoke_route_hints_never_exclude_supported_token_types() {
    // Each request starts with fresh unrevoked records, not an earlier request's result.
    for hint in [
        None,
        Some("access_token"),
        Some("refresh_token"),
        Some("unknown"),
    ] {
        for kind in ["opaque", "jwt", "refresh"] {
            assert!(take_revokes().is_empty());
            assert!(take_family_revokes().is_empty());
            let (_file, state) = fixture().await;
            let repo = &*state.repo;
            seed_families(repo).await;
            let token = match kind {
                "opaque" => super::super::encode_opaque_access_token("opaque"),
                "jwt" => signed_token(&state, "jwt", None, "api"),
                _ => signed_token(&state, "refresh-jti", Some("family"), "client"),
            };
            let mut expected = full_snapshot(repo).await;
            let (access_calls, family_calls) = if kind == "refresh" {
                expected["families"][0]["revoked"] = true.into();
                (vec![], vec![("family".into(), "test".into())])
            } else {
                expected["tokens"][usize::from(kind == "jwt")]["revoked"] = true.into();
                (vec![(kind.into(), "test".into())], vec![])
            };
            let response = crate::routes(&state.paths)
                .with_state(state.clone())
                .oneshot(request_with_hint(&state.paths.revoke, &token, hint))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                axum::http::StatusCode::OK,
                "{kind} {hint:?}"
            );
            assert!(
                axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(take_revokes(), access_calls, "{kind} {hint:?}");
            assert_eq!(take_family_revokes(), family_calls, "{kind} {hint:?}");
            assert_eq!(full_snapshot(repo).await, expected, "{kind} {hint:?}");
        }
    }
}

#[tokio::test]
async fn revoke_route_hints_preserve_empty_success_without_writes_for_invalid_tokens() {
    let (_file, state) = fixture().await;
    let repo = &*state.repo;
    seed_families(repo).await;
    let before = full_snapshot(repo).await;
    let mut tokens = vec!["not-a-token".to_string()];
    for id in ["missing", "foreign-realm", "foreign-client"] {
        tokens.push(super::super::encode_opaque_access_token(id));
        tokens.push(signed_token(&state, id, None, "api"));
        tokens.push(signed_token(&state, "refresh-jti", Some(id), "client"));
    }
    tokens.push(signed_token(
        &state,
        "refresh-jti",
        Some("family"),
        "wrong-client",
    ));
    for hint in [
        None,
        Some("access_token"),
        Some("refresh_token"),
        Some("unknown"),
    ] {
        for token in &tokens {
            assert!(take_revokes().is_empty());
            assert!(take_family_revokes().is_empty());
            let response = crate::routes(&state.paths)
                .with_state(state.clone())
                .oneshot(request_with_hint(&state.paths.revoke, token, hint))
                .await
                .unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::OK, "{hint:?}");
            assert!(
                axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(take_revokes().is_empty());
            assert!(take_family_revokes().is_empty());
            assert_eq!(full_snapshot(repo).await, before, "{hint:?}");
        }
    }
}
