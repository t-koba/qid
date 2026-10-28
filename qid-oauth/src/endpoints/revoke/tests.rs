//! Observe arguments at the real OAuth route's write; backend tests cover atomicity.
use super::*;
use axum::{body::Body, http::Request};
use qid_core::{
    models::{AccessToken, TokenFormat},
    test_helpers::test_config,
};
use qid_crypto::LocalSigner;
use qid_storage::{AnyRepository, FileRepository};
use tower::ServiceExt;

thread_local! {
    static REVOKES: std::cell::RefCell<Vec<(String, String)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

pub(super) struct ObservedTokens<'a, R>(pub &'a R);
impl<R: TokenRepository> ObservedTokens<'_, R> {
    pub async fn revoke_access_token(&self, jti: &str, realm: &str) -> QidResult<()> {
        REVOKES.with(|calls| calls.borrow_mut().push((jti.into(), realm.into())));
        self.0.revoke_access_token(jti, realm).await
    }
}

fn take_revokes() -> Vec<(String, String)> {
    REVOKES.with(|calls| std::mem::take(&mut *calls.borrow_mut()))
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

// Current-thread runtime keeps observation isolated; a unique file per test.
#[tokio::test]
async fn revoke_route_passes_authenticated_realm_to_storage() {
    assert!(take_revokes().is_empty());
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
            expires_at: 200,
            issued_at: 100,
            revoked: false,
        })
        .await
        .unwrap();
    }
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
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "client_id=client&token_type_hint=access_token&token={token}"
        )))
        .unwrap()
}
