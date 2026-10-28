//! Observe the real sub-logout write seam; storage contracts cover atomic ownership.
use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use qid_core::{
    jwt::Signer,
    models::{ClientType, Session},
    test_helpers::test_config,
};
use qid_crypto::LocalSigner;
use tower::ServiceExt;

thread_local! {
    static REVOKES: std::cell::RefCell<Vec<(String, Option<String>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

// The handler's repository receiver is replaced only in unit tests. Record the
// exact arguments and delegate to the real backend, not a helper-only imitation.
pub(super) struct ObservedSessions<'a, R>(pub &'a R);

impl<R: SessionRepository> ObservedSessions<'_, R> {
    pub async fn revoke_session(&self, id: &str, scope: Option<&str>) -> QidResult<bool> {
        REVOKES.with(|calls| {
            calls
                .borrow_mut()
                .push((id.into(), scope.map(str::to_owned)))
        });
        self.0.revoke_session(id, scope).await
    }
}

fn take_revokes() -> Vec<(String, Option<String>)> {
    REVOKES.with(|calls| std::mem::take(&mut *calls.borrow_mut()))
}

struct TestFile(std::path::PathBuf);
impl Drop for TestFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[tokio::test]
async fn backchannel_sub_route_scopes_writes_to_validated_issuer_realm() {
    let file =
        TestFile(std::env::temp_dir().join(format!("qid-oidc-logout-{}.json", ulid::Ulid::new())));
    let repo = Arc::new(
        qid_storage::FileRepository::new(file.0.to_str().unwrap())
            .await
            .unwrap(),
    );
    repo.migrate().await.unwrap();
    let realm_id = "logout-issuer";
    repo.create_realm(
        &"tenant-1".into(),
        &realm_id.into(),
        "https://id.example.com",
        None,
    )
    .await
    .unwrap();
    repo.create_client(&Client {
        id: "client-id".to_string(),
        realm_id: realm_id.into(),
        client_id: "par-client".to_string(),
        client_type: ClientType::Public,
        token_endpoint_auth_method: "none".to_string(),
        client_secret_hash: None,
        mtls_certificate_thumbprints: Vec::new(),
        jwks: qid_core::models::default_client_jwks(),
        redirect_uris: vec!["https://app.example.com/callback".to_string()],
        grant_types: vec!["authorization_code".to_string()],
        client_name: None,
        client_uri: None,
        logo_uri: None,
        contacts: Vec::new(),
        post_logout_redirect_uris: vec!["https://app.example.com/callback".to_string()],
        default_max_age: None,
        require_auth_time: false,
        sector_identifier_uri: None,
        subject_type: None,
        backchannel_logout_uri: None,
        frontchannel_logout_uri: None,
        backchannel_client_notification_endpoint: None,
        require_pushed_authorization_requests: false,
    })
    .await
    .expect("client creation failed");

    let mut config = test_config();
    config.realms[0].id = realm_id.into();
    config.realms[0].protocols.oidc.logout.backchannel = true;
    let issuer = config.realms[0].issuer.clone();
    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    let state =
        Arc::new(SharedState::new(config, repo.clone(), signer.clone(), json!({})).unwrap());
    let now = util::now_seconds();
    for (id, realm, user, revoked) in [
        ("local-a", realm_id, "user", false),
        ("local-b", realm_id, "user", false),
        ("already-revoked", realm_id, "user", true),
        ("other-user", realm_id, "other-user", false),
        ("foreign", "other-realm", "user", false),
    ] {
        repo.create_session(&Session {
            id: id.into(),
            realm_id: realm.into(),
            user_id: user.into(),
            auth_time: now,
            acr: None,
            amr: vec!["pwd".into()],
            idle_expires_at: now + 600,
            absolute_expires_at: now + 600,
            revoked,
            created_at: now,
            cnf: None,
        })
        .await
        .unwrap();
        state.session_cache_put(id.into(), id.as_bytes().to_vec(), 60);
    }
    let mut unchanged = Vec::new();
    for id in ["already-revoked", "other-user", "foreign"] {
        unchanged.push((
            id,
            serde_json::to_value(repo.get_session(id).await.unwrap()).unwrap(),
        ));
    }
    let mut claims = JwtClaims {
        iss: Some(issuer),
        sub: Some("user".into()),
        aud: Some(Audience::single("par-client")),
        exp: Some(now as usize + 300),
        nbf: Some(now as usize),
        iat: Some(now as usize),
        jti: Some(ulid::Ulid::new().to_string()),
        extra: HashMap::from([(
            "events".into(),
            json!({"http://schemas.openid.net/event/backchannel-logout": {}}),
        )]),
    };
    let path = state.paths.backchannel_logout.clone();
    let app = routes(&state.paths).with_state(state.clone());
    // Direct object-key lookup must keep rejecting absent/non-object events.
    for events in [
        None,
        Some(json!(null)),
        Some(json!(false)),
        Some(json!(1)),
        Some(json!("http://schemas.openid.net/event/backchannel-logout")),
        Some(json!([{"http://schemas.openid.net/event/backchannel-logout": {}}])),
        Some(json!({"unrelated": {}})),
    ] {
        claims.extra.remove("events");
        if let Some(events) = events {
            claims.extra.insert("events".into(), events);
        }
        let token = signer.sign(&claims).unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&path)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "logout_token={}",
                        urlencoding::encode(&token)
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(take_revokes().is_empty());
        for id in ["local-a", "local-b"] {
            assert!(!repo.get_session(id).await.unwrap().unwrap().revoked);
            assert_eq!(state.session_cache_get(id), Some(id.as_bytes().to_vec()));
        }
    }
    claims.extra.insert(
        "events".into(),
        json!({"http://schemas.openid.net/event/backchannel-logout": {}}),
    );
    let token = signer.sign(&claims).unwrap();
    for attempt in 0..2 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&path)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "logout_token={}",
                        urlencoding::encode(&token)
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"result": "acknowledged"})
        );
        let mut calls = take_revokes();
        calls.sort();
        assert_eq!(
            calls,
            if attempt == 0 {
                vec![
                    ("local-a".into(), Some(realm_id.into())),
                    ("local-b".into(), Some(realm_id.into())),
                ]
            } else {
                vec![]
            }
        );
        for id in ["local-a", "local-b"] {
            assert!(repo.get_session(id).await.unwrap().unwrap().revoked);
            assert!(state.session_cache_get(id).is_none());
        }
        for (id, before) in &unchanged {
            assert_eq!(
                &serde_json::to_value(repo.get_session(id).await.unwrap()).unwrap(),
                before
            );
            assert_eq!(state.session_cache_get(id), Some(id.as_bytes().to_vec()));
        }
    }
}
