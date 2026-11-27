//! Exercise local termination failures and observe realm-scoped sub-logout writes.
use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use qid_core::{
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

async fn logout_state() -> (TestFile, Arc<SharedState<qid_storage::FileRepository>>) {
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
    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    let state =
        Arc::new(SharedState::new(config, repo.clone(), signer.clone(), json!({})).unwrap());
    (file, state)
}

#[tokio::test]
async fn backchannel_sub_route_scopes_writes_to_validated_issuer_realm() {
    let (_file, state) = logout_state().await;
    let repo = &state.repo;
    let realm_id = state.config.realms[0].id.as_str();
    let issuer = state.config.realms[0].issuer.clone();
    let signer = &state.signer;
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    Get,
    List,
    Revoke(&'static str),
}

#[derive(Default)]
struct FaultySessions {
    sessions: std::sync::Mutex<Vec<Session>>,
    fault: std::sync::Mutex<Option<Fault>>,
}

impl FaultySessions {
    fn check(&self, operation: Fault) -> QidResult<()> {
        if *self.fault.lock().unwrap() == Some(operation) {
            return Err(qid_core::error::QidError::Storage {
                message: "injected session repository outage".into(),
            });
        }
        Ok(())
    }

    fn revoked(&self, id: &str) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .iter()
            .find(|session| session.id == id)
            .unwrap()
            .revoked
    }
}

#[async_trait::async_trait]
impl SessionRepository for FaultySessions {
    async fn create_session(&self, session: &Session) -> QidResult<()> {
        self.sessions.lock().unwrap().push(session.clone());
        Ok(())
    }

    async fn get_session(&self, id: &str) -> QidResult<Option<Session>> {
        self.check(Fault::Get)?;
        Ok(self
            .sessions
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.id == id)
            .cloned())
    }

    async fn update_session_idle_expiry(
        &self,
        _: &str,
        _: u64,
        _: Option<&str>,
    ) -> QidResult<bool> {
        panic!("logout must not update session expiry")
    }

    async fn revoke_session(&self, id: &str, scope: Option<&str>) -> QidResult<bool> {
        let fault = *self.fault.lock().unwrap();
        if let Some(Fault::Revoke(target)) = fault
            && id == target
        {
            self.check(Fault::Revoke(target))?;
        }
        let mut sessions = self.sessions.lock().unwrap();
        let Some(session) = sessions
            .iter_mut()
            .find(|s| s.id == id && scope.is_none_or(|realm| s.realm_id == realm) && !s.revoked)
        else {
            return Ok(false);
        };
        session.revoked = true;
        Ok(true)
    }

    async fn list_sessions(
        &self,
        realm_id: &str,
        user_id: Option<&str>,
    ) -> QidResult<Vec<Session>> {
        self.check(Fault::List)?;
        Ok(self
            .sessions
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.realm_id == realm_id && user_id.is_none_or(|user| s.user_id == user))
            .cloned()
            .collect())
    }
}

async fn faulty_sessions(state: &SharedState<qid_storage::FileRepository>) -> FaultySessions {
    let repo = FaultySessions::default();
    let now = util::now_seconds();
    for (id, realm, user, revoked) in [
        ("local-a", "logout-issuer", "user", false),
        ("local-b", "logout-issuer", "user", false),
        ("already-revoked", "logout-issuer", "user", true),
        ("foreign", "other-realm", "user", false),
        ("other-user", "logout-issuer", "other-user", false),
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
    repo
}

fn logout_claims(state: &SharedState<qid_storage::FileRepository>) -> JwtClaims {
    let now = util::now_seconds() as usize;
    JwtClaims {
        iss: Some(state.config.realms[0].issuer.clone()),
        sub: Some("user".into()),
        aud: Some(Audience::single("par-client")),
        exp: Some(now + 300),
        nbf: Some(now),
        iat: Some(now),
        jti: Some(ulid::Ulid::new().to_string()),
        extra: HashMap::from([(
            "events".into(),
            json!({
                "http://schemas.openid.net/event/backchannel-logout": {}
            }),
        )]),
    }
}

async fn assert_session_failure(response: Response) {
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert!(
        !String::from_utf8(body.to_vec())
            .unwrap()
            .contains("acknowledged")
    );
}

async fn browser_logout_with_headers(
    state: &SharedState<qid_storage::FileRepository>,
    sessions: &FaultySessions,
    headers: axum::http::HeaderMap,
) -> Response {
    logout_with_sessions(
        state,
        sessions,
        "/logout".parse().unwrap(),
        headers,
        LogoutRequest {
            id_token_hint: Some(state.signer.sign(&logout_claims(state)).unwrap()),
            client_id: Some("par-client".into()),
            post_logout_redirect_uri: None,
        },
    )
    .await
}

async fn browser_logout_with_cookie(
    state: &SharedState<qid_storage::FileRepository>,
    sessions: &FaultySessions,
    cookie: &str,
) -> Response {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(header::COOKIE, cookie.parse().unwrap());
    browser_logout_with_headers(state, sessions, headers).await
}

async fn browser_logout(
    state: &SharedState<qid_storage::FileRepository>,
    sessions: &FaultySessions,
    sid: &str,
) -> Response {
    let cookie = &state
        .realm("logout-issuer")
        .unwrap()
        .browser_session
        .cookie_name;
    browser_logout_with_cookie(state, sessions, &format!("{cookie}={sid}")).await
}

#[tokio::test]
async fn duplicate_browser_session_cookies_terminate_no_session() {
    let (_file, state) = logout_state().await;
    let sessions = faulty_sessions(&state).await;
    let cookie_name = &state
        .realm("logout-issuer")
        .unwrap()
        .browser_session
        .cookie_name;
    let cookie = format!("{cookie_name}=local-a; {cookie_name}=local-b");
    let response = browser_logout_with_cookie(&state, &sessions, &cookie).await;
    assert_eq!(response.status(), StatusCode::OK);
    for sid in ["local-a", "local-b"] {
        assert!(!sessions.revoked(sid));
        assert!(state.session_cache_get(sid).is_some());
    }
}

#[tokio::test]
async fn browser_session_cookie_split_across_headers_terminates_no_session() {
    let (_file, state) = logout_state().await;
    let sessions = faulty_sessions(&state).await;
    let cookie_name = &state
        .realm("logout-issuer")
        .unwrap()
        .browser_session
        .cookie_name;
    let mut headers = axum::http::HeaderMap::new();
    headers.append(
        header::COOKIE,
        format!("{cookie_name}=local-a").parse().unwrap(),
    );
    headers.append(
        header::COOKIE,
        format!("{cookie_name}=local-b").parse().unwrap(),
    );
    let response = browser_logout_with_headers(&state, &sessions, headers).await;
    assert_eq!(response.status(), StatusCode::OK);
    for sid in ["local-a", "local-b"] {
        assert!(!sessions.revoked(sid));
        assert!(state.session_cache_get(sid).is_some());
    }
}

#[tokio::test]
async fn browser_session_cookie_in_second_header_terminates_session() {
    let (_file, state) = logout_state().await;
    let sessions = faulty_sessions(&state).await;
    let cookie_name = &state
        .realm("logout-issuer")
        .unwrap()
        .browser_session
        .cookie_name;
    let mut headers = axum::http::HeaderMap::new();
    headers.append(header::COOKIE, "theme=dark".parse().unwrap());
    headers.append(
        header::COOKIE,
        format!("{cookie_name}=local-b").parse().unwrap(),
    );
    let response = browser_logout_with_headers(&state, &sessions, headers).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(sessions.revoked("local-b"));
    assert!(state.session_cache_get("local-b").is_none());
    assert!(!sessions.revoked("local-a"));
}

#[tokio::test]
async fn browser_session_failures_preserve_cookie_until_successful_retry() {
    for fault in [Fault::Get, Fault::Revoke("local-a")] {
        let (_file, state) = logout_state().await;
        let sessions = faulty_sessions(&state).await;
        *sessions.fault.lock().unwrap() = Some(fault);
        assert_session_failure(browser_logout(&state, &sessions, "local-a").await).await;
        assert!(!sessions.revoked("local-a"));
        assert!(state.session_cache_get("local-a").is_some());

        *sessions.fault.lock().unwrap() = None;
        for _ in 0..2 {
            let response = browser_logout(&state, &sessions, "local-a").await;
            assert_eq!(response.status(), StatusCode::OK);
            assert!(
                response.headers()[header::SET_COOKIE]
                    .to_str()
                    .unwrap()
                    .contains("Max-Age=0")
            );
            assert!(sessions.revoked("local-a"));
            assert!(state.session_cache_get("local-a").is_none());
        }
        assert!(!sessions.revoked("foreign"));
        assert!(!sessions.revoked("other-user"));
    }
}

#[tokio::test]
async fn backchannel_session_failures_do_not_acknowledge_and_allow_retry() {
    for (sid, sub, fault) in [
        (Some("local-a"), None, Fault::Revoke("local-a")),
        (None, Some("user"), Fault::List),
        (None, Some("user"), Fault::Revoke("local-b")),
        // The sid fallback lookup is also authoritative when revocation is a no-op.
        (Some("already-revoked"), None, Fault::Get),
    ] {
        let (_file, state) = logout_state().await;
        let sessions = faulty_sessions(&state).await;
        let mut claims = logout_claims(&state);
        claims.sub = sub.map(str::to_owned);
        if let Some(sid) = sid {
            claims.extra.insert("sid".into(), json!(sid));
        }
        let token = state.signer.sign(&claims).unwrap();
        *sessions.fault.lock().unwrap() = Some(fault);
        let response = backchannel_logout_with_sessions(
            &state,
            &sessions,
            BackchannelLogoutRequest {
                logout_token: token.clone(),
            },
        )
        .await;
        assert_session_failure(response).await;
        let partial = fault == Fault::Revoke("local-b");
        assert_eq!(sessions.revoked("local-a"), partial);
        assert_eq!(state.session_cache_get("local-a").is_none(), partial);
        assert!(!sessions.revoked("local-b"));
        assert!(state.session_cache_get("local-b").is_some());
        assert!(state.session_cache_get("already-revoked").is_some());

        *sessions.fault.lock().unwrap() = None;
        for _ in 0..2 {
            let response = backchannel_logout_with_sessions(
                &state,
                &sessions,
                BackchannelLogoutRequest {
                    logout_token: token.clone(),
                },
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap(),
                json!({"result": "acknowledged"})
            );
        }
        for id in if sub.is_some() {
            vec!["local-a", "local-b"]
        } else {
            vec![sid.unwrap()]
        } {
            assert!(sessions.revoked(id));
            assert!(state.session_cache_get(id).is_none());
        }
        for id in ["foreign", "other-user"] {
            assert!(!sessions.revoked(id));
            assert!(state.session_cache_get(id).is_some());
        }
        take_revokes();
    }
}

#[tokio::test]
async fn local_logout_keeps_missing_and_foreign_sessions_idempotent() {
    let (_file, state) = logout_state().await;
    let sessions = faulty_sessions(&state).await;
    for sid in ["missing", "foreign", "already-revoked"] {
        let response = browser_logout(&state, &sessions, sid).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().contains_key(header::SET_COOKIE),
            sid != "foreign"
        );
        let mut claims = logout_claims(&state);
        claims.sub = None;
        claims.extra.insert("sid".into(), json!(sid));
        let response = backchannel_logout_with_sessions(
            &state,
            &sessions,
            BackchannelLogoutRequest {
                logout_token: state.signer.sign(&claims).unwrap(),
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert!(!sessions.revoked("foreign"));
    assert!(state.session_cache_get("foreign").is_some());
}
