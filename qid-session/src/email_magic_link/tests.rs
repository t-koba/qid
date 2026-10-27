use super::*;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::Request,
};
use qid_core::{
    config::{QidConfig, ServerNotificationConfig},
    models::User,
    notification::{NotificationResponse, NotificationTransport},
    test_helpers,
};
use qid_crypto::LocalSigner;
use qid_storage::{FileRepository, SqlRepository};
use serde_json::{Value, json};
use std::sync::{
    Mutex,
    atomic::{AtomicU16, Ordering},
};
use tower::ServiceExt;

// Same recording/error-echo transport pattern as the CIAM delivery tests;
// requests are observed only by the test, never by a route response.
#[derive(Default)]
struct Delivery {
    requests: Mutex<Vec<NotificationRequest>>,
    outcome: AtomicU16,
}
#[async_trait::async_trait]
impl NotificationTransport for Delivery {
    async fn send(&self, request: NotificationRequest) -> Result<NotificationResponse, String> {
        tracing::debug!(?request, "test delivery");
        self.requests.lock().unwrap().push(request.clone());
        let status = self.outcome.load(Ordering::Relaxed);
        if status == 0 {
            return Err(format!(
                "untrusted adapter error {} {}",
                request.recipient, request.body
            ));
        }
        Ok(NotificationResponse {
            status,
            sent: status == 200,
            provider_message_id: Some(request.body),
        })
    }
}
fn config() -> QidConfig {
    let mut config = test_helpers::test_config();
    config.realms[0].authentication.email_magic_link.enabled = true;
    config.server.notification = Some(ServerNotificationConfig {
        provider: "https://delivery.example.com".into(),
        timeout_seconds: 10,
        max_concurrent_deliveries: 1,
    });
    config
}
async fn seed(repo: &impl Repository) {
    for realm in ["test", "other"] {
        repo.create_realm(
            &"tenant".into(),
            &realm.into(),
            &format!("https://id.example.com/{realm}"),
            None,
        )
        .await
        .unwrap();
    }
    repo.create_user(&user()).await.unwrap();
}
fn user() -> User {
    User {
        id: "alice".into(),
        realm_id: "test".into(),
        email: Some("Stored.Address@example.com".into()),
        email_verified: true,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    }
}
fn state<R: Repository>(
    repo: Arc<R>,
    config: QidConfig,
    transport: Option<Arc<Delivery>>,
) -> Arc<SharedState<R>> {
    let mut state = SharedState::new(
        config,
        repo,
        Arc::new(LocalSigner::from_secret("test", b"test-secret")),
        json!({"keys":[]}),
    )
    .unwrap();
    state.notification_transport = transport.map(|t| t as Arc<dyn NotificationTransport>);
    Arc::new(state)
}
struct Fixture {
    app: Router,
    state: Arc<SharedState<FileRepository>>,
    delivery: Arc<Delivery>,
    _dir: tempfile::TempDir,
}
impl Fixture {
    async fn new(configure: impl FnOnce(&mut QidConfig), transport: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let repo = Arc::new(
            FileRepository::new(dir.path().join("store.json").to_str().unwrap())
                .await
                .unwrap(),
        );
        repo.migrate().await.unwrap();
        seed(&*repo).await;
        let mut config = config();
        configure(&mut config);
        let delivery = Arc::new(Delivery::default());
        delivery.outcome.store(200, Ordering::Relaxed);
        let state = state(repo, config, transport.then(|| delivery.clone()));
        let app = crate::auth_routes(&state.paths)
            .with_state(state.clone())
            .layer(axum::middleware::from_fn_with_state(
                state.paths.clone(),
                qid_http::csrf_protection_layer_with_server_paths,
            ))
            .layer(axum::middleware::from_fn(qid_http::csp_headers_layer))
            .layer(axum::middleware::from_fn(
                qid_http::security_headers_middleware,
            ));
        Self {
            app,
            state,
            delivery,
            _dir: dir,
        }
    }
    async fn drain(&self) {
        let permit = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.state.notification_delivery_slots.acquire(),
        )
        .await
        .unwrap()
        .unwrap();
        drop(permit);
    }
    async fn issue(&self, cookie: Option<&str>) -> (String, Value, String) {
        let response = post(
            &self.app,
            "/api/v1/test/auth/email-magic-link/send",
            cookie,
            json!({"email": user().email}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let cookie = cookie_value(&response);
        let body = body(response).await;
        self.drain().await;
        let requests = self.delivery.requests.lock().unwrap();
        let request = requests.last().unwrap();
        assert_eq!(request.recipient, user().email.unwrap());
        assert!(request.body.contains("same browser"));
        let link = url::Url::parse(request.body.lines().last().unwrap()).unwrap();
        assert_eq!(
            link.origin().ascii_serialization(),
            "https://id.example.com"
        );
        assert!(link.query().is_none());
        let (id, token) = link.fragment().unwrap().split_once('.').unwrap();
        assert!(well_formed(id) && well_formed(token));
        assert!(!body.contains(id) && !body.contains(token) && !body.contains(&request.recipient));
        (cookie, json!({"challenge_id":id,"token":token}), body)
    }
}
async fn post(app: &Router, path: &str, cookie: Option<&str>, body: Value) -> Response {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::HOST, "untrusted.example")
        .header("forwarded", "host=untrusted.example;proto=http");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    app.clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}
async fn body(response: Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}
fn cookie_value(response: &Response) -> String {
    let value = response.headers()[header::SET_COOKIE].to_str().unwrap();
    for flag in [
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Path=/",
        "Max-Age=3600",
    ] {
        assert!(value.contains(flag));
    }
    value.split(';').next().unwrap().into()
}
async fn reject(app: &Router, realm: &str, cookie: Option<&str>, credential: Value) {
    let response = post(
        app,
        &format!("/api/v1/{realm}/auth/email-magic-link/verify"),
        cookie,
        credential,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(
        body(response).await,
        r#"{"status":"authentication_failed"}"#
    );
}
async fn row(repo: &impl Repository, credential: &Value) -> CiamVerificationChallengeRecord {
    repo.get_ciam_verification_challenge(
        &"test".into(),
        credential["challenge_id"].as_str().unwrap(),
    )
    .await
    .unwrap()
    .unwrap()
}

#[tokio::test]
async fn delivered_link_needs_explicit_post_and_regenerates_a_browser_session_once() {
    let f = Fixture::new(|_| {}, true).await;
    let (cookie, credential, _) = f.issue(None).await;
    let delivery_events = f.state.repo.list_audit_events(None, 100).await.unwrap();
    assert_eq!(delivery_events.len(), 1);
    assert_eq!(
        delivery_events[0].action,
        "auth.email_magic_link.delivery_accepted"
    );
    assert_eq!(delivery_events[0].target_type, "authentication_challenge");
    let audit_json = serde_json::to_string(&delivery_events).unwrap();
    assert!(!audit_json.contains(credential["token"].as_str().unwrap()));
    assert!(!audit_json.contains(cookie.split_once('=').unwrap().1));
    assert!(!audit_json.contains(user().email.as_deref().unwrap()));
    let record = row(&*f.state.repo, &credential).await;
    let stored = std::fs::read_to_string(f._dir.path().join("store.json")).unwrap();
    assert!(!stored.contains(credential["token"].as_str().unwrap()));
    assert!(!stored.contains(cookie.split_once('=').unwrap().1));
    assert_eq!(
        record.expires_at_epoch_seconds - record.created_at_epoch_seconds,
        600
    );
    assert_ne!(record.code_hash, credential["token"].as_str().unwrap());
    assert_eq!(
        record.code_hash,
        challenge_hash(
            &record,
            credential["token"].as_str().unwrap(),
            cookie.split_once('=').unwrap().1
        )
    );
    let get = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/test/auth/email-magic-link/verify?challenge_id=ignored&token=ignored")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    assert!(get.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(get.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(get.headers()["referrer-policy"], "no-referrer");
    let csp = get.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        csp.contains("default-src 'none'")
            && csp.contains("frame-ancestors 'none'")
            && !csp.contains("unsafe-inline")
    );
    let page = body(get).await;
    assert!(page.contains("history.replaceState(null, '', location.pathname)"));
    assert!(page.contains("addEventListener('click'"));
    assert!(page.contains("browser where you requested it"));
    let nonce = page
        .split("<script nonce=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    assert!(csp.contains(&format!("'nonce-{nonce}'")));
    assert!(!page.contains("https://"));
    assert!(
        row(&*f.state.repo, &credential)
            .await
            .consumed_at_epoch_seconds
            .is_none()
    );
    assert!(
        f.state
            .repo
            .list_sessions("test", None)
            .await
            .unwrap()
            .is_empty()
    );
    let manager = SessionManager::new(f.state.repo.clone(), 30, 12);
    let old = manager
        .create("test", "alice", "urn:qid:acr:password", &["pwd".into()])
        .await
        .unwrap();
    let with_old = format!(
        "{cookie}; {}={}",
        f.state.plan.realms[0].browser_session.cookie_name, old.id
    );
    let response = post(
        &f.app,
        "/api/v1/test/auth/email-magic-link/verify",
        Some(&with_old),
        credential.clone(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let session_cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(session_cookie.starts_with("__Host-qid=sid_") && !session_cookie.contains(&old.id));
    assert_eq!(body(response).await, r#"{"status":"authenticated"}"#);
    let sessions = f.state.repo.list_sessions("test", None).await.unwrap();
    let active = sessions.iter().find(|s| !s.revoked).unwrap();
    assert_eq!(active.acr.as_deref(), Some("urn:qid:acr:email_magic_link"));
    assert_eq!(active.amr, ["email"]);
    assert!(sessions.iter().find(|s| s.id == old.id).unwrap().revoked);
    reject(&f.app, "test", Some(&cookie), credential).await;
    assert_eq!(
        f.state
            .repo
            .list_sessions("test", None)
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        f.state
            .repo
            .list_audit_events(None, 100)
            .await
            .unwrap()
            .len(),
        1,
        "delivery acceptance is audited separately from user authentication"
    );
}

#[tokio::test]
async fn send_is_generic_with_stable_binding_across_all_suppressions() {
    let f = Fixture::new(|_| {}, true).await;
    let (cookie, _, expected) = f.issue(None).await;
    let (same_cookie, _, _) = f.issue(Some(&cookie)).await;
    assert_eq!(same_cookie, cookie);
    let mut unverified = user();
    unverified.email_verified = false;
    f.state.repo.update_user(&unverified, None).await.unwrap();
    for (realm, email) in [
        ("test", "Stored.Address@example.com"),
        ("test", "unknown@example.com"),
        ("unknown", "Stored.Address@example.com"),
    ] {
        let response = post(
            &f.app,
            &format!("/api/v1/{realm}/auth/email-magic-link/send"),
            Some(&cookie),
            json!({"email":email}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(cookie_value(&response), cookie);
        assert_eq!(body(response).await, expected);
    }
    unverified.email_verified = true;
    unverified.email = None;
    f.state.repo.update_user(&unverified, None).await.unwrap();
    let response = post(
        &f.app,
        "/api/v1/test/auth/email-magic-link/send",
        Some(&cookie),
        json!({"email":"Stored.Address@example.com"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(body(response).await, expected);
    assert_eq!(f.delivery.requests.lock().unwrap().len(), 2);
    for configure in [0, 1, 2, 3] {
        let f = Fixture::new(
            |c| {
                if configure == 0 {
                    c.realms[0].authentication.email_magic_link.enabled = false;
                }
                if configure == 1 {
                    c.server.notification = None;
                }
            },
            configure != 2,
        )
        .await;
        let _capacity = if configure == 3 {
            Some(f.state.notification_delivery_slots.acquire().await.unwrap())
        } else {
            None
        };
        let response = post(
            &f.app,
            "/api/v1/test/auth/email-magic-link/send",
            None,
            json!({"email":user().email}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        cookie_value(&response);
        assert_eq!(body(response).await, expected);
        assert!(f.delivery.requests.lock().unwrap().is_empty());
    }
    let budget = Fixture::new(
        |c| {
            c.realms[0]
                .authentication
                .email_magic_link
                .max_issuances_per_window = 1
        },
        true,
    )
    .await;
    let (cookie, _, _) = budget.issue(None).await;
    let response = post(
        &budget.app,
        "/api/v1/test/auth/email-magic-link/send",
        Some(&cookie),
        json!({"email":user().email}),
    )
    .await;
    assert_eq!(body(response).await, expected);
    budget.drain().await;
    assert_eq!(budget.delivery.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn malformed_selector_or_extra_destination_is_not_accepted() {
    let f = Fixture::new(|_| {}, true).await;
    for request in [
        json!({"email":user().email, "redirect_url":"https://untrusted.example"}),
        json!({"email":user().email, "recipient":"untrusted@example.com"}),
        json!({"user_id":"alice"}),
    ] {
        let response = post(
            &f.app,
            "/api/v1/test/auth/email-magic-link/send",
            None,
            request,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
    assert!(f.delivery.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn wrong_browser_cannot_exhaust_a_valid_link() {
    let f = Fixture::new(|_| {}, true).await;
    let (cookie, credential, _) = f.issue(None).await;
    let original = row(&*f.state.repo, &credential).await;
    let wrong_cookie = format!("{BINDING_COOKIE}={}", random_secret());
    let malformed_cookie = format!("{BINDING_COOKIE}=malformed");
    for _ in 0..=f.state.plan.realms[0].email_magic_link.max_attempts {
        for binding in [
            None,
            Some(wrong_cookie.as_str()),
            Some(malformed_cookie.as_str()),
        ] {
            reject(&f.app, "test", binding, credential.clone()).await;
            assert_eq!(row(&*f.state.repo, &credential).await, original);
        }
    }
    let response = post(
        &f.app,
        &f.state
            .paths
            .auth_email_magic_link_verify
            .replace(":realm", "test"),
        Some(&cookie),
        credential.clone(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key(header::SET_COOKIE));
    let consumed = row(&*f.state.repo, &credential).await;
    assert_eq!(consumed.attempt_count, 1);
    assert!(consumed.consumed_at_epoch_seconds.is_some());
    reject(&f.app, "test", Some(&cookie), credential.clone()).await;
    assert_eq!(row(&*f.state.repo, &credential).await, consumed);
}

#[tokio::test]
async fn bindings_invalid_tokens_and_attempt_cap_fail_uniformly_without_sessions() {
    let f = Fixture::new(
        |c| {
            let mut other = c.realms[0].clone();
            other.id = "other".into();
            other.issuer = "https://id.example.com/other".into();
            c.realms.push(other);
        },
        true,
    )
    .await;
    let (cookie, credential, _) = f.issue(None).await;
    for malformed in [
        json!({}),
        json!({"challenge_id":credential["challenge_id"]}),
        json!({"challenge_id":credential["challenge_id"],"token":credential["token"],"extra":"ignored"}),
        json!({"challenge_id":"bad","token":"bad"}),
    ] {
        reject(&f.app, "test", Some(&cookie), malformed).await;
    }
    let wrong_cookie = format!("{BINDING_COOKIE}={}", random_secret());
    reject(&f.app, "test", None, credential.clone()).await;
    reject(&f.app, "test", Some(&wrong_cookie), credential.clone()).await;
    let mut wrong_token = credential.clone();
    wrong_token["token"] = json!(random_secret());
    reject(&f.app, "test", Some(&cookie), wrong_token.clone()).await;
    reject(
        &f.app,
        "test",
        Some(&cookie),
        json!({"challenge_id":random_secret(),"token":random_secret()}),
    )
    .await;
    reject(&f.app, "other", Some(&cookie), credential.clone()).await;
    assert_eq!(row(&*f.state.repo, &credential).await.attempt_count, 1);
    // Malformed tokens with the correct binding also spend a persisted attempt.
    let mut malformed_token = credential.clone();
    malformed_token["token"] = json!("malformed");
    reject(&f.app, "test", Some(&cookie), malformed_token).await;
    assert_eq!(row(&*f.state.repo, &credential).await.attempt_count, 2);
    for _ in 0..3 {
        reject(&f.app, "test", Some(&cookie), wrong_token.clone()).await;
    }
    reject(&f.app, "test", Some(&cookie), credential.clone()).await;
    assert_eq!(row(&*f.state.repo, &credential).await.attempt_count, 5);
    assert!(
        f.state
            .repo
            .list_sessions("test", None)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn stale_unverified_expired_and_foreign_purpose_credentials_fail() {
    for case in ["stale", "unverified", "expired", "purpose"] {
        let f = Fixture::new(|_| {}, true).await;
        let (cookie, mut credential, _) = f.issue(None).await;
        if matches!(case, "stale" | "unverified") {
            let mut user = user();
            if case == "stale" {
                user.email = Some("changed@example.com".into());
            } else {
                user.email_verified = false;
            }
            f.state.repo.update_user(&user, None).await.unwrap();
        } else {
            let mut record = row(&*f.state.repo, &credential).await;
            record.id = random_secret();
            credential["challenge_id"] = json!(&record.id);
            if case == "expired" {
                record.created_at_epoch_seconds = now_seconds() - 20;
                record.expires_at_epoch_seconds = now_seconds() - 10;
            } else {
                record.purpose = "email_verification".into();
            }
            // Even an otherwise valid digest for the changed immutable identity is refused.
            record.code_hash = challenge_hash(
                &record,
                credential["token"].as_str().unwrap(),
                cookie.split_once('=').unwrap().1,
            );
            f.state
                .repo
                .store_ciam_verification_challenge(&record)
                .await
                .unwrap();
        }
        reject(&f.app, "test", Some(&cookie), credential).await;
        assert!(
            f.state
                .repo
                .list_sessions("test", None)
                .await
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn configured_paths_are_used_for_delivery_and_redemption() {
    let f = Fixture::new(
        |c| {
            c.server.public_base_url = "https://id.example.com/proxy".into();
            for realm in &mut c.realms {
                realm.issuer = format!("https://id.example.com/proxy/realms/{}", realm.id);
            }
            c.server.paths.auth_email_magic_link_send = "/mail/:realm/send".into();
            c.server.paths.auth_email_magic_link_verify = "/mail/:realm/confirm".into();
        },
        true,
    )
    .await;
    let response = post(
        &f.app,
        "/mail/test/send",
        None,
        json!({"email":user().email}),
    )
    .await;
    let cookie = cookie_value(&response);
    f.drain().await;
    let request = f.delivery.requests.lock().unwrap().last().unwrap().clone();
    let link = url::Url::parse(request.body.lines().last().unwrap()).unwrap();
    assert_eq!(link.path(), "/proxy/mail/test/confirm");
    let (id, token) = link.fragment().unwrap().split_once('.').unwrap();
    let response = post(
        &f.app,
        "/mail/test/confirm",
        Some(&cookie),
        json!({"challenge_id":id,"token":token}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn cookie_failure_stays_consumed() {
    let f = Fixture::new(
        |c| c.realms[0].sessions.browser.cookie_name = "invalid\r\nname".into(),
        true,
    )
    .await;
    let (cookie, credential, _) = f.issue(None).await;
    reject(&f.app, "test", Some(&cookie), credential.clone()).await;
    assert!(
        row(&*f.state.repo, &credential)
            .await
            .consumed_at_epoch_seconds
            .is_some()
    );
    reject(&f.app, "test", Some(&cookie), credential).await;
}

#[tokio::test]
async fn session_write_failure_stays_consumed() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite:{}", dir.path().join("store.db").display());
    let repo = Arc::new(SqlRepository::connect(&url).await.unwrap());
    repo.migrate().await.unwrap();
    seed(&*repo).await;
    let pool = sqlx::AnyPool::connect(&url).await.unwrap();
    sqlx::query("CREATE TRIGGER fail_session BEFORE INSERT ON sessions BEGIN SELECT RAISE(FAIL, 'session write rejected'); END").execute(&pool).await.unwrap();
    let delivery = Arc::new(Delivery::default());
    delivery.outcome.store(200, Ordering::Relaxed);
    let state = state(repo.clone(), config(), Some(delivery.clone()));
    let app = crate::auth_routes(&state.paths).with_state(state.clone());
    let response = post(
        &app,
        "/api/v1/test/auth/email-magic-link/send",
        None,
        json!({"email":user().email}),
    )
    .await;
    let cookie = cookie_value(&response);
    drop(
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            state.notification_delivery_slots.acquire(),
        )
        .await
        .unwrap()
        .unwrap(),
    );
    let request = delivery.requests.lock().unwrap().last().unwrap().clone();
    let link = url::Url::parse(request.body.lines().last().unwrap()).unwrap();
    let (id, token) = link.fragment().unwrap().split_once('.').unwrap();
    let credential = json!({"challenge_id":id,"token":token});
    reject(&app, "test", Some(&cookie), credential.clone()).await;
    assert!(
        row(&*repo, &credential)
            .await
            .consumed_at_epoch_seconds
            .is_some()
    );
    sqlx::query("DROP TRIGGER fail_session")
        .execute(&pool)
        .await
        .unwrap();
    reject(&app, "test", Some(&cookie), credential).await;
    assert!(repo.list_sessions("test", None).await.unwrap().is_empty());
    pool.close().await;
    drop(app);
    drop(state);
    Arc::try_unwrap(repo).ok().unwrap().close().await;
}

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[tokio::test]
async fn delivery_failure_is_not_authentication_and_does_not_leak_secrets_in_logs() {
    let logs = Logs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    async {
        for outcome in [0, 202, 500] {
            let f = Fixture::new(|_| {}, true).await;
            f.delivery.outcome.store(outcome, Ordering::Relaxed);
            let (_, credential, _) = f.issue(None).await;
            assert!(
                f.state
                    .repo
                    .list_sessions("test", None)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(
                row(&*f.state.repo, &credential)
                    .await
                    .consumed_at_epoch_seconds
                    .is_none()
            );
            assert!(
                f.state
                    .repo
                    .list_audit_events(None, 100)
                    .await
                    .unwrap()
                    .is_empty()
            );
            let captured = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
            for secret in [
                credential["token"].as_str().unwrap(),
                credential["challenge_id"].as_str().unwrap(),
                user().email.as_deref().unwrap(),
                "untrusted adapter error",
                "provider_message_id",
            ] {
                assert!(!captured.contains(secret));
            }
            assert!(captured.contains("email magic link delivery failed"));
        }
    }
    .with_subscriber(subscriber)
    .await;
}

#[tokio::test]
async fn redemption_fails_closed_when_disabled_or_transport_is_missing() {
    let f = Fixture::new(|_| {}, true).await;
    let (cookie, credential, _) = f.issue(None).await;
    for case in ["disabled", "transport", "provider"] {
        let mut config = f.state.config.clone();
        if case == "disabled" {
            config.realms[0].authentication.email_magic_link.enabled = false;
        }
        if case == "provider" {
            config.server.notification = None;
        }
        let state = state(
            f.state.repo.clone(),
            config,
            (case != "transport").then(|| f.delivery.clone()),
        );
        let app = crate::auth_routes(&state.paths).with_state(state);
        reject(&app, "test", Some(&cookie), credential.clone()).await;
        assert!(
            row(&*f.state.repo, &credential)
                .await
                .consumed_at_epoch_seconds
                .is_none()
        );
        assert!(
            f.state
                .repo
                .list_sessions("test", None)
                .await
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn outstanding_links_keep_one_browser_binding_and_each_consume_once() {
    let f = Fixture::new(|_| {}, true).await;
    let (cookie, first, _) = f.issue(None).await;
    let (second_cookie, second, _) = f.issue(Some(&cookie)).await;
    assert_eq!(cookie, second_cookie);
    assert_ne!(first["challenge_id"], second["challenge_id"]);
    for credential in [first, second] {
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/test/auth/email-magic-link/verify")
            .header(header::HOST, "id.example.com")
            .header(header::ORIGIN, "https://id.example.com")
            .header(header::COOKIE, &cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(credential.to_string()))
            .unwrap();
        let response = f.app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        reject(&f.app, "test", Some(&cookie), credential).await;
    }
    assert_eq!(
        f.state
            .repo
            .list_sessions("test", None)
            .await
            .unwrap()
            .len(),
        2
    );
}
