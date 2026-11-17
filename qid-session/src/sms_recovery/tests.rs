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
    atomic::{AtomicBool, Ordering},
};
use tower::ServiceExt;

const PHONE: &str = "+12025550123";
#[derive(Default)]
struct Delivery {
    requests: Mutex<Vec<NotificationRequest>>,
    fail: AtomicBool,
}
#[async_trait::async_trait]
impl NotificationTransport for Delivery {
    async fn send(&self, request: NotificationRequest) -> Result<NotificationResponse, String> {
        tracing::debug!(?request, "test delivery");
        self.requests.lock().unwrap().push(request.clone());
        if self.fail.load(Ordering::Relaxed) {
            return Err(format!(
                "provider diagnostic {} {}",
                request.recipient, request.body
            ));
        }
        let response = NotificationResponse {
            sent: true,
            status: 202,
            provider_message_id: Some(request.body),
        };
        tracing::debug!(?response, "test acceptance");
        Ok(response)
    }
}
fn config() -> QidConfig {
    let mut c = test_helpers::test_config();
    c.realms[0].authentication.mfa.sms_recovery.enabled = true;
    c.realms[0]
        .authentication
        .mfa
        .sms_recovery
        .destinations
        .insert("alice".into(), PHONE.into());
    c.realms[0].authentication.email_magic_link.enabled = true;
    let mut other = c.realms[0].clone();
    other.id = "other".into();
    other.issuer = "https://id.example.com/other".into();
    c.realms.push(other);
    c.server.notification = Some(ServerNotificationConfig {
        provider: "https://delivery.example.com".into(),
        timeout_seconds: 10,
        max_concurrent_deliveries: 1,
    });
    c
}
struct Fixture<R: Repository> {
    app: Router,
    state: Arc<SharedState<R>>,
    delivery: Arc<Delivery>,
}
impl<R: Repository> Fixture<R> {
    async fn new(repo: Arc<R>, c: QidConfig) -> Self {
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
        for id in ["alice", "bob"] {
            repo.create_user(&User {
                id: id.into(),
                realm_id: "test".into(),
                email: Some(format!("{id}@example.com")),
                email_verified: true,
                display_name: None,
                failed_login_attempts: 0,
                locked_until: None,
                org: None,
            })
            .await
            .unwrap();
        }
        let delivery = Arc::new(Delivery::default());
        let state = state(repo, c, Some(delivery.clone()));
        let app = crate::auth_routes(&state.paths).with_state(state.clone());
        Self {
            app,
            state,
            delivery,
        }
    }
    async fn drain(&self) {
        let _permit = self
            .state
            .notification_delivery_slots
            .acquire()
            .await
            .unwrap();
    }
    async fn issue(&self) -> (String, Value) {
        let response = post(
            &self.app,
            &path("test", "send"),
            None,
            json!({"user_id":"alice"}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let cookie = cookie(&response);
        let response = body(response).await;
        self.drain().await;
        let request = self
            .delivery
            .requests
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        assert_eq!(request.channel, NotificationChannel::Sms);
        assert_eq!(request.recipient, PHONE);
        let code = request
            .body
            .split_whitespace()
            .nth(6)
            .unwrap()
            .trim_end_matches('.');
        assert_eq!(code.len(), 8);
        assert!(!response.contains(code) && !response.contains(PHONE));
        let response: Value = serde_json::from_str(&response).unwrap();
        (
            cookie,
            json!({"user_id":"alice", "challenge_id":response["challenge_id"], "code":code}),
        )
    }
    async fn record(&self, credential: &Value) -> CiamVerificationChallengeRecord {
        self.state
            .repo
            .get_ciam_verification_challenge(
                &"test".into(),
                credential["challenge_id"].as_str().unwrap(),
            )
            .await
            .unwrap()
            .unwrap()
    }
    async fn reject(&self, realm: &str, cookie: Option<&str>, credential: Value) {
        let response = post(&self.app, &path(realm, "redeem"), cookie, credential).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        assert_eq!(body(response).await, "{\"status\":\"recovery_failed\"}");
    }
}
fn state<R: Repository>(
    repo: Arc<R>,
    c: QidConfig,
    delivery: Option<Arc<Delivery>>,
) -> Arc<SharedState<R>> {
    let mut s = SharedState::new(
        c,
        repo,
        Arc::new(LocalSigner::from_secret("test", b"test-secret")),
        json!({"keys":[]}),
    )
    .unwrap();
    s.notification_transport = delivery.map(|d| d as Arc<dyn NotificationTransport>);
    Arc::new(s)
}
fn path(realm: &str, action: &str) -> String {
    format!("/api/v1/{realm}/auth/password/recovery/sms/{action}")
}
fn cookie(response: &Response) -> String {
    response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .into()
}
async fn body(response: Response) -> String {
    String::from_utf8(to_bytes(response.into_body(), 8192).await.unwrap().to_vec()).unwrap()
}
async fn post(app: &Router, path: &str, cookie: Option<&str>, data: Value) -> Response {
    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    app.clone()
        .oneshot(req.body(Body::from(data.to_string())).unwrap())
        .await
        .unwrap()
}
async fn exercise<R: Repository>(f: &Fixture<R>) {
    let (browser, credential) = f.issue().await;
    let original = f.record(&credential).await;
    assert!(original.consumed_at_epoch_seconds.is_none());
    assert!(
        !original
            .code_hash
            .contains(credential["code"].as_str().unwrap())
    );
    assert!(
        f.state
            .repo
            .list_sessions("test", None)
            .await
            .unwrap()
            .is_empty()
    );
    let wrong_browser = format!("{COOKIE}={}", random_secret());
    for browser in [None, Some(wrong_browser.as_str())] {
        f.reject("test", browser, credential.clone()).await;
    }
    let mut wrong_owner = credential.clone();
    wrong_owner["user_id"] = json!("bob");
    f.reject("test", Some(&browser), wrong_owner).await;
    f.reject("other", Some(&browser), credential.clone()).await;
    assert_eq!(f.record(&credential).await, original);
    // SMS credentials cannot be exchanged as email login or email verification.
    let response = post(
        &f.app,
        "/api/v1/test/auth/email-magic-link/verify",
        Some(&browser),
        json!({"challenge_id":original.id, "token":credential["code"]}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        f.state
            .repo
            .redeem_email_magic_link_challenge(
                &"test".into(),
                &original.id,
                &original.code_hash,
                now_seconds(),
                5
            )
            .await
            .unwrap()
            .is_none()
    );
    let mut wrong = credential.clone();
    wrong["code"] = json!("not-a-code");
    f.reject("test", Some(&browser), wrong).await;
    assert_eq!(f.record(&credential).await.attempt_count, 1);
    // Concurrent redemption creates exactly one session.
    let redeem_path = path("test", "redeem");
    let (a, b) = tokio::join!(
        post(&f.app, &redeem_path, Some(&browser), credential.clone()),
        post(&f.app, &redeem_path, Some(&browser), credential.clone())
    );
    let statuses = [a.status(), b.status()];
    assert_eq!(statuses.iter().filter(|s| **s == StatusCode::OK).count(), 1);
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::UNAUTHORIZED)
            .count(),
        1
    );
    let success = if a.status() == StatusCode::OK { a } else { b };
    assert_eq!(success.headers()[header::CACHE_CONTROL], "no-store");
    assert!(cookie(&success).starts_with(&f.state.plan.realms[0].browser_session.cookie_name));
    assert_eq!(body(success).await, "{\"status\":\"recovered\"}");
    let sessions = f.state.repo.list_sessions("test", None).await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].user_id, "alice");
    assert_eq!(sessions[0].amr, ["sms_recovery"]);
    assert_eq!(sessions[0].acr.as_deref(), Some("urn:qid:acr:recovery"));
    let consumed = f.record(&credential).await;
    assert_eq!(consumed.attempt_count, 2);
    assert!(consumed.consumed_at_epoch_seconds.is_some());
    f.reject("test", Some(&browser), credential.clone()).await;
    assert_eq!(f.record(&credential).await, consumed);
    // Expiry, future creation and foreign purpose reject even with a matching proof.
    for case in ["expiry", "future", "purpose"] {
        let mut record = original.clone();
        record.id = random_secret();
        if case == "expiry" {
            record.created_at_epoch_seconds = now_seconds() - 20;
            record.expires_at_epoch_seconds = now_seconds();
        }
        if case == "future" {
            record.created_at_epoch_seconds = now_seconds() + 30;
            record.expires_at_epoch_seconds = now_seconds() + 60;
        }
        if case == "purpose" {
            record.purpose = "phone_verification".into();
        }
        record.code_hash = challenge_hash(
            &record,
            credential["code"].as_str().unwrap(),
            browser.split_once('=').unwrap().1,
        );
        f.state
            .repo
            .store_ciam_verification_challenge(&record)
            .await
            .unwrap();
        let mut c = credential.clone();
        c["challenge_id"] = json!(record.id);
        f.reject("test", Some(&browser), c).await;
    }
    let (browser, credential) = f.issue().await;
    let mut wrong = credential.clone();
    let code = credential["code"].as_str().unwrap();
    wrong["code"] = json!(if code == "00000000" {
        "11111111"
    } else {
        "00000000"
    });
    for _ in 0..5 {
        f.reject("test", Some(&browser), wrong.clone()).await;
    }
    f.reject("test", Some(&browser), credential.clone()).await;
    assert_eq!(f.record(&credential).await.attempt_count, 5);
    // Consumption and failed delivery do not reset the durable issuance budget.
    let mut next = original.clone();
    next.id = random_secret();
    assert!(
        !f.state
            .repo
            .try_issue_delivery_challenge(&next, 1, 3600)
            .await
            .unwrap()
    );
    assert!(
        f.state
            .repo
            .get_ciam_verification_challenge(&"test".into(), &next.id)
            .await
            .unwrap()
            .is_none()
    );
    // Retire unreferenced SMS history, but not a foreign purpose, on the next issuance.
    next.created_at_epoch_seconds += 4000;
    next.expires_at_epoch_seconds = next.created_at_epoch_seconds + 300;
    assert!(
        f.state
            .repo
            .try_issue_delivery_challenge(&next, 1, 3600)
            .await
            .unwrap()
    );
    assert!(
        f.state
            .repo
            .get_ciam_verification_challenge(&"test".into(), &original.id)
            .await
            .unwrap()
            .is_none()
    );
}
#[tokio::test]
async fn file_recovery_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("store.json");
    let repo = Arc::new(FileRepository::new(file.to_str().unwrap()).await.unwrap());
    let f = Fixture::new(repo, config()).await;
    exercise(&f).await;
    let persisted = std::fs::read_to_string(file).unwrap();
    let last = f.delivery.requests.lock().unwrap().last().unwrap().clone();
    assert!(!persisted.contains(&last.body));
    assert!(!persisted.contains("\"code\":"));
    assert!(persisted.contains("sr1:"));
}
#[tokio::test]
async fn sqlite_recovery_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let repo = Arc::new(
        SqlRepository::connect(&format!("sqlite:{}", dir.path().join("store.db").display()))
            .await
            .unwrap(),
    );
    repo.migrate().await.unwrap();
    let f = Fixture::new(repo.clone(), config()).await;
    exercise(&f).await;
    drop(f);
    Arc::try_unwrap(repo).ok().unwrap().close().await;
}
#[tokio::test]
async fn defaults_destination_and_runtime_prerequisites_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let repo = Arc::new(
        FileRepository::new(dir.path().join("store.json").to_str().unwrap())
            .await
            .unwrap(),
    );
    let f = Fixture::new(repo.clone(), config()).await;
    let (browser, credential) = f.issue().await;
    for case in [
        "disabled",
        "unenrolled",
        "changed",
        "transport",
        "notification",
    ] {
        let mut c = config();
        match case {
            "disabled" => c.realms[0].authentication.mfa.sms_recovery = Default::default(),
            "unenrolled" => c.realms[0]
                .authentication
                .mfa
                .sms_recovery
                .destinations
                .clear(),
            "changed" => {
                c.realms[0]
                    .authentication
                    .mfa
                    .sms_recovery
                    .destinations
                    .insert("alice".into(), "+12025550456".into());
            }
            // Construct the checked configuration first, then remove prerequisites below.
            _ => {}
        }
        let mut s = Arc::try_unwrap(state(repo.clone(), c, Some(f.delivery.clone())))
            .ok()
            .unwrap();
        if case == "transport" {
            s.notification_transport = None;
        }
        if case == "notification" {
            s.config.server.notification = None;
        }
        let s = Arc::new(s);
        let app = crate::auth_routes(&s.paths).with_state(s);
        let response = post(
            &app,
            &path("test", "redeem"),
            Some(&browser),
            credential.clone(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        if case != "changed" {
            let n = f.delivery.requests.lock().unwrap().len();
            assert_eq!(
                post(
                    &app,
                    &path("test", "send"),
                    None,
                    json!({"user_id":"alice"})
                )
                .await
                .status(),
                StatusCode::ACCEPTED
            );
            f.drain().await;
            assert_eq!(f.delivery.requests.lock().unwrap().len(), n);
        }
    }
    // No login endpoint accepts a caller-supplied destination.
    let response = post(
        &f.app,
        &path("test", "send"),
        None,
        json!({"user_id":"alice", "phone":"+12025550999"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        f.state
            .repo
            .list_sessions("test", None)
            .await
            .unwrap()
            .is_empty()
    );
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
async fn delivery_acceptance_and_provider_failure_never_recover_or_leak() {
    let logs = Logs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    async {
        let dir = tempfile::tempdir().unwrap();
        let repo = Arc::new(
            FileRepository::new(dir.path().join("store.json").to_str().unwrap())
                .await
                .unwrap(),
        );
        let f = Fixture::new(repo, config()).await;
        for fail in [false, true] {
            f.delivery.fail.store(fail, Ordering::Relaxed);
            let (browser, credential) = f.issue().await;
            let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
            for secret in [
                PHONE,
                credential["code"].as_str().unwrap(),
                browser.split_once('=').unwrap().1,
                "provider diagnostic",
            ] {
                assert!(!text.contains(secret));
            }
            assert!(
                f.record(&credential)
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
        assert!(
            String::from_utf8(logs.0.lock().unwrap().clone())
                .unwrap()
                .contains("SMS recovery delivery failed")
        );
    }
    .with_subscriber(subscriber)
    .await;
}

#[tokio::test]
async fn session_failure_does_not_revive_recovery_code() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite:{}", dir.path().join("store.db").display());
    let repo = Arc::new(SqlRepository::connect(&url).await.unwrap());
    repo.migrate().await.unwrap();
    let f = Fixture::new(repo.clone(), config()).await;
    let (browser, credential) = f.issue().await;
    let pool = sqlx::AnyPool::connect(&url).await.unwrap();
    sqlx::query("CREATE TRIGGER fail_session BEFORE INSERT ON sessions BEGIN SELECT RAISE(FAIL, 'rejected'); END").execute(&pool).await.unwrap();
    f.reject("test", Some(&browser), credential.clone()).await;
    let spent = f.record(&credential).await;
    assert!(spent.consumed_at_epoch_seconds.is_some());
    sqlx::query("DROP TRIGGER fail_session")
        .execute(&pool)
        .await
        .unwrap();
    f.reject("test", Some(&browser), credential.clone()).await;
    assert_eq!(f.record(&credential).await, spent);
    assert!(repo.list_sessions("test", None).await.unwrap().is_empty());
    pool.close().await;
    drop(f);
    Arc::try_unwrap(repo).ok().unwrap().close().await;
}
