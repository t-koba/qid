//! Real route, durable SQL challenge and strict COSE device-proof tests.
#![allow(clippy::unwrap_used)]
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::Value;
use http_body_util::BodyExt;
use qid_core::{
    config::ServerNotificationConfig, models::*, notification::*, state::SharedState, test_helpers,
    util,
};
use qid_crypto::{ARGON2ID_ALGORITHM, Argon2idParams, LocalSigner, hash_password_with_params};
use qid_storage::{SqlRepository, prelude::*};
use ring::{
    rand::SystemRandom,
    signature::{self, KeyPair},
};
use serde_json::{Value as JsonValue, json};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const BASE: &str = "/api/v1/corp/auth/password";
static SCHEMA_TEMPLATE: tokio::sync::OnceCell<(tempfile::TempDir, PathBuf)> =
    tokio::sync::OnceCell::const_new();

async fn schema_template_path() -> &'static PathBuf {
    let (_, path) = SCHEMA_TEMPLATE
        .get_or_init(|| async {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("schema.db");
            let repo = SqlRepository::connect(&format!("sqlite:{}", path.display()))
                .await
                .unwrap();
            repo.migrate().await.unwrap();
            repo.close().await;
            for suffix in ["-wal", "-shm", "-journal"] {
                let mut sidecar = path.as_os_str().to_os_string();
                sidecar.push(suffix);
                assert!(
                    !PathBuf::from(sidecar).exists(),
                    "schema template has a sidecar after closing the pool: {}",
                    path.display()
                );
            }
            (dir, path)
        })
        .await;
    path
}
const PASSWORD: &str = "correct-password-123!";
#[derive(Default)]
struct Delivery {
    requests: Mutex<Vec<NotificationRequest>>,
    fail: std::sync::atomic::AtomicBool,
    hang: bool,
}
#[async_trait::async_trait]
impl NotificationTransport for Delivery {
    async fn send(&self, req: NotificationRequest) -> Result<NotificationResponse, String> {
        self.requests.lock().unwrap().push(req);
        if self.hang {
            std::future::pending::<()>().await;
        }
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("sensitive provider diagnostic must not reach the browser".into());
        }
        Ok(NotificationResponse {
            status: 202,
            sent: true,
            provider_message_id: None,
        })
    }
}
struct Fixture {
    app: Router,
    state: Arc<SharedState<SqlRepository>>,
    delivery: Arc<Delivery>,
    url: String,
    _dir: tempfile::TempDir,
}
async fn fixture(enabled: bool, provider: bool, fail: bool) -> Fixture {
    fixture_with_options(enabled, provider, fail, false).await
}
async fn fixture_with_options(enabled: bool, provider: bool, fail: bool, hang: bool) -> Fixture {
    fixture_policy(enabled, provider, fail, hang, 2, 5, 30).await
}
async fn fixture_policy(
    enabled: bool,
    provider: bool,
    fail: bool,
    hang: bool,
    attempts: u32,
    sends: u32,
    cooldown: u64,
) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    // Storage tests cover fresh migrations; copying keeps each push case isolated
    // without rerunning the full migration set for every fixture.
    std::fs::copy(schema_template_path().await, &db_path).unwrap();
    let url = format!("sqlite:{}", db_path.display());
    let repo = Arc::new(SqlRepository::connect(&url).await.unwrap());
    repo.create_realm(
        &"tenant-1".into(),
        &"corp".into(),
        "https://login.example.com",
        Some("Corp"),
    )
    .await
    .unwrap();
    repo.create_user(&User {
        id: "user-1".into(),
        realm_id: "corp".into(),
        email: Some("alice@example.com".into()),
        email_verified: true,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();
    repo.store_password_credential(&PasswordCredential {
        user_id: "user-1".into(),
        hash: hash_password_with_params(PASSWORD, &Argon2idParams::new(8, 1, 1)).unwrap(),
        algorithm: ARGON2ID_ALGORITHM.into(),
    })
    .await
    .unwrap();
    let mut config = test_helpers::test_config();
    let realm = &mut config.realms[0];
    realm.id = "corp".into();
    realm.authentication.password.argon2id.memory_kib = 8;
    realm.authentication.password.argon2id.time_cost = 1;
    realm.authentication.password.argon2id.parallelism = 1;
    realm.authentication.mfa.push.enabled = enabled;
    realm.authentication.mfa.totp.enabled = true;
    realm.authentication.mfa.push.max_attempts = attempts;
    realm.authentication.mfa.push.resend_cooldown_seconds = cooldown;
    realm.authentication.mfa.push.max_issuances_per_window = sends;
    if provider {
        config.server.notification = Some(ServerNotificationConfig {
            provider: "https://delivery.example.com".into(),
            timeout_seconds: if hang { 1 } else { 5 },
            max_concurrent_deliveries: 1,
        });
    }
    let delivery = Arc::new(Delivery {
        fail: fail.into(),
        hang,
        ..Delivery::default()
    });
    let mut state = SharedState::new(
        config,
        repo,
        Arc::new(LocalSigner::from_secret("test", b"test-secret")),
        json!({"keys":[]}),
    )
    .unwrap();
    if provider {
        state = state.with_notification_transport(delivery.clone());
    }
    let state = Arc::new(state);
    let app = qid_session::auth_routes(&state.paths).with_state(state.clone());
    Fixture {
        app,
        state,
        delivery,
        url,
        _dir: dir,
    }
}
fn device_key() -> signature::EcdsaKeyPair {
    let rng = SystemRandom::new();
    let pkcs8 =
        signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .unwrap();
    signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        pkcs8.as_ref(),
        &rng,
    )
    .unwrap()
}
fn sign(key: &signature::EcdsaKeyPair, payload: Vec<u8>) -> Vec<u8> {
    let protected = vec![0xa1, 1, 0x26];
    let mut signed = Vec::new();
    ciborium::into_writer(
        &(
            "Signature1",
            Value::Bytes(protected.clone()),
            Value::Bytes(vec![]),
            Value::Bytes(payload.clone()),
        ),
        &mut signed,
    )
    .unwrap();
    let signature = key.sign(&SystemRandom::new(), &signed).unwrap();
    let mut proof = Vec::new();
    ciborium::into_writer(
        &Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(vec![]),
            Value::Bytes(payload),
            Value::Bytes(signature.as_ref().to_vec()),
        ]),
        &mut proof,
    )
    .unwrap();
    proof
}
async fn enroll(f: &Fixture) -> signature::EcdsaKeyPair {
    let key = device_key();
    let point = key.public_key().as_ref();
    let nonce = URL_SAFE_NO_PAD.encode([1; 32]);
    let now = util::now_seconds();
    let c = PushRegistrationChallenge {
        authenticator: PushAuthenticator {
            id: "device".into(),
            realm_id: "corp".into(),
            user_id: "user-1".into(),
            destination: "account-owned-destination".into(),
            device_name: "Test Phone".into(),
            device_platform: "android".into(),
            public_jwk: PushPublicJwk::EC {
                crv: "P-256".into(),
                x: URL_SAFE_NO_PAD.encode(&point[1..33]),
                y: URL_SAFE_NO_PAD.encode(&point[33..]),
            },
            created_at: now,
            revoked_at: None,
        },
        nonce_verifier: util::sha256_hex(nonce.as_bytes()),
        expires_at: now + 300,
        max_attempts: 2,
        attempt_count: 0,
    };
    assert!(
        f.state
            .repo
            .try_issue_push_registration(&c, 5, 3600)
            .await
            .unwrap()
    );
    let proof = sign(
        &key,
        qid_mfa::push::registration_payload(&c, &nonce).unwrap(),
    );
    qid_mfa::push::verify_registration(&c, &nonce, &proof).unwrap();
    assert!(
        f.state
            .repo
            .attempt_push_registration(&c, true, util::now_seconds())
            .await
            .unwrap()
    );
    key
}
async fn post(f: &Fixture, path: &str, cookie: Option<&str>, body: JsonValue) -> Response {
    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(cookie) = cookie {
        req = req.header("cookie", cookie);
    }
    f.app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}
async fn body(response: Response) -> JsonValue {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
async fn login(f: &Fixture) -> Response {
    post(
        f,
        BASE,
        None,
        json!({"email":"alice@example.com", "password":PASSWORD}),
    )
    .await
}
async fn no_sessions(f: &Fixture) {
    assert!(
        f.state
            .repo
            .list_sessions("corp", Some("user-1"))
            .await
            .unwrap()
            .is_empty()
    );
}
async fn pending(f: &Fixture) -> (String, NotificationRequest) {
    let response = login(f).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    let cookie = response.headers()["set-cookie"].to_str().unwrap();
    for protection in [
        "HttpOnly",
        "Secure",
        "SameSite=Strict",
        "Path=/",
        "Max-Age=",
    ] {
        assert!(cookie.contains(protection));
    }
    assert!(cookie.starts_with("__Host-qid-password-push="));
    let cookie = cookie.split(';').next().unwrap().to_string();
    let json = body(response).await;
    assert_eq!(json["challenge"], "push_required");
    for secret in [
        "session",
        "nonce",
        "proof",
        "browser_binding_verifier",
        "destination",
    ] {
        assert!(json.get(secret).is_none());
    }
    no_sessions(f).await;
    let delivery = f.delivery.requests.lock().unwrap().last().unwrap().clone();
    assert_eq!(delivery.channel, NotificationChannel::Push);
    assert_eq!(delivery.recipient, "account-owned-destination");
    assert_eq!(json["challenge_id"], delivery.data_json["challenge_id"]);
    assert_eq!(
        json["transaction_number"],
        delivery.data_json["transaction_number"]
    );
    let number = json["transaction_number"].as_str().unwrap();
    assert_eq!(number.len(), 6);
    assert!(number.bytes().all(|b| b.is_ascii_digit()));
    let c = challenge(f, &delivery).await;
    assert_ne!(
        c.nonce_verifier,
        delivery.data_json["nonce"].as_str().unwrap()
    );
    assert!(c.decision.is_none()); // delivery acceptance is not approval
    (cookie, delivery)
}
async fn challenge(f: &Fixture, d: &NotificationRequest) -> PushLoginChallenge {
    f.state
        .repo
        .get_push_login(
            &"corp".into(),
            "user-1",
            d.data_json["challenge_id"].as_str().unwrap(),
        )
        .await
        .unwrap()
        .unwrap()
}
async fn decision_body(
    f: &Fixture,
    key: &signature::EcdsaKeyPair,
    d: &NotificationRequest,
    decision: PushDecision,
) -> JsonValue {
    let c = challenge(f, d).await;
    let nonce = d.data_json["nonce"].as_str().unwrap();
    let proof = sign(
        key,
        qid_mfa::push::login_payload(&c, nonce, decision).unwrap(),
    );
    json!({"realm_id":"corp", "user_id":"user-1", "challenge_id": c.id, "nonce": nonce, "decision": decision, "proof": URL_SAFE_NO_PAD.encode(proof)})
}
async fn decide(
    f: &Fixture,
    key: &signature::EcdsaKeyPair,
    d: &NotificationRequest,
    decision: PushDecision,
) -> Response {
    post(
        f,
        &format!("{BASE}/push/decision"),
        None,
        decision_body(f, key, d, decision).await,
    )
    .await
}
fn completion(d: &NotificationRequest) -> JsonValue {
    json!({"user_id":"user-1", "challenge_id": d.data_json["challenge_id"]})
}
async fn finish(f: &Fixture, cookie: Option<&str>, d: &NotificationRequest) -> Response {
    post(f, &format!("{BASE}/push/complete"), cookie, completion(d)).await
}
fn refused(r: &Response) {
    assert!(r.status().is_client_error(), "{}", r.status());
    assert!(r.headers().get("set-cookie").is_none());
    assert!(r.headers().get("location").is_none());
}

#[tokio::test]
async fn approval_requires_the_same_browser_then_rotates_session_and_is_one_use() {
    let f = fixture(true, true, false).await;
    let key = enroll(&f).await;
    let (cookie, d) = pending(&f).await;
    refused(&finish(&f, Some(&cookie), &d).await);
    assert_eq!(
        decide(&f, &key, &d, PushDecision::Approve).await.status(),
        StatusCode::NO_CONTENT
    );
    no_sessions(&f).await;
    refused(&finish(&f, None, &d).await);
    refused(
        &finish(
            &f,
            Some(&format!(
                "__Host-qid-password-push={}",
                URL_SAFE_NO_PAD.encode([4; 32])
            )),
            &d,
        )
        .await,
    );
    let mut wrong_owner = completion(&d);
    wrong_owner["user_id"] = json!("other-user");
    refused(
        &post(
            &f,
            &format!("{BASE}/push/complete"),
            Some(&cookie),
            wrong_owner,
        )
        .await,
    );
    let manager = qid_session::browser::SessionManager::new(f.state.repo.clone(), 30, 24);
    let old = manager
        .create("corp", "user-1", "urn:qid:acr:password", &["pwd".into()])
        .await
        .unwrap();
    let both = format!(
        "{cookie}; {}={}",
        f.state.plan.realms[0].browser_session.cookie_name, old.id
    );
    let response = finish(&f, Some(&both), &d).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies: Vec<_> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    assert_eq!(cookies.len(), 2);
    assert!(
        cookies
            .iter()
            .any(|v| v.starts_with("__Host-qid-password-push=;") && v.contains("Max-Age=0"))
    );
    let json = body(response).await;
    let sid = json["session"].as_str().unwrap();
    assert_ne!(sid, old.id);
    let session = f.state.repo.get_session(sid).await.unwrap().unwrap();
    assert_eq!(session.amr, ["pwd", "push"]);
    assert_eq!(session.acr.as_deref(), Some("urn:qid:acr:password"));
    assert_eq!(session.user_id, "user-1");
    assert!(session.auth_time >= challenge(&f, &d).await.created_at);
    assert!(
        f.state
            .repo
            .get_session(&old.id)
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    assert!(
        cookies
            .iter()
            .any(|v| v.contains(sid) && v.contains("HttpOnly; Secure; Path=/; SameSite="))
    );
    refused(&finish(&f, Some(&cookie), &d).await);
    refused(&decide(&f, &key, &d, PushDecision::Approve).await);
}

#[tokio::test]
async fn signed_denial_and_invalid_device_proofs_never_create_sessions() {
    let f = fixture(true, true, false).await;
    let key = enroll(&f).await;
    let (cookie, d) = pending(&f).await;
    let mut substituted = decision_body(&f, &key, &d, PushDecision::Deny).await;
    substituted["decision"] = json!("approve");
    refused(&post(&f, &format!("{BASE}/push/decision"), None, substituted).await);
    assert_eq!(challenge(&f, &d).await.attempt_count, 1);
    assert_eq!(
        decide(&f, &key, &d, PushDecision::Deny).await.status(),
        StatusCode::NO_CONTENT
    );
    refused(&finish(&f, Some(&cookie), &d).await);
    refused(&decide(&f, &key, &d, PushDecision::Approve).await);
    no_sessions(&f).await;
    let (cookie, d) = pending(&f).await;
    let wrong_key = device_key();
    for _ in 0..2 {
        refused(&decide(&f, &wrong_key, &d, PushDecision::Approve).await);
    }
    assert_eq!(challenge(&f, &d).await.attempt_count, 2);
    refused(&decide(&f, &key, &d, PushDecision::Approve).await);
    refused(&finish(&f, Some(&cookie), &d).await);
    refused(&resend(&f, Some(&cookie), &d).await);
    no_sessions(&f).await;
}

#[tokio::test]
async fn approved_completion_is_atomic_under_concurrency() {
    let f = fixture(true, true, false).await;
    let key = enroll(&f).await;
    let (cookie, d) = pending(&f).await;
    assert_eq!(
        decide(&f, &key, &d, PushDecision::Approve).await.status(),
        StatusCode::NO_CONTENT
    );
    let (a, b) = tokio::join!(finish(&f, Some(&cookie), &d), finish(&f, Some(&cookie), &d));
    assert_eq!(
        usize::from(a.status() == StatusCode::OK) + usize::from(b.status() == StatusCode::OK),
        1
    );
    assert_eq!(
        f.state
            .repo
            .list_sessions("corp", Some("user-1"))
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn revocation_invalidates_pending_and_approved_logins() {
    for approve in [false, true] {
        let f = fixture(true, true, false).await;
        let key = enroll(&f).await;
        let (cookie, d) = pending(&f).await;
        if approve {
            assert_eq!(
                decide(&f, &key, &d, PushDecision::Approve).await.status(),
                StatusCode::NO_CONTENT
            );
        }
        assert!(
            f.state
                .repo
                .revoke_push_authenticator(&"corp".into(), "user-1", "device", util::now_seconds())
                .await
                .unwrap()
        );
        refused(&decide(&f, &key, &d, PushDecision::Approve).await);
        refused(&finish(&f, Some(&cookie), &d).await);
        refused(&resend(&f, Some(&cookie), &d).await);
        no_sessions(&f).await;
    }
}

#[tokio::test]
async fn expired_approved_challenge_is_rejected_without_sleeping() {
    let f = fixture(true, true, false).await;
    let key = enroll(&f).await;
    let (cookie, d) = pending(&f).await;
    assert_eq!(
        decide(&f, &key, &d, PushDecision::Approve).await.status(),
        StatusCode::NO_CONTENT
    );
    // Move an otherwise-valid approved record and its SQL lifecycle metadata
    // into the past. Exercise expiry, not corrupt/mismatched-record rejection.
    let mut c = challenge(&f, &d).await;
    c.created_at -= 1000;
    c.expires_at -= 1000;
    c.decided_at = c.decided_at.map(|t| t - 1000);
    let pool = sqlx::AnyPool::connect(&f.url).await.unwrap();
    sqlx::query("UPDATE push_login_challenges SET issued_at = issued_at - 1000, expires_at = $1, record_json = $2 WHERE id = $3")
        .bind(c.expires_at as i64).bind(serde_json::to_string(&c).unwrap()).bind(&c.id).execute(&pool).await.unwrap();
    pool.close().await;
    assert_eq!(challenge(&f, &d).await, c);
    assert!(util::now_seconds() >= c.expires_at);
    refused(&finish(&f, Some(&cookie), &d).await);
    refused(&resend(&f, Some(&cookie), &d).await);
    no_sessions(&f).await;
}

#[tokio::test]
async fn expired_pending_challenge_cannot_be_resent() {
    let f = fixture(true, true, false).await;
    enroll(&f).await;
    let (cookie, delivery) = pending(&f).await;
    let mut c = challenge(&f, &delivery).await;
    let mut a = f
        .state
        .repo
        .get_push_authenticator(&"corp".into(), "user-1", "device")
        .await
        .unwrap()
        .unwrap();
    // Move both trusted timestamps together so ownership remains valid while
    // the pending challenge is expired without adding wall-clock test delay.
    c.created_at -= 1000;
    c.expires_at = c.created_at + 300;
    a.created_at -= 1000;
    let pool = sqlx::AnyPool::connect(&f.url).await.unwrap();
    sqlx::query("UPDATE push_authenticators SET issued_at = issued_at - 1000, record_json = $1 WHERE id = $2")
        .bind(serde_json::to_string(&PushAuthenticatorRecord::Enrolled(a)).unwrap())
        .bind("device")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE push_login_challenges SET issued_at = issued_at - 1000, expires_at = $1, record_json = $2 WHERE id = $3")
        .bind(c.expires_at as i64)
        .bind(serde_json::to_string(&c).unwrap())
        .bind(&c.id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    assert!(util::now_seconds() >= c.expires_at);
    refused(&resend(&f, Some(&cookie), &delivery).await);
    assert_eq!(challenge(&f, &delivery).await, c);
    assert_eq!(f.delivery.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn disabled_or_missing_or_failed_delivery_fails_closed_for_registered_accounts() {
    for (enabled, provider, fail) in [
        (false, true, false),
        (true, false, false),
        (true, true, true),
    ] {
        let f = fixture(enabled, provider, fail).await;
        enroll(&f).await;
        let response = login(&f).await;
        refused(&response);
        let json = body(response).await.to_string();
        assert!(!json.contains("sensitive provider diagnostic"));
        assert!(!json.contains("nonce"));
        no_sessions(&f).await;
    }
}

#[tokio::test]
async fn no_registration_keeps_ordinary_password_login_without_push_configuration() {
    let f = fixture(false, false, false).await;
    let response = login(&f).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("HttpOnly; Secure")
    );
    let json = body(response).await;
    let sid = json["session"].as_str().unwrap();
    assert_eq!(
        f.state.repo.get_session(sid).await.unwrap().unwrap().amr,
        ["pwd"]
    );
    assert!(f.delivery.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn browser_and_transaction_substitution_does_not_spend_approval() {
    let f = fixture(true, true, false).await;
    let key = enroll(&f).await;
    let (cookie_a, a) = pending(&f).await;
    let (cookie_b, b) = pending(&f).await;
    assert_eq!(
        decide(&f, &key, &a, PushDecision::Approve).await.status(),
        StatusCode::NO_CONTENT
    );
    refused(&finish(&f, Some(&cookie_b), &a).await);
    refused(&finish(&f, Some(&cookie_a), &b).await);
    // An OIDC-style (undomained) verifier cannot redeem a direct-login challenge.
    let binding = cookie_a.split_once('=').unwrap().1;
    let c = challenge(&f, &a).await;
    assert!(
        qid_session::push::complete_password(&f.state, &c, &util::sha256_hex(binding.as_bytes()))
            .await
            .is_err()
    );
    assert_eq!(
        finish(&f, Some(&cookie_a), &a).await.status(),
        StatusCode::OK
    );
    refused(&finish(&f, Some(&cookie_b), &b).await);
    assert!(challenge(&f, &b).await.consumed_at.is_none());
}

fn reconfigure(
    f: &mut Fixture,
    edit: impl FnOnce(&mut qid_core::config::QidConfig),
    transport: bool,
) {
    let mut config = f.state.config.clone();
    edit(&mut config);
    let mut state = SharedState::new(
        config,
        f.state.repo.clone(),
        Arc::new(LocalSigner::from_secret("test", b"test-secret")),
        json!({"keys":[]}),
    )
    .unwrap();
    if transport {
        state = state.with_notification_transport(f.delivery.clone());
    }
    let state = Arc::new(state);
    f.app = qid_session::auth_routes(&state.paths).with_state(state.clone());
    f.state = state;
}

#[tokio::test]
async fn configured_notification_without_a_runtime_transport_is_not_a_password_fallback() {
    let mut f = fixture(true, true, false).await;
    enroll(&f).await;
    reconfigure(&mut f, |_| {}, false);
    refused(&login(&f).await);
    assert!(f.delivery.requests.lock().unwrap().is_empty());
    no_sessions(&f).await;
}

#[tokio::test]
async fn policy_and_provider_are_rechecked_after_signed_approval() {
    for change in 0..3 {
        let mut f = fixture(true, true, false).await;
        let key = enroll(&f).await;
        let (cookie, d) = pending(&f).await;
        assert_eq!(
            decide(&f, &key, &d, PushDecision::Approve).await.status(),
            StatusCode::NO_CONTENT
        );
        reconfigure(
            &mut f,
            |config| match change {
                0 => config.realms[0].authentication.mfa.push.enabled = false,
                1 => config.server.notification = None,
                _ => {}
            },
            change != 2,
        );
        refused(&finish(&f, Some(&cookie), &d).await);
        assert!(challenge(&f, &d).await.consumed_at.is_none());
        no_sessions(&f).await;
    }
}

#[tokio::test]
async fn direct_push_uses_durable_issuance_limits_after_password_success() {
    let f = fixture(true, true, false).await;
    enroll(&f).await;
    for _ in 0..5 {
        pending(&f).await;
    }
    refused(&login(&f).await);
    assert_eq!(f.delivery.requests.lock().unwrap().len(), 5);
    no_sessions(&f).await;
}

#[tokio::test]
async fn request_methods_and_wrong_realms_cannot_substitute_for_device_proof() {
    let f = fixture(true, true, false).await;
    let key = enroll(&f).await;
    let (cookie, d) = pending(&f).await;
    let mut req = decision_body(&f, &key, &d, PushDecision::Approve).await;
    req["realm_id"] = json!("other-realm");
    refused(&post(&f, &format!("{BASE}/push/decision"), None, req).await);
    assert_eq!(challenge(&f, &d).await.attempt_count, 0);
    let mut req = completion(&d);
    req["amr"] = json!(["pwd", "push"]);
    refused(&post(&f, &format!("{BASE}/push/complete"), Some(&cookie), req).await);
    let wrong_path = BASE.replace("corp", "other-realm");
    refused(
        &post(
            &f,
            &format!("{wrong_path}/push/complete"),
            Some(&cookie),
            completion(&d),
        )
        .await,
    );
    no_sessions(&f).await;
}

async fn get(f: &Fixture, path: &str, cookie: Option<&str>) -> Response {
    let mut req = Request::builder().method("GET").uri(path);
    if let Some(cookie) = cookie {
        req = req.header("cookie", cookie);
    }
    f.app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
}
async fn account_cookie(f: &Fixture, user: &str) -> String {
    if f.state.repo.get_user_by_id(user).await.unwrap().is_none() {
        f.state
            .repo
            .create_user(&User {
                id: user.into(),
                realm_id: "corp".into(),
                email: None,
                email_verified: false,
                display_name: None,
                failed_login_attempts: 0,
                locked_until: None,
                org: None,
            })
            .await
            .unwrap();
    }
    let now = util::now_seconds();
    let sid = format!("sid_{}", ulid::Ulid::new());
    f.state
        .repo
        .create_session(&Session {
            id: sid.clone(),
            user_id: user.into(),
            realm_id: "corp".into(),
            auth_time: now,
            acr: None,
            amr: vec!["pwd".into()],
            idle_expires_at: now + 1000,
            absolute_expires_at: now + 2000,
            revoked: false,
            created_at: now,
            cnf: None,
        })
        .await
        .unwrap();
    format!(
        "{}={sid}",
        f.state.plan.realms[0].browser_session.cookie_name
    )
}
#[tokio::test]
async fn device_list_is_owner_scoped_and_redacted() {
    let f = fixture(true, true, false).await;
    enroll(&f).await;
    let cookie = account_cookie(&f, "user-1").await;
    let response = get(&f, &format!("{BASE}/push/registrations"), Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    let json = body(response).await;
    assert_eq!(json.as_object().unwrap().len(), 1);
    let devices = json["authenticators"].as_array().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["registration_id"], "device");
    assert_eq!(devices[0]["device_name"], "Test Phone");
    assert_eq!(devices[0]["device_platform"], "android");
    assert_eq!(devices[0]["status"], "active");
    assert!(devices[0].get("created_at").unwrap().is_number());
    assert_eq!(devices[0].as_object().unwrap().len(), 5);
    for secret in [
        "destination",
        "public_jwk",
        "nonce",
        "verifier",
        "account-owned-destination",
    ] {
        assert!(
            !json.to_string().contains(secret),
            "secret in list response"
        );
    }
    f.state
        .repo
        .revoke_push_authenticator(&"corp".into(), "user-1", "device", util::now_seconds())
        .await
        .unwrap();
    let json = body(get(&f, &format!("{BASE}/push/registrations"), Some(&cookie)).await).await;
    assert_eq!(json["authenticators"][0]["status"], "revoked");
    assert_eq!(json["authenticators"][0]["device_name"], "Test Phone");
    let peer = account_cookie(&f, "user-2").await;
    let json = body(get(&f, &format!("{BASE}/push/registrations"), Some(&peer)).await).await;
    assert!(json["authenticators"].as_array().unwrap().is_empty());
    assert_eq!(
        get(&f, &format!("{BASE}/push/registrations"), None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn device_list_stays_available_without_push_delivery() {
    let f = fixture(false, false, false).await;
    enroll(&f).await;
    let cookie = account_cookie(&f, "user-1").await;
    let response = get(&f, &format!("{BASE}/push/registrations"), Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body(response).await;
    assert_eq!(json["authenticators"].as_array().unwrap().len(), 1);
}
#[tokio::test]
async fn enrollment_start_rejects_invalid_device_metadata() {
    let f = fixture(true, true, false).await;
    let response = login(&f).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(";")
        .next()
        .unwrap()
        .to_string();
    let sessions = f
        .state
        .repo
        .list_sessions("corp", Some("user-1"))
        .await
        .unwrap();
    assert_eq!(sessions.len(), 1);
    let key = device_key();
    let point = key.public_key().as_ref();
    let jwk = json!({
        "kty": "EC", "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
        "y": URL_SAFE_NO_PAD.encode(&point[33..]),
    });
    for (name, platform) in [
        ("", "android"),
        ("   ", "android"),
        ("bad-name", ""),
        (" Test Phone", "android"),
        ("bad\u{7}name", "android"),
        (
            "ok",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        ),
    ] {
        let response = post(
            &f,
            &format!("{BASE}/push/registrations/start"),
            Some(&cookie),
            json!({"destination": "account-owned-destination", "device_name": name, "device_platform": platform, "public_jwk": jwk}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let after = f
        .state
        .repo
        .list_sessions("corp", Some("user-1"))
        .await
        .unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].id, sessions[0].id);
}

#[path = "support/push_enrollment.rs"]
mod enrollment;

async fn resend(f: &Fixture, cookie: Option<&str>, d: &NotificationRequest) -> Response {
    post(f, &format!("{BASE}/push/resend"), cookie, completion(d)).await
}
#[tokio::test]
async fn resend_rotates_only_nonce_and_requires_same_browser_then_signed_completion() {
    let f = fixture_policy(true, true, false, false, 5, 5, 1).await;
    let key = enroll(&f).await;
    let (cookie, old) = pending(&f).await;
    let old_approve = decision_body(&f, &key, &old, PushDecision::Approve).await;
    let old_deny = decision_body(&f, &key, &old, PushDecision::Deny).await;
    let before = challenge(&f, &old).await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    refused(&resend(&f, None, &old).await);
    refused(&resend(&f, Some("__Host-qid-password-push=invalid"), &old).await);
    let other = cookie.replace("password-push", "oidc-push");
    refused(&resend(&f, Some(&other), &old).await);
    for field in ["user_id", "challenge_id"] {
        let mut wrong = completion(&old);
        wrong[field] = json!("wrong");
        refused(&post(&f, &format!("{BASE}/push/resend"), Some(&cookie), wrong).await);
    }
    let response = resend(&f, Some(&cookie), &old).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let response = body(response).await;
    let new = f.delivery.requests.lock().unwrap().last().unwrap().clone();
    assert_eq!(
        response["transaction_number"],
        old.data_json["transaction_number"]
    );
    assert_eq!(
        response["transaction_number"],
        new.data_json["transaction_number"]
    );
    assert_eq!(response["challenge_id"], old.data_json["challenge_id"]);
    assert_ne!(new.data_json["nonce"], old.data_json["nonce"]);
    let after = challenge(&f, &new).await;
    assert_eq!(after.created_at, before.created_at);
    assert_eq!(after.expires_at, before.expires_at);
    assert_eq!(after.attempt_count, before.attempt_count);
    assert_eq!(
        after.browser_binding_verifier,
        before.browser_binding_verifier
    );
    assert_eq!(after.resend_admitted_at.len(), 1);
    refused(&post(&f, &format!("{BASE}/push/decision"), None, old_approve).await);
    refused(&post(&f, &format!("{BASE}/push/decision"), None, old_deny).await);
    no_sessions(&f).await;
    // Display context cannot replace the signed nonce, even with a real proof.
    let mut number_as_nonce = decision_body(&f, &key, &new, PushDecision::Approve).await;
    number_as_nonce["nonce"] = new.data_json["transaction_number"].clone();
    refused(&post(&f, &format!("{BASE}/push/decision"), None, number_as_nonce).await);
    assert_eq!(
        decide(&f, &key, &new, PushDecision::Approve).await.status(),
        StatusCode::NO_CONTENT
    );
    refused(&resend(&f, Some(&cookie), &new).await);
    assert_eq!(
        finish(&f, Some(&cookie), &new).await.status(),
        StatusCode::OK
    );
    refused(&finish(&f, Some(&cookie), &new).await);
}
#[tokio::test]
async fn failed_resend_rotates_durably_and_spends_the_unified_send_budget() {
    let f = fixture_policy(true, true, false, false, 5, 2, 1).await;
    let key = enroll(&f).await;
    let (cookie, old) = pending(&f).await;
    let old_proof = decision_body(&f, &key, &old, PushDecision::Approve).await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    f.delivery
        .fail
        .store(true, std::sync::atomic::Ordering::SeqCst);
    refused(&resend(&f, Some(&cookie), &old).await);
    assert_eq!(f.delivery.requests.lock().unwrap().len(), 2);
    let c = challenge(&f, &old).await;
    assert_eq!(c.resend_admitted_at.len(), 1);
    assert_ne!(
        c.nonce_verifier,
        util::sha256_hex(old.data_json["nonce"].as_str().unwrap().as_bytes())
    );
    refused(&post(&f, &format!("{BASE}/push/decision"), None, old_proof).await);
    f.delivery
        .fail
        .store(false, std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    refused(&resend(&f, Some(&cookie), &old).await);
    refused(&login(&f).await); // initial sends use the same exhausted quota
    assert_eq!(f.delivery.requests.lock().unwrap().len(), 2);
    no_sessions(&f).await;
}

#[tokio::test]
async fn resend_cooldown_refuses_without_sending_or_mutating() {
    let f = fixture_policy(true, true, false, false, 5, 5, 600).await;
    enroll(&f).await;
    let (cookie, d) = pending(&f).await;
    let before = challenge(&f, &d).await;
    refused(&resend(&f, Some(&cookie), &d).await);
    assert_eq!(challenge(&f, &d).await, before);
    assert_eq!(f.delivery.requests.lock().unwrap().len(), 1);
}
