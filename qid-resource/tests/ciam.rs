use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use qid_core::{models::User, state::SharedState, tenant::RealmId, test_helpers};
use qid_crypto::LocalSigner;
use qid_storage::{SqlRepository, prelude::*};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU16, Ordering};
use tower::ServiceExt;

static DB_SEQ: AtomicU16 = AtomicU16::new(0);

fn db_url() -> String {
    let dir = std::env::temp_dir().join("qid_test_resource_ciam");
    std::fs::create_dir_all(&dir).ok();
    static CLEANED: OnceLock<()> = OnceLock::new();
    CLEANED.get_or_init(|| {
        for entry in std::fs::read_dir(&dir).ok().into_iter().flatten().flatten() {
            let name = entry.file_name();
            let s = name.to_string_lossy();
            if s.starts_with("test_") && s.ends_with(".db") {
                std::fs::remove_file(entry.path()).ok();
            }
        }
    });
    let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("test_{n}.db"));
    format!("sqlite:{}", path.display())
}

async fn setup() -> (axum::Router, Arc<SharedState<SqlRepository>>) {
    let config = test_helpers::test_config();
    let repo = Arc::new(SqlRepository::connect(&db_url()).await.unwrap());
    repo.migrate().await.unwrap();
    repo.create_realm(
        &"tenant-1".into(),
        &"test".into(),
        "https://id.example.com",
        Some("Test Realm"),
    )
    .await
    .unwrap();
    repo.create_user(&User {
        id: "user-ciam".to_string(),
        realm_id: "test".to_string(),
        email: Some("ciam@example.com".to_string()),
        email_verified: false,
        display_name: Some("CIAM User".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();
    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    let state = Arc::new(SharedState::new(config, repo, signer, serde_json::json!({})).unwrap());
    let app = qid_resource::resource_routes(&state.paths).with_state(state.clone());
    (app, state)
}

async fn add_session(state: &Arc<SharedState<SqlRepository>>, user_id: &str) -> String {
    let cookie_name = &state.config.realms[0].sessions.browser.cookie_name;
    let now = qid_core::util::now_seconds();
    let session = qid_core::models::Session {
        id: format!("ciam-session-{user_id}"),
        realm_id: "test".to_string(),
        user_id: user_id.to_string(),
        auth_time: now,
        acr: None,
        amr: Vec::new(),
        absolute_expires_at: now + 3600,
        idle_expires_at: now + 900,
        revoked: false,
        created_at: now,
        cnf: None,
    };
    state.repo.create_session(&session).await.unwrap();
    format!("{}={}", cookie_name, session.id)
}

fn with_cookie(req: Request<Body>, cookie: &str) -> Request<Body> {
    let (parts, body) = req.into_parts();
    let mut parts = parts;
    parts
        .headers
        .insert(axum::http::header::COOKIE, cookie.parse().unwrap());
    Request::from_parts(parts, body)
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn ciam_consent_grant_drives_evaluation_and_privacy_dashboard() {
    let (app, state) = setup().await;
    let cookie = add_session(&state, "user-ciam").await;
    let grant_request = with_cookie(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/test/ciam/consent/grants")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{
                    "id":"consent-route-1",
                    "realm_id":"ignored",
                    "user_id":"user-ciam",
                    "client_id":"client-ciam",
                    "granted_claims":["email"],
                    "terms_version":"2026-06",
                    "granted_at_epoch_seconds":1800000000,
                    "revoked":false
                }"#,
            ))
            .unwrap(),
        &cookie,
    );
    let grant_response = app.clone().oneshot(grant_request).await.unwrap();
    assert_eq!(grant_response.status(), StatusCode::CREATED);

    let evaluate_request = with_cookie(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/test/ciam/consent/evaluate")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{
                    "user_id":"user-ciam",
                    "client_id":"client-ciam",
                    "requested_claims":["sub","email","phone"],
                    "granted_claims":[],
                    "sensitive_claims":["email","phone"]
                }"#,
            ))
            .unwrap(),
        &cookie,
    );
    let evaluate_response = app.clone().oneshot(evaluate_request).await.unwrap();
    assert_eq!(evaluate_response.status(), StatusCode::OK);
    let evaluated = json(evaluate_response).await;
    assert_eq!(
        evaluated["evaluation"]["released_claims"],
        serde_json::json!(["email", "sub"])
    );
    assert_eq!(
        evaluated["evaluation"]["denied_claims"],
        serde_json::json!(["phone"])
    );

    let dashboard_request = with_cookie(
        Request::builder()
            .method(Method::GET)
            .uri("/api/v1/test/ciam/privacy/user-ciam")
            .body(Body::empty())
            .unwrap(),
        &cookie,
    );
    let dashboard_response = app.clone().oneshot(dashboard_request).await.unwrap();
    assert_eq!(dashboard_response.status(), StatusCode::OK);
    let dashboard = json(dashboard_response).await;
    assert_eq!(dashboard["consents"][0]["id"], "consent-route-1");
    assert_eq!(dashboard["identity_links"], serde_json::json!([]));
}

#[tokio::test]
async fn ciam_identity_links_are_persisted_lookupable_and_audited() {
    let (app, state) = setup().await;
    let cookie = add_session(&state, "user-ciam").await;
    let create_request = with_cookie(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/test/ciam/identity-links")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{
                    "id":"link-route-1",
                    "realm_id":"ignored",
                    "user_id":"user-ciam",
                    "provider":"google",
                    "external_subject":"google-subject-1",
                    "external_email":"social@example.com",
                    "profile_json":{"name":"Social User"},
                    "linked_at_epoch_seconds":1800000400,
                    "verified":true
                }"#,
            ))
            .unwrap(),
        &cookie,
    );
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created = json(create_response).await;
    assert_eq!(created["realm_id"], "test");

    let list_request = with_cookie(
        Request::builder()
            .method(Method::GET)
            .uri("/api/v1/test/ciam/users/user-ciam/identity-links")
            .body(Body::empty())
            .unwrap(),
        &cookie,
    );
    let list_response = app.clone().oneshot(list_request).await.unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let links = json(list_response).await;
    assert_eq!(links[0]["provider"], "google");

    let lookup_request = with_cookie(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/test/ciam/identity-links/lookup")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{
                    "provider":"google",
                    "external_subject":"google-subject-1"
                }"#,
            ))
            .unwrap(),
        &cookie,
    );
    let lookup_response = app.clone().oneshot(lookup_request).await.unwrap();
    assert_eq!(lookup_response.status(), StatusCode::OK);
    let lookup = json(lookup_response).await;
    assert_eq!(lookup["id"], "link-route-1");

    let dashboard_request = with_cookie(
        Request::builder()
            .method(Method::GET)
            .uri("/api/v1/test/ciam/privacy/user-ciam")
            .body(Body::empty())
            .unwrap(),
        &cookie,
    );
    let dashboard_response = app.clone().oneshot(dashboard_request).await.unwrap();
    assert_eq!(dashboard_response.status(), StatusCode::OK);
    let dashboard = json(dashboard_response).await;
    assert_eq!(dashboard["identity_links"][0]["id"], "link-route-1");

    let delete_request = with_cookie(
        Request::builder()
            .method(Method::DELETE)
            .uri("/api/v1/test/ciam/identity-links/link-route-1")
            .body(Body::empty())
            .unwrap(),
        &cookie,
    );
    let delete_response = app.oneshot(delete_request).await.unwrap();
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    let realm_id = RealmId("test".to_string());
    let audits = state
        .repo
        .list_audit_events(Some(&realm_id), 10)
        .await
        .unwrap();
    let actions = audits
        .iter()
        .map(|event| event.action.as_str())
        .collect::<Vec<_>>();
    assert!(actions.contains(&"ciam.identity_link.create"));
    assert!(actions.contains(&"ciam.identity_link.delete"));
    assert!(
        audits
            .iter()
            .all(|event| event.metadata_json.get("external_subject").is_none())
    );
}

#[tokio::test]
async fn ciam_verification_and_password_reset_are_persisted_and_single_use() {
    let (app, state) = setup().await;
    let verify_issue = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/test/ciam/verification/issue")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{
                "user_id":"user-ciam",
                "channel":"email",
                "address":"ciam@example.com",
                "purpose":"email_verification",
                "now_epoch_seconds":1800000000,
                "ttl_seconds":600
            }"#,
        ))
        .unwrap();
    let verify_response = app.clone().oneshot(verify_issue).await.unwrap();
    assert_eq!(verify_response.status(), StatusCode::CREATED);
    let verify_json = json(verify_response).await;
    assert_eq!(verify_json["user_id"], "user-ciam");
    assert!(verify_json.get("code_hash").is_none());
    assert!(verify_json.get("code").is_none());

    let reset_issue = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/test/ciam/password-reset/issue")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{
                "user_id":"user-ciam",
                "device_id":"device-1",
                "risk":{"score":10},
                "now_epoch_seconds":1800000100,
                "ttl_seconds":900
            }"#,
        ))
        .unwrap();
    let reset_response = app.clone().oneshot(reset_issue).await.unwrap();
    assert_eq!(reset_response.status(), StatusCode::CREATED);
    let reset_json = json(reset_response).await;
    let token_id = reset_json["id"].as_str().unwrap();
    assert!(reset_json.get("token_hash").is_none());
    assert!(reset_json.get("token").is_none());
    let token = format!("test:user-ciam:device-1:1800000100:{token_id}");

    let consume_request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/test/ciam/password-reset/consume")
        .header("Content-Type", "application/json")
        .body(Body::from(format!(
            r#"{{
                "token_id":"{token_id}",
                "token":"{token}",
                "device_id":"device-1",
                "new_password":"new-secure-password",
                "now_epoch_seconds":1800000200
            }}"#
        )))
        .unwrap();
    let consume_response = app.oneshot(consume_request).await.unwrap();
    assert_eq!(consume_response.status(), StatusCode::BAD_REQUEST);
    assert!(
        state
            .repo
            .get_password_credential("user-ciam")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn ciam_protection_evaluation_rate_limits_and_records_audit() {
    let (app, state) = setup().await;
    let cookie = add_session(&state, "user-ciam").await;
    let protection_request = with_cookie(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/test/ciam/protection/evaluate")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{
                "user_id":"user-ciam",
                "client_id":"client-ciam",
                "action":"login",
                "ip":"203.0.113.10",
                "asn":"64500",
                "device_id":"device-1",
                "user_agent":"test-agent",
                "known_bad_ip":false,
                "automation_signals":[],
                "recent_attempts":25,
                "failed_attempts":10,
                "window_seconds":300,
                "now_epoch_seconds":1800000300
            }"#,
            ))
            .unwrap(),
        &cookie,
    );

    let response = app.oneshot(protection_request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    assert_eq!(body["decision"]["outcome"], "rate_limit");
    assert_eq!(body["decision"]["retry_after_seconds"], 300);
    assert!(
        body["decision"]["rate_limit_key"]
            .as_str()
            .unwrap()
            .starts_with("ciam_rate_")
    );
    let realm_id = RealmId("test".to_string());
    let audits = state
        .repo
        .list_audit_events(Some(&realm_id), 10)
        .await
        .unwrap();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].action, "ciam.protection.evaluate");
    assert_eq!(audits[0].actor, "user-ciam");
    assert_eq!(audits[0].metadata_json["outcome"], "rate_limit");
}
