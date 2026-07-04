use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use qid_core::{state::SharedState, test_helpers};
use qid_crypto::LocalSigner;
use qid_storage::{SqlRepository, prelude::*};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU16, Ordering};
use tower::ServiceExt;

static DB_SEQ: AtomicU16 = AtomicU16::new(0);

fn db_url() -> String {
    let dir = std::env::temp_dir().join("qid_test_resource_fedcm");
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
    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    let state = Arc::new(SharedState::new(config, repo, signer, serde_json::json!({})).unwrap());
    let app = qid_resource::resource_routes(&state.paths).with_state(state.clone());
    (app, state)
}

async fn add_session(state: &Arc<SharedState<SqlRepository>>, user_id: &str) -> String {
    // Ensure the user exists before creating a session (FK constraint).
    let user = qid_core::models::User {
        id: user_id.to_string(),
        realm_id: "test".to_string(),
        email: Some(format!("{user_id}@example.com")),
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    state.repo.create_user(&user).await.unwrap();

    let cookie_name = &state.config.realms[0].sessions.browser.cookie_name;
    let now = qid_core::util::now_seconds();
    let session = qid_core::models::Session {
        id: format!("fedcm-session-{user_id}"),
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

#[tokio::test]
async fn fedcm_token_is_signed_for_approved_client() {
    let (app, state) = setup().await;
    let cookie = add_session(&state, "acct-1").await;

    let create_request = with_cookie(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/test/fedcm/accounts")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{
                    "account_id":"acct-1",
                    "email":"user@example.com",
                    "name":"FedCM User",
                    "approved_clients":["rp-client"]
                }"#,
            ))
            .unwrap(),
        &cookie,
    );
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let token_request = with_cookie(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/test/fedcm/token")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"account_id":"acct-1","client_id":"rp-client"}"#,
            ))
            .unwrap(),
        &cookie,
    );
    let token_response = app.oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let bytes = token_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["token_type"], "JWT");
    let claims = state
        .signer
        .decode_signature_only(json["token"].as_str().unwrap())
        .expect("FedCM token should verify")
        .claims;
    assert_eq!(claims.sub.as_deref(), Some("acct-1"));
    assert_eq!(claims.aud.as_deref(), Some("rp-client"));
    assert_eq!(claims.extra["email"], "user@example.com");
    assert_eq!(claims.extra["typ"], "fedcm");
}

#[tokio::test]
async fn fedcm_token_rejects_unapproved_client() {
    let (app, state) = setup().await;
    let cookie = add_session(&state, "acct-2").await;

    let create_request = with_cookie(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/test/fedcm/accounts")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{
                    "account_id":"acct-2",
                    "email":"user2@example.com",
                    "approved_clients":["rp-client"]
                }"#,
            ))
            .unwrap(),
        &cookie,
    );
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let token_request = with_cookie(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/test/fedcm/token")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"account_id":"acct-2","client_id":"evil-client"}"#,
            ))
            .unwrap(),
        &cookie,
    );
    let token_response = app.oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::UNAUTHORIZED);
}
