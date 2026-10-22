use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use qid_core::{config::QidConfig, state::SharedState, tenant::RealmId, test_helpers};
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
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.fedcm.enabled = true;
    setup_with_config(config).await
}

/// A configuration whose realms are named, and which enable or disable
/// the FedCM protocol in each of them.
fn config_with_realms(realms: &[(&str, bool)]) -> QidConfig {
    let mut config = test_helpers::test_config();
    let template = config.realms[0].clone();
    config.realms.clear();
    for (id, fedcm_enabled) in realms {
        let mut realm = template.clone();
        realm.id = id.to_string();
        realm.issuer = format!("https://{id}.example.com");
        realm.display_name = Some(format!("Realm {id}"));
        realm.protocols.fedcm.enabled = *fedcm_enabled;
        config.realms.push(realm);
    }
    config
}

/// Read a discovery document and its status.
async fn get_json(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn setup_with_config(config: QidConfig) -> (axum::Router, Arc<SharedState<SqlRepository>>) {
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

/// A session in one realm of the deployment.
async fn add_session_in_realm(
    state: &Arc<SharedState<SqlRepository>>,
    realm_id: &str,
    user_id: &str,
) -> String {
    state
        .repo
        .create_realm(
            &"tenant-fedcm".into(),
            &RealmId(realm_id.to_string()),
            &format!("https://{realm_id}.example.com"),
            None,
        )
        .await
        .ok();
    let user = qid_core::models::User {
        id: user_id.to_string(),
        realm_id: realm_id.to_string(),
        email: Some(format!("{user_id}@example.com")),
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    state.repo.create_user(&user).await.unwrap();

    let cookie_name = &state
        .plan
        .realm(realm_id)
        .unwrap()
        .browser_session
        .cookie_name;
    let now = qid_core::util::now_seconds();
    let session = qid_core::models::Session {
        id: format!("fedcm-session-{realm_id}-{user_id}"),
        realm_id: realm_id.to_string(),
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
    assert_eq!(claims.aud_primary(), Some("rp-client"));
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

#[tokio::test]
async fn fedcm_config_describes_the_realm_that_enables_the_protocol() {
    let (app, _state) =
        setup_with_config(config_with_realms(&[("realm-a", true), ("realm-b", false)])).await;
    let (status, json) = get_json(app, "/.well-known/fedcm.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["id"], "realm-a");
    assert_eq!(
        json["accounts_endpoint"],
        "https://id.example.com/api/v1/realm-a/fedcm/accounts"
    );
    assert_eq!(
        json["id_assertion_endpoint"],
        "https://id.example.com/api/v1/realm-a/fedcm/token"
    );
    assert!(!json.to_string().contains("realm-default"));
}

#[tokio::test]
async fn fedcm_config_is_absent_when_no_realm_enables_the_protocol() {
    let (app, _state) = setup_with_config(config_with_realms(&[("realm-a", false)])).await;
    let (status, _json) = get_json(app, "/.well-known/fedcm.json").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn fedcm_config_is_ambiguous_when_several_realms_enable_the_protocol() {
    let (app, _state) =
        setup_with_config(config_with_realms(&[("realm-a", true), ("realm-b", true)])).await;
    let (status, _json) = get_json(app, "/.well-known/fedcm.json").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn fedcm_provider_manifest_lists_the_fedcm_realms_only() {
    let (app, _state) =
        setup_with_config(config_with_realms(&[("realm-a", true), ("realm-b", false)])).await;
    let (status, json) = get_json(app, "/.well-known/web-identity").await;
    assert_eq!(status, StatusCode::OK);
    let providers = json["provider_lists"][0]["providers"].as_array().unwrap();
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0]["id"], "realm-a");
    assert_eq!(
        providers[0]["accounts_endpoint"],
        "https://id.example.com/api/v1/realm-a/fedcm/accounts"
    );
}

#[tokio::test]
async fn fedcm_provider_manifest_is_absent_when_no_realm_enables_the_protocol() {
    let (app, _state) = setup_with_config(config_with_realms(&[("realm-a", false)])).await;
    let (status, _json) = get_json(app, "/.well-known/web-identity").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn fedcm_provider_url_is_a_served_realm_configuration() {
    let (app, _state) = setup_with_config(config_with_realms(&[("realm-a", true)])).await;
    let (_status, json) = get_json(app.clone(), "/.well-known/web-identity").await;
    let url = json["provider_lists"][0]["providers"][0]["url"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        url,
        "https://id.example.com/realms/realm-a/.well-known/fedcm.json"
    );
    let (status, document) = get_json(app, "/realms/realm-a/.well-known/fedcm.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(document["id"], "realm-a");
}

#[tokio::test]
async fn fedcm_realm_configuration_is_absent_without_the_protocol() {
    let (app, _state) =
        setup_with_config(config_with_realms(&[("realm-a", true), ("realm-b", false)])).await;
    let (status, _json) = get_json(app.clone(), "/realms/realm-b/.well-known/fedcm.json").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _json) = get_json(app, "/realms/unknown/.well-known/fedcm.json").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_fedcm_api_serves_only_the_realms_that_enable_the_protocol() {
    let (app, state) =
        setup_with_config(config_with_realms(&[("test", true), ("realm-b", false)])).await;

    // The realm that enables the protocol serves its FedCM API.
    let cookie = add_session(&state, "acct-enabled").await;
    let create = with_cookie(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/test/fedcm/accounts")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"account_id":"acct-enabled","email":"enabled@example.com"}"#,
            ))
            .unwrap(),
        &cookie,
    );
    assert_eq!(
        app.clone().oneshot(create).await.unwrap().status(),
        StatusCode::CREATED
    );

    // The realm that does not enable it serves none of it, even to a
    // session of that realm.
    let other = add_session_in_realm(&state, "realm-b", "acct-disabled").await;
    let list = with_cookie(
        Request::builder()
            .uri("/api/v1/realm-b/fedcm/accounts?account_id=acct-disabled")
            .body(Body::empty())
            .unwrap(),
        &other,
    );
    assert_eq!(
        app.clone().oneshot(list).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    let create = with_cookie(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/realm-b/fedcm/accounts")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"account_id":"acct-disabled","email":"disabled@example.com"}"#,
            ))
            .unwrap(),
        &other,
    );
    assert_eq!(
        app.clone().oneshot(create).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    let token = with_cookie(
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/realm-b/fedcm/token")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"account_id":"acct-disabled","client_id":"rp-client"}"#,
            ))
            .unwrap(),
        &other,
    );
    assert_eq!(
        app.oneshot(token).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
}
