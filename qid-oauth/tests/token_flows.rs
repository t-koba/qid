#![allow(clippy::expect_used, clippy::unwrap_used)]

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use base64::Engine;
use http_body_util::BodyExt;
use qid_core::{
    config::{OAuthProtocolConfig, OAuthResourceServerConfig, PepRegistrationConfig, QidConfig},
    models::{AuthorizationCode, Client, ClientType, TokenFormat, User},
    state::SharedState,
    tenant::RealmId,
    test_helpers, util,
};
use qid_crypto::{
    Audience, Jwk, JwtClaims, LocalSigner, jwk::generate_es256, jwt::sign_es256_jwt_with_jwk_header,
};
use qid_session::browser::SessionManager;
use qid_storage::{SqlRepository, prelude::*};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU16, Ordering};
use tower::ServiceExt;

static DB_SEQ: AtomicU16 = AtomicU16::new(0);
static SCHEMA_TEMPLATE: tokio::sync::OnceCell<std::path::PathBuf> =
    tokio::sync::OnceCell::const_new();

/// Build and close one migrated schema for independent per-test database copies.
async fn schema_template_path() -> &'static std::path::PathBuf {
    SCHEMA_TEMPLATE
        .get_or_init(|| async {
            let path = std::env::temp_dir()
                .join("qid_test_oauth")
                .join("test_template.db");
            let repo = SqlRepository::connect(&format!("sqlite:{}", path.display()))
                .await
                .unwrap();
            repo.migrate().await.unwrap();
            repo.close().await;
            path
        })
        .await
}

fn db_url() -> String {
    let dir = std::env::temp_dir().join("qid_test_oauth");
    std::fs::create_dir_all(&dir).ok();
    static CLEANED: OnceLock<()> = OnceLock::new();
    CLEANED.get_or_init(|| {
        for e in std::fs::read_dir(&dir).ok().into_iter().flatten().flatten() {
            let name = e.file_name();
            let s = name.to_string_lossy();
            if s.starts_with("test_") && s.ends_with(".db") {
                std::fs::remove_file(e.path()).ok();
            }
        }
    });
    let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("test_{n}.db"));
    format!("sqlite:{}", path.display())
}

fn build_dpop_proof(jti: &str) -> String {
    build_dpop_proof_with_nonce(jti, None)
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn post_form(
    app: Router,
    uri: &str,
    form_body: impl Into<String>,
) -> axum::response::Response {
    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(form_body.into()))
        .unwrap();
    app.oneshot(request).await.unwrap()
}

async fn get_response(app: Router, uri: &str) -> axum::response::Response {
    app.oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn mint_access_token(app: Router, token_path: &str, form_body: &str) -> String {
    let response = post_form(app, token_path, form_body.to_string()).await;
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await["access_token"]
        .as_str()
        .unwrap()
        .to_string()
}

fn decode_claims(state: &Arc<SharedState<SqlRepository>>, token: &str) -> JwtClaims {
    state.signer.decode_signature_only(token).unwrap().claims
}

async fn post_token_json(app: Router, token_path: &str, form_body: String) -> serde_json::Value {
    let response = post_form(app, token_path, form_body).await;
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

fn test_server(
    audience: &str,
    scopes: &[&str],
    introspection_client: &str,
) -> OAuthResourceServerConfig {
    let name = audience.strip_prefix("api://").unwrap_or(audience);
    OAuthResourceServerConfig {
        audience: audience.to_string(),
        resources: vec![format!("https://api.example.com/{name}")],
        scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
        introspection_client_ids: vec![introspection_client.to_string()],
        require_sender_constraint: false,
        high_risk: false,
    }
}

async fn post_introspect(
    app: Router,
    introspect_path: &str,
    form_body: String,
) -> serde_json::Value {
    let request = Request::builder()
        .method(Method::POST)
        .uri(introspect_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(form_body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

async fn post_token_status(app: Router, token_path: &str, form_body: String) -> StatusCode {
    post_form(app, token_path, form_body).await.status()
}

fn dpop_private_pem_and_jwk() -> (String, Jwk) {
    static KEY: OnceLock<(String, Jwk)> = OnceLock::new();
    KEY.get_or_init(|| {
        let generated = generate_es256("dpop-flow-key").expect("DPoP key generation failed");
        (generated.private_pem, generated.public_jwk)
    })
    .clone()
}

fn build_dpop_proof_with_nonce(jti: &str, nonce: Option<&str>) -> String {
    let now = util::now_seconds();
    let (private_pem, jwk) = dpop_private_pem_and_jwk();
    let mut payload = serde_json::json!({
        "jti": jti,
        "htm": "POST",
        "htu": "https://id.example.com/oauth2/token",
        "iat": now
    });
    if let Some(nonce) = nonce {
        payload["nonce"] = serde_json::json!(nonce);
    }
    sign_es256_jwt_with_jwk_header(private_pem.as_bytes(), &jwk, "dpop+jwt", &payload)
        .expect("DPoP proof signing failed")
}

fn private_key_jwt_jwks() -> serde_json::Value {
    let (_, jwk) = dpop_private_pem_and_jwk();
    serde_json::json!({ "keys": [serde_json::to_value(jwk).expect("JWK serialization failed")] })
}

fn build_client_assertion(client_id: &str, jti: &str) -> String {
    let now = util::now_seconds();
    let (private_pem, jwk) = dpop_private_pem_and_jwk();
    let payload = serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": "https://id.example.com/oauth2/token",
        "exp": now + 300,
        "iat": now,
        "jti": jti,
    });
    sign_es256_jwt_with_jwk_header(private_pem.as_bytes(), &jwk, "JWT", &payload)
        .expect("client assertion signing failed")
}

fn build_adapter_auth_token(
    state: &SharedState<SqlRepository>,
    adapter_name: &str,
    audience: &str,
    x5t_s256: &str,
) -> String {
    let now = util::now_seconds();
    let mut extra = HashMap::new();
    extra.insert(
        "x5t#S256".to_string(),
        serde_json::Value::String(x5t_s256.to_string()),
    );
    state
        .signer
        .sign(&JwtClaims {
            iss: Some("https://id.example.com".to_string()),
            sub: Some(adapter_name.to_string()),
            aud: Some(Audience::single(audience.to_string())),
            exp: Some((now + 60) as usize),
            nbf: Some((now - 5) as usize),
            iat: Some(now as usize),
            jti: Some(format!("adapter-auth-{adapter_name}-{now}")),
            extra,
        })
        .unwrap()
}

/// Set up a test environment with a temporary SQLite database and a minimal config.
async fn setup() -> (Router, String, Arc<SharedState<SqlRepository>>) {
    setup_with_config(test_helpers::test_config()).await
}

async fn setup_with_config(config: QidConfig) -> (Router, String, Arc<SharedState<SqlRepository>>) {
    let url = db_url();
    let path = std::path::Path::new(url.strip_prefix("sqlite:").unwrap());
    // Migrations are run once here and covered on fresh databases by qid-storage;
    // copying keeps every OAuth case isolated without repeating the migration set.
    std::fs::copy(schema_template_path().await, path).unwrap();
    let repo = Arc::new(SqlRepository::connect(&url).await.unwrap());
    // Seed the realm so FK constraints are satisfied.
    repo.create_realm(
        &"tenant-1".into(),
        &"test".into(),
        "https://id.example.com",
        Some("Test Realm"),
    )
    .await
    .unwrap();

    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    let jwks = serde_json::json!({ "keys": [] });
    let state = Arc::new(SharedState::new(config, repo, signer, jwks).unwrap());
    seed_token_flow_clients(&state).await;
    let token_path = state.paths.token.clone();

    let app = qid_oauth::routes(&state.paths).with_state(state.clone());

    (app, token_path, state)
}

async fn setup_with_oauth(
    tweak: impl FnOnce(&mut OAuthProtocolConfig),
) -> (Router, String, Arc<SharedState<SqlRepository>>) {
    let mut config = test_helpers::test_config();
    tweak(&mut config.realms[0].protocols.oauth);
    setup_with_config(config).await
}

#[allow(clippy::too_many_arguments)]
async fn create_user_with_code(
    state: &Arc<SharedState<SqlRepository>>,
    user_id: &str,
    code: &str,
    verifier: &str,
    scopes: Vec<String>,
    auth_time: Option<u64>,
    acr: Option<String>,
    amr: Vec<String>,
    resource: Vec<String>,
) {
    state
        .repo
        .create_user(&User {
            id: user_id.to_string(),
            realm_id: "test".to_string(),
            email: Some(format!("{user_id}@example.com")),
            email_verified: true,
            display_name: Some(user_id.to_string()),
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .unwrap();
    state
        .repo
        .create_authorization_code(&AuthorizationCode {
            code_hash: util::sha256_base64url(code),
            client_id: "test-client".to_string(),
            user_id: user_id.to_string(),
            realm_id: "test".to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            state: None,
            nonce: None,
            auth_time,
            acr,
            amr,
            code_challenge: Some(util::sha256_base64url(verifier)),
            code_challenge_method: Some("S256".to_string()),
            scopes,
            resource,
            authorization_details: None,
            expires_at: util::now_seconds() + 300,
            used: false,
            created_at: util::now_seconds(),
            session_id: None,
        })
        .await
        .unwrap();
}

async fn seed_token_flow_clients(state: &Arc<SharedState<SqlRepository>>) {
    let mut test_client = base_test_client(
        "test-client",
        ClientType::Public,
        "none",
        vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
    );
    test_client.redirect_uris = vec!["https://app.example.com/callback".to_string()];
    let clients = [
        test_client,
        client_credentials_client("service-client", "client_secret_post"),
        client_credentials_client("auto-create-test", "client_secret_post"),
        client_credentials_client("dpop-client", "client_secret_post"),
        client_credentials_client("opaque-client", "client_secret_post"),
        client_credentials_client("introspection-client", "client_secret_post"),
        client_credentials_client("introspection-jwt-client", "client_secret_post"),
        client_credentials_client("basic-client", "client_secret_basic"),
        private_key_jwt_client("pkjwt-client"),
        token_exchange_client("exchange-client"),
        jwt_bearer_client("jwt-bearer-client"),
        client_credentials_client("mtls-client", "tls_client_auth"),
        ciba_client("ciba-client"),
    ];
    for client in clients {
        state.repo.create_client(&client).await.unwrap();
    }
}

fn base_test_client(
    client_id: &str,
    client_type: ClientType,
    auth_method: &str,
    grant_types: Vec<String>,
) -> Client {
    Client {
        id: format!("client-{client_id}"),
        realm_id: "test".to_string(),
        client_id: client_id.to_string(),
        client_type,
        token_endpoint_auth_method: auth_method.to_string(),
        client_secret_hash: None,
        mtls_certificate_thumbprints: Vec::new(),
        jwks: qid_core::models::default_client_jwks(),
        redirect_uris: Vec::new(),
        grant_types,
        client_name: None,
        client_uri: None,
        logo_uri: None,
        contacts: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        default_max_age: None,
        require_auth_time: false,
        sector_identifier_uri: None,
        subject_type: None,
        backchannel_logout_uri: None,
        frontchannel_logout_uri: None,
        backchannel_client_notification_endpoint: None,
    }
}

fn private_key_jwt_client(client_id: &str) -> Client {
    let mut client = base_test_client(
        client_id,
        ClientType::Confidential,
        "private_key_jwt",
        vec!["client_credentials".to_string()],
    );
    client.jwks = private_key_jwt_jwks();
    client
}

fn ciba_client(client_id: &str) -> Client {
    let mut client = base_test_client(
        client_id,
        ClientType::Confidential,
        "client_secret_post",
        vec!["urn:openid:params:grant-type:ciba".to_string()],
    );
    client.client_secret_hash = Some(qid_core::util::client_secret_hash("secret"));
    client
}

fn client_credentials_client(client_id: &str, auth_method: &str) -> Client {
    let mut client = base_test_client(
        client_id,
        ClientType::Confidential,
        auth_method,
        vec!["client_credentials".to_string()],
    );
    client.client_secret_hash = matches!(auth_method, "client_secret_basic" | "client_secret_post")
        .then(|| qid_core::util::client_secret_hash("secret"));
    if auth_method == "tls_client_auth" {
        client.mtls_certificate_thumbprints =
            vec!["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".to_string()];
    }
    client
}

fn token_exchange_client(client_id: &str) -> Client {
    let mut client = base_test_client(
        client_id,
        ClientType::Confidential,
        "client_secret_post",
        vec!["urn:ietf:params:oauth:grant-type:token-exchange".to_string()],
    );
    client.client_secret_hash = Some(qid_core::util::client_secret_hash("secret"));
    client.jwks = private_key_jwt_jwks();
    client
}

fn jwt_bearer_client(client_id: &str) -> Client {
    let mut client = base_test_client(
        client_id,
        ClientType::Confidential,
        "client_secret_post",
        vec!["urn:ietf:params:oauth:grant-type:jwt-bearer".to_string()],
    );
    client.client_secret_hash = Some(qid_core::util::client_secret_hash("secret"));
    client.jwks = private_key_jwt_jwks();
    client
}

#[tokio::test]
async fn client_credentials_grant_succeeds() {
    let (app, token_path, state) = setup().await;

    let body =
        "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=api";
    let response = post_form(app, &token_path, body).await;
    assert_eq!(response.status(), StatusCode::OK);

    let json = json_body(response).await;
    assert_eq!(json["token_type"], "Bearer");
    assert!(json["access_token"].as_str().unwrap().len() > 10);
    assert_eq!(json["scope"], "api");
    // No audience requested and none configured: the JWT still names the
    // client itself, matching the stored audience fallback.
    let token = json["access_token"].as_str().unwrap().to_string();
    let claims = decode_claims(&state, &token);
    assert_eq!(claims.aud_primary(), Some("service-client"));
    assert!(
        state
            .signer
            .decode_with_aud(&token, "service-client")
            .is_ok()
    );
}

#[tokio::test]
async fn client_credentials_grant_rejects_wrong_client_secret_post() {
    let (app, token_path, _) = setup().await;

    let body =
        "grant_type=client_credentials&client_id=service-client&client_secret=wrong&scope=api";
    let response = post_form(app, &token_path, body).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn client_credentials_grant_accepts_client_secret_basic() {
    let (app, token_path, _) = setup().await;
    let credentials =
        base64::engine::general_purpose::STANDARD.encode("basic-client:secret".as_bytes());

    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Authorization", format!("Basic {credentials}"))
        .body(Body::from(
            "grant_type=client_credentials&client_id=basic-client&scope=api",
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn client_credentials_grant_accepts_private_key_jwt() {
    let (app, token_path, _) = setup_with_oauth(|oauth| oauth.private_key_jwt.enabled = true).await;
    let assertion = build_client_assertion("pkjwt-client", "pkjwt-success-1");
    let body = format!(
        "grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={assertion}&scope=api"
    );
    let response = post_form(app, &token_path, body).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn client_credentials_grant_rejects_tampered_private_key_jwt() {
    let (app, token_path, _) = setup_with_oauth(|oauth| oauth.private_key_jwt.enabled = true).await;
    let assertion = build_client_assertion("pkjwt-client", "pkjwt-tampered-1");
    let (header_and_payload, signature) = assertion
        .rsplit_once('.')
        .expect("client assertion should contain signature");
    let (header, _payload) = header_and_payload
        .split_once('.')
        .expect("client assertion should contain payload");
    let payload = serde_json::json!({
        "iss": "pkjwt-client",
        "sub": "pkjwt-client",
        "aud": "https://id.example.com/oauth2/token",
        "exp": util::now_seconds() + 300,
        "scope": "admin",
    });
    let encoded_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_string(&payload).unwrap().as_bytes());
    let tampered = format!("{header}.{encoded_payload}.{signature}");
    let body = format!(
        "grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={tampered}&scope=api"
    );
    let response = post_form(app, &token_path, body).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn client_credentials_grant_rejects_private_key_jwt_when_disabled() {
    let (app, token_path, _) = setup().await;
    let assertion = build_client_assertion("pkjwt-client", "pkjwt-disabled-1");
    let body = format!(
        "grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={assertion}&scope=api"
    );
    let response = post_form(app, &token_path, body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn client_credentials_grant_rejects_wrong_client_secret_basic() {
    let (app, token_path, _) = setup().await;
    let credentials =
        base64::engine::general_purpose::STANDARD.encode("basic-client:wrong".as_bytes());

    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Authorization", format!("Basic {credentials}"))
        .body(Body::from(
            "grant_type=client_credentials&client_id=basic-client&scope=api",
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn client_credentials_grant_auto_creates_service_account() {
    let (app, token_path, state) = setup().await;

    let body =
        "grant_type=client_credentials&client_id=auto-create-test&client_secret=secret&scope=api";
    let response = post_form(app, &token_path, body).await;
    assert_eq!(response.status(), StatusCode::OK);

    let sa = state
        .repo
        .get_service_account_by_client_id("test", "auto-create-test")
        .await
        .unwrap();
    assert!(
        sa.is_some(),
        "service account should have been auto-created"
    );
}

#[tokio::test]
async fn token_exchange_requires_active_access_token_subject() {
    let (app, token_path, state) = setup_with_oauth(|oauth| oauth.dpop.enabled = true).await;

    let subject_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=api",
        ))
        .unwrap();
    let subject_response = app.clone().oneshot(subject_request).await.unwrap();
    assert_eq!(subject_response.status(), StatusCode::OK);
    let subject_json = json_body(subject_response).await;
    let subject_token = subject_json["access_token"].as_str().unwrap();

    let exchange_body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=exchange-client&client_secret=secret&subject_token_type=urn:ietf:params:oauth:token-type:access_token&subject_token={}&audience=api://payments&resource=https://api.example.com/payments&scope=payments",
        urlencoding::encode(subject_token)
    );
    let exchange_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("DPoP", build_dpop_proof("token-exchange-dpop-response"))
        .body(Body::from(exchange_body))
        .unwrap();
    let exchange_response = app.oneshot(exchange_request).await.unwrap();
    assert_eq!(exchange_response.status(), StatusCode::OK);
    let exchange_json = json_body(exchange_response).await;
    assert_eq!(exchange_json["token_type"], "DPoP");
    let exchanged_token = exchange_json["access_token"].as_str().unwrap();
    let claims = decode_claims(&state, exchanged_token);
    assert_eq!(claims.sub.as_deref(), Some("service:service-client"));
    assert_eq!(claims.aud_primary(), Some("api://payments"));
    assert_eq!(claims.extra["client_id"], "exchange-client");
    assert_eq!(claims.extra["scope"], "payments");
    assert_eq!(
        claims.extra["resource"],
        serde_json::json!(["https://api.example.com/payments"])
    );
    assert!(claims.extra["cnf"]["jkt"].is_string());
    assert_eq!(claims.extra["token_type"], "DPoP");
}

#[tokio::test]
async fn token_exchange_with_actor_token_emits_actor_claim() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.resource_servers =
        vec![test_server("api://delegated", &[], "introspection-client")];
    let (app, token_path, state) = setup_with_config(config).await;

    let subject_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=api&resource=https%3A%2F%2Fapi.example.com%2Fdelegated",
        ))
        .unwrap();
    let subject_response = app.clone().oneshot(subject_request).await.unwrap();
    assert_eq!(subject_response.status(), StatusCode::OK);
    let subject_json = json_body(subject_response).await;
    let subject_token = subject_json["access_token"].as_str().unwrap();

    let actor_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=introspection-client&client_secret=secret&scope=actor&resource=https%3A%2F%2Fapi.example.com%2Fdelegated",
        ))
        .unwrap();
    let actor_response = app.clone().oneshot(actor_request).await.unwrap();
    assert_eq!(actor_response.status(), StatusCode::OK);
    let actor_json = json_body(actor_response).await;
    let actor_token = actor_json["access_token"].as_str().unwrap();

    let exchange_body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=exchange-client&client_secret=secret&subject_token_type=urn:ietf:params:oauth:token-type:access_token&subject_token={}&actor_token_type=urn:ietf:params:oauth:token-type:access_token&actor_token={}&audience=api://delegated&scope=delegated",
        urlencoding::encode(subject_token),
        urlencoding::encode(actor_token)
    );
    let exchange_response = post_form(app.clone(), &token_path, exchange_body).await;
    assert_eq!(exchange_response.status(), StatusCode::OK);
    let exchange_json = json_body(exchange_response).await;
    assert_eq!(
        exchange_json["issued_token_type"],
        "urn:ietf:params:oauth:token-type:access_token"
    );
    let exchanged_token = exchange_json["access_token"].as_str().unwrap();
    let claims = decode_claims(&state, exchanged_token);
    assert_eq!(claims.sub.as_deref(), Some("service:service-client"));
    assert_eq!(claims.extra["act"]["sub"], "service:introspection-client");
    assert_eq!(claims.extra["act"]["client_id"], "introspection-client");
    assert_eq!(claims.extra["act"]["scope"], "actor");

    let introspection = post_introspect(
        app,
        &state.paths.introspect,
        format!(
            "token={}&client_id=introspection-client&client_secret=secret",
            urlencoding::encode(exchanged_token)
        ),
    )
    .await;
    assert_eq!(introspection["act"]["sub"], "service:introspection-client");
    assert_eq!(introspection["act"]["client_id"], "introspection-client");
    assert_eq!(introspection["act"]["scope"], "actor");
}

#[tokio::test]
async fn token_exchange_rejects_foreign_realm_tokens() {
    // RFC 8693 section 2.1: grant enablement is not cross-realm trust. Local
    // subject and actor tokens must belong to the exchange client realm.
    let mut config = test_helpers::test_config();
    for (id, issuer, format) in [
        (
            "foreign-jwt",
            "https://foreign.example.com",
            TokenFormat::Jwt,
        ),
        (
            "foreign-opaque",
            "https://opaque.example.com",
            TokenFormat::Opaque,
        ),
    ] {
        let mut realm = config.realms[0].clone();
        realm.id = id.to_string();
        realm.issuer = issuer.to_string();
        realm.protocols.oauth.tokens.access_token_format = format;
        config.realms.push(realm);
    }
    let (app, token_path, state) = setup_with_config(config).await;
    for (realm_id, issuer) in [
        ("foreign-jwt", "https://foreign.example.com"),
        ("foreign-opaque", "https://opaque.example.com"),
    ] {
        state
            .repo
            .create_realm(&"tenant-1".into(), &realm_id.into(), issuer, None)
            .await
            .unwrap();
        let mut client =
            client_credentials_client(&format!("{realm_id}-service"), "client_secret_post");
        client.realm_id = realm_id.to_string();
        state.repo.create_client(&client).await.unwrap();
    }

    let foreign_jwt = mint_access_token(
        app.clone(),
        &token_path,
        "grant_type=client_credentials&client_id=foreign-jwt-service&client_secret=secret&scope=api",
    )
    .await;
    let foreign_opaque = mint_access_token(
        app.clone(),
        &token_path,
        "grant_type=client_credentials&client_id=foreign-opaque-service&client_secret=secret&scope=api",
    )
    .await;
    assert!(foreign_opaque.starts_with("oat_"));
    let own_token = mint_access_token(
        app.clone(),
        &token_path,
        "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=api",
    )
    .await;

    // Foreign JWT and opaque subjects are rejected without issuing.
    for subject in [&foreign_jwt, &foreign_opaque] {
        let status = post_token_status(
            app.clone(),
            &token_path,
            format!(
                "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=exchange-client&client_secret=secret&subject_token_type=urn:ietf:params:oauth:token-type:access_token&subject_token={}&audience=api://payments&resource=https%3A%2F%2Fapi.example.com%2Fpayments&scope=payments",
                urlencoding::encode(subject)
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    // A same-realm subject with a foreign actor is rejected as well.
    let status = post_token_status(
        app.clone(),
        &token_path,
        format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=exchange-client&client_secret=secret&subject_token_type=urn:ietf:params:oauth:token-type:access_token&subject_token={}&actor_token_type=urn:ietf:params:oauth:token-type:access_token&actor_token={}&audience=api://delegated&scope=delegated",
            urlencoding::encode(&own_token),
            urlencoding::encode(&foreign_jwt)
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Same-realm exchange still succeeds: the gate is a boundary, not a block.
    let status = post_token_status(
        app.clone(),
        &token_path,
        format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=exchange-client&client_secret=secret&subject_token_type=urn:ietf:params:oauth:token-type:access_token&subject_token={}&audience=api://payments&resource=https%3A%2F%2Fapi.example.com%2Fpayments&scope=payments",
            urlencoding::encode(&own_token)
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Rejected inputs stay live: neither foreign record was revoked.
    let foreign_jwt_jti = decode_claims(&state, &foreign_jwt).jti.unwrap();
    for jti in [
        foreign_jwt_jti,
        foreign_opaque.strip_prefix("oat_").unwrap().to_string(),
    ] {
        let record = state.repo.get_access_token(&jti).await.unwrap().unwrap();
        assert!(!record.revoked);
    }
}

#[tokio::test]
async fn client_credentials_rejects_scope_outside_any_target_ceiling() {
    // RFC 8707 section 2.2: each target's scope list is its own ceiling, so
    // adding a permissive target must not widen a restrictive one.
    let (app, token_path, _) = setup_with_oauth(|oauth| {
        oauth.resource_servers = vec![
            OAuthResourceServerConfig {
                audience: "api://reader".to_string(),
                resources: Vec::new(),
                scopes: vec!["read".to_string()],
                introspection_client_ids: Vec::new(),
                require_sender_constraint: false,
                high_risk: false,
            },
            OAuthResourceServerConfig {
                audience: "api://admin".to_string(),
                resources: Vec::new(),
                scopes: vec!["admin".to_string()],
                introspection_client_ids: Vec::new(),
                require_sender_constraint: false,
                high_risk: false,
            },
        ]
    })
    .await;
    let status = post_token_status(
        app.clone(),
        &token_path,
        "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=admin&audience=api%3A%2F%2Freader".to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let status = post_token_status(
        app.clone(),
        &token_path,
        "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=admin&audience=api%3A%2F%2Freader%20api%3A%2F%2Fadmin".to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let status = post_token_status(
        app,
        &token_path,
        "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=admin&audience=api%3A%2F%2Fadmin".to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn jwt_bearer_preserves_explicit_auth_time_and_omits_otherwise() {
    // RFC 7523 section 3: iat marks assertion issuance, never the
    // authentication event, so only an explicit auth_time is preserved.
    let (app, token_path, state) = setup().await;
    let now = util::now_seconds();
    let token_url = format!("https://id.example.com{token_path}");
    let (private_pem, jwk) = dpop_private_pem_and_jwk();
    let assertion = |iss: &str, jti: &str, iat: Option<u64>, auth_time: Option<u64>| {
        let mut payload = serde_json::json!({
            "iss": iss,
            "sub": "workload-123",
            "aud": token_url,
            "exp": now + 300,
            "jti": jti,
        });
        if let Some(iat) = iat {
            payload["iat"] = serde_json::json!(iat);
        }
        if let Some(auth_time) = auth_time {
            payload["auth_time"] = serde_json::json!(auth_time);
        }
        sign_es256_jwt_with_jwk_header(private_pem.as_bytes(), &jwk, "JWT", &payload).unwrap()
    };
    let token_for = |assertion: String| {
        post_token_json(
            app.clone(),
            &token_path,
            format!(
                "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&client_id=jwt-bearer-client&client_secret=secret&assertion={}&audience=api://workload&scope=workload",
                urlencoding::encode(&assertion)
            ),
        )
    };
    // Recent issuance with an hour-old authentication preserves the old time.
    let json = token_for(assertion(
        "jwt-bearer-client",
        "auth-time-old",
        Some(now),
        Some(now - 3600),
    ))
    .await;
    let claims = decode_claims(&state, json["access_token"].as_str().unwrap());
    assert_eq!(claims.extra["auth_time"], serde_json::json!(now - 3600));
    // Present iat without auth_time, and neither claim, both omit auth_time.
    for (jti, iat) in [
        ("auth-time-no-time", Some(now)),
        ("auth-time-no-claims", None),
    ] {
        let json = token_for(assertion("jwt-bearer-client", jti, iat, None)).await;
        let claims = decode_claims(&state, json["access_token"].as_str().unwrap());
        assert!(
            !claims.extra.contains_key("auth_time"),
            "{jti} must omit auth_time"
        );
    }
    // The shared JWT-as-subject exchange path preserves it the same way.
    let exchange_assertion = assertion(
        "exchange-client",
        "auth-time-exchange",
        Some(now),
        Some(now - 3600),
    );
    let json = post_token_json(
        app.clone(),
        &token_path,
        format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=exchange-client&client_secret=secret&subject_token_type=urn:ietf:params:oauth:token-type:jwt&subject_token={}&audience=api://payments&resource=https%3A%2F%2Fapi.example.com%2Fpayments&scope=payments",
            urlencoding::encode(&exchange_assertion)
        ),
    )
    .await;
    let claims = decode_claims(&state, json["access_token"].as_str().unwrap());
    assert_eq!(claims.extra["auth_time"], serde_json::json!(now - 3600));
}

#[tokio::test]
async fn token_exchange_rejects_unknown_subject_token() {
    let (app, token_path, _) = setup().await;

    let exchange_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=exchange-client&client_secret=secret&subject_token_type=urn:ietf:params:oauth:token-type:access_token&subject_token=oat_missing-jti",
        ))
        .unwrap();
    let response = app.oneshot(exchange_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_bearer_grant_validates_assertion_and_uses_subject() {
    let (app, token_path, state) = setup().await;
    let now = util::now_seconds();
    let token_url = format!("https://id.example.com{token_path}");
    let mut extra = HashMap::new();
    extra.insert("acr".to_string(), serde_json::json!("urn:qid:acr:workload"));
    extra.insert("amr".to_string(), serde_json::json!(["jwt"]));
    extra.insert(
        "cnf".to_string(),
        serde_json::json!({ "jkt": "workload-key-thumbprint" }),
    );
    let (private_pem, jwk) = dpop_private_pem_and_jwk();
    let payload = serde_json::json!({
        "iss": "jwt-bearer-client",
        "sub": "workload-123",
        "aud": token_url,
        "exp": now + 300,
        "nbf": now - 1,
        "iat": now,
        "jti": "jwt-bearer-valid",
        "acr": extra["acr"],
        "amr": extra["amr"],
        "cnf": extra["cnf"],
    });
    let assertion =
        sign_es256_jwt_with_jwk_header(private_pem.as_bytes(), &jwk, "JWT", &payload).unwrap();

    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&client_id=jwt-bearer-client&client_secret=secret&assertion={}&audience=api://workload&scope=workload",
        urlencoding::encode(&assertion)
    );
    let response = post_form(app, &token_path, body).await;
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let access_token = json["access_token"].as_str().unwrap();
    let claims = decode_claims(&state, access_token);
    assert!(claims.sub.as_deref().unwrap().starts_with("jwt:v1:"));
    assert_eq!(claims.aud_primary(), Some("api://workload"));
    assert_eq!(claims.extra["client_id"], "jwt-bearer-client");
    assert_eq!(claims.extra["scope"], "workload");
    assert_eq!(claims.extra["acr"], "urn:qid:acr:workload");
    assert_eq!(claims.extra["amr"], serde_json::json!(["jwt"]));
    assert_eq!(
        claims.extra["cnf"],
        serde_json::json!({ "jkt": "workload-key-thumbprint" })
    );
}

#[tokio::test]
async fn jwt_bearer_grant_rejects_wrong_audience() {
    let (app, token_path, state) = setup().await;
    let now = util::now_seconds();
    let assertion = state
        .signer
        .sign(&JwtClaims {
            iss: Some("https://issuer.example.com".to_string()),
            sub: Some("workload-123".to_string()),
            aud: Some(Audience::single(
                "https://id.example.com/not-token".to_string(),
            )),
            exp: Some((now + 300) as usize),
            nbf: Some(now as usize),
            iat: Some(now as usize),
            jti: Some("jwt-bearer-wrong-aud".to_string()),
            extra: HashMap::new(),
        })
        .unwrap();

    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&client_id=jwt-bearer-client&client_secret=secret&assertion={}",
        urlencoding::encode(&assertion)
    );
    let response = post_form(app, &token_path, body).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn client_credentials_grant_rejects_wrong_client_auth_method() {
    let (app, token_path, _) = setup().await;

    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=service-client&scope=api",
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn client_credentials_enforces_registered_resource_server_policy() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.dpop.enabled = true;
    let mut payments = test_server("api://payments", &["payments"], "introspection-client");
    payments.high_risk = true;
    config.realms[0].protocols.oauth.resource_servers = vec![
        test_server("api://profile", &["api"], "introspection-client"),
        payments,
    ];
    let (app, token_path, state) = setup_with_config(config).await;

    let profile_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=api&resource=https%3A%2F%2Fapi.example.com%2Fprofile",
        ))
        .unwrap();
    let profile_response = app.clone().oneshot(profile_request).await.unwrap();
    assert_eq!(profile_response.status(), StatusCode::OK);
    let json = json_body(profile_response).await;
    let claims = decode_claims(&state, json["access_token"].as_str().unwrap());
    assert_eq!(claims.aud_primary(), Some("api://profile"));
    assert_eq!(
        claims.extra["resource"],
        serde_json::json!(["https://api.example.com/profile"])
    );

    let unknown_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=api&resource=https%3A%2F%2Fapi.example.com%2Funknown",
        ))
        .unwrap();
    let unknown_response = app.clone().oneshot(unknown_request).await.unwrap();
    assert_eq!(unknown_response.status(), StatusCode::UNAUTHORIZED);

    let invalid_scope_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=payments&resource=https%3A%2F%2Fapi.example.com%2Fprofile",
        ))
        .unwrap();
    let invalid_scope_response = app.clone().oneshot(invalid_scope_request).await.unwrap();
    assert_eq!(invalid_scope_response.status(), StatusCode::BAD_REQUEST);

    let high_risk_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=payments&audience=api%3A%2F%2Fpayments",
        ))
        .unwrap();
    let high_risk_response = app.clone().oneshot(high_risk_request).await.unwrap();
    assert_eq!(high_risk_response.status(), StatusCode::UNAUTHORIZED);

    let dpop_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("DPoP", build_dpop_proof("resource-policy-dpop"))
        .body(Body::from(
            "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=payments&audience=api%3A%2F%2Fpayments",
        ))
        .unwrap();
    let dpop_response = app.oneshot(dpop_request).await.unwrap();
    let dpop_status = dpop_response.status();
    let bytes = dpop_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(
        dpop_status,
        StatusCode::OK,
        "DPoP resource policy response body: {}",
        String::from_utf8_lossy(&bytes)
    );
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let claims = decode_claims(&state, json["access_token"].as_str().unwrap());
    assert_eq!(claims.aud_primary(), Some("api://payments"));
    assert!(claims.extra["cnf"]["jkt"].is_string());
}

#[tokio::test]
async fn public_client_credentials_grant_is_rejected() {
    let (app, token_path, _) = setup().await;

    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=test-client&scope=api",
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn dpop_client_credentials_binds_access_token_cnf() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.dpop.enabled = true;
    config.realms[0].protocols.oauth.resource_servers =
        vec![test_server("api://default", &[], "introspection-client")];
    let (app, token_path, state) = setup_with_config(config).await;
    let proof = build_dpop_proof("dpop-proof-token-flow");
    let expected_jkt = qid_oauth::dpop::dpop_jkt_from_proof(&proof).unwrap();

    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("DPoP", proof)
        .body(Body::from(
            "grant_type=client_credentials&client_id=dpop-client&client_secret=secret&scope=api&resource=https%3A%2F%2Fapi.example.com%2Fdefault",
        ))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = json_body(response).await;
    assert_eq!(json["token_type"], "DPoP");
    let access_token = json["access_token"].as_str().unwrap();
    let claims = decode_claims(&state, access_token);
    assert_eq!(
        claims.extra["cnf"],
        serde_json::json!({"jkt": expected_jkt})
    );

    let introspection = post_introspect(
        app,
        &state.paths.introspect,
        format!(
            "token={}&client_id=introspection-client&client_secret=secret",
            urlencoding::encode(access_token)
        ),
    )
    .await;
    assert_eq!(
        introspection["cnf"],
        serde_json::json!({"jkt": expected_jkt})
    );
}

#[tokio::test]
async fn dpop_client_credentials_rejects_proof_when_disabled() {
    let (app, token_path, _) = setup().await;
    let proof = build_dpop_proof("dpop-disabled-token-flow");

    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("DPoP", proof)
        .body(Body::from(
            "grant_type=client_credentials&client_id=dpop-client&client_secret=secret&scope=api",
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn dpop_nonce_challenge_requires_nonce_retry() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.dpop.enabled = true;
    config.realms[0].protocols.oauth.dpop.nonce = true;
    let (app, token_path, _) = setup_with_config(config).await;
    let first_proof = build_dpop_proof("dpop-nonce-first");

    let first_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("DPoP", first_proof)
        .body(Body::from(
            "grant_type=client_credentials&client_id=dpop-client&client_secret=secret&scope=api",
        ))
        .unwrap();

    let first_response = app.clone().oneshot(first_request).await.unwrap();
    assert_eq!(first_response.status(), StatusCode::BAD_REQUEST);
    let nonce = first_response
        .headers()
        .get("DPoP-Nonce")
        .and_then(|value| value.to_str().ok())
        .expect("DPoP nonce challenge header should be present")
        .to_string();
    assert!(nonce.starts_with("dpop_nonce_"));
    let first_json = json_body(first_response).await;
    assert_eq!(first_json["error"], "use_dpop_nonce");
    assert!(first_json["error_description"].is_string());

    // A non-nonce failure in a nonce realm keeps its own error category.
    let wrong_secret_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header(
            "DPoP",
            build_dpop_proof_with_nonce("dpop-nonce-wrong-secret", Some(&nonce)),
        )
        .body(Body::from(
            "grant_type=client_credentials&client_id=dpop-client&client_secret=wrong&scope=api",
        ))
        .unwrap();
    let wrong_secret_response = app.clone().oneshot(wrong_secret_request).await.unwrap();
    assert_eq!(wrong_secret_response.status(), StatusCode::UNAUTHORIZED);
    let wrong_secret_json = json_body(wrong_secret_response).await;
    assert_ne!(wrong_secret_json["error"], "use_dpop_nonce");

    // The wrong-secret attempt consumed the first nonce; take a fresh one.
    let second_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("DPoP", build_dpop_proof("dpop-nonce-second"))
        .body(Body::from(
            "grant_type=client_credentials&client_id=dpop-client&client_secret=secret&scope=api",
        ))
        .unwrap();
    let second_response = app.clone().oneshot(second_request).await.unwrap();
    assert_eq!(second_response.status(), StatusCode::BAD_REQUEST);
    let nonce = second_response
        .headers()
        .get("DPoP-Nonce")
        .and_then(|value| value.to_str().ok())
        .expect("second DPoP nonce challenge header should be present")
        .to_string();

    let proof = build_dpop_proof_with_nonce("dpop-nonce-retry", Some(&nonce));
    let retry_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("DPoP", proof.clone())
        .body(Body::from(
            "grant_type=client_credentials&client_id=dpop-client&client_secret=secret&scope=api",
        ))
        .unwrap();
    let retry_response = app.clone().oneshot(retry_request).await.unwrap();
    assert_eq!(retry_response.status(), StatusCode::OK);

    let replay_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("DPoP", proof)
        .body(Body::from(
            "grant_type=client_credentials&client_id=dpop-client&client_secret=secret&scope=api",
        ))
        .unwrap();
    let replay_response = app.clone().oneshot(replay_request).await.unwrap();
    assert_eq!(replay_response.status(), StatusCode::BAD_REQUEST);
    assert!(
        replay_response.headers().get("DPoP-Nonce").is_some(),
        "nonce replay failure should return a fresh challenge"
    );
    let replay_json = json_body(replay_response).await;
    assert_eq!(replay_json["error"], "use_dpop_nonce");
    assert!(replay_json["error_description"].is_string());

    // First challenge body carries the standard code plus the diagnostic text.
    let unknown_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header(
            "DPoP",
            build_dpop_proof_with_nonce("dpop-nonce-unknown", Some("dpop_nonce_bogus")),
        )
        .body(Body::from(
            "grant_type=client_credentials&client_id=dpop-client&client_secret=secret&scope=api",
        ))
        .unwrap();
    let unknown_response = app.oneshot(unknown_request).await.unwrap();
    assert_eq!(unknown_response.status(), StatusCode::BAD_REQUEST);
    assert!(unknown_response.headers().get("DPoP-Nonce").is_some());
    let unknown_json = json_body(unknown_response).await;
    assert_eq!(unknown_json["error"], "use_dpop_nonce");
    assert!(unknown_json["error_description"].is_string());
}

#[tokio::test]
async fn mtls_client_credentials_rejects_certificate_headers() {
    let (app, token_path, _) = setup_with_oauth(|oauth| oauth.mtls.enabled = true).await;
    let thumbprint_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("X-Client-Cert-Sha256", thumbprint_hex)
        .body(Body::from(
            "grant_type=client_credentials&client_id=mtls-client&scope=api",
        ))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mtls_client_credentials_rejects_unregistered_thumbprint() {
    let (app, token_path, _) = setup_with_oauth(|oauth| oauth.mtls.enabled = true).await;
    let wrong_thumbprint_hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("X-Client-Cert-Sha256", wrong_thumbprint_hex)
        .body(Body::from(
            "grant_type=client_credentials&client_id=mtls-client&scope=api",
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mtls_client_credentials_accepts_authenticated_pep_metadata() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.mtls.enabled = true;
    config.realms[0].pep_registrations.enabled = true;
    config.realms[0].pep_registrations.registrations = vec![PepRegistrationConfig {
        name: "egress-main".to_string(),
        audience: Some("qid-pep-adapter".to_string()),
        capabilities: Vec::new(),
        assertion: Default::default(),
        decision: Default::default(),
        auth: Default::default(),
    }];
    let (app, token_path, state) = setup_with_config(config).await;
    let registered_thumbprint = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    let adapter_auth = build_adapter_auth_token(
        &state,
        "egress-main",
        "qid-pep-adapter",
        registered_thumbprint,
    );

    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header(
            "x-qid-pep-adapter-authorization",
            format!("Bearer {adapter_auth}"),
        )
        .header("x-qid-mtls-x5t-s256", registered_thumbprint)
        .body(Body::from(
            "grant_type=client_credentials&client_id=mtls-client&scope=api",
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = json_body(response).await;
    assert_eq!(json["token_type"], "Bearer");
    let claims = decode_claims(&state, json["access_token"].as_str().unwrap());
    assert_eq!(claims.extra["token_type"], "Bearer");
    assert_eq!(claims.extra["cnf"]["x5t#S256"], registered_thumbprint);
    assert!(claims.extra["cnf"]["jkt"].is_null());
}

#[tokio::test]
async fn mtls_bound_token_introspects_without_presented_certificate() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.mtls.enabled = true;
    config.realms[0].protocols.oauth.introspection.jwt_response = true;
    config.realms[0].pep_registrations.enabled = true;
    config.realms[0].pep_registrations.registrations = vec![PepRegistrationConfig {
        name: "egress-main".to_string(),
        audience: Some("qid-pep-adapter".to_string()),
        capabilities: Vec::new(),
        assertion: Default::default(),
        decision: Default::default(),
        auth: Default::default(),
    }];
    config.realms[0].protocols.oauth.resource_servers =
        vec![test_server("api://default", &[], "introspection-client")];
    let (app, token_path, state) = setup_with_config(config).await;
    let registered_thumbprint = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    let adapter_auth = build_adapter_auth_token(
        &state,
        "egress-main",
        "qid-pep-adapter",
        registered_thumbprint,
    );

    let token_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header(
            "x-qid-pep-adapter-authorization",
            format!("Bearer {adapter_auth}"),
        )
        .header("x-qid-mtls-x5t-s256", registered_thumbprint)
        .body(Body::from(
            "grant_type=client_credentials&client_id=mtls-client&scope=api&resource=https%3A%2F%2Fapi.example.com%2Fdefault",
        ))
        .unwrap();
    let token_response = app.clone().oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let json = json_body(token_response).await;
    let access_token = json["access_token"].as_str().unwrap().to_string();
    assert_eq!(json["token_type"], "Bearer");
    let issued_claims = decode_claims(&state, &access_token);
    assert_eq!(
        issued_claims.extra["cnf"]["x5t#S256"],
        serde_json::Value::String(registered_thumbprint.to_string())
    );

    // RFC 8705 section 3.2: the introspection caller authenticates as a
    // resource server and receives cnf.x5t#S256 as metadata. The inspected
    // token's certificate is not presented on this call; comparison happens
    // at the protected resource.
    let introspection = post_introspect(
        app.clone(),
        &state.paths.introspect,
        format!(
            "token={}&client_id=introspection-client&client_secret=secret",
            urlencoding::encode(&access_token)
        ),
    )
    .await;
    assert_eq!(introspection["active"], true);
    assert_eq!(introspection["client_id"], "mtls-client");
    assert_eq!(
        introspection["cnf"]["x5t#S256"],
        serde_json::Value::String(registered_thumbprint.to_string())
    );

    let jwt_body = format!(
        "token={}&client_id=introspection-client&client_secret=secret&response_format=jwt",
        urlencoding::encode(&access_token)
    );
    let jwt_response = post_form(app, &state.paths.introspect, jwt_body).await;
    assert_eq!(jwt_response.status(), StatusCode::OK);
    let jwt_introspection = json_body(jwt_response).await;
    assert_eq!(jwt_introspection["active"], true);
    assert_eq!(
        jwt_introspection["cnf"]["x5t#S256"],
        serde_json::Value::String(registered_thumbprint.to_string())
    );
    let token_introspection = jwt_introspection["token_introspection"]
        .as_str()
        .expect("JWT introspection response should be present");
    let claims = decode_claims(&state, token_introspection);
    assert_eq!(claims.aud_primary(), Some("introspection-client"));
    assert_eq!(
        claims.extra["cnf"]["x5t#S256"],
        serde_json::Value::String(registered_thumbprint.to_string())
    );
}

#[tokio::test]
async fn refresh_preserves_original_scope_ceiling() {
    // RFC 6749 section 6: omitted scope means the original grant, explicit
    // scope must be a subset, and the replacement refresh token keeps the
    // original ceiling. The realm default must never widen a grant.
    let (app, token_path, state) =
        setup_with_oauth(|oauth| oauth.default_scope = "write".to_string()).await;
    let code = "scope-ceiling-code-1";
    let code_verifier = "e1f2a3b4c5d60718293a4b5c6d7e8f9012345678";
    create_user_with_code(
        &state,
        "scope-ceiling-user",
        code,
        code_verifier,
        vec!["read".to_string(), "profile".to_string()],
        Some(1234),
        None,
        vec!["pwd".to_string()],
        Vec::new(),
    )
    .await;

    let token_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=authorization_code&code={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&client_id=test-client&code_verifier={}",
            urlencoding::encode(code),
            urlencoding::encode(code_verifier)
        )))
        .unwrap();
    let token_response = app.clone().oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_json = json_body(token_response).await;
    assert_eq!(token_json["scope"], "read profile");
    let refresh_1 = token_json["refresh_token"].as_str().unwrap().to_string();

    // Omitted scope must issue the original grant, not the realm default.
    let refresh_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=refresh_token&client_id=test-client&refresh_token={}",
            urlencoding::encode(&refresh_1)
        )))
        .unwrap();
    let refresh_response = app.clone().oneshot(refresh_request).await.unwrap();
    assert_eq!(refresh_response.status(), StatusCode::OK);
    let refresh_json = json_body(refresh_response).await;
    assert_eq!(refresh_json["scope"], "read profile");
    let access_1 = refresh_json["access_token"].as_str().unwrap().to_string();
    let claims_1 = decode_claims(&state, &access_1);
    assert_eq!(
        claims_1.extra["scope"],
        serde_json::Value::String("read profile".to_string())
    );
    let stored_jti_1 = claims_1.jti.clone().unwrap();
    let stored_1 = state
        .repo
        .get_access_token(&stored_jti_1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored_1.scopes,
        vec!["read".to_string(), "profile".to_string()]
    );
    let refresh_2 = refresh_json["refresh_token"].as_str().unwrap().to_string();

    // Explicit subset narrows this access token but must not shrink the family.
    let narrow_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=refresh_token&client_id=test-client&refresh_token={}&scope=read",
            urlencoding::encode(&refresh_2)
        )))
        .unwrap();
    let narrow_response = app.clone().oneshot(narrow_request).await.unwrap();
    assert_eq!(narrow_response.status(), StatusCode::OK);
    let narrow_json = json_body(narrow_response).await;
    assert_eq!(narrow_json["scope"], "read");
    let refresh_3 = narrow_json["refresh_token"].as_str().unwrap().to_string();

    // Omitted scope after narrowing must return the full original ceiling.
    let full_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=refresh_token&client_id=test-client&refresh_token={}",
            urlencoding::encode(&refresh_3)
        )))
        .unwrap();
    let full_response = app.clone().oneshot(full_request).await.unwrap();
    assert_eq!(full_response.status(), StatusCode::OK);
    let full_json = json_body(full_response).await;
    assert_eq!(full_json["scope"], "read profile");
    let refresh_4 = full_json["refresh_token"].as_str().unwrap().to_string();

    // Requesting a scope outside the original grant must fail without
    // consuming the current refresh token.
    let exceed_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=refresh_token&client_id=test-client&refresh_token={}&scope=write",
            urlencoding::encode(&refresh_4)
        )))
        .unwrap();
    let exceed_response = app.clone().oneshot(exceed_request).await.unwrap();
    assert_eq!(exceed_response.status(), StatusCode::BAD_REQUEST);

    let retry_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=refresh_token&client_id=test-client&refresh_token={}",
            urlencoding::encode(&refresh_4)
        )))
        .unwrap();
    let retry_response = app.oneshot(retry_request).await.unwrap();
    assert_eq!(retry_response.status(), StatusCode::OK);
    let retry_json = json_body(retry_response).await;
    assert_eq!(retry_json["scope"], "read profile");
}

#[tokio::test]
async fn refresh_preserves_original_authentication_context() {
    // RFC 9068 section 2.2.1: auth_time/acr/amr are fixed across all access
    // tokens deriving from an authorization response, including refresh.
    // Refresh must not manufacture a recent auth_time or drop assurance.
    let (app, token_path, state) = setup().await;
    let original_auth_time = util::now_seconds() - 3600;
    let code = "auth-context-code-1";
    let code_verifier = "f1e2d3c4b5a69788796a5b4c3d2e1f0012345678";
    create_user_with_code(
        &state,
        "auth-context-user",
        code,
        code_verifier,
        vec!["openid".to_string()],
        Some(original_auth_time),
        Some("urn:qid:acr:password".to_string()),
        vec!["pwd".to_string()],
        Vec::new(),
    )
    .await;

    let token_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=authorization_code&code={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&client_id=test-client&code_verifier={}",
            urlencoding::encode(code),
            urlencoding::encode(code_verifier)
        )))
        .unwrap();
    let token_response = app.clone().oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_json = json_body(token_response).await;
    let first_access = token_json["access_token"].as_str().unwrap().to_string();
    let first_claims = decode_claims(&state, &first_access);
    assert_eq!(
        first_claims.extra["auth_time"],
        serde_json::json!(original_auth_time)
    );
    assert_eq!(
        first_claims.extra["acr"],
        serde_json::json!("urn:qid:acr:password")
    );
    assert_eq!(first_claims.extra["amr"], serde_json::json!(["pwd"]));
    let first_iat = first_claims.iat.unwrap();
    let refresh_1 = token_json["refresh_token"].as_str().unwrap().to_string();

    let refresh_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=refresh_token&client_id=test-client&refresh_token={}",
            urlencoding::encode(&refresh_1)
        )))
        .unwrap();
    let refresh_response = app.oneshot(refresh_request).await.unwrap();
    assert_eq!(refresh_response.status(), StatusCode::OK);
    let refresh_json = json_body(refresh_response).await;
    let second_access = refresh_json["access_token"].as_str().unwrap().to_string();
    let second_claims = decode_claims(&state, &second_access);
    assert_eq!(
        second_claims.extra["auth_time"],
        serde_json::json!(original_auth_time)
    );
    assert_eq!(
        second_claims.extra["acr"],
        serde_json::json!("urn:qid:acr:password")
    );
    assert_eq!(second_claims.extra["amr"], serde_json::json!(["pwd"]));
    let second_iat = second_claims.iat.unwrap();
    assert!(
        second_iat >= first_iat,
        "refreshed token must advance issuance, got {second_iat} < {first_iat}"
    );
    let stored_jti = second_claims.jti.clone().unwrap();
    let stored = state
        .repo
        .get_access_token(&stored_jti)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.auth_time, Some(original_auth_time));
    assert_eq!(stored.acr.as_deref(), Some("urn:qid:acr:password"));
    assert_eq!(stored.amr, vec!["pwd".to_string()]);
}

#[tokio::test]
async fn refresh_omits_unknown_authentication_context_without_inventing_time() {
    // Legacy/unknown context: omit unavailable claims, never synthesize now.
    let (app, token_path, state) = setup().await;
    let code = "auth-unknown-code-1";
    let code_verifier = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
    create_user_with_code(
        &state,
        "auth-unknown-user",
        code,
        code_verifier,
        vec!["openid".to_string()],
        None,
        None,
        Vec::new(),
        Vec::new(),
    )
    .await;

    let token_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=authorization_code&code={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&client_id=test-client&code_verifier={}",
            urlencoding::encode(code),
            urlencoding::encode(code_verifier)
        )))
        .unwrap();
    let token_response = app.clone().oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_json = json_body(token_response).await;
    let first_access = token_json["access_token"].as_str().unwrap().to_string();
    let first_claims = decode_claims(&state, &first_access);
    assert!(
        !first_claims.extra.contains_key("auth_time"),
        "unknown auth_time must be omitted, got {:?}",
        first_claims.extra.get("auth_time")
    );
    assert!(!first_claims.extra.contains_key("acr"));
    assert!(!first_claims.extra.contains_key("amr"));
    let refresh_1 = token_json["refresh_token"].as_str().unwrap().to_string();

    let refresh_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=refresh_token&client_id=test-client&refresh_token={}",
            urlencoding::encode(&refresh_1)
        )))
        .unwrap();
    let refresh_response = app.oneshot(refresh_request).await.unwrap();
    assert_eq!(refresh_response.status(), StatusCode::OK);
    let refresh_json = json_body(refresh_response).await;
    let second_access = refresh_json["access_token"].as_str().unwrap().to_string();
    let second_claims = decode_claims(&state, &second_access);
    assert!(!second_claims.extra.contains_key("auth_time"));
    assert!(!second_claims.extra.contains_key("acr"));
    assert!(!second_claims.extra.contains_key("amr"));
}

#[tokio::test]
async fn refresh_preserves_authentication_context_for_opaque_tokens() {
    // Opaque counterpart: stored records and introspection carry the original
    // auth_time/acr/amr across refresh with advancing issuance.
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.tokens.access_token_format = TokenFormat::Opaque;
    config.realms[0].protocols.oauth.resource_servers =
        vec![test_server("api://default", &[], "introspection-client")];
    let (app, token_path, state) = setup_with_config(config).await;
    let original_auth_time = util::now_seconds() - 3600;
    let code = "auth-opaque-code-1";
    let code_verifier = "b1c2d3e4f5a60718293a4b5c6d7e8f9012345678";
    create_user_with_code(
        &state,
        "auth-opaque-user",
        code,
        code_verifier,
        vec!["openid".to_string()],
        Some(original_auth_time),
        Some("urn:qid:acr:password".to_string()),
        vec!["pwd".to_string()],
        vec!["https://api.example.com/default".to_string()],
    )
    .await;

    let token_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=authorization_code&code={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&client_id=test-client&code_verifier={}",
            urlencoding::encode(code),
            urlencoding::encode(code_verifier)
        )))
        .unwrap();
    let token_response = app.clone().oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_json = json_body(token_response).await;
    let first_opaque = token_json["access_token"].as_str().unwrap().to_string();
    assert!(first_opaque.starts_with("oat_"));
    let first_jti = qid_oauth::endpoints::decode_opaque_access_token(&first_opaque).unwrap();
    let first_stored = state
        .repo
        .get_access_token(first_jti)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first_stored.auth_time, Some(original_auth_time));
    let refresh_1 = token_json["refresh_token"].as_str().unwrap().to_string();

    let refresh_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=refresh_token&client_id=test-client&refresh_token={}",
            urlencoding::encode(&refresh_1)
        )))
        .unwrap();
    let refresh_response = app.clone().oneshot(refresh_request).await.unwrap();
    assert_eq!(refresh_response.status(), StatusCode::OK);
    let refresh_json = json_body(refresh_response).await;
    let second_opaque = refresh_json["access_token"].as_str().unwrap().to_string();
    assert!(second_opaque.starts_with("oat_"));
    let second_jti = qid_oauth::endpoints::decode_opaque_access_token(&second_opaque).unwrap();
    let second_stored = state
        .repo
        .get_access_token(second_jti)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second_stored.auth_time, Some(original_auth_time));
    assert_eq!(second_stored.acr.as_deref(), Some("urn:qid:acr:password"));
    assert_eq!(second_stored.amr, vec!["pwd".to_string()]);
    assert!(second_stored.issued_at >= first_stored.issued_at);

    let introspection = post_introspect(
        app,
        &state.paths.introspect,
        format!(
            "token={}&client_id=introspection-client&client_secret=secret",
            urlencoding::encode(&second_opaque)
        ),
    )
    .await;
    assert_eq!(introspection["active"], true);
    assert_eq!(
        introspection["auth_time"],
        serde_json::json!(original_auth_time)
    );
    assert_eq!(introspection["acr"], "urn:qid:acr:password");
    assert_eq!(introspection["amr"], serde_json::json!(["pwd"]));
}

#[tokio::test]
async fn refresh_rejects_cross_client_caller_without_consuming() {
    // RFC 6749 section 6: the authenticated caller must own the family.
    // A confidential refresh token must not redeem via another client's
    // authentication, whether by form, Basic, or unauthenticated public use.
    let (app, token_path, state) = setup().await;
    let code = "cross-client-code-1";
    let code_verifier = "c1d2e3f4a5b60718293a4b5c6d7e8f9012345678";
    create_user_with_code(
        &state,
        "cross-client-user",
        code,
        code_verifier,
        vec!["openid".to_string()],
        Some(util::now_seconds() - 60),
        None,
        Vec::new(),
        Vec::new(),
    )
    .await;
    let mut foreign = client_credentials_client("foreign-refresh-client", "client_secret_post");
    foreign.grant_types = vec!["refresh_token".to_string()];
    state.repo.create_client(&foreign).await.unwrap();

    let token_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=authorization_code&code={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&client_id=test-client&code_verifier={}",
            urlencoding::encode(code),
            urlencoding::encode(code_verifier)
        )))
        .unwrap();
    let token_response = app.clone().oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_json = json_body(token_response).await;
    let owner_refresh = token_json["refresh_token"].as_str().unwrap().to_string();

    // Grant-authorized foreign caller by form credentials must fail without
    // consuming: the owner retry below would otherwise hit reuse detection.
    let foreign_form = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=refresh_token&client_id=foreign-refresh-client&client_secret=secret&refresh_token={}",
            urlencoding::encode(&owner_refresh)
        )))
        .unwrap();
    let foreign_form_response = app.clone().oneshot(foreign_form).await.unwrap();
    assert_eq!(foreign_form_response.status(), StatusCode::UNAUTHORIZED);

    // Basic selection must win over a spoofed form client_id.
    let basic = base64::engine::general_purpose::STANDARD.encode("foreign-refresh-client:secret");
    let foreign_basic = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Authorization", format!("Basic {basic}"))
        .body(Body::from(format!(
            "grant_type=refresh_token&client_id=test-client&refresh_token={}",
            urlencoding::encode(&owner_refresh)
        )))
        .unwrap();
    let foreign_basic_response = app.clone().oneshot(foreign_basic).await.unwrap();
    assert_eq!(foreign_basic_response.status(), StatusCode::UNAUTHORIZED);

    // Owner public caller still succeeds: foreign attempts did not consume.
    let owner_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=refresh_token&client_id=test-client&refresh_token={}",
            urlencoding::encode(&owner_refresh)
        )))
        .unwrap();
    let owner_response = app.oneshot(owner_request).await.unwrap();
    assert_eq!(owner_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn opaque_client_credentials_token_introspects_and_revokes() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.tokens.access_token_format = TokenFormat::Opaque;
    config.realms[0].protocols.oauth.resource_servers =
        vec![test_server("api://default", &[], "introspection-client")];
    let (app, token_path, state) = setup_with_config(config).await;

    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=opaque-client&client_secret=secret&scope=api&resource=https%3A%2F%2Fapi.example.com%2Fdefault",
        ))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = json_body(response).await;
    let access_token = json["access_token"].as_str().unwrap();
    assert!(access_token.starts_with("oat_oat_"));
    assert!(
        state.signer.decode_signature_only(access_token).is_err(),
        "opaque access token must not be a JWT"
    );

    let introspect_body = format!(
        "token={}&client_id=introspection-client&client_secret=secret",
        urlencoding::encode(access_token)
    );
    let introspect_response = post_form(
        app.clone(),
        &state.paths.introspect,
        introspect_body.clone(),
    )
    .await;
    assert_eq!(introspect_response.status(), StatusCode::OK);
    let introspection = json_body(introspect_response).await;
    assert_eq!(introspection["active"], true);
    assert_eq!(introspection["client_id"], "opaque-client");
    assert_eq!(introspection["scope"], "api");

    let revoke_body = format!(
        "token={}&client_id=opaque-client&client_secret=secret",
        urlencoding::encode(access_token)
    );
    let revoke_response = post_form(app.clone(), &state.paths.revoke, revoke_body).await;
    assert_eq!(revoke_response.status(), StatusCode::OK);

    let introspect_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.introspect)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "token={}&client_id=introspection-client&client_secret=secret",
            urlencoding::encode(access_token)
        )))
        .unwrap();
    let introspect_response = app.oneshot(introspect_request).await.unwrap();
    assert_eq!(introspect_response.status(), StatusCode::OK);
    let introspection = json_body(introspect_response).await;
    assert_eq!(introspection["active"], false);
}

#[tokio::test]
async fn revocation_requires_client_auth_and_preserves_other_client_tokens() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.resource_servers =
        vec![test_server("api://default", &[], "introspection-client")];
    let (app, token_path, state) = setup_with_config(config).await;

    let token_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=api&resource=https%3A%2F%2Fapi.example.com%2Fdefault",
        ))
        .unwrap();
    let token_response = app.clone().oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_json = json_body(token_response).await;
    let access_token = token_json["access_token"].as_str().unwrap();

    let unauthenticated_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.revoke)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "token={}",
            urlencoding::encode(access_token)
        )))
        .unwrap();
    let unauthenticated_response = app.clone().oneshot(unauthenticated_request).await.unwrap();
    assert_eq!(unauthenticated_response.status(), StatusCode::UNAUTHORIZED);

    let wrong_client_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.revoke)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "token={}&client_id=introspection-client&client_secret=secret",
            urlencoding::encode(access_token)
        )))
        .unwrap();
    let wrong_client_response = app.clone().oneshot(wrong_client_request).await.unwrap();
    assert_eq!(wrong_client_response.status(), StatusCode::OK);

    let introspect_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.introspect)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "token={}&client_id=introspection-client&client_secret=secret",
            urlencoding::encode(access_token)
        )))
        .unwrap();
    let introspect_response = app.oneshot(introspect_request).await.unwrap();
    assert_eq!(introspect_response.status(), StatusCode::OK);
    let introspection = json_body(introspect_response).await;
    assert_eq!(introspection["active"], true);
    assert_eq!(introspection["client_id"], "service-client");
}

#[tokio::test]
async fn revocation_rejects_when_disabled() {
    let (app, token_path, state) = setup_with_oauth(|oauth| oauth.revocation.enabled = false).await;

    let token_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=api",
        ))
        .unwrap();
    let token_response = app.clone().oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_json = json_body(token_response).await;
    let access_token = token_json["access_token"].as_str().unwrap();

    let revoke_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.revoke)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "token={}&client_id=service-client&client_secret=secret",
            urlencoding::encode(access_token)
        )))
        .unwrap();
    let revoke_response = app.oneshot(revoke_request).await.unwrap();
    assert_eq!(revoke_response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn revocation_can_revoke_refresh_token_family() {
    let (app, token_path, state) = setup().await;
    let user = User {
        id: "revocation-user".to_string(),
        realm_id: "test".to_string(),
        email: Some("revocation@example.com".to_string()),
        email_verified: true,
        display_name: Some("Revocation User".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    state.repo.create_user(&user).await.unwrap();

    let code = "refresh-revoke-code-123";
    let code_verifier = "d1c2b3a4e5f60718293a4b5c6d7e8f9012345678";
    let auth_code = AuthorizationCode {
        code_hash: util::sha256_base64url(code),
        client_id: "test-client".to_string(),
        user_id: "revocation-user".to_string(),
        realm_id: "test".to_string(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        state: Some("state-refresh-revoke".to_string()),
        nonce: None,
        auth_time: Some(1234),
        acr: None,
        amr: vec!["pwd".to_string()],
        code_challenge: Some(util::sha256_base64url(code_verifier)),
        code_challenge_method: Some("S256".to_string()),
        scopes: vec!["openid".to_string()],
        resource: Vec::new(),
        authorization_details: None,
        expires_at: util::now_seconds() + 300,
        used: false,
        created_at: util::now_seconds(),
        session_id: None,
    };
    state
        .repo
        .create_authorization_code(&auth_code)
        .await
        .unwrap();

    let token_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=authorization_code&code={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&client_id=test-client&code_verifier={}",
            urlencoding::encode(code),
            urlencoding::encode(code_verifier)
        )))
        .unwrap();
    let token_response = app.clone().oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_json = json_body(token_response).await;
    let refresh_token = token_json["refresh_token"].as_str().unwrap();

    let revoke_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.revoke)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "token={}&token_type_hint=refresh_token&client_id=test-client",
            urlencoding::encode(refresh_token)
        )))
        .unwrap();
    let revoke_response = app.clone().oneshot(revoke_request).await.unwrap();
    assert_eq!(revoke_response.status(), StatusCode::OK);

    let refresh_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=refresh_token&client_id=test-client&refresh_token={}",
            urlencoding::encode(refresh_token)
        )))
        .unwrap();
    let refresh_response = app.oneshot(refresh_request).await.unwrap();
    assert_eq!(refresh_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_introspection_response_requires_config_flag() {
    let (app, token_path, state) = setup().await;

    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=introspection-client&client_secret=secret&scope=api",
        ))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = json_body(response).await;
    let access_token = json["access_token"].as_str().unwrap();

    let request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.introspect)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "token={}&client_id=introspection-client&client_secret=secret&response_format=jwt",
            urlencoding::encode(access_token)
        )))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn jwt_introspection_response_returns_signed_response_when_enabled() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.introspection.jwt_response = true;
    config.realms[0].protocols.oauth.resource_servers = vec![test_server(
        "api://default",
        &[],
        "introspection-jwt-client",
    )];
    let (app, token_path, state) = setup_with_config(config).await;

    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=introspection-jwt-client&client_secret=secret&scope=api&resource=https%3A%2F%2Fapi.example.com%2Fdefault",
        ))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = json_body(response).await;
    let access_token = json["access_token"].as_str().unwrap();

    let request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.introspect)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "token={}&client_id=introspection-jwt-client&client_secret=secret&response_format=jwt",
            urlencoding::encode(access_token)
        )))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = json_body(response).await;
    assert_eq!(json["active"], true);
    let token_introspection = json["token_introspection"].as_str().unwrap();
    let claims = decode_claims(&state, token_introspection);
    assert_eq!(claims.extra["active"], true);
    assert_eq!(claims.extra["client_id"], "introspection-jwt-client");
    assert_eq!(claims.extra["scope"], "api");
}

#[tokio::test]
async fn introspection_enforces_resource_server_policy() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.introspection.jwt_response = true;
    config.realms[0].protocols.oauth.resource_servers = vec![
        test_server("api://profile", &["api"], "introspection-client"),
        test_server("api://payments", &["payments"], "introspection-client"),
    ];
    let (app, token_path, state) = setup_with_config(config).await;

    let token_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=api&resource=https%3A%2F%2Fapi.example.com%2Fprofile",
        ))
        .unwrap();
    let token_response = app.clone().oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_json = json_body(token_response).await;
    let access_token = token_json["access_token"].as_str().unwrap();

    let unauthenticated_body = format!("token={}", urlencoding::encode(access_token));
    let unauthenticated_response =
        post_form(app.clone(), &state.paths.introspect, unauthenticated_body).await;
    assert_eq!(unauthenticated_response.status(), StatusCode::UNAUTHORIZED);

    let allowed_body = format!(
        "token={}&client_id=introspection-client&client_secret=secret&resource=https%3A%2F%2Fapi.example.com%2Fprofile&response_format=jwt",
        urlencoding::encode(access_token)
    );
    let allowed_response = post_form(app.clone(), &state.paths.introspect, allowed_body).await;
    assert_eq!(allowed_response.status(), StatusCode::OK);
    let introspection = json_body(allowed_response).await;
    assert_eq!(introspection["active"], true);
    assert_eq!(introspection["client_id"], "service-client");
    assert_eq!(introspection["scope"], "api");
    assert_eq!(introspection["aud"], serde_json::json!(["api://profile"]));
    assert_eq!(
        introspection["resource"],
        serde_json::json!(["https://api.example.com/profile"])
    );
    let token_introspection = introspection["token_introspection"].as_str().unwrap();
    let claims = decode_claims(&state, token_introspection);
    assert_eq!(claims.aud_primary(), Some("introspection-client"));
    assert_eq!(claims.extra["client_id"], "service-client");
    assert_eq!(
        claims.extra["resource"],
        serde_json::json!(["https://api.example.com/profile"])
    );

    let wrong_resource_body = format!(
        "token={}&client_id=introspection-client&client_secret=secret&resource=https%3A%2F%2Fapi.example.com%2Fpayments",
        urlencoding::encode(access_token)
    );
    let wrong_resource_response =
        post_form(app, &state.paths.introspect, wrong_resource_body).await;
    assert_eq!(wrong_resource_response.status(), StatusCode::OK);
    let wrong_resource = json_body(wrong_resource_response).await;
    assert_eq!(wrong_resource["active"], false);
    assert!(wrong_resource.get("client_id").is_none());
}

#[tokio::test]
async fn authorization_code_grant_succeeds() {
    let (app, token_path, state) = setup().await;

    // Prepare: create a user and an authorization code in the repository.
    let user = User {
        id: "test-user".to_string(),
        realm_id: "test".to_string(),
        email: Some("user@example.com".to_string()),
        email_verified: true,
        display_name: Some("Test User".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    state.repo.create_user(&user).await.unwrap();

    let code = "test-auth-code-123";
    let code_hash = util::sha256_base64url(code);
    let code_verifier = "e9b6c8a7d5f4e3c2b1a0d9f8e7c6b5a4d3f2e1c0";
    let code_challenge = util::sha256_base64url(code_verifier);

    let auth_code = AuthorizationCode {
        code_hash,
        client_id: "test-client".to_string(),
        user_id: "test-user".to_string(),
        realm_id: "test".to_string(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        state: Some("state-auth-code".to_string()),
        nonce: Some("nonce-auth-code".to_string()),
        auth_time: Some(1234),
        acr: Some("urn:qid:acr:password".to_string()),
        amr: vec!["pwd".to_string()],
        code_challenge: Some(code_challenge),
        code_challenge_method: Some("S256".to_string()),
        scopes: vec!["openid".to_string(), "profile".to_string()],
        resource: vec!["https://api.example.com".to_string()],
        authorization_details: Some(serde_json::json!([
            {
                "type": "payment_initiation",
                "actions": ["read", "confirm"],
                "locations": ["https://api.example.com/payments"]
            }
        ])),
        expires_at: util::now_seconds() + 3600,
        used: false,
        created_at: util::now_seconds(),
        session_id: None,
    };
    state
        .repo
        .create_authorization_code(&auth_code)
        .await
        .unwrap();

    // Exchange code for tokens.
    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri=https://app.example.com/callback&code_verifier={}",
        code, code_verifier
    );
    let response = post_form(app.clone(), &token_path, body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = json_body(response).await;
    let access_token = json["access_token"].as_str().unwrap();
    let access_claims = decode_claims(&state, access_token);
    assert_eq!(
        access_claims.extra["resource"],
        serde_json::json!(["https://api.example.com"])
    );
    assert_eq!(
        access_claims.extra["authorization_details"],
        serde_json::json!([
            {
                "type": "payment_initiation",
                "actions": ["read", "confirm"],
                "locations": ["https://api.example.com/payments"]
            }
        ])
    );
    assert_eq!(access_claims.extra["auth_time"], serde_json::json!(1234));
    assert_eq!(
        access_claims.extra["acr"],
        serde_json::json!("urn:qid:acr:password")
    );
    assert_eq!(access_claims.extra["amr"], serde_json::json!(["pwd"]));
    assert_eq!(
        access_claims.extra["nonce"],
        serde_json::json!("nonce-auth-code")
    );
    let id_token = json["id_token"].as_str().unwrap();
    let id_claims = state.signer.decode_signature_only(id_token).unwrap().claims;
    assert_eq!(
        id_claims.extra["nonce"],
        serde_json::json!("nonce-auth-code")
    );
    assert_eq!(id_claims.extra["auth_time"], serde_json::json!(1234));

    let refresh_token = json["refresh_token"].as_str().unwrap();
    let refresh_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=refresh_token&client_id=test-client&refresh_token={}",
            urlencoding::encode(refresh_token)
        )))
        .unwrap();
    let refresh_response = app.oneshot(refresh_request).await.unwrap();
    assert_eq!(refresh_response.status(), StatusCode::OK);
    let refresh_json = json_body(refresh_response).await;
    let refreshed_access = refresh_json["access_token"].as_str().unwrap();
    let refreshed_claims = decode_claims(&state, refreshed_access);
    assert_eq!(
        refreshed_claims.extra["resource"],
        serde_json::json!(["https://api.example.com"])
    );
    assert_eq!(
        refreshed_claims.extra["authorization_details"],
        serde_json::json!([
            {
                "type": "payment_initiation",
                "actions": ["read", "confirm"],
                "locations": ["https://api.example.com/payments"]
            }
        ])
    );
}

#[tokio::test]
async fn authorization_code_grant_wrong_verifier_fails() {
    let (app, token_path, state) = setup().await;

    let user = User {
        id: "test-user-2".to_string(),
        realm_id: "test".to_string(),
        email: Some("user2@example.com".to_string()),
        email_verified: true,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    state.repo.create_user(&user).await.unwrap();

    let code = "test-auth-code-wrong-vf";
    let code_hash = util::sha256_base64url(code);
    let code_challenge = util::sha256_base64url("correct-verifier");

    let auth_code = AuthorizationCode {
        code_hash,
        client_id: "test-client".to_string(),
        user_id: "test-user-2".to_string(),
        realm_id: "test".to_string(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        state: None,
        nonce: None,
        auth_time: None,
        acr: None,
        amr: Vec::new(),
        code_challenge: Some(code_challenge),
        code_challenge_method: Some("S256".to_string()),
        scopes: vec!["openid".to_string()],
        resource: Vec::new(),
        authorization_details: None,
        expires_at: util::now_seconds() + 3600,
        used: false,
        created_at: util::now_seconds(),
        session_id: None,
    };
    state
        .repo
        .create_authorization_code(&auth_code)
        .await
        .unwrap();

    // Use wrong verifier
    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri=https://app.example.com/callback&code_verifier=wrong-verifier",
        code
    );
    let response = post_form(app, &token_path, body).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn client_credentials_grant_missing_client_id_fails() {
    let (app, token_path, _) = setup().await;

    let body = "grant_type=client_credentials&scope=api";
    let response = post_form(app, &token_path, body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unsupported_grant_type_fails() {
    let (app, token_path, _) = setup().await;

    let body = "grant_type=password&username=test&password=test";
    let response = post_form(app, &token_path, body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn dynamic_client_registration_creates_client() {
    let mut config = test_helpers::test_config();
    config.realms[0]
        .protocols
        .oauth
        .dynamic_client_registration
        .enabled = true;
    config.realms[0]
        .protocols
        .oauth
        .dynamic_client_registration
        .allow_open_registration = true;
    let (app, _, state) = setup_with_config(config).await;
    let path = state.paths.dynamic_client_registration.clone();

    let request = Request::builder()
        .method(Method::POST)
        .uri(&path)
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"client_id":"dcr-client","redirect_uris":["https://app.example.com/cb"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"none"}"#,
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let client = state
        .repo
        .get_client_by_client_id(&RealmId::from("test"), "dcr-client")
        .await
        .unwrap();
    assert!(client.is_some(), "DCR should persist the registered client");
}

#[tokio::test]
async fn dynamic_client_registration_returns_secret_for_confidential_client() {
    let mut config = test_helpers::test_config();
    config.realms[0]
        .protocols
        .oauth
        .dynamic_client_registration
        .enabled = true;
    config.realms[0]
        .protocols
        .oauth
        .dynamic_client_registration
        .allow_open_registration = true;
    let (app, _, state) = setup_with_config(config).await;
    let path = state.paths.dynamic_client_registration.clone();

    let request = Request::builder()
        .method(Method::POST)
        .uri(&path)
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"client_id":"dcr-secret-client","redirect_uris":["https://app.example.com/cb"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"client_secret_basic"}"#,
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = json_body(response).await;
    let secret = json["client_secret"].as_str().unwrap();
    assert!(secret.starts_with("secret_"));
    assert!(json["registration_access_token"].as_str().unwrap().len() > 20);
    assert_eq!(
        json["registration_client_uri"],
        "https://id.example.com/oauth2/register/dcr-secret-client"
    );

    let client = state
        .repo
        .get_client_by_client_id(&RealmId::from("test"), "dcr-secret-client")
        .await
        .unwrap()
        .expect("DCR should persist confidential client");
    let expected_hash = qid_core::util::client_secret_hash(secret);
    assert_eq!(
        client.client_secret_hash.as_deref(),
        Some(expected_hash.as_str())
    );
}

#[tokio::test]
async fn dynamic_client_registration_management_updates_client() {
    let mut config = test_helpers::test_config();
    config.realms[0]
        .protocols
        .oauth
        .dynamic_client_registration
        .enabled = true;
    config.realms[0]
        .protocols
        .oauth
        .dynamic_client_registration
        .allow_open_registration = true;
    let (app, _, state) = setup_with_config(config).await;
    let create_path = state.paths.dynamic_client_registration.clone();
    let create_request = Request::builder()
        .method(Method::POST)
        .uri(&create_path)
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"client_id":"dcr-managed-client","redirect_uris":["https://app.example.com/cb"],"grant_types":["client_credentials"],"token_endpoint_auth_method":"client_secret_post"}"#,
        ))
        .unwrap();
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::OK);
    let create_json = json_body(create_response).await;
    let secret = create_json["client_secret"].as_str().unwrap();
    let registration_access_token = create_json["registration_access_token"].as_str().unwrap();
    assert_eq!(
        create_json["registration_client_uri"],
        "https://id.example.com/oauth2/register/dcr-managed-client"
    );

    let update_path = state
        .paths
        .dynamic_client_registration_management
        .replace(":client_id", "dcr-managed-client");
    let update_request = Request::builder()
        .method(Method::PUT)
        .uri(&update_path)
        .header("Content-Type", "application/json")
        .header(
            "Authorization",
            format!("Bearer {registration_access_token}"),
        )
        .body(Body::from(
            r#"{"client_id":"dcr-managed-client","redirect_uris":["https://app.example.com/updated"],"grant_types":["client_credentials"],"token_endpoint_auth_method":"client_secret_post"}"#,
        ))
        .unwrap();
    let update_response = app.clone().oneshot(update_request).await.unwrap();
    assert_eq!(update_response.status(), StatusCode::OK);
    let json = json_body(update_response).await;
    assert!(json.get("client_secret").is_none());
    assert!(json["registration_access_token"].as_str().unwrap().len() > 20);

    let client = state
        .repo
        .get_client_by_client_id(&RealmId::from("test"), "dcr-managed-client")
        .await
        .unwrap()
        .expect("DCR management update should preserve client");
    assert_eq!(client.client_type, ClientType::Confidential);
    assert_eq!(client.token_endpoint_auth_method, "client_secret_post");
    assert_eq!(
        client.redirect_uris,
        vec!["https://app.example.com/updated"]
    );
    assert_eq!(client.grant_types, vec!["client_credentials"]);
    assert_eq!(
        client.client_secret_hash.as_deref(),
        Some(qid_core::util::client_secret_hash(secret).as_str())
    );

    let get_request = Request::builder()
        .method(Method::GET)
        .uri(&update_path)
        .header(
            "Authorization",
            format!("Bearer {registration_access_token}"),
        )
        .body(Body::empty())
        .unwrap();
    let get_response = app.oneshot(get_request).await.unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    let get_json = json_body(get_response).await;
    assert_eq!(
        get_json["registration_client_uri"],
        "https://id.example.com/oauth2/register/dcr-managed-client"
    );
    assert!(
        get_json["registration_access_token"]
            .as_str()
            .unwrap()
            .len()
            > 20
    );
    assert!(get_json.get("client_secret").is_none());
}

#[tokio::test]
async fn dynamic_client_registration_management_rejects_client_id_mismatch() {
    let mut config = test_helpers::test_config();
    config.realms[0]
        .protocols
        .oauth
        .dynamic_client_registration
        .enabled = true;
    let (app, _, state) = setup_with_config(config).await;
    let update_path = state
        .paths
        .dynamic_client_registration_management
        .replace(":client_id", "dcr-path-client");
    let request = Request::builder()
        .method(Method::PUT)
        .uri(&update_path)
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"client_id":"dcr-body-client","redirect_uris":["https://app.example.com/cb"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"none"}"#,
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn dynamic_client_registration_rejects_unsupported_auth_method() {
    let mut config = test_helpers::test_config();
    config.realms[0]
        .protocols
        .oauth
        .dynamic_client_registration
        .enabled = true;
    config.realms[0]
        .protocols
        .oauth
        .dynamic_client_registration
        .allow_open_registration = true;
    let (app, _, state) = setup_with_config(config).await;
    let path = state.paths.dynamic_client_registration.clone();
    let request = Request::builder()
        .method(Method::POST)
        .uri(&path)
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"client_id":"bad-client","redirect_uris":["https://app.example.com/cb"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"client_secret_jwt"}"#,
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn dynamic_client_registration_is_disabled_by_default() {
    let (app, _, state) = setup().await;
    let request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.dynamic_client_registration)
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"client_id":"disabled-dcr","redirect_uris":["https://app.example.com/cb"],"grant_types":["authorization_code"],"token_endpoint_auth_method":"none"}"#,
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn dynamic_client_registration_management_requires_client_auth() {
    let mut config = test_helpers::test_config();
    config.realms[0]
        .protocols
        .oauth
        .dynamic_client_registration
        .enabled = true;
    config.realms[0]
        .protocols
        .oauth
        .dynamic_client_registration
        .allow_open_registration = true;
    let (app, _, state) = setup_with_config(config).await;
    let create_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.dynamic_client_registration)
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"client_id":"dcr-auth-required","redirect_uris":["https://app.example.com/cb"],"grant_types":["client_credentials"],"token_endpoint_auth_method":"client_secret_post"}"#,
        ))
        .unwrap();
    let create_response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(create_response.status(), StatusCode::OK);

    let update_path = state
        .paths
        .dynamic_client_registration_management
        .replace(":client_id", "dcr-auth-required");
    let unauthenticated_request = Request::builder()
        .method(Method::GET)
        .uri(&update_path)
        .body(Body::empty())
        .unwrap();
    let unauthenticated_response = app.oneshot(unauthenticated_request).await.unwrap();
    assert_eq!(unauthenticated_response.status(), StatusCode::UNAUTHORIZED);
}

fn device_test_client(id: &str, client_id: &str) -> Client {
    let mut client = base_test_client(
        client_id,
        ClientType::Public,
        "none",
        vec!["urn:ietf:params:oauth:grant-type:device_code".to_string()],
    );
    client.id = id.to_string();
    client
}

#[tokio::test]
async fn device_authorization_returns_codes_for_known_client() {
    let mut config = test_helpers::test_config();
    config.realms[0]
        .protocols
        .oauth
        .device_authorization
        .enabled = true;
    let (app, _, state) = setup_with_config(config).await;
    state
        .repo
        .create_client(&device_test_client("device-client-id", "device-client"))
        .await
        .unwrap();

    let response = post_form(
        app.clone(),
        &state.paths.device_authorization,
        "client_id=device-client&scope=api",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = json_body(response).await;
    let device_code = json["device_code"].as_str().unwrap();
    let user_code = json["user_code"].as_str().unwrap();
    assert!(device_code.starts_with("dc_"));
    // 128-bit device secret (`dc_` + 22 base64url chars), independent of the user code.
    assert_eq!(device_code.len(), 3 + 22);
    let user_fragment = user_code.strip_prefix("QID-").unwrap();
    assert!(
        json["verification_uri"]
            .as_str()
            .unwrap()
            .ends_with("/oauth2/device")
    );

    // A second issuance draws fresh randomness: nothing repeats and neither
    // user code shares a fragment with either device secret.
    let second = json_body(
        post_form(
            app,
            &state.paths.device_authorization,
            "client_id=device-client&scope=api",
        )
        .await,
    )
    .await;
    let device_2 = second["device_code"].as_str().unwrap();
    let user_2 = second["user_code"].as_str().unwrap();
    assert_ne!(device_2, device_code);
    assert_ne!(user_2, user_code);
    let fragment_2 = user_2.strip_prefix("QID-").unwrap();
    assert!(!device_2.contains(user_fragment));
    assert!(!device_code.contains(fragment_2));
}

#[tokio::test]
async fn device_verification_uri_reaches_interaction_page() {
    let mut config = test_helpers::test_config();
    config.realms[0]
        .protocols
        .oauth
        .device_authorization
        .enabled = true;
    let (app, _, state) = setup_with_config(config).await;
    state
        .repo
        .create_client(&device_test_client("device-verify-id", "device-verify"))
        .await
        .unwrap();

    let json = post_token_json(
        app.clone(),
        &state.paths.device_authorization,
        "client_id=device-verify&scope=api".to_string(),
    )
    .await;
    let user_code = json["user_code"].as_str().unwrap();
    let verification_uri = json["verification_uri"].as_str().unwrap();
    let complete_uri = json["verification_uri_complete"].as_str().unwrap();
    assert!(complete_uri.contains(user_code));

    // The bare URI serves code entry, not grant creation.
    let entry = get_response(app.clone(), verification_uri).await;
    assert_eq!(entry.status(), StatusCode::OK);
    assert_eq!(entry.headers()["content-type"], "text/html; charset=utf-8");

    // The complete URI reaches the approval interaction for the grant.
    let page = get_response(app.clone(), complete_uri).await;
    assert_eq!(page.status(), StatusCode::OK);
    let html = String::from_utf8(
        page.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains(user_code));
    assert!(html.contains("device-verify"));
    assert!(html.contains("approve"));

    // Unknown codes fail closed; the interaction path accepts no POSTs.
    let missing = get_response(app.clone(), "/oauth2/device?user_code=QID-UNKNOWN").await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    let post_to_page = post_form(app, verification_uri, "user_code=whatever").await;
    assert_eq!(post_to_page.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn device_authorization_is_disabled_by_default() {
    let (app, _, state) = setup().await;
    state
        .repo
        .create_client(&device_test_client(
            "device-disabled-client-id",
            "device-disabled-client",
        ))
        .await
        .unwrap();

    let response = post_form(
        app,
        &state.paths.device_authorization,
        "client_id=device-disabled-client&scope=api",
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn device_code_grant_requires_approval_then_consumes_code() {
    let mut config = test_helpers::test_config();
    config.realms[0]
        .protocols
        .oauth
        .device_authorization
        .enabled = true;
    config.realms[0].protocols.oauth.dpop.enabled = true;
    let cookie_name = config.realms[0].sessions.browser.cookie_name.clone();
    let (app, token_path, state) = setup_with_config(config).await;
    state
        .repo
        .create_client(&device_test_client(
            "device-client-flow-id",
            "device-client-flow",
        ))
        .await
        .unwrap();
    state
        .repo
        .create_user(&User {
            id: "device-user".to_string(),
            realm_id: "test".to_string(),
            email: Some("device@example.com".to_string()),
            email_verified: true,
            display_name: Some("Device User".to_string()),
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .unwrap();

    let authorize_response = post_form(
        app.clone(),
        &state.paths.device_authorization,
        "client_id=device-client-flow&scope=api",
    )
    .await;
    assert_eq!(authorize_response.status(), StatusCode::OK);
    let json = json_body(authorize_response).await;
    let device_code = json["device_code"].as_str().unwrap();
    let user_code = json["user_code"].as_str().unwrap();

    let pending_body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=device-client-flow&device_code={device_code}"
    );
    let pending_response = post_form(app.clone(), &token_path, pending_body.clone()).await;
    assert_eq!(pending_response.status(), StatusCode::UNAUTHORIZED);
    let first_poll_grant = state
        .repo
        .get_device_authorization_grant(&util::sha256_base64url(device_code))
        .await
        .unwrap()
        .expect("device grant should exist after first poll");
    assert_eq!(first_poll_grant.poll_interval_seconds, 5);
    assert!(first_poll_grant.last_poll_at.is_some());

    let slow_down_response = post_form(app.clone(), &token_path, pending_body.clone()).await;
    assert_eq!(slow_down_response.status(), StatusCode::UNAUTHORIZED);
    let throttled_grant = state
        .repo
        .get_device_authorization_grant(&util::sha256_base64url(device_code))
        .await
        .unwrap()
        .expect("device grant should exist after slow_down");
    assert_eq!(throttled_grant.poll_interval_seconds, 10);

    let sessions = SessionManager::new(state.repo.clone(), 60, 24);
    let session = sessions
        .create("test", "device-user", "password", &["password".to_string()])
        .await
        .unwrap();

    let approve_path = format!("{}/approve", state.paths.device_authorization);
    let approve_request = Request::builder()
        .method(Method::POST)
        .uri(&approve_path)
        .header("Content-Type", "application/json")
        .header("Cookie", format!("{cookie_name}={}", session.id))
        .body(Body::from(format!(
            r#"{{"user_code":"{user_code}","user_id":"device-user"}}"#
        )))
        .unwrap();
    let approve_response = app.clone().oneshot(approve_request).await.unwrap();
    assert_eq!(approve_response.status(), StatusCode::OK);

    let token_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("DPoP", build_dpop_proof("device-code-dpop-response"))
        .body(Body::from(pending_body.clone()))
        .unwrap();
    let token_response = app.clone().oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_json = json_body(token_response).await;
    assert_eq!(token_json["token_type"], "DPoP");

    let replay_response = post_form(app, &token_path, pending_body).await;
    assert_eq!(replay_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ciba_flow_requires_approval_then_consumes_auth_req_id() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.ciba.enabled = true;
    config.realms[0].protocols.oauth.dpop.enabled = true;
    let (app, token_path, state) = setup_with_config(config).await;
    let user = User {
        id: "ciba-user".to_string(),
        realm_id: "test".to_string(),
        email: Some("ciba@example.com".to_string()),
        email_verified: true,
        display_name: Some("CIBA User".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    state.repo.create_user(&user).await.unwrap();

    let request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.backchannel_authentication)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "client_id=ciba-client&client_secret=secret&login_hint=ciba%40example.com&binding_message=login-123&scope=openid",
        ))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = json_body(response).await;
    let auth_req_id = json["auth_req_id"].as_str().unwrap();

    let pending_body = format!(
        "grant_type=urn:openid:params:grant-type:ciba&client_id=ciba-client&client_secret=secret&auth_req_id={auth_req_id}"
    );
    let pending_response = post_form(app.clone(), &token_path, pending_body.clone()).await;
    assert_eq!(pending_response.status(), StatusCode::UNAUTHORIZED);
    let first_poll_grant = state
        .repo
        .get_backchannel_authentication_grant(&util::sha256_base64url(auth_req_id))
        .await
        .unwrap()
        .expect("CIBA grant should exist after first poll");
    assert_eq!(first_poll_grant.poll_interval_seconds, 5);
    assert!(first_poll_grant.last_poll_at.is_some());

    let slow_down_response = post_form(app.clone(), &token_path, pending_body.clone()).await;
    assert_eq!(slow_down_response.status(), StatusCode::UNAUTHORIZED);
    let throttled_grant = state
        .repo
        .get_backchannel_authentication_grant(&util::sha256_base64url(auth_req_id))
        .await
        .unwrap()
        .expect("CIBA grant should exist after slow_down");
    assert_eq!(throttled_grant.poll_interval_seconds, 10);

    // Create a session so the CIBA approval can verify the user's identity.
    let cookie_name = &state.config.realms[0].sessions.browser.cookie_name.clone();
    let sessions = SessionManager::new(state.repo.clone(), 15, 1);
    let session = sessions
        .create("test", "ciba-user", "password", &[])
        .await
        .unwrap();
    let cookie_value = format!("{}={}", cookie_name, session.id);

    let approve_path = format!("{}/approve", state.paths.backchannel_authentication);
    let approve_request = Request::builder()
        .method(Method::POST)
        .uri(&approve_path)
        .header("Content-Type", "application/json")
        .header(axum::http::header::COOKIE, &cookie_value)
        .body(Body::from(
            serde_json::json!({
                "auth_req_id": auth_req_id,
                "user_id": "ciba-user"
            })
            .to_string(),
        ))
        .unwrap();
    let approve_response = app.clone().oneshot(approve_request).await.unwrap();
    assert_eq!(approve_response.status(), StatusCode::OK);

    let token_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("DPoP", build_dpop_proof("ciba-dpop-response"))
        .body(Body::from(pending_body.clone()))
        .unwrap();
    let token_response = app.clone().oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_json = json_body(token_response).await;
    assert_eq!(token_json["token_type"], "DPoP");
    assert!(token_json["id_token"].as_str().unwrap().len() > 10);

    let replay_response = post_form(app, &token_path, pending_body).await;
    assert_eq!(replay_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn authorization_code_used_twice_fails() {
    let (app, token_path, state) = setup().await;

    let user = User {
        id: "test-user-replay".to_string(),
        realm_id: "test".to_string(),
        email: Some("replay@example.com".to_string()),
        email_verified: true,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    state.repo.create_user(&user).await.unwrap();

    let code = "replay-code";
    let code_hash = util::sha256_base64url(code);
    let verifier = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";
    let challenge = util::sha256_base64url(verifier);

    let auth_code = AuthorizationCode {
        code_hash: code_hash.clone(),
        client_id: "test-client".to_string(),
        user_id: "test-user-replay".to_string(),
        realm_id: "test".to_string(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        state: None,
        nonce: None,
        auth_time: None,
        acr: None,
        amr: Vec::new(),
        code_challenge: Some(challenge),
        code_challenge_method: Some("S256".to_string()),
        scopes: vec!["openid".to_string()],
        resource: Vec::new(),
        authorization_details: None,
        expires_at: util::now_seconds() + 3600,
        used: false,
        created_at: util::now_seconds(),
        session_id: None,
    };
    state
        .repo
        .create_authorization_code(&auth_code)
        .await
        .unwrap();

    // First use - should succeed
    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri=https://app.example.com/callback&code_verifier={}",
        code, verifier
    );
    let resp1 = post_form(app.clone(), &token_path, body.clone()).await;
    assert_eq!(resp1.status(), StatusCode::OK);

    // Second use with same code - should fail
    let resp2 = post_form(app, &token_path, body).await;
    assert_eq!(resp2.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn authorization_code_expired_fails() {
    let (app, token_path, state) = setup().await;

    let user = User {
        id: "user-expired".to_string(),
        realm_id: "test".to_string(),
        email: Some("expired@example.com".to_string()),
        email_verified: true,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    state.repo.create_user(&user).await.unwrap();

    let code = "expired-code";
    let code_hash = util::sha256_base64url(code);
    let verifier = "x1y2z3w4v5u6t7s8r9q0p1o2i3u4y5t6r7e8w9q0";
    let challenge = util::sha256_base64url(verifier);

    let auth_code = AuthorizationCode {
        code_hash,
        client_id: "test-client".to_string(),
        user_id: "user-expired".to_string(),
        realm_id: "test".to_string(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        state: None,
        nonce: None,
        auth_time: None,
        acr: None,
        amr: Vec::new(),
        code_challenge: Some(challenge),
        code_challenge_method: Some("S256".to_string()),
        scopes: vec!["openid".to_string()],
        resource: Vec::new(),
        authorization_details: None,
        expires_at: util::now_seconds() - 10,
        used: false,
        created_at: util::now_seconds() - 3600,
        session_id: None,
    };
    state
        .repo
        .create_authorization_code(&auth_code)
        .await
        .unwrap();

    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri=https://app.example.com/callback&code_verifier={}",
        code, verifier
    );
    let response = post_form(app, &token_path, body).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn introspection_fails_closed_without_resource_servers() {
    let (app, token_path, state) = setup().await;

    let token_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=api",
        ))
        .unwrap();
    let token_response = app.clone().oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_json = json_body(token_response).await;
    let access_token = token_json["access_token"].as_str().unwrap().to_string();

    for body in [
        format!("token={}", urlencoding::encode(&access_token)),
        "token=invalid-token-value".to_string(),
    ] {
        let request = Request::builder()
            .method(Method::POST)
            .uri(&state.paths.introspect)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let authenticated_body = format!(
        "token={}&client_id=service-client&client_secret=secret",
        urlencoding::encode(&access_token)
    );
    let authenticated_response =
        post_form(app.clone(), &state.paths.introspect, authenticated_body).await;
    assert_eq!(authenticated_response.status(), StatusCode::UNAUTHORIZED);

    let invalid_authenticated_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.introspect)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "token=invalid-token-value&client_id=service-client&client_secret=secret",
        ))
        .unwrap();
    let invalid_authenticated_response = app.oneshot(invalid_authenticated_request).await.unwrap();
    assert_eq!(invalid_authenticated_response.status(), StatusCode::OK);
    let introspection = json_body(invalid_authenticated_response).await;
    assert_eq!(introspection["active"], false);
}

#[tokio::test]
async fn introspection_rejects_unauthenticated_invalid_token_with_resource_servers() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.resource_servers =
        vec![test_server("api://default", &[], "introspection-client")];
    let (app, _, state) = setup_with_config(config).await;

    let response = post_form(app, &state.paths.introspect, "token=invalid-token-value").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

struct FailingIntrospectionSigner {
    inner: LocalSigner,
}

impl qid_core::jwt::Signer for FailingIntrospectionSigner {
    fn sign(&self, _claims: &JwtClaims) -> anyhow::Result<String> {
        anyhow::bail!("introspection signing unavailable")
    }
    fn sign_with_typ(&self, _claims: &JwtClaims, _typ: &str) -> anyhow::Result<String> {
        anyhow::bail!("introspection signing unavailable")
    }
    fn decode_signature_only(
        &self,
        token: &str,
    ) -> anyhow::Result<qid_core::jwt::TokenData<JwtClaims>> {
        self.inner.decode_signature_only(token)
    }
    fn decode_with_aud(
        &self,
        token: &str,
        expected_audience: &str,
    ) -> anyhow::Result<qid_core::jwt::TokenData<JwtClaims>> {
        self.inner.decode_with_aud(token, expected_audience)
    }
    fn algorithm(&self) -> &'static str {
        self.inner.algorithm()
    }
}

#[tokio::test]
async fn jwt_introspection_signing_failure_fails_closed_without_disclosure() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.introspection.jwt_response = true;
    config.realms[0].protocols.oauth.resource_servers = vec![test_server(
        "api://default",
        &[],
        "introspection-jwt-client",
    )];
    let (app, token_path, state) = setup_with_config(config.clone()).await;

    let token_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=introspection-jwt-client&client_secret=secret&scope=api&resource=https%3A%2F%2Fapi.example.com%2Fdefault",
        ))
        .unwrap();
    let token_response = app.oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_json = json_body(token_response).await;
    let access_token = token_json["access_token"].as_str().unwrap().to_string();

    // Same repo/config/paths but a signer that fails every signature.
    let failing_signer = Arc::new(FailingIntrospectionSigner {
        inner: LocalSigner::from_secret("test", b"test-secret-for-tests"),
    });
    let failing_state = Arc::new(
        SharedState::new(
            config,
            state.repo.clone(),
            failing_signer,
            serde_json::json!({ "keys": [] }),
        )
        .unwrap(),
    );
    let failing_app = qid_oauth::routes(&failing_state.paths).with_state(failing_state.clone());

    // Requested JWT form must fail closed, not downgrade to unsigned active:true.
    let jwt_request = Request::builder()
        .method(Method::POST)
        .uri(&failing_state.paths.introspect)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "token={}&client_id=introspection-jwt-client&client_secret=secret&response_format=jwt",
            urlencoding::encode(&access_token)
        )))
        .unwrap();
    let jwt_response = failing_app.clone().oneshot(jwt_request).await.unwrap();
    assert!(
        jwt_response.status().is_client_error() || jwt_response.status().is_server_error(),
        "signing failure must not return success, got {}",
        jwt_response.status()
    );
    let body = json_body(jwt_response).await;
    assert!(
        body.get("active").is_none(),
        "signing failure must not disclose token metadata, got {body}"
    );
    assert!(
        body.get("sub").is_none() && body.get("token_introspection").is_none(),
        "signing failure must not disclose token metadata, got {body}"
    );

    // Ordinary JSON introspection without a requested signature still works.
    let json_request = Request::builder()
        .method(Method::POST)
        .uri(&failing_state.paths.introspect)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "token={}&client_id=introspection-jwt-client&client_secret=secret",
            urlencoding::encode(&access_token)
        )))
        .unwrap();
    let json_response = failing_app.oneshot(json_request).await.unwrap();
    assert_eq!(json_response.status(), StatusCode::OK);
    let json = json_body(json_response).await;
    assert_eq!(json["active"], true);
    assert!(json.get("token_introspection").is_none());
}

#[tokio::test]
async fn multi_audience_issuance_names_every_resource_server() {
    let (app, token_path, state) = setup_with_oauth(|oauth| {
        oauth.resource_servers = vec![
            test_server("api://profile", &[], "introspection-client"),
            test_server("api://payments", &[], "introspection-client"),
        ]
    })
    .await;

    let token = mint_access_token(
        app.clone(),
        &token_path,
        "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=api&audience=api%3A%2F%2Fprofile%20api%3A%2F%2Fpayments",
    )
    .await;

    // The signed JWT names both audiences in array form — previously only
    // the first was signed, leaving the second RS unable to validate it.
    let claims = decode_claims(&state, &token);
    assert_eq!(claims.audiences(), ["api://payments", "api://profile"]);
    // Either named resource server validates the token locally.
    for audience in ["api://profile", "api://payments"] {
        assert!(state.signer.decode_with_aud(&token, audience).is_ok());
    }
    assert!(state.signer.decode_with_aud(&token, "api://other").is_err());

    // Introspection serves the stored audience set per resource server: the
    // caller disambiguates a multi-target token via `audience`, and the
    // response is filtered to that server.
    for audience in ["api://profile", "api://payments"] {
        let introspection = post_introspect(
            app.clone(),
            &state.paths.introspect,
            format!(
                "token={}&client_id=introspection-client&client_secret=secret&audience={}",
                urlencoding::encode(&token),
                urlencoding::encode(audience)
            ),
        )
        .await;
        assert_eq!(introspection["active"], true);
        assert_eq!(introspection["aud"], serde_json::json!([audience]));
    }
    // Without disambiguation a multi-target token stays inactive rather
    // than leaking another server's view.
    let ambiguous = post_introspect(
        app,
        &state.paths.introspect,
        format!(
            "token={}&client_id=introspection-client&client_secret=secret",
            urlencoding::encode(&token)
        ),
    )
    .await;
    assert_eq!(ambiguous["active"], serde_json::Value::Bool(false));
}
