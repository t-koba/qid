#![allow(clippy::expect_used, clippy::unwrap_used)]

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use qid_core::{
    config::{OAuthResourceServerConfig, QidConfig},
    jwt::{Audience, JwtClaims},
    models::{
        AccessToken, Admin, AdminElevation, Client, ClientType, ParRequest, PasswordCredential,
        Session, TokenFormat, User,
    },
    state::SharedState,
    test_helpers, util,
};
use qid_crypto::{
    LocalSigner, hash_password, jwk::generate_es256, jwt::sign_es256_jwt_with_jwk_header,
};
use qid_storage::{SqlRepository, prelude::*};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU16, Ordering};
use tower::ServiceExt;

static DB_SEQ: AtomicU16 = AtomicU16::new(0);
static SCHEMA_TEMPLATE: tokio::sync::OnceCell<PathBuf> = tokio::sync::OnceCell::const_new();

fn sqlite_main_path(path: &Path) -> PathBuf {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return path.to_path_buf();
    };
    ["-wal", "-shm", "-journal"]
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix))
        .map_or_else(|| path.to_path_buf(), |name| path.with_file_name(name))
}

fn remove_sqlite_database_files(path: &Path) -> std::io::Result<()> {
    for suffix in ["-wal", "-shm", "-journal", ""] {
        let mut candidate = path.as_os_str().to_os_string();
        candidate.push(suffix);
        match std::fs::remove_file(PathBuf::from(candidate)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn clean_oidc_test_databases(dir: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let database = sqlite_main_path(&entry?.path());
        let name = database
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if name.starts_with("test_") && name.ends_with(".db") {
            remove_sqlite_database_files(&database)?;
        }
    }
    Ok(())
}

/// Build and close one migrated schema for independent per-test database copies.
async fn schema_template_path() -> &'static PathBuf {
    SCHEMA_TEMPLATE
        .get_or_init(|| async {
            let path = std::env::temp_dir()
                .join("qid_test_oidc")
                .join("schema_template.db");
            remove_sqlite_database_files(&path).expect("remove stale OIDC schema template");
            let repo = SqlRepository::connect(&format!("sqlite:{}", path.display()))
                .await
                .unwrap();
            repo.migrate().await.unwrap();
            repo.close().await;
            for suffix in ["-wal", "-shm", "-journal"] {
                let mut sidecar = path.as_os_str().to_os_string();
                sidecar.push(suffix);
                let sidecar = PathBuf::from(sidecar);
                assert!(
                    !sidecar.exists(),
                    "schema template has a sidecar after closing the pool: {}",
                    sidecar.display()
                );
            }
            path
        })
        .await
}

fn db_url() -> String {
    let dir = std::env::temp_dir().join("qid_test_oidc");
    std::fs::create_dir_all(&dir).ok();
    static CLEANED: OnceLock<()> = OnceLock::new();
    CLEANED.get_or_init(|| {
        clean_oidc_test_databases(&dir).expect("remove stale OIDC test database files");
    });
    let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("test_{n}.db"));
    format!("sqlite:{}", path.display())
}

#[test]
fn sqlite_database_cleanup_removes_stale_sidecars_without_matching_template() {
    let dir = std::env::temp_dir().join(format!("qid_oidc_cleanup_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let test_database = dir.join("test_123.db");
    let template = dir.join("schema_template.db");
    for (path, suffixes) in [
        (&test_database, &["", "-wal", "-shm", "-journal"][..]),
        (&template, &["", "-wal", "-shm", "-journal"][..]),
    ] {
        for suffix in suffixes {
            let mut candidate = path.as_os_str().to_os_string();
            candidate.push(suffix);
            std::fs::write(PathBuf::from(candidate), b"stale database artifact").unwrap();
        }
    }

    clean_oidc_test_databases(&dir).unwrap();

    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut test_file = test_database.as_os_str().to_os_string();
        test_file.push(suffix);
        assert!(!PathBuf::from(test_file).exists());
        let mut template_file = template.as_os_str().to_os_string();
        template_file.push(suffix);
        assert!(PathBuf::from(template_file).exists());
    }
    remove_sqlite_database_files(&template).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

// Each isolated fixture uses the same test password, so hash it once per process.
fn correct_password_hash() -> String {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| hash_password("correct-password").expect("test password hashing failed"))
        .clone()
}

fn dpop_test_key() -> (String, qid_crypto::Jwk) {
    static KEY: OnceLock<(String, qid_crypto::Jwk)> = OnceLock::new();
    KEY.get_or_init(|| {
        let generated = generate_es256("userinfo-dpop-key").expect("DPoP key generation failed");
        (generated.private_pem, generated.public_jwk)
    })
    .clone()
}

fn dpop_proof(
    jti: &str,
    htm: &str,
    htu: &str,
    ath: Option<&str>,
    key: Option<(String, qid_crypto::Jwk)>,
) -> String {
    let (private_pem, jwk) = key.unwrap_or_else(dpop_test_key);
    let mut payload =
        serde_json::json!({"jti": jti, "htm": htm, "htu": htu, "iat": util::now_seconds()});
    if let Some(ath) = ath {
        payload["ath"] = serde_json::json!(ath);
    }
    sign_es256_jwt_with_jwk_header(private_pem.as_bytes(), &jwk, "dpop+jwt", &payload)
        .expect("DPoP proof signing failed")
}

async fn setup() -> (Router, Arc<SharedState<SqlRepository>>) {
    let mut config = test_helpers::test_config();
    // The test signer is HS256-based; permit HS256 for the test realm so
    // signed request objects and JARM responses can round-trip.
    config.realms[0]
        .protocols
        .oidc
        .authorization_code
        .request_object_signing_alg_values
        .push("HS256".to_string());
    setup_with_config(config).await
}

async fn setup_with_config(config: QidConfig) -> (Router, Arc<SharedState<SqlRepository>>) {
    let url = db_url();
    let path = std::path::Path::new(url.strip_prefix("sqlite:").unwrap());
    // Migrations are run once here and covered on fresh databases by qid-storage;
    // copying keeps every OIDC case isolated without repeating the migration set.
    std::fs::copy(schema_template_path().await, path).unwrap();
    let repo = Arc::new(SqlRepository::connect(&url).await.unwrap());
    repo.create_realm(
        &"tenant-1".into(),
        &"test".into(),
        "https://id.example.com",
        Some("Test Realm"),
    )
    .await
    .unwrap();
    repo.create_client(&Client {
        id: "par-client-id".to_string(),
        realm_id: "test".to_string(),
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
    })
    .await
    .unwrap();
    repo.create_user(&User {
        id: "par-user".to_string(),
        realm_id: "test".to_string(),
        email: Some("par@example.com".to_string()),
        email_verified: true,
        display_name: Some("PAR User".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    })
    .await
    .unwrap();
    repo.store_password_credential(&PasswordCredential {
        user_id: "par-user".to_string(),
        hash: correct_password_hash(),
        algorithm: "argon2id".to_string(),
    })
    .await
    .unwrap();

    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    let state = Arc::new(SharedState::new(config, repo, signer, serde_json::json!({})).unwrap());
    let app = qid_oidc::routes(&state.paths)
        .merge(qid_oauth::routes(&state.paths))
        .with_state(state.clone());
    (app, state)
}

/// Read the redirect `location` header.
fn redirect_location(response: &axum::response::Response) -> String {
    response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

/// Assert a login challenge with no issued code.
async fn assert_login_challenge(response: axum::response::Response) {
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("location").is_none());
    assert_eq!(json_body(response).await["challenge"], "login_required");
}

/// Assert a code-issuing redirect.
fn assert_code_issued(response: &axum::response::Response) {
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert!(redirect_location(response).contains("code=ac_"));
}

/// Parse a response body as JSON.
async fn json_body(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// GET a URI, optionally with a browser session cookie.
async fn get_uri(
    app: Router,
    uri: impl Into<String>,
    cookie: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder().method(Method::GET).uri(uri.into());
    if let Some(cookie) = cookie {
        builder = builder.header("Cookie", cookie);
    }
    app.oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn get_json(app: Router, uri: impl Into<String>, cookie: Option<&str>) -> serde_json::Value {
    let response = get_uri(app, uri, cookie).await;
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

/// Shared password-login form body.
const LOGIN_FORM: &str = "email=par%40example.com&password=correct-password";

/// POST an `application/x-www-form-urlencoded` body.
async fn post_form(app: Router, uri: impl Into<String>, body: &str) -> axum::response::Response {
    app.oneshot(
        Request::builder()
            .method(Method::POST)
            .uri(uri.into())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn post_logout(
    app: Router,
    uri: String,
    cookie: &str,
    body: &str,
) -> axum::response::Response {
    app.oneshot(
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Cookie", cookie)
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
    .unwrap()
}

/// Sign an authorization request object for `par-client`.
async fn signed_request_object(
    state: &Arc<SharedState<SqlRepository>>,
    jti: &str,
    key: &str,
    extra: HashMap<String, serde_json::Value>,
) -> String {
    let generated = generate_es256(key).unwrap();
    let mut client = state
        .repo
        .get_client_by_client_id(&"test".into(), "par-client")
        .await
        .unwrap()
        .unwrap();
    client.jwks = serde_json::json!({
        "keys": [serde_json::to_value(&generated.public_jwk).unwrap()]
    });
    state.repo.update_client(&client).await.unwrap();
    let mut payload = serde_json::json!({
        "iss": "par-client",
        "sub": "par-client",
        "aud": "https://id.example.com",
        "exp": util::now_seconds() + 60,
        "nbf": util::now_seconds(),
        "iat": util::now_seconds(),
        "jti": jti,
    });
    for (name, value) in extra {
        payload[name] = value;
    }
    sign_es256_jwt_with_jwk_header(
        generated.private_pem.as_bytes(),
        &generated.public_jwk,
        "oauth-authz-req+jwt",
        &payload,
    )
    .unwrap()
}

/// Redeem an authorization code with PKCE and return the token JSON.
async fn redeem_code(
    app: Router,
    token_path: String,
    code: &str,
    verifier: &str,
) -> serde_json::Value {
    let body = format!(
        "grant_type=authorization_code&client_id=par-client&code={}&redirect_uri={}&code_verifier={verifier}",
        urlencoding::encode(code),
        urlencoding::encode("https://app.example.com/callback")
    );
    let response = post_form(app, token_path, &body).await;
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

/// GET an authorize URL carrying only a PAR `request_uri`.
async fn get_par_request(
    app: Router,
    state: &Arc<SharedState<SqlRepository>>,
    request_uri: &str,
    cookie: Option<&str>,
) -> axum::response::Response {
    get_uri(
        app,
        format!(
            "{}?request_uri={}",
            state.paths.authorize,
            urlencoding::encode(request_uri)
        ),
        cookie,
    )
    .await
}

/// Store a pushed authorization request for `request_uri`.
async fn store_par_request(
    state: &Arc<SharedState<SqlRepository>>,
    request_uri: &str,
    params_json: serde_json::Value,
) {
    state
        .repo
        .store_par_request(&ParRequest {
            request_uri: request_uri.to_string(),
            client_id: "par-client".to_string(),
            realm_id: "test".to_string(),
            params_json,
            expires_at: util::now_seconds() + 60,
            used: false,
            created_at: util::now_seconds(),
        })
        .await
        .unwrap();
}

async fn create_browser_session(state: &Arc<SharedState<SqlRepository>>, session_id: &str) -> u64 {
    let auth_time = util::now_seconds() - 60;
    state
        .repo
        .create_session(&Session {
            id: session_id.to_string(),
            realm_id: "test".to_string(),
            user_id: "par-user".to_string(),
            auth_time,
            acr: Some("urn:qid:acr:phishing-resistant".to_string()),
            amr: vec!["pwd".to_string(), "hwk".to_string()],
            idle_expires_at: util::now_seconds() + 300,
            absolute_expires_at: util::now_seconds() + 3600,
            revoked: false,
            created_at: auth_time,
            cnf: None,
        })
        .await
        .unwrap();
    auth_time
}

#[tokio::test]
async fn discovery_metadata_only_advertises_implemented_bearer_grants() {
    let (app, state) = setup().await;
    let metadata = get_json(
        app,
        state.paths.well_known_oauth_authorization_server.clone(),
        None,
    )
    .await;
    let grant_types = metadata["grant_types_supported"].as_array().unwrap();
    assert!(!grant_types.contains(&serde_json::json!(
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
    )));
    assert!(!grant_types.contains(&serde_json::json!(
        "urn:ietf:params:oauth:grant-type:saml2-bearer"
    )));
    let subject_token_types = metadata["subject_token_types_supported"]
        .as_array()
        .unwrap();
    assert!(
        subject_token_types.contains(&serde_json::json!("urn:ietf:params:oauth:token-type:jwt"))
    );
    assert!(
        subject_token_types.contains(&serde_json::json!("urn:ietf:params:oauth:token-type:saml2"))
    );
}

#[tokio::test]
async fn discovery_metadata_hides_disabled_oauth_endpoints() {
    let (app, state) = setup().await;
    let metadata = get_json(
        app.clone(),
        state.paths.well_known_oauth_authorization_server.clone(),
        None,
    )
    .await;
    assert!(
        metadata
            .get("pushed_authorization_request_endpoint")
            .is_none()
    );
    assert!(metadata.get("device_authorization_endpoint").is_none());
    assert!(
        metadata
            .get("backchannel_authentication_endpoint")
            .is_none()
    );
    assert!(metadata.get("registration_endpoint").is_none());
    assert!(metadata.get("registration_management_endpoint").is_none());
    assert!(metadata.get("introspection_endpoint").is_some());
    assert!(metadata.get("revocation_endpoint").is_some());

    let openid = get_json(app, &state.paths.well_known_openid_configuration, None).await;
    assert!(openid.get("device_authorization_endpoint").is_none());
    assert!(openid.get("registration_endpoint").is_none());
    assert_eq!(openid["backchannel_logout_supported"], true);
    assert_eq!(openid["frontchannel_logout_supported"], true);
}

#[tokio::test]
async fn discovery_metadata_advertises_enabled_oauth_endpoints() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.par.enabled = true;
    config.realms[0]
        .protocols
        .oauth
        .device_authorization
        .enabled = true;
    config.realms[0].protocols.oauth.ciba.enabled = true;
    config.realms[0]
        .protocols
        .oauth
        .dynamic_client_registration
        .enabled = true;
    let (app, state) = setup_with_config(config).await;
    let metadata = get_json(
        app.clone(),
        state.paths.well_known_oauth_authorization_server.clone(),
        None,
    )
    .await;
    assert_eq!(
        metadata["pushed_authorization_request_endpoint"],
        "https://id.example.com/oauth2/par"
    );
    assert_eq!(
        metadata["device_authorization_endpoint"],
        "https://id.example.com/oauth2/device_authorization"
    );
    assert_eq!(
        metadata["backchannel_authentication_endpoint"],
        "https://id.example.com/oauth2/backchannel-authentication"
    );
    assert_eq!(
        metadata["registration_endpoint"],
        "https://id.example.com/oauth2/register"
    );
    assert_eq!(
        metadata["registration_management_endpoint"],
        "https://id.example.com/oauth2/register/:client_id"
    );
    let grant_types = metadata["grant_types_supported"].as_array().unwrap();
    assert!(grant_types.contains(&serde_json::json!(
        "urn:ietf:params:oauth:grant-type:device_code"
    )));
    assert!(grant_types.contains(&serde_json::json!("urn:openid:params:grant-type:ciba")));
}

#[tokio::test]
async fn discovery_metadata_reflects_disabled_oidc_logout_channels() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oidc.logout.backchannel = false;
    config.realms[0].protocols.oidc.logout.frontchannel = false;
    let (app, state) = setup_with_config(config).await;
    let metadata = get_json(
        app.clone(),
        state.paths.well_known_openid_configuration.clone(),
        None,
    )
    .await;
    assert_eq!(metadata["backchannel_logout_supported"], false);
    assert_eq!(metadata["frontchannel_logout_supported"], false);

    let logout_request = Request::builder()
        .method(Method::GET)
        .uri(&state.paths.frontchannel_logout)
        .body(Body::empty())
        .unwrap();
    let logout_response = app.oneshot(logout_request).await.unwrap();
    assert_eq!(logout_response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn frontchannel_logout_page_escapes_reflected_sid() {
    let (app, state) = setup().await;
    let uri = format!(
        "{}?iss={}&sid={}",
        state.paths.frontchannel_logout,
        urlencoding::encode("https://id.example.com"),
        urlencoding::encode(r#""}></script><script>alert(1)</script>"#),
    );
    let response = get_uri(app, uri, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        !html.contains("</script><script>"),
        "raw sid reflected: {html}"
    );
    assert!(html.contains("&quot;"));
}

#[tokio::test]
async fn oidc_disabled_hides_openid_metadata_and_rejects_oidc_handlers() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oidc.enabled = false;
    let (app, state) = setup_with_config(config).await;

    let metadata_request = Request::builder()
        .method(Method::GET)
        .uri(&state.paths.well_known_openid_configuration)
        .body(Body::empty())
        .unwrap();
    let metadata_response = app.clone().oneshot(metadata_request).await.unwrap();
    assert_eq!(metadata_response.status(), StatusCode::BAD_REQUEST);

    let authorize_request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "{}?client_id=par-client&response_type=code&redirect_uri={}&scope=openid&code_challenge={}&code_challenge_method=S256",
            state.paths.authorize,
            urlencoding::encode("https://app.example.com/callback"),
            util::sha256_base64url("verifier")
        ))
        .body(Body::empty())
        .unwrap();
    let authorize_response = app.clone().oneshot(authorize_request).await.unwrap();
    assert_eq!(authorize_response.status(), StatusCode::BAD_REQUEST);

    let userinfo_request = Request::builder()
        .method(Method::GET)
        .uri(&state.paths.userinfo)
        .body(Body::empty())
        .unwrap();
    let userinfo_response = app.clone().oneshot(userinfo_request).await.unwrap();
    assert_eq!(userinfo_response.status(), StatusCode::BAD_REQUEST);

    let logout_response = post_form(app, &state.paths.logout, "").await;
    assert_eq!(logout_response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oidc_authorization_code_disabled_hides_authorize_metadata_and_rejects_authorize() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oidc.authorization_code.enabled = false;
    let (app, state) = setup_with_config(config).await;

    let metadata_request = Request::builder()
        .method(Method::GET)
        .uri(&state.paths.well_known_openid_configuration)
        .body(Body::empty())
        .unwrap();
    let metadata_response = app.clone().oneshot(metadata_request).await.unwrap();
    assert_eq!(metadata_response.status(), StatusCode::OK);
    let metadata = json_body(metadata_response).await;
    assert!(metadata.get("authorization_endpoint").is_none());
    assert!(
        !metadata["grant_types_supported"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("authorization_code"))
    );
    assert_eq!(metadata["response_types_supported"], serde_json::json!([]));

    let authorize_request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "{}?client_id=par-client&response_type=code&redirect_uri={}&scope=openid&code_challenge={}&code_challenge_method=S256",
            state.paths.authorize,
            urlencoding::encode("https://app.example.com/callback"),
            util::sha256_base64url("verifier")
        ))
        .body(Body::empty())
        .unwrap();
    let authorize_response = app.oneshot(authorize_request).await.unwrap();
    assert_eq!(authorize_response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn authorize_get_uses_browser_session_cookie_to_issue_code() {
    let (app, state) = setup().await;
    let auth_time = create_browser_session(&state, "sid-authorize").await;
    let response = get_uri(
        app,
        format!(
            "{}?client_id=par-client&response_type=code&redirect_uri={}&scope=openid%20profile&state=session-state&nonce=session-nonce&code_challenge={}&code_challenge_method=S256",
            state.paths.authorize,
            urlencoding::encode("https://app.example.com/callback"),
            util::sha256_base64url("verifier")
        ),
        Some("__Host-qid=sid-authorize"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = redirect_location(&response);
    assert!(location.starts_with("https://app.example.com/callback?code=ac_"));
    assert!(location.contains("state=session-state"));
    let code = extract_query_param(&location, "code").expect("redirect should include code");
    let code_hash = util::sha256_base64url(&code);
    let stored_code = state
        .repo
        .get_authorization_code(&code_hash)
        .await
        .unwrap()
        .expect("authorization code should be stored");
    assert_eq!(stored_code.user_id, "par-user");
    assert_eq!(stored_code.realm_id, "test");
    assert_eq!(stored_code.client_id, "par-client");
    assert_eq!(stored_code.auth_time, Some(auth_time));
    assert_eq!(
        stored_code.acr.as_deref(),
        Some("urn:qid:acr:phishing-resistant")
    );
    assert_eq!(stored_code.amr, vec!["pwd".to_string(), "hwk".to_string()]);
    assert_eq!(stored_code.nonce.as_deref(), Some("session-nonce"));
}

#[tokio::test]
async fn authorize_get_prompt_login_ignores_browser_session_cookie() {
    let (app, state) = setup().await;
    create_browser_session(&state, "sid-prompt-login").await;
    let response = get_uri(
        app,
        format!(
            "{}?client_id=par-client&response_type=code&redirect_uri={}&scope=openid&state=prompt-state&prompt=login&code_challenge={}&code_challenge_method=S256",
            state.paths.authorize,
            urlencoding::encode("https://app.example.com/callback"),
            util::sha256_base64url("verifier")
        ),
        Some("__Host-qid=sid-prompt-login"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let challenge = json_body(response).await;
    assert_eq!(challenge["challenge"], "login_required");
    assert_eq!(challenge["client_id"], "par-client");
    assert_eq!(challenge["state"], "prompt-state");
}

#[tokio::test]
async fn logout_redirect_requires_registered_client_uri() {
    let (app, state) = setup().await;
    let body =
        "client_id=par-client&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback";
    let response = post_form(app, &state.paths.logout, body).await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        response.headers().get("location").unwrap(),
        "https://app.example.com/callback"
    );
}

#[tokio::test]
async fn logout_attempts_backchannel_before_redirect_response() {
    let (app, state) = setup().await;
    let captured: Arc<std::sync::Mutex<Vec<(String, String)>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let capture_state = captured.clone();
    let capture_app = Router::new().route(
        "/bc/:client",
        axum::routing::post(
            |axum::extract::Path(client): axum::extract::Path<String>, body: String| async move {
                capture_state.lock().unwrap().push((client, body));
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, capture_app).await.unwrap();
    });
    for client_id in ["notify-client", "notify-other"] {
        let mut client = state
            .repo
            .get_client_by_client_id(&"test".into(), "par-client")
            .await
            .unwrap()
            .unwrap();
        client.id = format!("{client_id}-id");
        client.client_id = client_id.to_string();
        client.backchannel_logout_uri = Some(format!("http://127.0.0.1:{port}/bc/{client_id}"));
        state.repo.create_client(&client).await.unwrap();
    }
    create_browser_session(&state, "sid-logout-notify").await;

    let response = post_logout(
        app,
        state.paths.logout.clone(),
        "__Host-qid=sid-logout-notify",
        "client_id=notify-client&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback",
    )
    .await;
    // No frontchannel registrations: immediate redirect, but only after both
    // backchannel notifications were attempted.
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert!(response.headers().contains_key("set-cookie"));
    let paths: Vec<String> = captured
        .lock()
        .unwrap()
        .iter()
        .map(|(path, _)| path.clone())
        .collect();
    assert_eq!(paths.len(), 2);
    assert!(paths.contains(&"notify-client".to_string()));
    assert!(paths.contains(&"notify-other".to_string()));
    assert!(
        captured
            .lock()
            .unwrap()
            .iter()
            .all(|(_, body)| body.contains("logout_token=")),
        "backchannel posts must carry logout tokens"
    );
}

#[tokio::test]
async fn logout_redirect_with_frontchannel_renders_completion_page() {
    let (app, state) = setup().await;
    let mut client = state
        .repo
        .get_client_by_client_id(&"test".into(), "par-client")
        .await
        .unwrap()
        .unwrap();
    client.id = "notify-front-id".to_string();
    client.client_id = "notify-front".to_string();
    client.frontchannel_logout_uri = Some("https://rp.example.com/frontchannel".to_string());
    state.repo.create_client(&client).await.unwrap();
    create_browser_session(&state, "sid-logout-front").await;

    let response = post_logout(
        app,
        state.paths.logout.clone(),
        "__Host-qid=sid-logout-front",
        "client_id=notify-front&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback",
    )
    .await;
    // Frontchannel work exists: a completion page carries the notification,
    // not an immediate redirect.
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(html.contains("https://rp.example.com/frontchannel"));
    assert!(html.contains("sid-logout-front"));
    assert!(html.contains("https://app.example.com/callback"));
}

#[tokio::test]
async fn logout_completion_iframes_escape_malicious_cookie_sid() {
    let (app, state) = setup().await;
    let mut client = state
        .repo
        .get_client_by_client_id(&"test".into(), "par-client")
        .await
        .unwrap()
        .unwrap();
    client.id = "notify-xss-id".to_string();
    client.client_id = "notify-xss".to_string();
    client.frontchannel_logout_uri = Some("https://rp.example.com/frontchannel".to_string());
    state.repo.create_client(&client).await.unwrap();
    // No session is created: the cookie value is unvalidated input straight
    // into the iframe `src` construction.
    let response = post_logout(
        app,
        state.paths.logout.clone(),
        r#"__Host-qid="></script><script>alert(1)</script>"#,
        "client_id=notify-xss&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        !html.contains("</script><script>"),
        "raw cookie reflected: {html}"
    );
    assert!(
        html.contains("%3C%2Fscript%3E"),
        "sid not URL-encoded: {html}"
    );
}

#[tokio::test]
async fn logout_rejects_unregistered_redirect_uri() {
    let (app, state) = setup().await;
    let body =
        "client_id=par-client&post_logout_redirect_uri=https%3A%2F%2Fevil.example.com%2Fcallback";
    let response = post_form(app, &state.paths.logout, body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn discovery_metadata_advertises_mtls_auth_only_when_enabled() {
    let (_, state_disabled) = setup().await;
    let disabled_request = Request::builder()
        .method(Method::GET)
        .uri(&state_disabled.paths.well_known_oauth_authorization_server)
        .body(Body::empty())
        .unwrap();
    let disabled_response = qid_oidc::routes(&state_disabled.paths)
        .with_state(state_disabled.clone())
        .oneshot(disabled_request)
        .await
        .unwrap();
    let disabled_metadata = json_body(disabled_response).await;
    assert!(
        !disabled_metadata["token_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("tls_client_auth"))
    );

    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.mtls.enabled = true;
    let (app, state) = setup_with_config(config).await;
    let metadata = get_json(
        app,
        state.paths.well_known_oauth_authorization_server.clone(),
        None,
    )
    .await;
    let methods = metadata["token_endpoint_auth_methods_supported"]
        .as_array()
        .unwrap();
    assert!(methods.contains(&serde_json::json!("tls_client_auth")));
    assert!(methods.contains(&serde_json::json!("self_signed_tls_client_auth")));
}

#[tokio::test]
async fn discovery_metadata_advertises_configured_protected_resources() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.dpop.enabled = true;
    config.realms[0].protocols.oauth.mtls.enabled = true;
    config.realms[0].protocols.oauth.resource_servers = vec![
        OAuthResourceServerConfig {
            audience: "api://payments".to_string(),
            resources: vec!["https://api.example.com/payments".to_string()],
            scopes: vec!["payments".to_string()],
            introspection_client_ids: Vec::new(),
            require_sender_constraint: true,
            high_risk: true,
        },
        OAuthResourceServerConfig {
            audience: "api://profile".to_string(),
            resources: vec!["https://api.example.com/profile".to_string()],
            scopes: vec!["profile".to_string()],
            introspection_client_ids: Vec::new(),
            require_sender_constraint: false,
            high_risk: false,
        },
    ];
    let (app, state) = setup_with_config(config).await;

    let metadata = get_json(
        app.clone(),
        &state.paths.well_known_oauth_authorization_server,
        None,
    )
    .await;
    let protected_resources = metadata["protected_resources"].as_array().unwrap();
    assert!(protected_resources.contains(&serde_json::json!("api://payments")));
    assert!(protected_resources.contains(&serde_json::json!("https://api.example.com/payments")));

    let metadata = get_json(
        app.clone(),
        format!(
            "{}?resource={}",
            state.paths.well_known_oauth_protected_resource,
            urlencoding::encode("https://api.example.com/payments")
        ),
        None,
    )
    .await;
    assert_eq!(metadata["resource"], "https://api.example.com/payments");
    assert_eq!(metadata["audience"], "api://payments");
    assert_eq!(
        metadata["scopes_supported"],
        serde_json::json!(["payments"])
    );
    assert_eq!(metadata["sender_constrained_access_tokens"], true);
    assert_eq!(
        metadata["dpop_signing_alg_values_supported"],
        serde_json::json!(["ES256", "EdDSA", "RS256"])
    );
    assert_eq!(metadata["mtls_endpoint_aliases_supported"], true);

    let metadata = get_json(
        app.clone(),
        format!(
            "{}?audience={}",
            state.paths.well_known_oauth_protected_resource,
            urlencoding::encode("api://profile")
        ),
        None,
    )
    .await;
    assert_eq!(metadata["resource"], "https://api.example.com/profile");
    assert_eq!(metadata["sender_constrained_access_tokens"], false);

    let missing_response =
        get_uri(app, &state.paths.well_known_oauth_protected_resource, None).await;
    assert_eq!(missing_response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn path_issuer_single_realm_requires_scoped_discovery_metadata() {
    let mut config = test_helpers::test_config();
    config.realms[0].issuer = "https://id.example.com/realms/test".to_string();
    let (app, _state) = setup_with_config(config).await;

    let global_oidc_response =
        get_uri(app.clone(), "/.well-known/openid-configuration", None).await;
    assert_eq!(global_oidc_response.status(), StatusCode::BAD_REQUEST);

    let global_oauth_response =
        get_uri(app.clone(), "/.well-known/oauth-authorization-server", None).await;
    assert_eq!(global_oauth_response.status(), StatusCode::BAD_REQUEST);

    let metadata = get_json(
        app.clone(),
        "/realms/test/.well-known/openid-configuration",
        None,
    )
    .await;
    assert_eq!(metadata["issuer"], "https://id.example.com/realms/test");

    let metadata = get_json(
        app,
        "/.well-known/oauth-authorization-server/realms/test",
        None,
    )
    .await;
    assert_eq!(metadata["issuer"], "https://id.example.com/realms/test");
}

#[tokio::test]
async fn realm_scoped_discovery_metadata_supports_multi_realm() {
    let mut config = test_helpers::test_config();
    config.realms[0].issuer = "https://id.example.com/realms/test".to_string();
    let mut realm_b = config.realms[0].clone();
    realm_b.id = "realm-b".to_string();
    realm_b.issuer = "https://id.example.com/realms/realm-b".to_string();
    realm_b.protocols.oidc.session_management = true;
    realm_b.sessions.browser.cookie_name = "__Host-qid-realm-b".to_string();
    config.realms.push(realm_b);
    let (app, _state) = setup_with_config(config).await;

    let global_response = get_uri(app.clone(), "/.well-known/openid-configuration", None).await;
    assert_eq!(global_response.status(), StatusCode::BAD_REQUEST);

    let metadata = get_json(
        app.clone(),
        "/realms/realm-b/.well-known/openid-configuration",
        None,
    )
    .await;
    assert_eq!(metadata["issuer"], "https://id.example.com/realms/realm-b");
    assert_eq!(
        metadata["check_session_iframe"],
        "https://id.example.com/realms/realm-b/session/check"
    );

    let oauth_metadata = get_json(
        app.clone(),
        "/.well-known/oauth-authorization-server/realms/realm-b",
        None,
    )
    .await;
    assert_eq!(
        oauth_metadata["issuer"],
        "https://id.example.com/realms/realm-b"
    );

    let iframe_response = get_uri(app, "/realms/realm-b/session/check", None).await;
    assert_eq!(iframe_response.status(), StatusCode::OK);
    let iframe = iframe_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let iframe = String::from_utf8(iframe.to_vec()).unwrap();
    assert!(iframe.contains(r#"readCookie("__Host-qid-realm-b")"#));
}

#[tokio::test]
async fn ssf_requires_scoped_metadata_and_signed_set_events() {
    let mut config = test_helpers::test_config();
    config.realms[0].issuer = "https://id.example.com/realms/test".to_string();
    let (_base_app, state) = setup_with_config(config).await;
    let app = qid_oidc::shared_signals::ssf_routes::<SqlRepository>().with_state(state.clone());

    let global_response = get_uri(app.clone(), "/.well-known/ssf-configuration", None).await;
    assert_eq!(global_response.status(), StatusCode::BAD_REQUEST);

    let metadata = get_json(
        app.clone(),
        "/realms/test/.well-known/ssf-configuration",
        None,
    )
    .await;
    assert_eq!(metadata["issuer"], "https://id.example.com/realms/test");
    assert_eq!(
        metadata["delivery_methods_supported"][0]["url"],
        "https://id.example.com/realms/test/ssf/events"
    );

    let unsigned_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/realms/test/ssf/events")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "iss": "https://id.example.com/realms/test",
                        "jti": "unsigned-set",
                        "iat": util::now_seconds(),
                        "events": {
                            "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {}
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unsigned_response.status(), StatusCode::BAD_REQUEST);

    let transmitter_key = generate_es256("ssf-transmitter").unwrap();
    let stream_id = format!("stream-{}", ulid::Ulid::new());
    let stream_request = serde_json::json!({
        "stream_id": stream_id,
        "delivery": {
            "delivery_method": "http_post",
            "url": "https://receiver.example.com/ssf"
        },
        "events_requested": [
            "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
        ],
        "transmitter_issuer": "https://transmitter.example.com",
        "transmitter_jwks": {
            "keys": [transmitter_key.public_jwk.clone()]
        },
        "transmitter_alg": "ES256",
        "audience": "qid-ssf"
    });
    let unauthenticated_create = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/realms/test/ssf/stream")
                .header("content-type", "application/json")
                .body(Body::from(stream_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthenticated_create.status(), StatusCode::UNAUTHORIZED);

    let admin_now = util::now_seconds();
    state
        .repo
        .upsert_admin(&Admin {
            id: "ssf-admin".to_string(),
            tenant_id: "tenant-1".to_string(),
            subject: "admin@example.com".to_string(),
            roles: vec!["security.admin".to_string()],
            created_at: admin_now,
        })
        .await
        .unwrap();
    state
        .repo
        .store_admin_elevation(&AdminElevation {
            id: "ssf-elevation".to_string(),
            tenant_id: "tenant-1".to_string(),
            admin_id: "ssf-admin".to_string(),
            acr: Some(state.config.admin.security.required_acr.clone()),
            amr: vec![state.config.admin.security.required_amr[0].clone()],
            elevation_expires_at: admin_now + 300,
            created_at: admin_now,
        })
        .await
        .unwrap();
    let mut admin_extra = HashMap::new();
    admin_extra.insert("scope".to_string(), serde_json::json!("ssf.manage"));
    admin_extra.insert("realm_id".to_string(), serde_json::json!("test"));
    let admin_token_jti = format!("ssf-admin-{}", ulid::Ulid::new());
    let admin_token = state
        .signer
        .sign(&JwtClaims {
            iss: Some("https://id.example.com/realms/test".to_string()),
            sub: Some("ssf-admin".to_string()),
            aud: Some(Audience::single("qid-ssf-admin")),
            exp: Some((admin_now + 300) as usize),
            nbf: None,
            iat: Some(admin_now as usize),
            jti: Some(admin_token_jti.clone()),
            extra: admin_extra,
        })
        .unwrap();
    state
        .repo
        .create_access_token(&AccessToken {
            jti: admin_token_jti,
            family_id: None,
            user_id: "ssf-admin".to_string(),
            client_id: "ssf-admin-client".to_string(),
            realm_id: "test".to_string(),
            scopes: vec!["ssf.manage".to_string()],
            audience: vec!["qid-ssf-admin".to_string()],
            resource: Vec::new(),
            authorization_details: None,
            cnf: None,
            auth_time: Some(admin_now),
            acr: Some(state.config.admin.security.required_acr.clone()),
            amr: vec![state.config.admin.security.required_amr[0].clone()],
            nonce: None,
            sender_constraint: None,
            token_format: TokenFormat::Jwt,
            expires_at: admin_now + 300,
            revoked: false,
            issued_at: admin_now,
        })
        .await
        .unwrap();
    let authenticated_create = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/realms/test/ssf/stream")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {admin_token}"))
                .header("x-qid-admin-session-id", "ssf-elevation")
                .body(Body::from(stream_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authenticated_create.status(), StatusCode::CREATED);

    let now = util::now_seconds();
    let token = qid_oidc::shared_signals::encode_security_event_token(
        transmitter_key.private_pem.as_bytes(),
        &transmitter_key.public_jwk,
        &qid_oidc::shared_signals::SecurityEventToken {
            iss: "https://transmitter.example.com".to_string(),
            jti: "signed-set-1".to_string(),
            iat: now,
            aud: Some("qid-ssf".to_string()),
            exp: Some(now + 300),
            stream_id: Some(stream_request["stream_id"].as_str().unwrap().to_string()),
            events: serde_json::from_value(serde_json::json!({
                "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
                    "subject": {
                        "format": "iss_sub",
                        "iss": "https://transmitter.example.com",
                        "sub": "alice"
                    }
                }
            }))
            .unwrap(),
        },
    )
    .unwrap();

    let accepted = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/realms/test/ssf/events")
                .header("content-type", "application/secevent+jwt")
                .body(Body::from(token.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);

    let replay = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/realms/test/ssf/events")
                .header("content-type", "application/secevent+jwt")
                .body(Body::from(token))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn authorize_consumes_par_request_uri_once_after_successful_login() {
    let (app, state) = setup().await;
    let request_uri = "urn:ietf:params:oauth:request_uri:test-par";
    store_par_request(
        &state,
        request_uri,
        serde_json::json!({
            "client_id": "par-client",
            "response_type": "code",
            "redirect_uri": "https://app.example.com/callback",
            "scope": "openid profile",
            "state": "state-from-par",
            "code_challenge": util::sha256_base64url("verifier"),
            "code_challenge_method": "S256",
            "authorization_details": [
                {
                    "type": "payment_initiation",
                    "actions": ["initiate"],
                    "locations": ["https://payments.example.com"]
                }
            ]
        }),
    )
    .await;

    let challenge = get_json(
        app.clone(),
        format!(
            "{}?request_uri={}",
            state.paths.authorize,
            urlencoding::encode(request_uri)
        ),
        None,
    )
    .await;
    assert_eq!(challenge["client_id"], "par-client");
    assert_eq!(challenge["state"], "state-from-par");

    let post_response = post_form(
        app.clone(),
        format!(
            "{}?request_uri={}",
            state.paths.authorize,
            urlencoding::encode(request_uri)
        ),
        LOGIN_FORM,
    )
    .await;
    assert_eq!(post_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = redirect_location(&post_response);
    assert!(location.starts_with("https://app.example.com/callback?code=ac_"));
    assert!(location.contains("state=state-from-par"));
    let code = extract_query_param(&location, "code").expect("redirect should include code");

    let token_json = redeem_code(app.clone(), state.paths.token.clone(), &code, "verifier").await;
    let access_token = token_json["access_token"].as_str().unwrap();
    let claims = state
        .signer
        .decode_signature_only(access_token)
        .unwrap()
        .claims;
    assert_eq!(
        claims.extra["authorization_details"],
        serde_json::json!([
            {
                "type": "payment_initiation",
                "actions": ["initiate"],
                "locations": ["https://payments.example.com"]
            }
        ])
    );

    let replay_response = get_uri(
        app,
        format!(
            "{}?request_uri={}",
            state.paths.authorize,
            urlencoding::encode(request_uri)
        ),
        None,
    )
    .await;
    assert_eq!(replay_response.status(), StatusCode::UNAUTHORIZED);
}

/// Build a deployment with a second realm that requires pushed
/// authorization requests, and a client of that realm.
async fn setup_with_a_par_realm() -> (Router, Arc<SharedState<SqlRepository>>) {
    let mut config = test_helpers::test_config();
    config.realms[0].issuer = "https://id.example.com/realms/test".to_string();
    let mut strict = config.realms[0].clone();
    strict.id = "strict".to_string();
    strict.issuer = "https://id.example.com/realms/strict".to_string();
    strict.protocols.oauth.par.enabled = true;
    strict.protocols.oauth.require_pushed_authorization_requests = true;
    config.realms.push(strict);
    let (app, state) = setup_with_config(config).await;
    state
        .repo
        .create_realm(
            &"tenant-strict".into(),
            &"strict".into(),
            "https://id.example.com/realms/strict",
            Some("Strict Realm"),
        )
        .await
        .unwrap();
    state
        .repo
        .create_client(&Client {
            id: "strict-client-id".to_string(),
            realm_id: "strict".to_string(),
            client_id: "strict-client".to_string(),
            client_type: ClientType::Public,
            token_endpoint_auth_method: "none".to_string(),
            client_secret_hash: None,
            mtls_certificate_thumbprints: Vec::new(),
            jwks: qid_core::models::default_client_jwks(),
            redirect_uris: vec!["https://strict.example.com/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            client_name: None,
            client_uri: None,
            logo_uri: None,
            contacts: Vec::new(),
            post_logout_redirect_uris: vec!["https://strict.example.com/callback".to_string()],
            default_max_age: None,
            require_auth_time: false,
            sector_identifier_uri: None,
            subject_type: None,
            backchannel_logout_uri: None,
            frontchannel_logout_uri: None,
            backchannel_client_notification_endpoint: None,
        })
        .await
        .unwrap();
    (app, state)
}

/// Authorize query for the client of the realm that requires a pushed
/// authorization request.
fn strict_authorize_query(state: &Arc<SharedState<SqlRepository>>) -> String {
    format!(
        "{}?client_id=strict-client&response_type=code&redirect_uri={}&scope=openid&state=s&nonce=n&code_challenge={}&code_challenge_method=S256",
        state.paths.authorize,
        urlencoding::encode("https://strict.example.com/callback"),
        util::sha256_base64url("verifier"),
    )
}

#[tokio::test]
async fn the_pushed_authorization_request_requirement_is_scoped_to_the_client_realm() {
    let (app, state) = setup_with_a_par_realm().await;

    // The client's own realm does not require a pushed request, so the
    // client is served: the requirement of another realm does not reach
    // it.
    let response = get_uri(app.clone(), authorize_query(&state, ""), None).await;
    assert_login_challenge(response).await;

    // The client's own realm requires one, so the client is refused
    // without it.
    let response = get_uri(app.clone(), strict_authorize_query(&state), None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("pushed authorization request is required")),
        "{body}"
    );
}

#[tokio::test]
async fn a_pushed_authorization_request_satisfies_the_realm_requirement() {
    let (app, state) = setup_with_a_par_realm().await;
    let request_uri = "urn:ietf:params:oauth:request_uri:strict-par";
    state
        .repo
        .store_par_request(&ParRequest {
            request_uri: request_uri.to_string(),
            client_id: "strict-client".to_string(),
            realm_id: "strict".to_string(),
            params_json: serde_json::json!({
                "client_id": "strict-client",
                "response_type": "code",
                "redirect_uri": "https://strict.example.com/callback",
                "scope": "openid",
                "state": "state-strict",
                "code_challenge": util::sha256_base64url("verifier"),
                "code_challenge_method": "S256"
            }),
            expires_at: util::now_seconds() + 60,
            used: false,
            created_at: util::now_seconds(),
        })
        .await
        .unwrap();

    let challenge = get_json(
        app.clone(),
        format!(
            "{}?request_uri={}",
            state.paths.authorize,
            urlencoding::encode(request_uri)
        ),
        None,
    )
    .await;
    assert_eq!(challenge["client_id"], "strict-client");
}

/// Build a deployment with a second realm that registers the same client
/// id, so the client id names a client of two realms.
async fn setup_with_a_duplicate_client_id() -> (Router, Arc<SharedState<SqlRepository>>) {
    let mut config = test_helpers::test_config();
    let mut other = config.realms[0].clone();
    other.id = "other".to_string();
    other.issuer = "https://id.example.com/realms/other".to_string();
    config.realms.push(other);
    let (app, state) = setup_with_config(config).await;
    state
        .repo
        .create_realm(
            &"tenant-other".into(),
            &"other".into(),
            "https://id.example.com/realms/other",
            Some("Other Realm"),
        )
        .await
        .unwrap();
    state
        .repo
        .create_client(&Client {
            id: "other-client-id".to_string(),
            realm_id: "other".to_string(),
            client_id: "par-client".to_string(),
            client_type: ClientType::Public,
            token_endpoint_auth_method: "none".to_string(),
            client_secret_hash: None,
            mtls_certificate_thumbprints: Vec::new(),
            jwks: qid_core::models::default_client_jwks(),
            redirect_uris: vec!["https://other.example.com/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
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
        })
        .await
        .unwrap();
    (app, state)
}

#[tokio::test]
async fn an_authorization_request_without_a_client_is_refused_for_the_missing_parameter() {
    let (app, state) = setup().await;

    // A request that names no client names no realm, so it is refused for
    // the missing parameter rather than for an unknown client.
    let response = get_uri(
        app,
        format!(
            "{}?response_type=code&redirect_uri={}",
            state.paths.authorize,
            urlencoding::encode("https://app.example.com/callback")
        ),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("client_id required")),
        "{body}"
    );
}

#[tokio::test]
async fn a_client_id_registered_in_two_realms_is_refused() {
    let (app, state) = setup_with_a_duplicate_client_id().await;

    // The client id names a client of two realms, so the request names no
    // single client and is refused.
    let response = get_uri(app, authorize_query(&state, ""), None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn authorize_rejects_invalid_authorization_details_from_par() {
    let (app, state) = setup().await;
    let request_uri = "urn:ietf:params:oauth:request_uri:invalid-rar";
    store_par_request(
        &state,
        request_uri,
        serde_json::json!({
            "client_id": "par-client",
            "response_type": "code",
            "redirect_uri": "https://app.example.com/callback",
            "scope": "openid profile",
            "state": "state-invalid-rar",
            "code_challenge": util::sha256_base64url("verifier"),
            "code_challenge_method": "S256",
            "authorization_details": [
                {
                    "actions": ["initiate"],
                    "locations": ["https://payments.example.com"]
                }
            ]
        }),
    )
    .await;

    let response = get_uri(
        app,
        format!(
            "{}?request_uri={}",
            state.paths.authorize,
            urlencoding::encode(request_uri)
        ),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

fn extract_query_param(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| urlencoding::decode(value).ok().map(|v| v.into_owned()))?
    })
}

#[tokio::test]
async fn authorize_accepts_signed_request_object() {
    let (app, state) = setup().await;
    let mut extra = HashMap::new();
    extra.insert("client_id".to_string(), serde_json::json!("par-client"));
    extra.insert("response_type".to_string(), serde_json::json!("code"));
    extra.insert(
        "redirect_uri".to_string(),
        serde_json::json!("https://app.example.com/callback"),
    );
    extra.insert("scope".to_string(), serde_json::json!("openid profile"));
    extra.insert("state".to_string(), serde_json::json!("state-from-jar"));
    extra.insert(
        "code_challenge".to_string(),
        serde_json::json!(util::sha256_base64url("jar-verifier")),
    );
    extra.insert(
        "code_challenge_method".to_string(),
        serde_json::json!("S256"),
    );
    extra.insert(
        "authorization_details".to_string(),
        serde_json::json!([{
            "type": "account_information",
            "actions": ["read"],
            "locations": ["https://api.example.com/accounts"]
        }]),
    );
    let request_object = signed_request_object(&state, "jar-test", "jar-test-key", extra).await;

    let get_response = get_uri(
        app.clone(),
        format!(
            "{}?request={}",
            state.paths.authorize,
            urlencoding::encode(&request_object)
        ),
        None,
    )
    .await;
    assert_eq!(get_response.status(), StatusCode::OK);

    let post_response = post_form(
        app.clone(),
        format!(
            "{}?request={}",
            state.paths.authorize,
            urlencoding::encode(&request_object)
        ),
        LOGIN_FORM,
    )
    .await;
    assert_eq!(post_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = redirect_location(&post_response);
    assert!(location.contains("state=state-from-jar"));
    let code = extract_query_param(&location, "code").expect("redirect should include code");

    let token_json = redeem_code(app, state.paths.token.clone(), &code, "jar-verifier").await;
    let access_token = token_json["access_token"].as_str().unwrap();
    let claims = state
        .signer
        .decode_signature_only(access_token)
        .unwrap()
        .claims;
    assert_eq!(
        claims.extra["authorization_details"],
        serde_json::json!([{
            "type": "account_information",
            "actions": ["read"],
            "locations": ["https://api.example.com/accounts"]
        }])
    );
}

#[tokio::test]
async fn authorize_can_return_signed_jarm_response() {
    let (app, state) = setup().await;
    let mut extra = HashMap::new();
    extra.insert("client_id".to_string(), serde_json::json!("par-client"));
    extra.insert("response_type".to_string(), serde_json::json!("code"));
    extra.insert(
        "redirect_uri".to_string(),
        serde_json::json!("https://app.example.com/callback"),
    );
    extra.insert("scope".to_string(), serde_json::json!("openid profile"));
    extra.insert("state".to_string(), serde_json::json!("state-from-jarm"));
    extra.insert("response_mode".to_string(), serde_json::json!("jwt"));
    extra.insert(
        "code_challenge".to_string(),
        serde_json::json!(util::sha256_base64url("jarm-verifier")),
    );
    extra.insert(
        "code_challenge_method".to_string(),
        serde_json::json!("S256"),
    );
    let request_object =
        signed_request_object(&state, "jarm-request-test", "jarm-request-test-key", extra).await;

    let post_response = post_form(
        app.clone(),
        format!(
            "{}?request={}",
            state.paths.authorize,
            urlencoding::encode(&request_object)
        ),
        LOGIN_FORM,
    )
    .await;
    assert_eq!(post_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = redirect_location(&post_response);
    assert!(location.starts_with("https://app.example.com/callback?response="));
    let response = extract_query_param(&location, "response").expect("JARM response is required");
    let response_claims = state
        .signer
        .decode_signature_only(&response)
        .unwrap()
        .claims;
    assert_eq!(response_claims.aud, Some(Audience::single("par-client")));
    assert_eq!(response_claims.extra["state"], "state-from-jarm");
    let code = response_claims.extra["code"].as_str().unwrap();
    assert!(code.starts_with("ac_"));

    redeem_code(app, state.paths.token.clone(), code, "jarm-verifier").await;
}

#[tokio::test]
async fn protected_resource_path_inserted_and_401_pointer() {
    let mut config = test_helpers::test_config();
    let userinfo_url = format!(
        "{}{}",
        "https://id.example.com",
        qid_core::config::ServerPaths::default().userinfo
    );
    config.realms[0].protocols.oauth.resource_servers = vec![
        OAuthResourceServerConfig {
            audience: "api://mcp".to_string(),
            resources: vec!["https://id.example.com/mcp".to_string()],
            scopes: vec!["mcp".to_string()],
            introspection_client_ids: Vec::new(),
            require_sender_constraint: false,
            high_risk: false,
        },
        OAuthResourceServerConfig {
            audience: "api://userinfo".to_string(),
            resources: vec![userinfo_url.clone()],
            scopes: vec!["openid".to_string()],
            introspection_client_ids: Vec::new(),
            require_sender_constraint: false,
            high_risk: false,
        },
    ];
    let (app, state) = setup_with_config(config).await;
    assert_eq!(state.paths.userinfo, "/oidc/userinfo");

    // Exact RFC 9728 §3.1 derivation resolves.
    let response = get_uri(
        app.clone(),
        format!("{}/mcp", state.paths.well_known_oauth_protected_resource),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let metadata = json_body(response).await;
    assert_eq!(metadata["resource"], "https://id.example.com/mcp");
    assert_eq!(metadata["audience"], "api://mcp");

    // Query identifiers on the path-inserted URL are ignored: exact wins.
    let metadata = get_json(
        app.clone(),
        format!(
            "{}/mcp?resource={}",
            state.paths.well_known_oauth_protected_resource,
            urlencoding::encode(&userinfo_url)
        ),
        None,
    )
    .await;
    assert_eq!(metadata["resource"], "https://id.example.com/mcp");

    // Bare trailing-segment fallback is gone: `/userinfo` does not select
    // `/oidc/userinfo`, and the full inserted path does.
    let trailing_response = get_uri(
        app.clone(),
        format!(
            "{}/userinfo",
            state.paths.well_known_oauth_protected_resource
        ),
        None,
    )
    .await;
    assert_eq!(trailing_response.status(), StatusCode::BAD_REQUEST);

    let metadata = get_json(
        app.clone(),
        format!(
            "{}/oidc/userinfo",
            state.paths.well_known_oauth_protected_resource
        ),
        None,
    )
    .await;
    assert_eq!(metadata["resource"], userinfo_url);

    // Bare base without an identifier is ambiguous with two servers.
    let bare_response = get_uri(
        app.clone(),
        &state.paths.well_known_oauth_protected_resource,
        None,
    )
    .await;
    assert_eq!(bare_response.status(), StatusCode::BAD_REQUEST);

    let unknown_response = get_uri(
        app.clone(),
        format!(
            "{}/unknown-resource",
            state.paths.well_known_oauth_protected_resource
        ),
        None,
    )
    .await;
    assert_eq!(unknown_response.status(), StatusCode::BAD_REQUEST);

    // The 401 pointer identifies the userinfo resource and resolves.
    let userinfo_response = get_uri(app.clone(), &state.paths.userinfo, None).await;
    assert_eq!(userinfo_response.status(), StatusCode::UNAUTHORIZED);
    let challenge = userinfo_response
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let expected_pointer = format!(
        "{}{}?resource={}",
        state.plan.public_base_url.trim_end_matches('/'),
        state.paths.well_known_oauth_protected_resource,
        urlencoding::encode(&userinfo_url)
    );
    assert!(
        challenge.contains(&format!("resource_metadata=\"{expected_pointer}\"")),
        "unexpected challenge: {challenge}"
    );
    let metadata = get_json(app, &expected_pointer, None).await;
    assert_eq!(metadata["resource"], userinfo_url);
}

#[tokio::test]
async fn userinfo_401_omits_pointer_when_userinfo_unconfigured() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.resource_servers = vec![
        OAuthResourceServerConfig {
            audience: "api://one".to_string(),
            resources: vec!["https://api.example.com/one".to_string()],
            scopes: vec!["one".to_string()],
            introspection_client_ids: Vec::new(),
            require_sender_constraint: false,
            high_risk: false,
        },
        OAuthResourceServerConfig {
            audience: "api://two".to_string(),
            resources: vec!["https://api.example.com/two".to_string()],
            scopes: vec!["two".to_string()],
            introspection_client_ids: Vec::new(),
            require_sender_constraint: false,
            high_risk: false,
        },
    ];
    let (app, state) = setup_with_config(config).await;
    let response = get_uri(app, &state.paths.userinfo, None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let challenge = response
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        !challenge.contains("resource_metadata"),
        "unexpected challenge: {challenge}"
    );
}

#[tokio::test]
async fn userinfo_accepts_dpop_scheme_with_valid_proof() {
    // RFC 9449 section 7.1: an issued DPoP-bound token must work with the
    // DPoP authorization scheme, with proof, key, and ath enforced.
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.dpop.enabled = true;
    let (app, state) = setup_with_config(config).await;
    state
        .repo
        .create_client(&Client {
            id: "client-userinfo-service".to_string(),
            realm_id: "test".to_string(),
            client_id: "userinfo-service".to_string(),
            client_type: ClientType::Confidential,
            token_endpoint_auth_method: "client_secret_post".to_string(),
            client_secret_hash: Some(qid_core::util::client_secret_hash("secret")),
            mtls_certificate_thumbprints: Vec::new(),
            jwks: qid_core::models::default_client_jwks(),
            redirect_uris: Vec::new(),
            grant_types: vec!["client_credentials".to_string()],
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
        })
        .await
        .unwrap();

    let token_htu = format!("https://id.example.com{}", state.paths.token);
    let issue_proof = dpop_proof("userinfo-issue-1", "POST", &token_htu, None, None);
    let token_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.token)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("DPoP", issue_proof)
        .body(Body::from(
            "grant_type=client_credentials&client_id=userinfo-service&client_secret=secret&scope=openid",
        ))
        .unwrap();
    let token_response = app.clone().oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_json = json_body(token_response).await;
    assert_eq!(token_json["token_type"], "DPoP");
    let bound_token = token_json["access_token"].as_str().unwrap().to_string();

    let userinfo_htu = format!("https://id.example.com{}", state.paths.userinfo);
    let ath = util::sha256_base64url(&bound_token);
    let get_userinfo = |scheme: &str, token: &str, proof: Option<String>| {
        let mut builder = Request::builder()
            .method(Method::GET)
            .uri(&state.paths.userinfo)
            .header("Authorization", format!("{scheme} {token}"));
        if let Some(proof) = proof {
            builder = builder.header("DPoP", proof);
        }
        app.clone().oneshot(builder.body(Body::empty()).unwrap())
    };
    let valid_proof = || dpop_proof("userinfo-use", "GET", &userinfo_htu, Some(&ath), None);

    // DPoP scheme with a correct proof succeeds.
    let response = get_userinfo("DPoP", &bound_token, Some(valid_proof()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Missing proof, wrong key, and wrong ath all fail without disclosing.
    let response = get_userinfo("DPoP", &bound_token, None).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let other_key = generate_es256("userinfo-other-key").unwrap();
    let response = get_userinfo(
        "DPoP",
        &bound_token,
        Some(dpop_proof(
            "userinfo-wrong-key",
            "GET",
            &userinfo_htu,
            Some(&ath),
            Some((other_key.private_pem, other_key.public_jwk)),
        )),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = get_userinfo(
        "DPoP",
        &bound_token,
        Some(dpop_proof(
            "userinfo-wrong-ath",
            "GET",
            &userinfo_htu,
            Some("nope"),
            None,
        )),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // The DPoP scheme requires a sender-constrained token.
    let plain_response = post_form(
        app.clone(),
        state.paths.token.clone(),
        "grant_type=client_credentials&client_id=userinfo-service&client_secret=secret&scope=openid",
    )
    .await;
    assert_eq!(plain_response.status(), StatusCode::OK);
    let plain_json = json_body(plain_response).await;
    let plain_token = plain_json["access_token"].as_str().unwrap();
    let plain_ath = util::sha256_base64url(plain_token);
    let response = get_userinfo(
        "DPoP",
        plain_token,
        Some(dpop_proof(
            "userinfo-plain",
            "GET",
            &userinfo_htu,
            Some(&plain_ath),
            None,
        )),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Ordinary Bearer presentation of the unbound token still works.
    let bearer_response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&state.paths.userinfo)
                .header("Authorization", format!("Bearer {plain_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bearer_response.status(), StatusCode::OK);
}

/// Base authorize query with PKCE; `extra` appends raw query parameters.
fn authorize_query(state: &Arc<SharedState<SqlRepository>>, extra: impl Into<String>) -> String {
    format!(
        "{}?client_id=par-client&response_type=code&redirect_uri={}&scope=openid&state=s&nonce=n&code_challenge={}&code_challenge_method=S256{}",
        state.paths.authorize,
        urlencoding::encode("https://app.example.com/callback"),
        util::sha256_base64url("verifier"),
        extra.into(),
    )
}

/// Authorize query carrying one essential acr fragment in `claims`.
fn essential_acr_query(state: &Arc<SharedState<SqlRepository>>, fragment: &str) -> String {
    let raw = format!("{{\"id_token\":{{\"acr\":{{\"essential\":true,{fragment}}}}}}}");
    authorize_query(state, format!("&claims={}", urlencoding::encode(&raw)))
}

#[tokio::test]
async fn authorize_session_reuse_enforces_essential_acr() {
    let (app, state) = setup().await;
    create_browser_session(&state, "sid-acr").await;

    // Unmet essential values fall back to login: no redirect, no code.
    let unmet = essential_acr_query(&state, "\"values\":[\"urn:qid:acr:password\"]");
    let challenged = get_uri(app.clone(), unmet, Some("__Host-qid=sid-acr")).await;
    assert_login_challenge(challenged).await;

    // Voluntary `acr_values` alone never block reuse.
    let voluntary = authorize_query(&state, "&acr_values=urn:qid:acr:password");
    let reused = get_uri(app, voluntary, Some("__Host-qid=sid-acr")).await;
    assert_code_issued(&reused);
}

#[tokio::test]
async fn authorize_post_enforces_essential_acr_value() {
    let (app, state) = setup().await;

    // An unmet singular essential value fails the login flow without a code.
    let unmet = essential_acr_query(&state, "\"value\":\"urn:qid:acr:phishing-resistant\"");
    let denied = post_form(app.clone(), unmet, LOGIN_FORM).await;
    assert_eq!(denied.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = redirect_location(&denied);
    assert!(location.contains("error=unmet_authentication_requirements"));
    assert!(!location.contains("code=ac_"));

    // The password session satisfies its own essential value.
    let matched = essential_acr_query(&state, "\"value\":\"urn:qid:acr:password\"");
    let issued = post_form(app, matched, LOGIN_FORM).await;
    assert_code_issued(&issued);
}

#[tokio::test]
async fn authorize_post_refuses_password_login_for_passwordless_realm() {
    let mut config = test_helpers::test_config();
    // A passwordless realm must have passkeys enabled.
    config.realms[0].authentication.passkeys.enabled = true;
    config.realms[0].authentication.passwordless_only = true;
    let (app, state) = setup_with_config(config).await;

    // The password is correct, but the realm refuses password logins.
    let denied = post_form(app, authorize_query(&state, ""), LOGIN_FORM).await;
    assert_eq!(denied.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = redirect_location(&denied);
    assert!(location.contains("error=access_denied"), "{location}");
    assert!(!location.contains("code=ac_"), "{location}");
}

#[tokio::test]
async fn authorize_post_locks_the_account_after_the_realm_attempt_limit() {
    let mut config = test_helpers::test_config();
    config.realms[0].authentication.password.max_failed_attempts = 2;
    let (app, state) = setup_with_config(config).await;

    // Two failures are below the realm's limit, so each is a refusal of
    // the password.
    for _ in 0..2 {
        let refused = post_form(
            app.clone(),
            authorize_query(&state, ""),
            "email=par%40example.com&password=wrong-password",
        )
        .await;
        let location = redirect_location(&refused);
        assert!(location.contains("error=access_denied"), "{location}");
        assert!(!location.contains("code=ac_"), "{location}");
    }

    // The second failure locked the account.
    let user = state
        .repo
        .get_user_by_id("par-user")
        .await
        .expect("user lookup failed")
        .expect("the user is missing");
    assert!(
        user.locked_until.is_some(),
        "the account is locked after the realm's limit"
    );

    // The account's admission count is spent with the realm's limit, so
    // the correct password is refused before any credential is verified.
    // The refusal is a temporary condition of the address, so it issues
    // no code and says nothing about the password.
    let refused = post_form(app, authorize_query(&state, ""), LOGIN_FORM).await;
    let location = redirect_location(&refused);
    assert!(
        location.contains("error=temporarily_unavailable"),
        "{location}"
    );
    assert!(!location.contains("code=ac_"), "{location}");
}

#[tokio::test]
async fn authorize_post_refuses_password_logins_once_the_realm_budget_is_spent() {
    let mut config = test_helpers::test_config();
    // The realm accepts two failed logins per window. The account lockout
    // stays at five, so what refuses the third attempt is the budget of
    // the realm rather than the lockout of the account.
    config.realms[0].authentication.password.max_failed_attempts = 5;
    config.realms[0]
        .authentication
        .password
        .max_failed_attempts_per_realm = 2;
    let (app, state) = setup_with_config(config).await;

    for _ in 0..2 {
        let refused = post_form(
            app.clone(),
            authorize_query(&state, ""),
            "email=par%40example.com&password=wrong-password",
        )
        .await;
        let location = redirect_location(&refused);
        assert!(location.contains("error=access_denied"), "{location}");
    }

    // The realm's budget is spent, so the correct password is refused as
    // a temporary condition rather than as a wrong password.
    let refused = post_form(app, authorize_query(&state, ""), LOGIN_FORM).await;
    let location = redirect_location(&refused);
    assert!(
        location.contains("error=temporarily_unavailable"),
        "{location}"
    );
    assert!(!location.contains("code=ac_"), "{location}");
}

#[tokio::test]
async fn authorize_par_preserves_assurance_requirements() {
    let (app, state) = setup().await;
    create_browser_session(&state, "sid-par-acr").await;
    let base_params = |extra: (&str, serde_json::Value)| {
        let mut params = serde_json::json!({
            "client_id": "par-client",
            "response_type": "code",
            "redirect_uri": "https://app.example.com/callback",
            "code_challenge": util::sha256_base64url("verifier"),
            "code_challenge_method": "S256",
        });
        params[extra.0] = extra.1;
        params
    };

    // Essential claims carried only by PAR still gate session reuse.
    let claims_uri = "urn:ietf:params:oauth:request_uri:acr-claims";
    let claims_params = base_params((
        "claims",
        serde_json::json!(
            "{\"id_token\":{\"acr\":{\"essential\":true,\"values\":[\"urn:qid:acr:password\"]}}}"
        ),
    ));
    store_par_request(&state, claims_uri, claims_params).await;
    let challenged = get_par_request(
        app.clone(),
        &state,
        claims_uri,
        Some("__Host-qid=sid-par-acr"),
    )
    .await;
    assert_login_challenge(challenged).await;

    // A PAR-only max_age is honored against the reused session.
    let age_uri = "urn:ietf:params:oauth:request_uri:acr-max-age";
    let age_params = base_params(("max_age", serde_json::json!(1)));
    store_par_request(&state, age_uri, age_params).await;
    let stale = get_par_request(app, &state, age_uri, Some("__Host-qid=sid-par-acr")).await;
    assert_login_challenge(stale).await;
}

#[tokio::test]
async fn authorize_signed_request_preserves_essential_acr() {
    let (app, state) = setup().await;
    create_browser_session(&state, "sid-jar-acr").await;
    let extra: HashMap<String, serde_json::Value> = [
        ("client_id", serde_json::json!("par-client")),
        ("response_type", serde_json::json!("code")),
        (
            "redirect_uri",
            serde_json::json!("https://app.example.com/callback"),
        ),
        (
            "code_challenge",
            serde_json::json!(util::sha256_base64url("verifier")),
        ),
        ("code_challenge_method", serde_json::json!("S256")),
        (
            "claims",
            serde_json::json!({
                "id_token": {"acr": {"essential": true, "values": ["urn:qid:acr:password"]}}
            }),
        ),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value))
    .collect();
    let request_object = signed_request_object(&state, "acr-jar-test", "acr-jar-key", extra).await;
    let challenged = get_uri(
        app,
        format!(
            "{}?request={}",
            state.paths.authorize,
            urlencoding::encode(&request_object)
        ),
        Some("__Host-qid=sid-jar-acr"),
    )
    .await;
    assert_login_challenge(challenged).await;
}
