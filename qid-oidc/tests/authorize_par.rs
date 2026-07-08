#![allow(clippy::expect_used, clippy::unwrap_used)]

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use qid_core::{
    config::{OAuthResourceServerConfig, QidConfig},
    jwt::JwtClaims,
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
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU16, Ordering};
use tower::ServiceExt;

static DB_SEQ: AtomicU16 = AtomicU16::new(0);

fn db_url() -> String {
    let dir = std::env::temp_dir().join("qid_test_oidc");
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
        hash: hash_password("correct-password").unwrap(),
        algorithm: "argon2id".to_string(),
        pepper_ref: None,
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

async fn sign_registered_request_object(
    state: &Arc<SharedState<SqlRepository>>,
    claims: JwtClaims,
    kid: &str,
) -> String {
    let generated = generate_es256(kid).unwrap();
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
    let payload = serde_json::to_value(claims).unwrap();
    sign_es256_jwt_with_jwk_header(
        generated.private_pem.as_bytes(),
        &generated.public_jwk,
        "oauth-authz-req+jwt",
        &payload,
    )
    .unwrap()
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
    let request = Request::builder()
        .method(Method::GET)
        .uri(&state.paths.well_known_oauth_authorization_server)
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let request = Request::builder()
        .method(Method::GET)
        .uri(&state.paths.well_known_oauth_authorization_server)
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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

    let openid_request = Request::builder()
        .method(Method::GET)
        .uri(&state.paths.well_known_openid_configuration)
        .body(Body::empty())
        .unwrap();
    let openid_response = app.oneshot(openid_request).await.unwrap();
    assert_eq!(openid_response.status(), StatusCode::OK);
    let bytes = openid_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let openid: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let request = Request::builder()
        .method(Method::GET)
        .uri(&state.paths.well_known_oauth_authorization_server)
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let request = Request::builder()
        .method(Method::GET)
        .uri(&state.paths.well_known_openid_configuration)
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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

    let logout_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.logout)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::empty())
        .unwrap();
    let logout_response = app.oneshot(logout_request).await.unwrap();
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
    let bytes = metadata_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "{}?client_id=par-client&response_type=code&redirect_uri={}&scope=openid%20profile&state=session-state&nonce=session-nonce&code_challenge={}&code_challenge_method=S256",
            state.paths.authorize,
            urlencoding::encode("https://app.example.com/callback"),
            util::sha256_base64url("verifier")
        ))
        .header("Cookie", "__Host-qid=sid-authorize")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.starts_with("https://app.example.com/callback?code=ac_"));
    assert!(location.contains("state=session-state"));
    let code = extract_query_param(location, "code").expect("redirect should include code");
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
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "{}?client_id=par-client&response_type=code&redirect_uri={}&scope=openid&state=prompt-state&prompt=login&code_challenge={}&code_challenge_method=S256",
            state.paths.authorize,
            urlencoding::encode("https://app.example.com/callback"),
            util::sha256_base64url("verifier")
        ))
        .header("Cookie", "__Host-qid=sid-prompt-login")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let challenge: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(challenge["challenge"], "login_required");
    assert_eq!(challenge["client_id"], "par-client");
    assert_eq!(challenge["state"], "prompt-state");
}

#[tokio::test]
async fn logout_redirect_requires_registered_client_uri() {
    let (app, state) = setup().await;
    let body =
        "client_id=par-client&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback";
    let request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.logout)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        response.headers().get("location").unwrap(),
        "https://app.example.com/callback"
    );
}

#[tokio::test]
async fn logout_rejects_unregistered_redirect_uri() {
    let (app, state) = setup().await;
    let body =
        "client_id=par-client&post_logout_redirect_uri=https%3A%2F%2Fevil.example.com%2Fcallback";
    let request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.logout)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
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
    let disabled_bytes = disabled_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let disabled_metadata: serde_json::Value = serde_json::from_slice(&disabled_bytes).unwrap();
    assert!(
        !disabled_metadata["token_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("tls_client_auth"))
    );

    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.mtls.enabled = true;
    let (app, state) = setup_with_config(config).await;
    let request = Request::builder()
        .method(Method::GET)
        .uri(&state.paths.well_known_oauth_authorization_server)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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

    let as_request = Request::builder()
        .method(Method::GET)
        .uri(&state.paths.well_known_oauth_authorization_server)
        .body(Body::empty())
        .unwrap();
    let as_response = app.clone().oneshot(as_request).await.unwrap();
    assert_eq!(as_response.status(), StatusCode::OK);
    let bytes = as_response.into_body().collect().await.unwrap().to_bytes();
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let protected_resources = metadata["protected_resources"].as_array().unwrap();
    assert!(protected_resources.contains(&serde_json::json!("api://payments")));
    assert!(protected_resources.contains(&serde_json::json!("https://api.example.com/payments")));

    let pr_request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "{}?resource={}",
            state.paths.well_known_oauth_protected_resource,
            urlencoding::encode("https://api.example.com/payments")
        ))
        .body(Body::empty())
        .unwrap();
    let pr_response = app.clone().oneshot(pr_request).await.unwrap();
    assert_eq!(pr_response.status(), StatusCode::OK);
    let bytes = pr_response.into_body().collect().await.unwrap().to_bytes();
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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

    let audience_request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "{}?audience={}",
            state.paths.well_known_oauth_protected_resource,
            urlencoding::encode("api://profile")
        ))
        .body(Body::empty())
        .unwrap();
    let audience_response = app.clone().oneshot(audience_request).await.unwrap();
    assert_eq!(audience_response.status(), StatusCode::OK);
    let bytes = audience_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(metadata["resource"], "https://api.example.com/profile");
    assert_eq!(metadata["sender_constrained_access_tokens"], false);

    let missing_request = Request::builder()
        .method(Method::GET)
        .uri(&state.paths.well_known_oauth_protected_resource)
        .body(Body::empty())
        .unwrap();
    let missing_response = app.oneshot(missing_request).await.unwrap();
    assert_eq!(missing_response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn path_issuer_single_realm_requires_scoped_discovery_metadata() {
    let mut config = test_helpers::test_config();
    config.realms[0].issuer = "https://id.example.com/realms/test".to_string();
    let (app, _state) = setup_with_config(config).await;

    let global_oidc_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(global_oidc_response.status(), StatusCode::BAD_REQUEST);

    let global_oauth_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/.well-known/oauth-authorization-server")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(global_oauth_response.status(), StatusCode::BAD_REQUEST);

    let scoped_oidc_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/realms/test/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(scoped_oidc_response.status(), StatusCode::OK);
    let bytes = scoped_oidc_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(metadata["issuer"], "https://id.example.com/realms/test");

    let scoped_oauth_response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/.well-known/oauth-authorization-server/realms/test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(scoped_oauth_response.status(), StatusCode::OK);
    let bytes = scoped_oauth_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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

    let global_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(global_response.status(), StatusCode::BAD_REQUEST);

    let scoped_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/realms/realm-b/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(scoped_response.status(), StatusCode::OK);
    let bytes = scoped_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(metadata["issuer"], "https://id.example.com/realms/realm-b");
    assert_eq!(
        metadata["check_session_iframe"],
        "https://id.example.com/realms/realm-b/session/check"
    );

    let oauth_metadata_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/.well-known/oauth-authorization-server/realms/realm-b")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oauth_metadata_response.status(), StatusCode::OK);
    let bytes = oauth_metadata_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let oauth_metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        oauth_metadata["issuer"],
        "https://id.example.com/realms/realm-b"
    );

    let iframe_response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/realms/realm-b/session/check")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
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

    let global_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/.well-known/ssf-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(global_response.status(), StatusCode::BAD_REQUEST);

    let scoped_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/realms/test/.well-known/ssf-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(scoped_response.status(), StatusCode::OK);
    let bytes = scoped_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
            aud: Some("qid-ssf-admin".to_string()),
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
    state
        .repo
        .store_par_request(&ParRequest {
            request_uri: request_uri.to_string(),
            client_id: "par-client".to_string(),
            realm_id: "test".to_string(),
            params_json: serde_json::json!({
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
            expires_at: util::now_seconds() + 60,
            used: false,
            created_at: util::now_seconds(),
        })
        .await
        .unwrap();

    let get_request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "{}?request_uri={}",
            state.paths.authorize,
            urlencoding::encode(request_uri)
        ))
        .body(Body::empty())
        .unwrap();
    let get_response = app.clone().oneshot(get_request).await.unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    let bytes = get_response.into_body().collect().await.unwrap().to_bytes();
    let challenge: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(challenge["client_id"], "par-client");
    assert_eq!(challenge["state"], "state-from-par");

    let post_request = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "{}?request_uri={}",
            state.paths.authorize,
            urlencoding::encode(request_uri)
        ))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "email=par%40example.com&password=correct-password",
        ))
        .unwrap();
    let post_response = app.clone().oneshot(post_request).await.unwrap();
    assert_eq!(post_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = post_response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.starts_with("https://app.example.com/callback?code=ac_"));
    assert!(location.contains("state=state-from-par"));
    let code = extract_query_param(location, "code").expect("redirect should include code");

    let token_body = format!(
        "grant_type=authorization_code&client_id=par-client&code={}&redirect_uri={}&code_verifier=verifier",
        urlencoding::encode(&code),
        urlencoding::encode("https://app.example.com/callback")
    );
    let token_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.token)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(token_body))
        .unwrap();
    let token_response = app.clone().oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let bytes = token_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let token_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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

    let replay_request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "{}?request_uri={}",
            state.paths.authorize,
            urlencoding::encode(request_uri)
        ))
        .body(Body::empty())
        .unwrap();
    let replay_response = app.oneshot(replay_request).await.unwrap();
    assert_eq!(replay_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn authorize_rejects_invalid_authorization_details_from_par() {
    let (app, state) = setup().await;
    let request_uri = "urn:ietf:params:oauth:request_uri:invalid-rar";
    state
        .repo
        .store_par_request(&ParRequest {
            request_uri: request_uri.to_string(),
            client_id: "par-client".to_string(),
            realm_id: "test".to_string(),
            params_json: serde_json::json!({
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
            expires_at: util::now_seconds() + 60,
            used: false,
            created_at: util::now_seconds(),
        })
        .await
        .unwrap();

    let get_request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "{}?request_uri={}",
            state.paths.authorize,
            urlencoding::encode(request_uri)
        ))
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(get_request).await.unwrap();
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
    let request_object = sign_registered_request_object(
        &state,
        JwtClaims {
            iss: Some("par-client".to_string()),
            sub: Some("par-client".to_string()),
            aud: Some("https://id.example.com".to_string()),
            exp: Some((util::now_seconds() + 60) as usize),
            nbf: Some(util::now_seconds() as usize),
            iat: Some(util::now_seconds() as usize),
            jti: Some("jar-test".to_string()),
            extra,
        },
        "jar-test-key",
    )
    .await;

    let get_request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "{}?request={}",
            state.paths.authorize,
            urlencoding::encode(&request_object)
        ))
        .body(Body::empty())
        .unwrap();
    let get_response = app.clone().oneshot(get_request).await.unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);

    let post_request = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "{}?request={}",
            state.paths.authorize,
            urlencoding::encode(&request_object)
        ))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "email=par%40example.com&password=correct-password",
        ))
        .unwrap();
    let post_response = app.clone().oneshot(post_request).await.unwrap();
    assert_eq!(post_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = post_response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.contains("state=state-from-jar"));
    let code = extract_query_param(location, "code").expect("redirect should include code");

    let token_body = format!(
        "grant_type=authorization_code&client_id=par-client&code={}&redirect_uri={}&code_verifier=jar-verifier",
        urlencoding::encode(&code),
        urlencoding::encode("https://app.example.com/callback")
    );
    let token_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.token)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(token_body))
        .unwrap();
    let token_response = app.oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let bytes = token_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let token_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let request_object = sign_registered_request_object(
        &state,
        JwtClaims {
            iss: Some("par-client".to_string()),
            sub: Some("par-client".to_string()),
            aud: Some("https://id.example.com".to_string()),
            exp: Some((util::now_seconds() + 60) as usize),
            nbf: Some(util::now_seconds() as usize),
            iat: Some(util::now_seconds() as usize),
            jti: Some("jarm-request-test".to_string()),
            extra,
        },
        "jarm-request-test-key",
    )
    .await;

    let post_request = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "{}?request={}",
            state.paths.authorize,
            urlencoding::encode(&request_object)
        ))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "email=par%40example.com&password=correct-password",
        ))
        .unwrap();
    let post_response = app.clone().oneshot(post_request).await.unwrap();
    assert_eq!(post_response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = post_response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.starts_with("https://app.example.com/callback?response="));
    let response = extract_query_param(location, "response").expect("JARM response is required");
    let response_claims = state
        .signer
        .decode_signature_only(&response)
        .unwrap()
        .claims;
    assert_eq!(response_claims.aud, Some("par-client".to_string()));
    assert_eq!(response_claims.extra["state"], "state-from-jarm");
    let code = response_claims.extra["code"].as_str().unwrap();
    assert!(code.starts_with("ac_"));

    let token_body = format!(
        "grant_type=authorization_code&client_id=par-client&code={}&redirect_uri={}&code_verifier=jarm-verifier",
        urlencoding::encode(code),
        urlencoding::encode("https://app.example.com/callback")
    );
    let token_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.token)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(token_body))
        .unwrap();
    let token_response = app.oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
}
