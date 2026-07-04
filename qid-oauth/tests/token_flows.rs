use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use base64::Engine;
use http_body_util::BodyExt;
use qid_core::{
    config::{OAuthResourceServerConfig, PepRegistrationConfig, QidConfig},
    models::{AuthorizationCode, Client, ClientType, Session, TokenFormat, User},
    state::SharedState,
    tenant::RealmId,
    test_helpers, util,
};
use qid_crypto::{
    Jwk, JwtClaims, LocalSigner, jwk::generate_es256, jwt::sign_es256_jwt_with_jwk_header,
};
use qid_storage::{SqlRepository, prelude::*};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU16, Ordering};
use tower::ServiceExt;

static DB_SEQ: AtomicU16 = AtomicU16::new(0);

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
            aud: Some(audience.to_string()),
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
    let repo = Arc::new(SqlRepository::connect(&db_url()).await.unwrap());
    repo.migrate().await.unwrap();
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

async fn seed_token_flow_clients(state: &Arc<SharedState<SqlRepository>>) {
    let clients = [
        Client {
            id: "client-test-client".to_string(),
            realm_id: "test".to_string(),
            client_id: "test-client".to_string(),
            client_type: ClientType::Public,
            token_endpoint_auth_method: "none".to_string(),
            client_secret_hash: None,
            mtls_certificate_thumbprints: Vec::new(),
            jwks: qid_core::models::default_client_jwks(),
            redirect_uris: vec!["https://app.example.com/callback".to_string()],
            grant_types: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
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
        },
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
        saml_bearer_client("saml-bearer-client"),
        client_credentials_client("mtls-client", "tls_client_auth"),
        ciba_client("ciba-client"),
    ];
    for client in clients {
        state.repo.create_client(&client).await.unwrap();
    }
}

fn private_key_jwt_client(client_id: &str) -> Client {
    Client {
        id: format!("client-{client_id}"),
        realm_id: "test".to_string(),
        client_id: client_id.to_string(),
        client_type: ClientType::Confidential,
        token_endpoint_auth_method: "private_key_jwt".to_string(),
        client_secret_hash: None,
        mtls_certificate_thumbprints: Vec::new(),
        jwks: private_key_jwt_jwks(),
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
    }
}

fn ciba_client(client_id: &str) -> Client {
    Client {
        id: format!("client-{client_id}"),
        realm_id: "test".to_string(),
        client_id: client_id.to_string(),
        client_type: ClientType::Confidential,
        token_endpoint_auth_method: "client_secret_post".to_string(),
        client_secret_hash: Some(qid_core::util::client_secret_hash("secret")),
        mtls_certificate_thumbprints: Vec::new(),
        jwks: qid_core::models::default_client_jwks(),
        redirect_uris: Vec::new(),
        grant_types: vec!["urn:openid:params:grant-type:ciba".to_string()],
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

fn client_credentials_client(client_id: &str, auth_method: &str) -> Client {
    Client {
        id: format!("client-{client_id}"),
        realm_id: "test".to_string(),
        client_id: client_id.to_string(),
        client_type: ClientType::Confidential,
        token_endpoint_auth_method: auth_method.to_string(),
        client_secret_hash: matches!(auth_method, "client_secret_basic" | "client_secret_post")
            .then(|| qid_core::util::client_secret_hash("secret")),
        mtls_certificate_thumbprints: if auth_method == "tls_client_auth" {
            vec!["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".to_string()]
        } else {
            Vec::new()
        },
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
    }
}

fn token_exchange_client(client_id: &str) -> Client {
    Client {
        id: format!("client-{client_id}"),
        realm_id: "test".to_string(),
        client_id: client_id.to_string(),
        client_type: ClientType::Confidential,
        token_endpoint_auth_method: "client_secret_post".to_string(),
        client_secret_hash: Some(qid_core::util::client_secret_hash("secret")),
        mtls_certificate_thumbprints: Vec::new(),
        jwks: qid_core::models::default_client_jwks(),
        redirect_uris: Vec::new(),
        grant_types: vec!["urn:ietf:params:oauth:grant-type:token-exchange".to_string()],
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

fn jwt_bearer_client(client_id: &str) -> Client {
    Client {
        id: format!("client-{client_id}"),
        realm_id: "test".to_string(),
        client_id: client_id.to_string(),
        client_type: ClientType::Confidential,
        token_endpoint_auth_method: "client_secret_post".to_string(),
        client_secret_hash: Some(qid_core::util::client_secret_hash("secret")),
        mtls_certificate_thumbprints: Vec::new(),
        jwks: private_key_jwt_jwks(),
        redirect_uris: Vec::new(),
        grant_types: vec!["urn:ietf:params:oauth:grant-type:jwt-bearer".to_string()],
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

fn saml_bearer_client(client_id: &str) -> Client {
    Client {
        id: format!("client-{client_id}"),
        realm_id: "test".to_string(),
        client_id: client_id.to_string(),
        client_type: ClientType::Confidential,
        token_endpoint_auth_method: "client_secret_post".to_string(),
        client_secret_hash: Some(qid_core::util::client_secret_hash("secret")),
        mtls_certificate_thumbprints: Vec::new(),
        jwks: qid_core::models::default_client_jwks(),
        redirect_uris: Vec::new(),
        grant_types: vec!["urn:ietf:params:oauth:grant-type:saml2-bearer".to_string()],
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

fn build_saml_bearer_assertion(subject: &str, audience: &str, expires_at: u64) -> String {
    let now = util::now_seconds();
    let unsigned = format!(
        r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="assert-saml-bearer-1" Version="2.0" IssueInstant="{now}">
  <saml:Issuer>https://saml-idp.example.com</saml:Issuer>
  <!--SIGNATURE-->
  <saml:Subject>
    <saml:NameID>{subject}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData Recipient="{audience}" NotOnOrAfter="{expires_at}"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="{now}" NotOnOrAfter="{expires_at}">
    <saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="{now}"/>
</saml:Assertion>"##
    );
    let cert_pem = include_str!("data/test-sp.crt");
    let key_pem = include_str!("data/test-sp.key");
    let cert_body: String = cert_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    use qid_saml::{SamlXmlSignatureAlgorithm, sign_saml_element_with_key};
    let mut signature = sign_saml_element_with_key(
        &unsigned,
        "assert-saml-bearer-1",
        SamlXmlSignatureAlgorithm::RsaSha256,
        key_pem.as_bytes(),
    )
    .expect("SAML bearer assertion must sign");
    let keyinfo = format!(
        "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
        cert_body.trim()
    );
    let insertion = format!("{keyinfo}<ds:SignatureValue");
    if let Some(pos) = signature.find("<ds:SignatureValue") {
        let mut out = String::with_capacity(signature.len() + keyinfo.len());
        out.push_str(&signature[..pos]);
        out.push_str(&insertion);
        out.push_str(&signature[pos..]);
        signature = out;
    }
    unsigned.replace("<!--SIGNATURE-->", &signature)
}

#[tokio::test]
async fn client_credentials_grant_succeeds() {
    let (app, token_path, _) = setup().await;

    let body =
        "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=api";
    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["token_type"], "Bearer");
    assert!(json["access_token"].as_str().unwrap().len() > 10);
    assert_eq!(json["scope"], "api");
}

#[tokio::test]
async fn client_credentials_grant_rejects_wrong_client_secret_post() {
    let (app, token_path, _) = setup().await;

    let body =
        "grant_type=client_credentials&client_id=service-client&client_secret=wrong&scope=api";
    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
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
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.private_key_jwt.enabled = true;
    let (app, token_path, _) = setup_with_config(config).await;
    let assertion = build_client_assertion("pkjwt-client", "pkjwt-success-1");
    let body = format!(
        "grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={assertion}&scope=api"
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn client_credentials_grant_rejects_tampered_private_key_jwt() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.private_key_jwt.enabled = true;
    let (app, token_path, _) = setup_with_config(config).await;
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
    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn client_credentials_grant_rejects_private_key_jwt_when_disabled() {
    let (app, token_path, _) = setup().await;
    let assertion = build_client_assertion("pkjwt-client", "pkjwt-disabled-1");
    let body = format!(
        "grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={assertion}&scope=api"
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
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
    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
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
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.dpop.enabled = true;
    let (app, token_path, state) = setup_with_config(config).await;

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
    let bytes = subject_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let subject_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let bytes = exchange_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let exchange_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(exchange_json["token_type"], "DPoP");
    let exchanged_token = exchange_json["access_token"].as_str().unwrap();
    let claims = state
        .signer
        .decode_signature_only(exchanged_token)
        .unwrap()
        .claims;
    assert_eq!(claims.sub.as_deref(), Some("service:service-client"));
    assert_eq!(claims.aud.as_deref(), Some("api://payments"));
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
    let (app, token_path, state) = setup().await;

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
    let subject_bytes = subject_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let subject_json: serde_json::Value = serde_json::from_slice(&subject_bytes).unwrap();
    let subject_token = subject_json["access_token"].as_str().unwrap();

    let actor_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=introspection-client&client_secret=secret&scope=actor",
        ))
        .unwrap();
    let actor_response = app.clone().oneshot(actor_request).await.unwrap();
    assert_eq!(actor_response.status(), StatusCode::OK);
    let actor_bytes = actor_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let actor_json: serde_json::Value = serde_json::from_slice(&actor_bytes).unwrap();
    let actor_token = actor_json["access_token"].as_str().unwrap();

    let exchange_body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=exchange-client&client_secret=secret&subject_token_type=urn:ietf:params:oauth:token-type:access_token&subject_token={}&actor_token_type=urn:ietf:params:oauth:token-type:access_token&actor_token={}&audience=api://delegated&scope=delegated",
        urlencoding::encode(subject_token),
        urlencoding::encode(actor_token)
    );
    let exchange_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(exchange_body))
        .unwrap();
    let exchange_response = app.clone().oneshot(exchange_request).await.unwrap();
    assert_eq!(exchange_response.status(), StatusCode::OK);
    let exchange_bytes = exchange_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let exchange_json: serde_json::Value = serde_json::from_slice(&exchange_bytes).unwrap();
    assert_eq!(
        exchange_json["issued_token_type"],
        "urn:ietf:params:oauth:token-type:access_token"
    );
    let exchanged_token = exchange_json["access_token"].as_str().unwrap();
    let claims = state
        .signer
        .decode_signature_only(exchanged_token)
        .unwrap()
        .claims;
    assert_eq!(claims.sub.as_deref(), Some("service:service-client"));
    assert_eq!(claims.extra["act"]["sub"], "service:introspection-client");
    assert_eq!(claims.extra["act"]["client_id"], "introspection-client");
    assert_eq!(claims.extra["act"]["scope"], "actor");

    let introspect_body = format!("token={}", urlencoding::encode(exchanged_token));
    let introspect_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.introspect)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(introspect_body))
        .unwrap();
    let introspect_response = app.oneshot(introspect_request).await.unwrap();
    assert_eq!(introspect_response.status(), StatusCode::OK);
    let introspect_bytes = introspect_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let introspection: serde_json::Value = serde_json::from_slice(&introspect_bytes).unwrap();
    assert_eq!(introspection["act"]["sub"], "service:introspection-client");
    assert_eq!(introspection["act"]["client_id"], "introspection-client");
    assert_eq!(introspection["act"]["scope"], "actor");
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
    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
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
    let claims = state
        .signer
        .decode_signature_only(access_token)
        .unwrap()
        .claims;
    assert_eq!(claims.sub.as_deref(), Some("workload-123"));
    assert_eq!(claims.aud.as_deref(), Some("api://workload"));
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
async fn saml_bearer_grant_validates_assertion_and_uses_subject() {
    let (app, token_path, state) = setup().await;
    let token_url = format!("https://id.example.com{token_path}");
    let assertion =
        build_saml_bearer_assertion("saml-subject-123", &token_url, util::now_seconds() + 300);

    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer&client_id=saml-bearer-client&client_secret=secret&assertion={}&audience=api://saml&scope=saml",
        urlencoding::encode(&assertion)
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
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
    let claims = state
        .signer
        .decode_signature_only(access_token)
        .unwrap()
        .claims;
    assert_eq!(claims.sub.as_deref(), Some("saml-subject-123"));
    assert_eq!(claims.aud.as_deref(), Some("api://saml"));
    assert_eq!(claims.extra["client_id"], "saml-bearer-client");
    assert_eq!(claims.extra["scope"], "saml");
    assert_eq!(claims.extra["amr"], serde_json::json!(["saml"]));
}

#[tokio::test]
async fn saml_bearer_grant_rejects_wrong_audience() {
    let (app, token_path, _) = setup().await;
    let assertion = build_saml_bearer_assertion(
        "saml-subject-123",
        "https://wrong.example.com/oauth2/token",
        util::now_seconds() + 300,
    );

    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer&client_id=saml-bearer-client&client_secret=secret&assertion={}",
        urlencoding::encode(&assertion)
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
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
            aud: Some("https://id.example.com/not-token".to_string()),
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
    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
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
    config.realms[0].protocols.oauth.resource_servers = vec![
        OAuthResourceServerConfig {
            audience: "api://profile".to_string(),
            resources: vec!["https://api.example.com/profile".to_string()],
            scopes: vec!["api".to_string()],
            introspection_client_ids: vec!["introspection-client".to_string()],
            require_sender_constraint: false,
            high_risk: false,
        },
        OAuthResourceServerConfig {
            audience: "api://payments".to_string(),
            resources: vec!["https://api.example.com/payments".to_string()],
            scopes: vec!["payments".to_string()],
            introspection_client_ids: vec!["introspection-client".to_string()],
            require_sender_constraint: false,
            high_risk: true,
        },
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
    let bytes = profile_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let claims = state
        .signer
        .decode_signature_only(json["access_token"].as_str().unwrap())
        .unwrap()
        .claims;
    assert_eq!(claims.aud.as_deref(), Some("api://profile"));
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
    let claims = state
        .signer
        .decode_signature_only(json["access_token"].as_str().unwrap())
        .unwrap()
        .claims;
    assert_eq!(claims.aud.as_deref(), Some("api://payments"));
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
    let (app, token_path, state) = setup_with_config(config).await;
    let proof = build_dpop_proof("dpop-proof-token-flow");
    let expected_jkt = qid_oauth::dpop::dpop_jkt_from_proof(&proof).unwrap();

    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("DPoP", proof)
        .body(Body::from(
            "grant_type=client_credentials&client_id=dpop-client&client_secret=secret&scope=api",
        ))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["token_type"], "DPoP");
    let access_token = json["access_token"].as_str().unwrap();
    let claims = state
        .signer
        .decode_signature_only(access_token)
        .unwrap()
        .claims;
    assert_eq!(
        claims.extra["cnf"],
        serde_json::json!({"jkt": expected_jkt})
    );

    let introspect_body = format!("token={}", urlencoding::encode(access_token));
    let introspect_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.introspect)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(introspect_body))
        .unwrap();
    let introspect_response = app.oneshot(introspect_request).await.unwrap();
    assert_eq!(introspect_response.status(), StatusCode::OK);
    let bytes = introspect_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let introspection: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let replay_response = app.oneshot(replay_request).await.unwrap();
    assert_eq!(replay_response.status(), StatusCode::BAD_REQUEST);
    assert!(
        replay_response.headers().get("DPoP-Nonce").is_some(),
        "nonce replay failure should return a fresh challenge"
    );
}

#[tokio::test]
async fn mtls_client_credentials_rejects_certificate_headers() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.mtls.enabled = true;
    let (app, token_path, _) = setup_with_config(config).await;
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
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.mtls.enabled = true;
    let (app, token_path, _) = setup_with_config(config).await;
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
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["token_type"], "Bearer");
    let claims = state
        .signer
        .decode_signature_only(json["access_token"].as_str().unwrap())
        .unwrap()
        .claims;
    assert_eq!(claims.extra["token_type"], "Bearer");
    assert_eq!(claims.extra["cnf"]["x5t#S256"], registered_thumbprint);
    assert!(claims.extra["cnf"]["jkt"].is_null());
}

#[tokio::test]
async fn opaque_client_credentials_token_introspects_and_revokes() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.tokens.access_token_format = TokenFormat::Opaque;
    let (app, token_path, state) = setup_with_config(config).await;

    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=opaque-client&client_secret=secret&scope=api",
        ))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let access_token = json["access_token"].as_str().unwrap();
    assert!(access_token.starts_with("oat_oat_"));
    assert!(
        state.signer.decode_signature_only(access_token).is_err(),
        "opaque access token must not be a JWT"
    );

    let introspect_body = format!("token={}", urlencoding::encode(access_token));
    let introspect_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.introspect)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(introspect_body.clone()))
        .unwrap();
    let introspect_response = app.clone().oneshot(introspect_request).await.unwrap();
    assert_eq!(introspect_response.status(), StatusCode::OK);
    let bytes = introspect_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let introspection: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(introspection["active"], true);
    assert_eq!(introspection["client_id"], "opaque-client");
    assert_eq!(introspection["scope"], "api");

    let revoke_body = format!(
        "token={}&client_id=opaque-client&client_secret=secret",
        urlencoding::encode(access_token)
    );
    let revoke_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.revoke)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(revoke_body))
        .unwrap();
    let revoke_response = app.clone().oneshot(revoke_request).await.unwrap();
    assert_eq!(revoke_response.status(), StatusCode::OK);

    let introspect_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.introspect)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "token={}",
            urlencoding::encode(access_token)
        )))
        .unwrap();
    let introspect_response = app.oneshot(introspect_request).await.unwrap();
    assert_eq!(introspect_response.status(), StatusCode::OK);
    let bytes = introspect_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let introspection: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(introspection["active"], false);
}

#[tokio::test]
async fn revocation_requires_client_auth_and_preserves_other_client_tokens() {
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
    let bytes = token_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let token_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
            "token={}",
            urlencoding::encode(access_token)
        )))
        .unwrap();
    let introspect_response = app.oneshot(introspect_request).await.unwrap();
    assert_eq!(introspect_response.status(), StatusCode::OK);
    let bytes = introspect_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let introspection: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(introspection["active"], true);
    assert_eq!(introspection["client_id"], "service-client");
}

#[tokio::test]
async fn revocation_rejects_when_disabled() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.revocation.enabled = false;
    let (app, token_path, state) = setup_with_config(config).await;

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
    let bytes = token_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let token_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let bytes = token_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let token_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let access_token = json["access_token"].as_str().unwrap();

    let request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.introspect)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "token={}&response_format=jwt",
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
    let (app, token_path, state) = setup_with_config(config).await;

    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=introspection-jwt-client&client_secret=secret&scope=api",
        ))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let access_token = json["access_token"].as_str().unwrap();

    let request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.introspect)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "token={}&response_format=jwt",
            urlencoding::encode(access_token)
        )))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["active"], true);
    let token_introspection = json["token_introspection"].as_str().unwrap();
    let claims = state
        .signer
        .decode_signature_only(token_introspection)
        .unwrap()
        .claims;
    assert_eq!(claims.extra["active"], true);
    assert_eq!(claims.extra["client_id"], "introspection-jwt-client");
    assert_eq!(claims.extra["scope"], "api");
}

#[tokio::test]
async fn introspection_enforces_resource_server_policy() {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.oauth.introspection.jwt_response = true;
    config.realms[0].protocols.oauth.resource_servers = vec![
        OAuthResourceServerConfig {
            audience: "api://profile".to_string(),
            resources: vec!["https://api.example.com/profile".to_string()],
            scopes: vec!["api".to_string()],
            introspection_client_ids: vec!["introspection-client".to_string()],
            require_sender_constraint: false,
            high_risk: false,
        },
        OAuthResourceServerConfig {
            audience: "api://payments".to_string(),
            resources: vec!["https://api.example.com/payments".to_string()],
            scopes: vec!["payments".to_string()],
            introspection_client_ids: vec!["introspection-client".to_string()],
            require_sender_constraint: false,
            high_risk: false,
        },
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
    let bytes = token_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let token_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let access_token = token_json["access_token"].as_str().unwrap();

    let unauthenticated_body = format!("token={}", urlencoding::encode(access_token));
    let unauthenticated_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.introspect)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(unauthenticated_body))
        .unwrap();
    let unauthenticated_response = app.clone().oneshot(unauthenticated_request).await.unwrap();
    assert_eq!(unauthenticated_response.status(), StatusCode::UNAUTHORIZED);

    let allowed_body = format!(
        "token={}&client_id=introspection-client&client_secret=secret&resource=https%3A%2F%2Fapi.example.com%2Fprofile&response_format=jwt",
        urlencoding::encode(access_token)
    );
    let allowed_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.introspect)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(allowed_body))
        .unwrap();
    let allowed_response = app.clone().oneshot(allowed_request).await.unwrap();
    assert_eq!(allowed_response.status(), StatusCode::OK);
    let bytes = allowed_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let introspection: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(introspection["active"], true);
    assert_eq!(introspection["client_id"], "service-client");
    assert_eq!(introspection["scope"], "api");
    assert_eq!(introspection["aud"], serde_json::json!(["api://profile"]));
    assert_eq!(
        introspection["resource"],
        serde_json::json!(["https://api.example.com/profile"])
    );
    let token_introspection = introspection["token_introspection"].as_str().unwrap();
    let claims = state
        .signer
        .decode_signature_only(token_introspection)
        .unwrap()
        .claims;
    assert_eq!(claims.aud.as_deref(), Some("introspection-client"));
    assert_eq!(claims.extra["client_id"], "service-client");
    assert_eq!(
        claims.extra["resource"],
        serde_json::json!(["https://api.example.com/profile"])
    );

    let wrong_resource_body = format!(
        "token={}&client_id=introspection-client&client_secret=secret&resource=https%3A%2F%2Fapi.example.com%2Fpayments",
        urlencoding::encode(access_token)
    );
    let wrong_resource_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.introspect)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(wrong_resource_body))
        .unwrap();
    let wrong_resource_response = app.oneshot(wrong_resource_request).await.unwrap();
    assert_eq!(wrong_resource_response.status(), StatusCode::OK);
    let bytes = wrong_resource_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let wrong_resource: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let access_token = json["access_token"].as_str().unwrap();
    let access_claims = state
        .signer
        .decode_signature_only(access_token)
        .unwrap()
        .claims;
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
    let bytes = refresh_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let refresh_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let refreshed_access = refresh_json["access_token"].as_str().unwrap();
    let refreshed_claims = state
        .signer
        .decode_signature_only(refreshed_access)
        .unwrap()
        .claims;
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
    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn client_credentials_grant_missing_client_id_fails() {
    let (app, token_path, _) = setup().await;

    let body = "grant_type=client_credentials&scope=api";
    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unsupported_grant_type_fails() {
    let (app, token_path, _) = setup().await;

    let body = "grant_type=password&username=test&password=test";
    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
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
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let bytes = create_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let create_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let bytes = update_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
    let bytes = get_response.into_body().collect().await.unwrap().to_bytes();
    let get_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
        .create_client(&qid_core::models::Client {
            id: "device-client-id".to_string(),
            realm_id: "test".to_string(),
            client_id: "device-client".to_string(),
            client_type: qid_core::models::ClientType::Public,
            token_endpoint_auth_method: "none".to_string(),
            client_secret_hash: None,
            mtls_certificate_thumbprints: Vec::new(),
            jwks: qid_core::models::default_client_jwks(),
            redirect_uris: vec![],
            grant_types: vec!["urn:ietf:params:oauth:grant-type:device_code".to_string()],
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

    let request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.device_authorization)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from("client_id=device-client&scope=api"))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json["device_code"].as_str().unwrap().starts_with("dc_"));
    assert!(
        json["verification_uri"]
            .as_str()
            .unwrap()
            .contains("/oauth2/device_authorization")
    );
}

#[tokio::test]
async fn device_authorization_is_disabled_by_default() {
    let (app, _, state) = setup().await;
    state
        .repo
        .create_client(&qid_core::models::Client {
            id: "device-disabled-client-id".to_string(),
            realm_id: "test".to_string(),
            client_id: "device-disabled-client".to_string(),
            client_type: qid_core::models::ClientType::Public,
            token_endpoint_auth_method: "none".to_string(),
            client_secret_hash: None,
            mtls_certificate_thumbprints: Vec::new(),
            jwks: qid_core::models::default_client_jwks(),
            redirect_uris: vec![],
            grant_types: vec!["urn:ietf:params:oauth:grant-type:device_code".to_string()],
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

    let request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.device_authorization)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from("client_id=device-disabled-client&scope=api"))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
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
        .create_client(&qid_core::models::Client {
            id: "device-client-flow-id".to_string(),
            realm_id: "test".to_string(),
            client_id: "device-client-flow".to_string(),
            client_type: qid_core::models::ClientType::Public,
            token_endpoint_auth_method: "none".to_string(),
            client_secret_hash: None,
            mtls_certificate_thumbprints: Vec::new(),
            jwks: qid_core::models::default_client_jwks(),
            redirect_uris: vec![],
            grant_types: vec!["urn:ietf:params:oauth:grant-type:device_code".to_string()],
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

    let authorize_request = Request::builder()
        .method(Method::POST)
        .uri(&state.paths.device_authorization)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from("client_id=device-client-flow&scope=api"))
        .unwrap();
    let authorize_response = app.clone().oneshot(authorize_request).await.unwrap();
    assert_eq!(authorize_response.status(), StatusCode::OK);
    let bytes = authorize_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let device_code = json["device_code"].as_str().unwrap();
    let user_code = json["user_code"].as_str().unwrap();

    let pending_body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=device-client-flow&device_code={device_code}"
    );
    let pending_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(pending_body.clone()))
        .unwrap();
    let pending_response = app.clone().oneshot(pending_request).await.unwrap();
    assert_eq!(pending_response.status(), StatusCode::UNAUTHORIZED);
    let first_poll_grant = state
        .repo
        .get_device_authorization_grant(&util::sha256_base64url(device_code))
        .await
        .unwrap()
        .expect("device grant should exist after first poll");
    assert_eq!(first_poll_grant.poll_interval_seconds, 5);
    assert!(first_poll_grant.last_poll_at.is_some());

    let slow_down_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(pending_body.clone()))
        .unwrap();
    let slow_down_response = app.clone().oneshot(slow_down_request).await.unwrap();
    assert_eq!(slow_down_response.status(), StatusCode::UNAUTHORIZED);
    let throttled_grant = state
        .repo
        .get_device_authorization_grant(&util::sha256_base64url(device_code))
        .await
        .unwrap()
        .expect("device grant should exist after slow_down");
    assert_eq!(throttled_grant.poll_interval_seconds, 10);

    let now = util::now_seconds();
    let session = Session {
        id: "sid_device_approve_session".to_string(),
        realm_id: "test".to_string(),
        user_id: "device-user".to_string(),
        auth_time: now,
        acr: Some("password".to_string()),
        amr: vec!["password".to_string()],
        idle_expires_at: now + 3600,
        absolute_expires_at: now + 86400,
        revoked: false,
        created_at: now,
        cnf: None,
    };
    state.repo.create_session(&session).await.unwrap();

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
    let bytes = token_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let token_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(token_json["token_type"], "DPoP");

    let replay_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(pending_body))
        .unwrap();
    let replay_response = app.oneshot(replay_request).await.unwrap();
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
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let auth_req_id = json["auth_req_id"].as_str().unwrap();

    let pending_body = format!(
        "grant_type=urn:openid:params:grant-type:ciba&client_id=ciba-client&client_secret=secret&auth_req_id={auth_req_id}"
    );
    let pending_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(pending_body.clone()))
        .unwrap();
    let pending_response = app.clone().oneshot(pending_request).await.unwrap();
    assert_eq!(pending_response.status(), StatusCode::UNAUTHORIZED);
    let first_poll_grant = state
        .repo
        .get_backchannel_authentication_grant(&util::sha256_base64url(auth_req_id))
        .await
        .unwrap()
        .expect("CIBA grant should exist after first poll");
    assert_eq!(first_poll_grant.poll_interval_seconds, 5);
    assert!(first_poll_grant.last_poll_at.is_some());

    let slow_down_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(pending_body.clone()))
        .unwrap();
    let slow_down_response = app.clone().oneshot(slow_down_request).await.unwrap();
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
    let session_id = "ciba-session-id";
    let now = qid_core::util::now_seconds();
    let session = qid_core::models::Session {
        id: session_id.to_string(),
        realm_id: "test".to_string(),
        user_id: "ciba-user".to_string(),
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
    let cookie_value = format!("{}={}", cookie_name, session_id);

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
    let bytes = token_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let token_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(token_json["token_type"], "DPoP");
    assert!(token_json["id_token"].as_str().unwrap().len() > 10);

    let replay_request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(pending_body))
        .unwrap();
    let replay_response = app.oneshot(replay_request).await.unwrap();
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
    let req1 = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body.clone()))
        .unwrap();
    let resp1 = app.clone().oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);

    // Second use with same code - should fail
    let req2 = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let resp2 = app.oneshot(req2).await.unwrap();
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
    let request = Request::builder()
        .method(Method::POST)
        .uri(&token_path)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
