#![allow(clippy::expect_used, clippy::unwrap_used)]

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use qid_core::{
    config::{InboundProviderConfig, QidConfig},
    models::{Client, ClientType},
    state::SharedState,
    test_helpers, util,
};
use qid_crypto::{Jwk, JwtClaims, LocalSigner, jwk::generate_es256};
use qid_storage::{SqlRepository, prelude::*};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU16, Ordering};
use tower::ServiceExt;

static DB_SEQ: AtomicU16 = AtomicU16::new(0);

fn db_url() -> String {
    let dir = std::env::temp_dir().join("qid_test_oauth_saml");
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
) -> qid_core::config::OAuthResourceServerConfig {
    let name = audience.strip_prefix("api://").unwrap_or(audience);
    qid_core::config::OAuthResourceServerConfig {
        audience: audience.to_string(),
        resources: vec![format!("https://api.example.com/{name}")],
        scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
        introspection_client_ids: vec![introspection_client.to_string()],
        require_sender_constraint: false,
        high_risk: false,
    }
}

fn dpop_private_pem_and_jwk() -> (String, Jwk) {
    static KEY: OnceLock<(String, Jwk)> = OnceLock::new();
    KEY.get_or_init(|| {
        let generated = generate_es256("dpop-flow-key").expect("DPoP key generation failed");
        (generated.private_pem, generated.public_jwk)
    })
    .clone()
}

fn private_key_jwt_jwks() -> serde_json::Value {
    let (_, jwk) = dpop_private_pem_and_jwk();
    serde_json::json!({ "keys": [serde_json::to_value(jwk).expect("JWK serialization failed")] })
}

async fn setup() -> (Router, String, Arc<SharedState<SqlRepository>>) {
    setup_with_config(test_helpers::test_config()).await
}

async fn setup_with_config(config: QidConfig) -> (Router, String, Arc<SharedState<SqlRepository>>) {
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
    let jwks = serde_json::json!({ "keys": [] });
    let state = Arc::new(SharedState::new(config, repo, signer, jwks).unwrap());
    for client in [
        client_credentials_client("service-client", "client_secret_post"),
        client_credentials_client("introspection-client", "client_secret_post"),
        token_exchange_client("exchange-client"),
        saml_bearer_client("saml-bearer-client"),
    ] {
        state.repo.create_client(&client).await.unwrap();
    }
    let token_path = state.paths.token.clone();
    let app = qid_oauth::routes(&state.paths).with_state(state.clone());
    (app, token_path, state)
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

fn client_credentials_client(client_id: &str, auth_method: &str) -> Client {
    let mut client = base_test_client(
        client_id,
        ClientType::Confidential,
        auth_method,
        vec!["client_credentials".to_string()],
    );
    client.client_secret_hash = matches!(auth_method, "client_secret_basic" | "client_secret_post")
        .then(|| qid_core::util::client_secret_hash("secret"));
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

async fn assert_error_without_access_token(
    response: axum::response::Response,
    expected_status: StatusCode,
) {
    assert_eq!(response.status(), expected_status);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
        !String::from_utf8_lossy(&bytes).contains("access_token"),
        "error response must not contain an issued token"
    );
}

fn saml_bearer_client(client_id: &str) -> Client {
    let mut client = base_test_client(
        client_id,
        ClientType::Confidential,
        "client_secret_post",
        vec!["urn:ietf:params:oauth:grant-type:saml2-bearer".to_string()],
    );
    client.client_secret_hash = Some(qid_core::util::client_secret_hash("secret"));
    client
}

fn build_saml_bearer_assertion(subject: &str, audience: &str, expires_at: u64) -> String {
    build_saml_bearer_assertion_with(
        subject,
        audience,
        expires_at,
        "https://saml-idp.example.com",
        include_str!("../../qid-oauth/tests/data/test-sp.crt"),
        include_str!("../../qid-oauth/tests/data/test-sp.key"),
    )
}

fn build_saml_bearer_assertion_with(
    subject: &str,
    audience: &str,
    expires_at: u64,
    issuer: &str,
    cert_pem: &str,
    key_pem: &str,
) -> String {
    build_saml_bearer_assertion_with_id(
        subject,
        audience,
        expires_at,
        issuer,
        cert_pem,
        key_pem,
        "assert-saml-bearer-1",
    )
}

fn build_saml_bearer_assertion_with_id(
    subject: &str,
    audience: &str,
    expires_at: u64,
    issuer: &str,
    cert_pem: &str,
    key_pem: &str,
    assertion_id: &str,
) -> String {
    build_saml_bearer_assertion_with_name_id_attributes(
        subject,
        audience,
        expires_at,
        issuer,
        (cert_pem, key_pem),
        assertion_id,
        "",
    )
}

fn build_saml_bearer_assertion_with_name_id_attributes(
    subject: &str,
    audience: &str,
    expires_at: u64,
    issuer: &str,
    signer: (&str, &str),
    assertion_id: &str,
    name_id_attributes: &str,
) -> String {
    let (cert_pem, key_pem) = signer;
    let now = util::now_seconds();
    let unsigned = format!(
        r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="{assertion_id}" Version="2.0" IssueInstant="{now}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <!--SIGNATURE-->
  <saml:Subject>
    <saml:NameID{name_id_attributes}>{subject}</saml:NameID>
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
    let cert_body: String = cert_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let signature = format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#{assertion_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"##,
        cert_body.trim()
    );
    let template = unsigned.replace("<!--SIGNATURE-->", &signature);
    let mut keys = bergshamra_keys::KeysManager::new();
    keys.add_key(
        bergshamra_keys::loader::load_rsa_private_pem(key_pem.as_bytes())
            .expect("test SAML private key must load"),
    );
    bergshamra_dsig::sign::sign(&bergshamra_dsig::DsigContext::new(keys), &template)
        .expect("SAML bearer assertion must sign in the enforced inbound profile")
}

fn saml_inbound_provider(issuer: &str, certificate: &str) -> InboundProviderConfig {
    InboundProviderConfig {
        id: "synthetic-saml-idp".to_string(),
        kind: "saml".to_string(),
        issuer: issuer.to_string(),
        enabled: true,
        domains: Vec::new(),
        social_provider: None,
        client_id: None,
        client_secret: None,
        token_url: None,
        userinfo_url: None,
        jit_provisioning: false,
        account_linking: false,
        claim_mappings: Vec::new(),
        jwks_uri: None,
        jwks: None,
        saml_signing_certificates: vec![certificate.to_string()],
    }
}

fn config_with_saml_trust(issuer: &str, certificate: &str) -> QidConfig {
    let mut config = test_helpers::test_config();
    config.realms[0].protocols.federation.enabled = true;
    config.realms[0].protocols.federation.inbound_providers =
        vec![saml_inbound_provider(issuer, certificate)];
    config
}

async fn setup_with_saml_trust(
    issuer: &str,
    certificate: &str,
) -> (Router, String, Arc<SharedState<SqlRepository>>) {
    setup_with_config(config_with_saml_trust(issuer, certificate)).await
}

#[tokio::test]
async fn saml_oauth_subject_mapping_accounts_for_name_id_attributes() {
    let issuer = "https://saml-idp.example.com";
    let mut config = config_with_saml_trust(
        issuer,
        include_str!("../../qid-oauth/tests/data/test-sp.crt"),
    );
    config.realms[0].protocols.oauth.resource_servers = vec![
        test_server("api://saml", &["saml"], "introspection-client"),
        test_server("api://delegated", &["delegated"], "introspection-client"),
    ];
    let (app, token_path, state) = setup_with_config(config).await;
    let audience = format!("https://id.example.com{token_path}");
    let expires_at = util::now_seconds() + 300;
    let cert = include_str!("../../qid-oauth/tests/data/test-sp.crt");
    let key = include_str!("../../qid-oauth/tests/data/test-sp.key");
    let attributes = [
        r#" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" NameQualifier="https://tenant.example" SPNameQualifier="https://sp.example" SPProvidedID="same&amp;alias""#,
        r#" SPProvidedID="same&#38;alias" SPNameQualifier="https://sp.example" NameQualifier="https://tenant.example" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified""#,
        r#" NameQualifier="https://tenant.example" SPNameQualifier="https://sp.example" SPProvidedID="same&amp;alias""#,
        r#" xmlns:spoof="urn:wrong" spoof:Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" NameQualifier="https://tenant.example" SPNameQualifier="https://sp.example" SPProvidedID="same&amp;alias""#,
        r#" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" NameQualifier="https://tenant.example" SPNameQualifier="https://sp.example" SPProvidedID="same&amp;alias""#,
        r#" Format="urn:oasis:names:tc:SAML:1.0:nameid-format:unspecified" NameQualifier="https://tenant.example" SPNameQualifier="https://sp.example" SPProvidedID="same&amp;alias""#,
        r#" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" NameQualifier="https://other-tenant.example" SPNameQualifier="https://sp.example" SPProvidedID="same&amp;alias""#,
        r#" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" NameQualifier="https://tenant.example" SPNameQualifier="https://other-sp.example" SPProvidedID="same&amp;alias""#,
        r#" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" NameQualifier="https://tenant.example" SPNameQualifier="https://sp.example" SPProvidedID="other-alias""#,
        r#" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" SPNameQualifier="https://sp.example" SPProvidedID="same&amp;alias""#,
        r#" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" NameQualifier="" SPNameQualifier="https://sp.example" SPProvidedID="same&amp;alias""#,
    ];
    let mut subjects = Vec::new();
    for (index, name_id_attributes) in attributes.iter().enumerate() {
        let assertion = build_saml_bearer_assertion_with_name_id_attributes(
            "shared-nameid",
            &audience,
            expires_at,
            issuer,
            (cert, key),
            &format!("assert-name-id-attributes-{index}"),
            name_id_attributes,
        );
        let body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer&client_id=saml-bearer-client&client_secret=secret&assertion={}&audience=api://saml&scope=saml",
            urlencoding::encode(&assertion)
        );
        let json = post_token_json(app.clone(), &token_path, body).await;
        let claims = decode_claims(&state, json["access_token"].as_str().unwrap());
        subjects.push(claims.sub.unwrap());
    }

    assert_eq!(subjects[0], subjects[1]);
    assert_eq!(subjects[0], subjects[2]);
    for subject in &subjects[1..4] {
        assert_eq!(subjects[0], *subject);
    }
    for subject in &subjects[4..] {
        assert_ne!(subjects[0], *subject);
    }

    let mut exchange_subjects = Vec::new();
    for (index, name_id_attributes) in [attributes[0], attributes[5]].iter().enumerate() {
        let assertion = build_saml_bearer_assertion_with_name_id_attributes(
            "shared-nameid",
            &audience,
            expires_at,
            issuer,
            (cert, key),
            &format!("assert-name-id-exchange-{index}"),
            name_id_attributes,
        );
        let body = format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=exchange-client&client_secret=secret&subject_token_type=urn:ietf:params:oauth:token-type:saml2&subject_token={}&audience=api://delegated&scope=delegated",
            urlencoding::encode(&assertion)
        );
        let json = post_token_json(app.clone(), &token_path, body).await;
        let claims = decode_claims(&state, json["access_token"].as_str().unwrap());
        exchange_subjects.push(claims.sub.unwrap());
    }
    assert_eq!(subjects[0], exchange_subjects[0]);
    assert_ne!(exchange_subjects[0], exchange_subjects[1]);

    let signed_assertion = build_saml_bearer_assertion_with_name_id_attributes(
        "shared-nameid",
        &audience,
        expires_at,
        issuer,
        (cert, key),
        "assert-name-id-attribute-tampered",
        attributes[0],
    );
    let tampered_assertion = signed_assertion.replace(
        "NameQualifier=\"https://tenant.example\"",
        "NameQualifier=\"https://tampered.example\"",
    );
    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer&client_id=saml-bearer-client&client_secret=secret&assertion={}&audience=api://saml&scope=saml",
        urlencoding::encode(&tampered_assertion)
    );
    let response = post_form(app, &token_path, body).await;
    assert_error_without_access_token(response, StatusCode::UNAUTHORIZED).await;
}

#[tokio::test]
async fn saml_oauth_subject_is_scoped_to_trusted_issuer_and_stable_across_paths() {
    let mut config = config_with_saml_trust(
        "https://saml-idp-a.example.com",
        include_str!("../../qid-oauth/tests/data/test-sp.crt"),
    );
    config.realms[0].protocols.federation.inbound_providers[0]
        .saml_signing_certificates
        .push(include_str!("../../qid-oauth/tests/data/test-untrusted-saml.crt").to_string());
    let mut second_provider = saml_inbound_provider(
        "https://saml-idp-b.example.com",
        include_str!("../../qid-oauth/tests/data/test-untrusted-saml.crt"),
    );
    second_provider.id = "synthetic-saml-idp-b".to_string();
    config.realms[0]
        .protocols
        .federation
        .inbound_providers
        .push(second_provider);
    config.realms[0].protocols.oauth.resource_servers = vec![
        test_server("api://saml", &["saml"], "introspection-client"),
        test_server("api://delegated", &["delegated"], "introspection-client"),
    ];
    let (app, token_path, state) = setup_with_config(config).await;
    let audience = format!("https://id.example.com{token_path}");
    let now = util::now_seconds();
    let assertion_a1 = build_saml_bearer_assertion_with_id(
        "shared-nameid",
        &audience,
        now + 300,
        "https://saml-idp-a.example.com",
        include_str!("../../qid-oauth/tests/data/test-sp.crt"),
        include_str!("../../qid-oauth/tests/data/test-sp.key"),
        "assert-a-original-key",
    );
    let assertion_a2 = build_saml_bearer_assertion_with_id(
        "shared-nameid",
        &audience,
        now + 301,
        "https://saml-idp-a.example.com",
        include_str!("../../qid-oauth/tests/data/test-untrusted-saml.crt"),
        include_str!("../../qid-oauth/tests/data/test-untrusted-saml.key"),
        "assert-a-rotated-key",
    );
    let assertion_b = build_saml_bearer_assertion_with_id(
        "shared-nameid",
        &audience,
        now + 302,
        "https://saml-idp-b.example.com",
        include_str!("../../qid-oauth/tests/data/test-untrusted-saml.crt"),
        include_str!("../../qid-oauth/tests/data/test-untrusted-saml.key"),
        "assert-b",
    );
    let issue_bearer = |assertion: &str| {
        format!(
            "grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer&client_id=saml-bearer-client&client_secret=secret&assertion={}&audience=api://saml&scope=saml",
            urlencoding::encode(assertion)
        )
    };
    let bearer_a1 = post_token_json(app.clone(), &token_path, issue_bearer(&assertion_a1)).await;
    let bearer_a2 = post_token_json(app.clone(), &token_path, issue_bearer(&assertion_a2)).await;
    let bearer_b = post_token_json(app.clone(), &token_path, issue_bearer(&assertion_b)).await;
    let bearer_a1_claims = decode_claims(&state, bearer_a1["access_token"].as_str().unwrap());
    let bearer_a2_claims = decode_claims(&state, bearer_a2["access_token"].as_str().unwrap());
    let bearer_b_claims = decode_claims(&state, bearer_b["access_token"].as_str().unwrap());
    assert_eq!(bearer_a1_claims.sub, bearer_a2_claims.sub);
    assert_ne!(bearer_a1_claims.sub, bearer_b_claims.sub);

    let assertion_a_exchange = build_saml_bearer_assertion_with_id(
        "shared-nameid",
        &audience,
        now + 303,
        "https://saml-idp-a.example.com",
        include_str!("../../qid-oauth/tests/data/test-untrusted-saml.crt"),
        include_str!("../../qid-oauth/tests/data/test-untrusted-saml.key"),
        "assert-a-exchange",
    );
    let assertion_b_exchange = build_saml_bearer_assertion_with_id(
        "shared-nameid",
        &audience,
        now + 304,
        "https://saml-idp-b.example.com",
        include_str!("../../qid-oauth/tests/data/test-untrusted-saml.crt"),
        include_str!("../../qid-oauth/tests/data/test-untrusted-saml.key"),
        "assert-b-exchange",
    );
    let actor_assertion = build_saml_bearer_assertion_with_id(
        "raw-actor-nameid",
        &audience,
        now + 305,
        "https://saml-idp-b.example.com",
        include_str!("../../qid-oauth/tests/data/test-untrusted-saml.crt"),
        include_str!("../../qid-oauth/tests/data/test-untrusted-saml.key"),
        "assert-actor",
    );
    let exchange = |subject: &str, actor: Option<&str>| {
        let actor_fields = actor
            .map(|actor| {
                format!(
                    "&actor_token_type=urn:ietf:params:oauth:token-type:saml2&actor_token={}",
                    urlencoding::encode(actor)
                )
            })
            .unwrap_or_default();
        format!(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=exchange-client&client_secret=secret&subject_token_type=urn:ietf:params:oauth:token-type:saml2&subject_token={}{}&audience=api://delegated&scope=delegated",
            urlencoding::encode(subject),
            actor_fields
        )
    };
    let exchange_a = post_token_json(
        app.clone(),
        &token_path,
        exchange(&assertion_a_exchange, Some(&actor_assertion)),
    )
    .await;
    let exchange_b = post_token_json(app, &token_path, exchange(&assertion_b_exchange, None)).await;
    let exchange_a_claims = decode_claims(&state, exchange_a["access_token"].as_str().unwrap());
    let exchange_b_claims = decode_claims(&state, exchange_b["access_token"].as_str().unwrap());
    assert_eq!(exchange_a_claims.sub, bearer_a1_claims.sub);
    assert_eq!(exchange_b_claims.sub, bearer_b_claims.sub);
    assert_ne!(exchange_a_claims.sub, exchange_b_claims.sub);
    assert_eq!(
        exchange_a_claims.extra["act"]["iss"],
        "https://saml-idp-b.example.com"
    );
    let actor_subject = exchange_a_claims.extra["act"]["sub"].as_str().unwrap();
    assert!(actor_subject.starts_with("saml2:v2:"));
    assert_ne!(actor_subject, "raw-actor-nameid");
}

#[tokio::test]
async fn saml_bearer_grant_validates_assertion_and_uses_subject() {
    let (app, token_path, state) = setup_with_saml_trust(
        "https://saml-idp.example.com",
        include_str!("../../qid-oauth/tests/data/test-sp.crt"),
    )
    .await;
    let token_url = format!("https://id.example.com{token_path}");
    let assertion =
        build_saml_bearer_assertion("saml-subject-123", &token_url, util::now_seconds() + 300);

    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer&client_id=saml-bearer-client&client_secret=secret&assertion={}&audience=api://saml&scope=saml",
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
    assert!(
        claims
            .sub
            .as_deref()
            .is_some_and(|sub| sub.starts_with("saml2:v2:"))
    );
    assert_eq!(claims.aud_primary(), Some("api://saml"));
    assert_eq!(claims.extra["client_id"], "saml-bearer-client");
    assert_eq!(claims.extra["scope"], "saml");
    assert_eq!(claims.extra["amr"], serde_json::json!(["saml"]));
}

#[tokio::test]
async fn saml_bearer_grant_rejects_default_config_without_inbound_trust() {
    let (app, token_path, _) = setup().await;
    let assertion = build_saml_bearer_assertion(
        "saml-no-trust-subject",
        &format!("https://id.example.com{token_path}"),
        util::now_seconds() + 300,
    );
    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer&client_id=saml-bearer-client&client_secret=secret&assertion={}",
        urlencoding::encode(&assertion)
    );
    let response = post_form(app, &token_path, body).await;
    assert_error_without_access_token(response, StatusCode::UNAUTHORIZED).await;
}

#[tokio::test]
async fn saml_bearer_grant_rejects_unconfigured_issuer_even_with_trusted_key() {
    let (app, token_path, _) = setup_with_saml_trust(
        "https://saml-idp.example.com",
        include_str!("../../qid-oauth/tests/data/test-sp.crt"),
    )
    .await;
    let assertion = build_saml_bearer_assertion_with(
        "saml-unknown-issuer-subject",
        &format!("https://id.example.com{token_path}"),
        util::now_seconds() + 300,
        "https://unknown-saml-idp.example.com",
        include_str!("../../qid-oauth/tests/data/test-sp.crt"),
        include_str!("../../qid-oauth/tests/data/test-sp.key"),
    );
    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer&client_id=saml-bearer-client&client_secret=secret&assertion={}",
        urlencoding::encode(&assertion)
    );
    let response = post_form(app, &token_path, body).await;
    assert_error_without_access_token(response, StatusCode::UNAUTHORIZED).await;
}

#[tokio::test]
async fn saml_bearer_grant_rejects_matching_issuer_signed_by_untrusted_keyinfo_key() {
    let (app, token_path, _) = setup_with_saml_trust(
        "https://saml-idp.example.com",
        include_str!("../../qid-oauth/tests/data/test-sp.crt"),
    )
    .await;
    // This synthetic cert/key is test-only and deliberately differs from the configured trust.
    let assertion = build_saml_bearer_assertion_with(
        "saml-untrusted-key-subject",
        &format!("https://id.example.com{token_path}"),
        util::now_seconds() + 300,
        "https://saml-idp.example.com",
        include_str!("../../qid-oauth/tests/data/test-untrusted-saml.crt"),
        include_str!("../../qid-oauth/tests/data/test-untrusted-saml.key"),
    );
    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer&client_id=saml-bearer-client&client_secret=secret&assertion={}",
        urlencoding::encode(&assertion)
    );
    let response = post_form(app, &token_path, body).await;
    assert_error_without_access_token(response, StatusCode::UNAUTHORIZED).await;
}

#[tokio::test]
async fn saml_bearer_grant_rejects_a_key_trusted_for_a_different_issuer() {
    let mut config = config_with_saml_trust(
        "https://saml-idp-a.example.com",
        include_str!("../../qid-oauth/tests/data/test-sp.crt"),
    );
    config.realms[0]
        .protocols
        .federation
        .inbound_providers
        .push(saml_inbound_provider(
            "https://saml-idp-b.example.com",
            include_str!("../../qid-oauth/tests/data/test-untrusted-saml.crt"),
        ));
    let (app, token_path, _) = setup_with_config(config).await;
    let assertion = build_saml_bearer_assertion_with(
        "saml-cross-issuer-subject",
        &format!("https://id.example.com{token_path}"),
        util::now_seconds() + 300,
        "https://saml-idp-b.example.com",
        include_str!("../../qid-oauth/tests/data/test-sp.crt"),
        include_str!("../../qid-oauth/tests/data/test-sp.key"),
    );
    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer&client_id=saml-bearer-client&client_secret=secret&assertion={}",
        urlencoding::encode(&assertion)
    );
    let response = post_form(app, &token_path, body).await;
    assert_error_without_access_token(response, StatusCode::UNAUTHORIZED).await;
}

#[tokio::test]
async fn saml_bearer_grant_rejects_provider_when_federation_is_disabled() {
    let mut config = config_with_saml_trust(
        "https://saml-idp.example.com",
        include_str!("../../qid-oauth/tests/data/test-sp.crt"),
    );
    config.realms[0].protocols.federation.enabled = false;
    let (app, token_path, _) = setup_with_config(config).await;
    let assertion = build_saml_bearer_assertion(
        "saml-disabled-federation-subject",
        &format!("https://id.example.com{token_path}"),
        util::now_seconds() + 300,
    );
    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer&client_id=saml-bearer-client&client_secret=secret&assertion={}",
        urlencoding::encode(&assertion)
    );
    let response = post_form(app, &token_path, body).await;
    assert_error_without_access_token(response, StatusCode::UNAUTHORIZED).await;
}

#[tokio::test]
async fn token_exchange_saml_subject_rejects_without_inbound_trust() {
    let (app, token_path, _) = setup().await;
    let assertion = build_saml_bearer_assertion(
        "saml-exchange-subject",
        &format!("https://id.example.com{token_path}"),
        util::now_seconds() + 300,
    );
    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=exchange-client&client_secret=secret&subject_token_type=urn:ietf:params:oauth:token-type:saml2&subject_token={}&audience=api://delegated&scope=delegated",
        urlencoding::encode(&assertion)
    );
    let response = post_form(app, &token_path, body).await;
    assert_error_without_access_token(response, StatusCode::UNAUTHORIZED).await;
}

#[tokio::test]
async fn token_exchange_saml_actor_rejects_without_inbound_trust() {
    let (app, token_path, _) = setup().await;
    let subject_token = mint_access_token(
        app.clone(),
        &token_path,
        "grant_type=client_credentials&client_id=service-client&client_secret=secret&scope=api",
    )
    .await;
    let actor_assertion = build_saml_bearer_assertion(
        "saml-exchange-actor",
        &format!("https://id.example.com{token_path}"),
        util::now_seconds() + 300,
    );
    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=exchange-client&client_secret=secret&subject_token_type=urn:ietf:params:oauth:token-type:access_token&subject_token={}&actor_token_type=urn:ietf:params:oauth:token-type:saml2&actor_token={}&audience=api://delegated&scope=delegated",
        urlencoding::encode(&subject_token),
        urlencoding::encode(&actor_assertion)
    );
    let response = post_form(app, &token_path, body).await;
    assert_error_without_access_token(response, StatusCode::UNAUTHORIZED).await;
}

#[tokio::test]
async fn token_exchange_saml_subject_and_actor_use_configured_trust() {
    let mut config = config_with_saml_trust(
        "https://saml-idp.example.com",
        include_str!("../../qid-oauth/tests/data/test-sp.crt"),
    );
    config.realms[0].protocols.oauth.resource_servers = vec![test_server(
        "api://delegated",
        &["delegated"],
        "introspection-client",
    )];
    let (app, token_path, state) = setup_with_config(config).await;
    let audience = format!("https://id.example.com{token_path}");
    let subject_assertion = build_saml_bearer_assertion_with_id(
        "saml-exchange-subject",
        &audience,
        util::now_seconds() + 300,
        "https://saml-idp.example.com",
        include_str!("../../qid-oauth/tests/data/test-sp.crt"),
        include_str!("../../qid-oauth/tests/data/test-sp.key"),
        "assert-saml-exchange-subject-1",
    );
    let actor_attributes = r#" NameQualifier="https://tenant.example" SPNameQualifier="https://sp.example" SPProvidedID="actor-alias""#;
    let actor_assertion = build_saml_bearer_assertion_with_name_id_attributes(
        "saml-exchange-actor",
        &audience,
        util::now_seconds() + 300,
        "https://saml-idp.example.com",
        (
            include_str!("../../qid-oauth/tests/data/test-sp.crt"),
            include_str!("../../qid-oauth/tests/data/test-sp.key"),
        ),
        "assert-saml-exchange-actor-1",
        actor_attributes,
    );
    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=exchange-client&client_secret=secret&subject_token_type=urn:ietf:params:oauth:token-type:saml2&subject_token={}&actor_token_type=urn:ietf:params:oauth:token-type:saml2&actor_token={}&audience=api://delegated&scope=delegated",
        urlencoding::encode(&subject_assertion),
        urlencoding::encode(&actor_assertion)
    );
    let response = post_form(app.clone(), &token_path, body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = json_body(response).await;
    let claims = decode_claims(&state, json["access_token"].as_str().unwrap());
    assert!(
        claims
            .sub
            .as_deref()
            .is_some_and(|sub| sub.starts_with("saml2:v2:"))
    );
    assert_eq!(claims.extra["act"]["iss"], "https://saml-idp.example.com");
    let actor_id = claims.extra["act"]["sub"].as_str().unwrap();
    assert!(actor_id.starts_with("saml2:v2:"));
    assert_ne!(actor_id, "saml-exchange-actor");

    let actor_variant = build_saml_bearer_assertion_with_name_id_attributes(
        "saml-exchange-actor",
        &audience,
        util::now_seconds() + 301,
        "https://saml-idp.example.com",
        (
            include_str!("../../qid-oauth/tests/data/test-sp.crt"),
            include_str!("../../qid-oauth/tests/data/test-sp.key"),
        ),
        "assert-saml-exchange-actor-2",
        r#" NameQualifier="https://other-tenant.example" SPNameQualifier="https://sp.example" SPProvidedID="actor-alias""#,
    );
    let subject_variant = build_saml_bearer_assertion_with_id(
        "saml-exchange-subject",
        &audience,
        util::now_seconds() + 301,
        "https://saml-idp.example.com",
        include_str!("../../qid-oauth/tests/data/test-sp.crt"),
        include_str!("../../qid-oauth/tests/data/test-sp.key"),
        "assert-saml-exchange-subject-2",
    );
    let variant_body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=exchange-client&client_secret=secret&subject_token_type=urn:ietf:params:oauth:token-type:saml2&subject_token={}&actor_token_type=urn:ietf:params:oauth:token-type:saml2&actor_token={}&audience=api://delegated&scope=delegated",
        urlencoding::encode(&subject_variant),
        urlencoding::encode(&actor_variant)
    );
    let variant_response = post_form(app, &token_path, variant_body).await;
    assert_eq!(variant_response.status(), StatusCode::OK);
    let variant_json = json_body(variant_response).await;
    let variant_claims = decode_claims(&state, variant_json["access_token"].as_str().unwrap());
    assert_eq!(claims.sub, variant_claims.sub);
    assert_ne!(actor_id, variant_claims.extra["act"]["sub"]);
}

#[tokio::test]
async fn saml_bearer_grant_rejects_wrong_audience() {
    let (app, token_path, _) = setup_with_saml_trust(
        "https://saml-idp.example.com",
        include_str!("../../qid-oauth/tests/data/test-sp.crt"),
    )
    .await;
    let assertion = build_saml_bearer_assertion(
        "saml-subject-123",
        "https://wrong.example.com/oauth2/token",
        util::now_seconds() + 300,
    );

    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer&client_id=saml-bearer-client&client_secret=secret&assertion={}",
        urlencoding::encode(&assertion)
    );
    let response = post_form(app, &token_path, body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
