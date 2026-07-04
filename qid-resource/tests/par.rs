use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use base64::Engine;
use http_body_util::BodyExt;
use qid_core::{
    models::{Client, ClientType},
    state::SharedState,
    test_helpers,
};
use qid_crypto::LocalSigner;
use qid_storage::{SqlRepository, prelude::*};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU16, Ordering};
use tower::ServiceExt;

static DB_SEQ: AtomicU16 = AtomicU16::new(0);

fn db_url() -> String {
    let dir = std::env::temp_dir().join("qid_test_resource_par");
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
    config.realms[0].protocols.oauth.par.enabled = true;
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
        client_type: ClientType::Confidential,
        token_endpoint_auth_method: "client_secret_basic".to_string(),
        client_secret_hash: Some(qid_core::util::client_secret_hash("secret")),
        mtls_certificate_thumbprints: Vec::new(),
        jwks: qid_core::models::default_client_jwks(),
        redirect_uris: vec!["https://app.example.com/callback".to_string()],
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
    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    let state = Arc::new(SharedState::new(config, repo, signer, serde_json::json!({})).unwrap());
    let app = qid_resource::resource_routes(&state.paths).with_state(state.clone());
    (app, state)
}

#[tokio::test]
async fn par_stores_valid_authorization_details() {
    let (app, state) = setup().await;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/oauth2/par")
        .header("Content-Type", "application/json")
        .header(
            "Authorization",
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode("par-client:secret")
            ),
        )
        .body(Body::from(
            r#"{
                "client_id":"par-client",
                "response_type":"code",
                "redirect_uri":"https://app.example.com/callback",
                "authorization_details":[
                    {
                        "type":"payment_initiation",
                        "actions":["initiate"]
                    }
                ]
            }"#,
        ))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let request_uri = json["request_uri"].as_str().unwrap();
    let stored = state
        .repo
        .get_par_request(request_uri)
        .await
        .unwrap()
        .expect("PAR request should be stored");
    assert_eq!(stored.client_id, "par-client");
    assert_eq!(
        stored.params_json["authorization_details"][0]["type"],
        "payment_initiation"
    );
}

#[tokio::test]
async fn par_rejects_invalid_authorization_details() {
    let (app, _) = setup().await;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/oauth2/par")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{
                "client_id":"par-client",
                "response_type":"code",
                "redirect_uri":"https://app.example.com/callback",
                "authorization_details":[
                    {
                        "actions":["initiate"]
                    }
                ]
            }"#,
        ))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
