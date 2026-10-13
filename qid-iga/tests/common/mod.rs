#![allow(dead_code)]

use axum::{
    Router,
    body::Body,
    http::{Method, Request},
};
use http_body_util::BodyExt;
use qid_core::{
    models::{Admin, AdminElevation, IgaApprovalRecord},
    state::SharedState,
    test_helpers,
};
use qid_crypto::LocalSigner;
use qid_storage::{FileRepository, prelude::*};
use std::sync::Arc;
use tower::ServiceExt;

pub const ADMIN_SESSION_ID_HEADER: &str = "x-qid-admin-session-id";

pub async fn json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

pub fn request_with_headers(
    method: Method,
    uri: &str,
    body: serde_json::Value,
    session_id: &str,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("Content-Type", "application/json")
        .header(ADMIN_SESSION_ID_HEADER, session_id)
        .body(Body::from(body.to_string()))
        .unwrap()
}

pub async fn post_json(
    app: Router,
    uri: &str,
    body: serde_json::Value,
    session_id: &str,
) -> serde_json::Value {
    let response = app
        .oneshot(request_with_headers(Method::POST, uri, body, session_id))
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    json(response).await
}

pub async fn post_raw(app: Router, uri: &str, raw: &str, session_id: &str) -> serde_json::Value {
    let body: serde_json::Value = serde_json::from_str(raw).unwrap();
    post_json(app, uri, body, session_id).await
}

pub async fn seed_admin_session(repo: &FileRepository, tenant_id: &str, subject: &str) -> String {
    let now = qid_core::util::now_seconds();
    let admin = Admin {
        id: format!("{subject}-admin-id"),
        tenant_id: tenant_id.to_string(),
        subject: subject.to_string(),
        roles: vec!["security.admin".to_string()],
        created_at: now,
    };
    repo.upsert_admin(&admin).await.unwrap();
    let elevation = AdminElevation {
        id: format!("admin-session-{}", ulid::Ulid::new()),
        tenant_id: tenant_id.to_string(),
        admin_id: admin.id.clone(),
        acr: Some("urn:qid:acr:phishing-resistant".to_string()),
        amr: vec!["hwk".to_string()],
        elevation_expires_at: now + 300,
        created_at: now,
    };
    repo.store_admin_elevation(&elevation).await.unwrap();
    elevation.id
}

pub async fn setup_app(
    store_prefix: &str,
    tenant_id: Option<&str>,
    admin_subject: &str,
) -> (Router, Arc<FileRepository>, String) {
    let path = std::env::temp_dir().join(format!("{store_prefix}-{}.json", ulid::Ulid::new()));
    let repo = Arc::new(FileRepository::new(path.to_str().unwrap()).await.unwrap());
    repo.migrate().await.unwrap();
    let mut config = test_helpers::test_config();
    if let Some(tenant_id) = tenant_id {
        config.realms[0].tenant_id = Some(tenant_id.to_string());
        repo.create_realm(
            &tenant_id.into(),
            &tenant_id.into(),
            "https://id.example.com",
            Some("Test Realm"),
        )
        .await
        .unwrap();
    }
    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    let state = Arc::new(SharedState::new(config, repo, signer, serde_json::json!({})).unwrap());
    let repo = state.repo.clone();
    let session_id = seed_admin_session(&repo, &admin_tenant(tenant_id), admin_subject).await;
    (qid_iga::iga_routes().with_state(state), repo, session_id)
}

fn admin_tenant(tenant_id: Option<&str>) -> String {
    tenant_id.unwrap_or("admin").to_string()
}

pub async fn store_iga_approval(
    repo: &FileRepository,
    tenant_id: &str,
    request_id: &str,
    approver: &str,
    decision: &str,
) {
    let now = qid_core::util::now_seconds();
    repo.store_iga_approval(&IgaApprovalRecord {
        id: format!("stored-{approver}-{request_id}"),
        tenant_id: tenant_id.to_string(),
        request_id: request_id.to_string(),
        approver: approver.to_string(),
        decision: decision.to_string(),
        approved_at_epoch_seconds: now,
        expires_at_epoch_seconds: Some(now + 300),
        reason: Some("stored approval".to_string()),
    })
    .await
    .unwrap();
}
