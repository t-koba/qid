use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use qid_core::{
    models::{Admin, AdminElevation},
    state::SharedState,
    test_helpers,
};
use qid_crypto::LocalSigner;
use qid_storage::{FileRepository, prelude::*};
use std::sync::Arc;
use tower::ServiceExt;

const ADMIN_SESSION_ID_HEADER: &str = "x-qid-admin-session-id";

async fn seeded_setup() -> (Router, String) {
    let path = std::env::temp_dir().join(format!("qid-rebac-{}.json", ulid::Ulid::new()));
    let repo = Arc::new(FileRepository::new(path.to_str().unwrap()).await.unwrap());
    repo.migrate().await.unwrap();
    let config = test_helpers::test_config();
    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    let state = Arc::new(SharedState::new(config, repo, signer, serde_json::json!({})).unwrap());
    let repo = state.repo.clone();

    let now = qid_core::util::now_seconds();
    let admin = Admin {
        id: "rebac-test-admin".to_string(),
        tenant_id: "admin".to_string(),
        subject: "test-admin".to_string(),
        roles: vec!["security.admin".to_string()],
        created_at: now,
    };
    repo.upsert_admin(&admin).await.unwrap();
    let elevation = AdminElevation {
        id: format!("rebac-session-{}", ulid::Ulid::new()),
        tenant_id: "admin".to_string(),
        admin_id: admin.id.clone(),
        acr: Some("urn:qid:acr:phishing-resistant".to_string()),
        amr: vec!["hwk".to_string()],
        elevation_expires_at: now + 300,
        created_at: now,
    };
    repo.store_admin_elevation(&elevation).await.unwrap();

    (qid_iga::iga_routes().with_state(state), elevation.id)
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn direct_check_allows_and_denies() {
    let (app, session_id) = seeded_setup().await;

    let write_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/rebac/tuples")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{"tuples":[{"namespace":"document","object_id":"doc-1","relation":"viewer","subject_namespace":"user","subject_id":"alice","subject_relation":""}]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(write_resp.status(), StatusCode::OK);

    let check_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/rebac/check")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{"namespace":"document","object_id":"doc-1","relation":"viewer","subject":{"namespace":"user","subject_id":"alice"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(check_resp.status(), StatusCode::OK);
    let body = json(check_resp).await;
    assert_eq!(body["allowed"], true);

    let deny_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/rebac/check")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{"namespace":"document","object_id":"doc-1","relation":"viewer","subject":{"namespace":"user","subject_id":"bob"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(deny_resp.status(), StatusCode::OK);
    let body = json(deny_resp).await;
    assert_eq!(body["allowed"], false);
}

#[tokio::test]
async fn userset_check_expands_group_membership() {
    let (app, session_id) = seeded_setup().await;

    let write_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/rebac/tuples")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{"tuples":[
                        {"namespace":"document","object_id":"doc-2","relation":"viewer","subject_namespace":"group","subject_id":"eng","subject_relation":"member"},
                        {"namespace":"group","object_id":"eng","relation":"member","subject_namespace":"user","subject_id":"alice","subject_relation":""}
                    ]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(write_resp.status(), StatusCode::OK);

    let check_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/rebac/check")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{"namespace":"document","object_id":"doc-2","relation":"viewer","subject":{"namespace":"user","subject_id":"alice"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(check_resp.status(), StatusCode::OK);
    let body = json(check_resp).await;
    assert_eq!(body["allowed"], true);

    let deny_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/rebac/check")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{"namespace":"document","object_id":"doc-2","relation":"viewer","subject":{"namespace":"user","subject_id":"bob"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(deny_resp.status(), StatusCode::OK);
    let body = json(deny_resp).await;
    assert_eq!(body["allowed"], false);
}

#[tokio::test]
async fn expand_returns_subject_tree() {
    let (app, session_id) = seeded_setup().await;

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/rebac/tuples")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{"tuples":[
                        {"namespace":"document","object_id":"doc-3","relation":"viewer","subject_namespace":"user","subject_id":"alice","subject_relation":""},
                        {"namespace":"document","object_id":"doc-3","relation":"viewer","subject_namespace":"user","subject_id":"bob","subject_relation":""}
                    ]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let expand_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/rebac/expand")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{"namespace":"document","object_id":"doc-3","relation":"viewer"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(expand_resp.status(), StatusCode::OK);
    let body = json(expand_resp).await;
    assert_eq!(body["tree"]["relation"], "viewer");
    assert_eq!(body["tree"]["children"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn read_returns_stored_tuples() {
    let (app, session_id) = seeded_setup().await;

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/rebac/tuples")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{"tuples":[
                        {"namespace":"document","object_id":"doc-4","relation":"owner","subject_namespace":"user","subject_id":"alice","subject_relation":""}
                    ]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let read_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/rebac/tuples/read")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{"namespace":"document","object_id":"doc-4","relation":"owner"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read_resp.status(), StatusCode::OK);
    let body = json(read_resp).await;
    let tuples = body["tuples"].as_array().unwrap();
    assert_eq!(tuples.len(), 1);
    assert_eq!(tuples[0]["subject_id"], "alice");
}

#[tokio::test]
async fn delete_removes_tuple_and_check_denies() {
    let (app, session_id) = seeded_setup().await;

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/rebac/tuples")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{"tuples":[
                        {"namespace":"document","object_id":"doc-5","relation":"viewer","subject_namespace":"user","subject_id":"alice","subject_relation":""}
                    ]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/rebac/tuples/delete")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{"tuples":[
                        {"namespace":"document","object_id":"doc-5","relation":"viewer","subject_namespace":"user","subject_id":"alice","subject_relation":""}
                    ]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let check_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/rebac/check")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{"namespace":"document","object_id":"doc-5","relation":"viewer","subject":{"namespace":"user","subject_id":"alice"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(check_resp.status(), StatusCode::OK);
    let body = json(check_resp).await;
    assert_eq!(body["allowed"], false);
}
