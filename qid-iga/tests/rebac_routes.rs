mod common;

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use common::{ADMIN_SESSION_ID_HEADER, post_raw, setup_app};
use tower::ServiceExt;

async fn seeded_setup() -> (common::TestStoreDir, Router, String) {
    let (_store_dir, app, _repo, session_id) = setup_app("qid-rebac", None, "test-admin").await;
    (_store_dir, app, session_id)
}

#[tokio::test]
async fn direct_check_allows_and_denies() {
    let (_store_dir, app, session_id) = seeded_setup().await;

    let write_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/rebac/tuples")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"tuples":[{"namespace":"document","object_id":"doc-1","relation":"viewer","subject_namespace":"user","subject_id":"alice","subject_relation":""}]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(write_resp.status(), StatusCode::OK);

    let body = post_raw(app.clone(), "/iga/v1/rebac/check", r#"{"namespace":"document","object_id":"doc-1","relation":"viewer","subject":{"namespace":"user","subject_id":"alice"}}"#, &session_id).await;
    assert_eq!(body["allowed"], true);

    let body = post_raw(app.clone(), "/iga/v1/rebac/check", r#"{"namespace":"document","object_id":"doc-1","relation":"viewer","subject":{"namespace":"user","subject_id":"bob"}}"#, &session_id).await;
    assert_eq!(body["allowed"], false);
}

#[tokio::test]
async fn userset_check_expands_group_membership() {
    let (_store_dir, app, session_id) = seeded_setup().await;

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

    let body = post_raw(app.clone(), "/iga/v1/rebac/check", r#"{"namespace":"document","object_id":"doc-2","relation":"viewer","subject":{"namespace":"user","subject_id":"alice"}}"#, &session_id).await;
    assert_eq!(body["allowed"], true);

    let body = post_raw(app.clone(), "/iga/v1/rebac/check", r#"{"namespace":"document","object_id":"doc-2","relation":"viewer","subject":{"namespace":"user","subject_id":"bob"}}"#, &session_id).await;
    assert_eq!(body["allowed"], false);
}

#[tokio::test]
async fn expand_returns_subject_tree() {
    let (_store_dir, app, session_id) = seeded_setup().await;

    post_raw(app.clone(), "/iga/v1/rebac/tuples", r#"{"tuples":[
                        {"namespace":"document","object_id":"doc-3","relation":"viewer","subject_namespace":"user","subject_id":"alice","subject_relation":""},
                        {"namespace":"document","object_id":"doc-3","relation":"viewer","subject_namespace":"user","subject_id":"bob","subject_relation":""}
                    ]}"#, &session_id).await;

    let body = post_raw(
        app.clone(),
        "/iga/v1/rebac/expand",
        r#"{"namespace":"document","object_id":"doc-3","relation":"viewer"}"#,
        &session_id,
    )
    .await;
    assert_eq!(body["tree"]["relation"], "viewer");
    assert_eq!(body["tree"]["children"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn read_returns_stored_tuples() {
    let (_store_dir, app, session_id) = seeded_setup().await;

    post_raw(app.clone(), "/iga/v1/rebac/tuples", r#"{"tuples":[
                        {"namespace":"document","object_id":"doc-4","relation":"owner","subject_namespace":"user","subject_id":"alice","subject_relation":""}
                    ]}"#, &session_id).await;

    let body = post_raw(
        app.clone(),
        "/iga/v1/rebac/tuples/read",
        r#"{"namespace":"document","object_id":"doc-4","relation":"owner"}"#,
        &session_id,
    )
    .await;
    let tuples = body["tuples"].as_array().unwrap();
    assert_eq!(tuples.len(), 1);
    assert_eq!(tuples[0]["subject_id"], "alice");
}

#[tokio::test]
async fn delete_removes_tuple_and_check_denies() {
    let (_store_dir, app, session_id) = seeded_setup().await;

    post_raw(app.clone(), "/iga/v1/rebac/tuples", r#"{"tuples":[
                        {"namespace":"document","object_id":"doc-5","relation":"viewer","subject_namespace":"user","subject_id":"alice","subject_relation":""}
                    ]}"#, &session_id).await;

    post_raw(app.clone(), "/iga/v1/rebac/tuples/delete", r#"{"tuples":[
                        {"namespace":"document","object_id":"doc-5","relation":"viewer","subject_namespace":"user","subject_id":"alice","subject_relation":""}
                    ]}"#, &session_id).await;

    let body = post_raw(app.clone(), "/iga/v1/rebac/check", r#"{"namespace":"document","object_id":"doc-5","relation":"viewer","subject":{"namespace":"user","subject_id":"alice"}}"#, &session_id).await;
    assert_eq!(body["allowed"], false);
}
