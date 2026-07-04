use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use qid_core::{
    models::{
        Admin, AdminElevation, IgaAccessGrantRecord, IgaAccessRequestRecord, IgaApprovalRecord,
        IgaFindingRecord,
    },
    state::SharedState,
    test_helpers,
};
use qid_crypto::LocalSigner;
use qid_storage::{FileRepository, prelude::*};
use std::sync::Arc;
use tower::ServiceExt;

const ADMIN_SESSION_ID_HEADER: &str = "x-qid-admin-session-id";

async fn seed_admin(repo: &FileRepository) -> String {
    let now = qid_core::util::now_seconds();
    let admin = Admin {
        id: "test-admin-id".to_string(),
        tenant_id: "test".to_string(),
        subject: "security-admin".to_string(),
        roles: vec!["security.admin".to_string()],
        created_at: now,
    };
    repo.upsert_admin(&admin).await.unwrap();
    let elevation = AdminElevation {
        id: format!("admin-session-{}", ulid::Ulid::new()),
        tenant_id: "test".to_string(),
        admin_id: admin.id.clone(),
        acr: Some("urn:qid:acr:phishing-resistant".to_string()),
        amr: vec!["hwk".to_string()],
        elevation_expires_at: now + 300,
        created_at: now,
    };
    repo.store_admin_elevation(&elevation).await.unwrap();
    elevation.id
}

async fn setup_with_repo() -> (Router, Arc<FileRepository>, String) {
    let path = std::env::temp_dir().join(format!("qid-iga-{}.json", ulid::Ulid::new()));
    let repo = Arc::new(FileRepository::new(path.to_str().unwrap()).await.unwrap());
    repo.migrate().await.unwrap();
    let mut config = test_helpers::test_config();
    config.realms[0].tenant_id = Some("test".to_string());
    repo.create_realm(
        &"test".into(),
        &"test".into(),
        "https://id.example.com",
        Some("Test Realm"),
    )
    .await
    .unwrap();
    let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
    let state = Arc::new(SharedState::new(config, repo, signer, serde_json::json!({})).unwrap());
    let repo = state.repo.clone();
    let session_id = seed_admin(&repo).await;
    (qid_iga::iga_routes().with_state(state), repo, session_id)
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn request_with_headers(
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

async fn store_iga_approval(
    repo: &FileRepository,
    request_id: &str,
    approver: &str,
    decision: &str,
) {
    let now = qid_core::util::now_seconds();
    repo.store_iga_approval(&IgaApprovalRecord {
        id: format!("stored-{approver}-{request_id}"),
        tenant_id: "test".to_string(),
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

#[tokio::test]
async fn access_request_route_evaluates_catalog_duration_and_approval_steps() {
    let (app, repo, session_id) = setup_with_repo().await;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/access-requests")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{
                        "subject":"user-1",
                        "entitlement":"app:erp:admin",
                        "current_entitlements":[],
                        "requested_duration_seconds":3600,
                        "reason":"temporary admin"
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    let request_id = body["id"].as_str().unwrap();
    assert_eq!(body["tenant_id"], "test");
    assert_eq!(body["subject"], "user-1");
    assert_eq!(body["entitlement"], "app:erp:admin");
    assert_eq!(body["status"], "approval_required");
    assert_eq!(body["approval_steps"].as_array().unwrap().len(), 2);
    assert!(body["violations"].as_array().unwrap().is_empty());
    assert!(body["expires_at_epoch_seconds"].as_u64().is_some());

    let stored = repo
        .get_iga_access_request("test", request_id)
        .await
        .expect("load stored IGA access request failed")
        .expect("stored IGA access request missing");
    assert_eq!(stored.tenant_id, "test");
    assert_eq!(stored.subject, "user-1");
    assert_eq!(stored.entitlement, "app:erp:admin");
    assert_eq!(stored.status, "approval_required");
    assert_eq!(stored.approval_steps_json.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn access_request_route_rejects_unknown_entitlement() {
    let (app, _repo, session_id) = setup_with_repo().await;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/access-requests")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{
                        "subject":"user-1",
                        "entitlement":"app:unknown"
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    assert_eq!(body["status"], "rejected");
    assert_eq!(body["violations"][0], "unknown_entitlement");
}

#[tokio::test]
async fn entitlement_catalog_route_persists_and_drives_access_request_policy() {
    let (app, repo, session_id) = setup_with_repo().await;
    let entitlement = serde_json::json!({
        "id": "app:custom:admin",
        "display_name": "Custom administrator",
        "owner": "security-admin",
        "risk_level": "medium",
        "conflicting_entitlements": [],
        "max_duration_seconds": 600,
        "active": true
    });
    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/entitlements")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(entitlement.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_response.status(), StatusCode::OK);
    let create_body = json(create_response).await;
    assert_eq!(create_body["tenant_id"], "test");
    assert_eq!(create_body["entitlement"]["id"], "app:custom:admin");
    assert_eq!(create_body["entitlement"]["owner"], "security-admin");

    let stored = repo
        .list_iga_entitlements("test")
        .await
        .expect("list stored IGA entitlements failed");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].id, "app:custom:admin");
    assert_eq!(stored[0].risk_level, "medium");

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/iga/v1/entitlements")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body = json(list_response).await;
    assert_eq!(list_body["entitlements"].as_array().unwrap().len(), 1);
    assert_eq!(list_body["entitlements"][0]["id"], "app:custom:admin");

    let evaluation_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/access-requests")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{
                        "subject":"user-1",
                        "entitlement":"app:custom:admin",
                        "requested_duration_seconds":3600
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(evaluation_response.status(), StatusCode::OK);
    let evaluation = json(evaluation_response).await;
    assert_eq!(evaluation["status"], "approval_required");
    assert_eq!(
        evaluation["approval_steps"][0]["approver"],
        "security-admin"
    );
    assert_eq!(
        evaluation["violations"][0],
        "duration_exceeds_entitlement_max"
    );

    let delete_response = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/iga/v1/entitlements/app:custom:admin")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete_response.status(), StatusCode::OK);
    assert!(
        repo.list_iga_entitlements("test")
            .await
            .expect("list IGA entitlements after delete failed")
            .is_empty()
    );
}

#[tokio::test]
async fn access_package_route_persists_lists_and_deletes_packages() {
    let (app, repo, session_id) = setup_with_repo().await;
    let entitlement = serde_json::json!({
        "id": "app:custom:admin",
        "display_name": "Custom administrator",
        "owner": "security-admin",
        "risk_level": "high",
        "conflicting_entitlements": [],
        "max_duration_seconds": 3600,
        "active": true
    });
    let entitlement_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/entitlements")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(entitlement.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(entitlement_response.status(), StatusCode::OK);

    let package = serde_json::json!({
        "id": "pkg-custom-admin",
        "display_name": "Custom administration",
        "owner": "security-admin",
        "entitlement_ids": ["app:custom:admin"],
        "approval_policy_json": {
            "steps": [
                {"approver": "manager"},
                {"approver": "app_owner"}
            ]
        },
        "max_duration_seconds": 1800,
        "active": true
    });
    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/access-packages")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(package.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_response.status(), StatusCode::OK);
    let create_body = json(create_response).await;
    assert_eq!(create_body["tenant_id"], "test");
    assert_eq!(
        create_body["access_package"]["entitlement_ids"][0],
        "app:custom:admin"
    );
    assert_eq!(
        create_body["access_package"]["approval_policy_json"]["steps"][1]["approver"],
        "app_owner"
    );

    let stored = repo
        .list_iga_access_packages("test")
        .await
        .expect("list stored IGA access packages failed");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].id, "pkg-custom-admin");

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/iga/v1/access-packages")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body = json(list_response).await;
    assert_eq!(list_body["access_packages"].as_array().unwrap().len(), 1);
    assert_eq!(list_body["access_packages"][0]["id"], "pkg-custom-admin");

    let invalid_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/access-packages")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{
                        "id":"pkg-invalid",
                        "display_name":"Invalid package",
                        "owner":"security-admin",
                        "entitlement_ids":["app:missing"],
                        "approval_policy_json":{}
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_response.status(), StatusCode::BAD_REQUEST);
    let invalid_body = json(invalid_response).await;
    assert_eq!(invalid_body["error"], "access_package_unknown_entitlement");

    let delete_response = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/iga/v1/access-packages/pkg-custom-admin")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete_response.status(), StatusCode::OK);
    assert!(
        repo.list_iga_access_packages("test")
            .await
            .expect("list IGA access packages after delete failed")
            .is_empty()
    );
}

#[tokio::test]
async fn approval_validation_route_issues_time_bound_grant_when_complete() {
    let (app, repo, session_id) = setup_with_repo().await;
    let evaluation_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/access-requests")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{
                        "subject":"user-1",
                        "entitlement":"app:erp:admin",
                        "requested_duration_seconds":3600
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(evaluation_response.status(), StatusCode::OK);
    let evaluation = json(evaluation_response).await;
    let request_id = evaluation["id"].as_str().unwrap();
    store_iga_approval(&repo, request_id, "finance-ops", "approved").await;
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "issue_grant": true,
        "approvals": [
            {
                "id": "approval-owner",
                "request_id": request_id,
                "approver": "finance-ops",
                "decision": "approved",
                "approved_at_epoch_seconds": now,
                "expires_at_epoch_seconds": now + 300,
                "reason": "owner approved"
            },
            {
                "id": "approval-security",
                "request_id": request_id,
                "approver": "security-admin",
                "decision": "approved",
                "approved_at_epoch_seconds": now,
                "expires_at_epoch_seconds": now + 300,
                "reason": "security approved"
            }
        ]
    });

    let validation_response = app
        .clone()
        .oneshot(request_with_headers(
            Method::POST,
            "/iga/v1/access-requests/approvals/validate",
            payload,
            &session_id,
        ))
        .await
        .unwrap();
    assert_eq!(validation_response.status(), StatusCode::OK);
    let body = json(validation_response).await;
    assert_eq!(body["validation"]["valid"], true);
    assert_eq!(body["grant"]["subject"], "user-1");
    assert_eq!(body["grant"]["entitlement"], "app:erp:admin");
    assert_eq!(body["grant"]["approvals"].as_array().unwrap().len(), 2);
    assert!(body["grant"]["expires_at_epoch_seconds"].as_u64().is_some());

    let approvals = repo
        .list_iga_approvals("test", request_id)
        .await
        .expect("list stored IGA approvals failed");
    assert_eq!(approvals.len(), 2);
    assert_eq!(approvals[0].decision, "approved");

    let grants = repo
        .list_iga_access_grants("test", Some("user-1"))
        .await
        .expect("list stored IGA access grants failed");
    assert_eq!(grants.len(), 1);
    let grant_id = grants[0].id.clone();
    assert_eq!(grants[0].request_id, request_id);
    assert_eq!(grants[0].approval_ids.len(), 2);
    assert!(!grants[0].revoked);

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/iga/v1/access-grants?subject=user-1")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body = json(list_response).await;
    assert_eq!(list_body["tenant_id"], "test");
    assert_eq!(list_body["subject"], "user-1");
    assert_eq!(list_body["grants"].as_array().unwrap().len(), 1);
    assert_eq!(list_body["grants"][0]["id"], grant_id);
    assert_eq!(list_body["grants"][0]["revoked"], false);

    let unrelated_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/iga/v1/access-grants?subject=user-2")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unrelated_response.status(), StatusCode::OK);
    let unrelated_body = json(unrelated_response).await;
    assert!(unrelated_body["grants"].as_array().unwrap().is_empty());

    let revoke_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/iga/v1/access-grants/{grant_id}/revoke"))
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(r#"{"reason":"access no longer needed"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoke_response.status(), StatusCode::OK);
    let revoke_body = json(revoke_response).await;
    assert_eq!(revoke_body["id"], grant_id);
    assert_eq!(revoke_body["revoked"], true);
    assert_eq!(revoke_body["reason"], "access no longer needed");

    let revoked = repo
        .list_iga_access_grants("test", Some("user-1"))
        .await
        .expect("list stored IGA access grants after revoke failed");
    assert_eq!(revoked.len(), 1);
    assert!(revoked[0].revoked);

    let missing_revoke_response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/access-grants/missing-grant/revoke")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(r#"{}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_revoke_response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn access_package_request_can_issue_grants_for_each_entitlement() {
    let (app, repo, session_id) = setup_with_repo().await;
    for entitlement in [
        serde_json::json!({
            "id": "app:custom:admin",
            "display_name": "Custom administrator",
            "owner": "security-admin",
            "risk_level": "high",
            "conflicting_entitlements": [],
            "max_duration_seconds": 3600,
            "active": true
        }),
        serde_json::json!({
            "id": "app:custom:read",
            "display_name": "Custom reader",
            "owner": "security-admin",
            "risk_level": "low",
            "conflicting_entitlements": [],
            "max_duration_seconds": 7200,
            "active": true
        }),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/iga/v1/entitlements")
                    .header("Content-Type", "application/json")
                    .header(ADMIN_SESSION_ID_HEADER, &session_id)
                    .body(Body::from(entitlement.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let package = serde_json::json!({
        "id": "pkg-custom-ops",
        "display_name": "Custom operations",
        "owner": "security-admin",
        "entitlement_ids": ["app:custom:admin", "app:custom:read"],
        "approval_policy_json": {},
        "max_duration_seconds": 1800,
        "active": true
    });
    let package_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/access-packages")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(package.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(package_response.status(), StatusCode::OK);

    let request_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/access-requests")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{
                        "subject":"user-1",
                        "access_package_id":"pkg-custom-ops",
                        "requested_duration_seconds":3600,
                        "reason":"temporary operations"
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(request_response.status(), StatusCode::OK);
    let request_body = json(request_response).await;
    let request_id = request_body["id"].as_str().unwrap();
    assert_eq!(request_body["access_package_id"], "pkg-custom-ops");
    assert_eq!(request_body["entitlement"], "access_package:pkg-custom-ops");
    assert_eq!(request_body["status"], "approval_required");
    assert_eq!(
        request_body["package_evaluation"]["entitlements"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        request_body["approval_steps"][0]["approver"],
        "security-admin"
    );

    let stored_request = repo
        .get_iga_access_request("test", request_id)
        .await
        .expect("get stored IGA package request failed")
        .expect("stored IGA package request missing");
    assert_eq!(stored_request.entitlement, "access_package:pkg-custom-ops");
    assert_eq!(stored_request.status, "approval_required");
    store_iga_approval(&repo, request_id, "security-admin", "approved").await;

    let now = qid_core::util::now_seconds();
    let validation_payload = serde_json::json!({
        "issue_grant": true,
        "approvals": [
            {
                "id": "package-approval-owner",
                "request_id": request_id,
                "approver": "security-admin",
                "decision": "approved",
                "approved_at_epoch_seconds": now,
                "expires_at_epoch_seconds": now + 300,
                "reason": "owner approved"
            },
            {
                "id": "package-approval-security",
                "request_id": request_id,
                "approver": "security-admin",
                "decision": "approved",
                "approved_at_epoch_seconds": now,
                "expires_at_epoch_seconds": now + 300,
                "reason": "security approved"
            }
        ]
    });
    let validation_response = app
        .clone()
        .oneshot(request_with_headers(
            Method::POST,
            "/iga/v1/access-requests/approvals/validate",
            validation_payload,
            &session_id,
        ))
        .await
        .unwrap();
    assert_eq!(validation_response.status(), StatusCode::OK);
    let validation_body = json(validation_response).await;
    assert_eq!(validation_body["validation"]["valid"], true);
    assert_eq!(validation_body["grants"].as_array().unwrap().len(), 1);
    assert_eq!(validation_body["grant"]["request_id"], request_id);
    assert_eq!(
        validation_body["grant"]["entitlement"],
        "access_package:pkg-custom-ops"
    );

    let grants = repo
        .list_iga_access_grants("test", Some("user-1"))
        .await
        .expect("list package grants failed");
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].entitlement, "access_package:pkg-custom-ops");
    assert_eq!(grants[0].request_id, request_id);
}

#[tokio::test]
async fn jit_privilege_route_issues_lists_and_revokes_short_lived_privilege() {
    let (app, repo, session_id) = setup_with_repo().await;
    let entitlement = serde_json::json!({
        "id": "app:custom:admin",
        "display_name": "Custom administrator",
        "owner": "security-admin",
        "risk_level": "high",
        "conflicting_entitlements": [],
        "max_duration_seconds": 900,
        "active": true
    });
    let entitlement_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/entitlements")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(entitlement.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(entitlement_response.status(), StatusCode::OK);
    let now = qid_core::util::now_seconds();
    repo.store_iga_access_request(&IgaAccessRequestRecord {
        id: "jit-request-1".to_string(),
        tenant_id: "test".to_string(),
        subject: "user-1".to_string(),
        entitlement: "app:custom:admin".to_string(),
        reason: Some("Emergency fix".to_string()),
        status: "approved".to_string(),
        approval_steps_json: serde_json::json!([
            {"approver":"security-admin","reason":"owner_approval_required"}
        ]),
        violations_json: serde_json::json!([]),
        expires_at_epoch_seconds: Some(now + 3600),
        created_at_epoch_seconds: now,
    })
    .await
    .expect("store JIT source access request failed");
    store_iga_approval(&repo, "jit-request-1", "security-admin", "approved").await;

    let issue_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/jit-privileges")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{
                        "request_id":"jit-request-1",
                        "subject":"user-1",
                        "entitlement":"app:custom:admin",
                        "reason":"Emergency fix",
                        "duration_seconds":300,
                        "constraints_json":{"ticket":"INC-1"}
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(issue_response.status(), StatusCode::OK);
    let issue_body = json(issue_response).await;
    let grant_id = issue_body["jit_privilege"]["id"].as_str().unwrap();
    assert_eq!(issue_body["tenant_id"], "test");
    assert_eq!(issue_body["jit_privilege"]["subject"], "user-1");
    assert_eq!(
        issue_body["jit_privilege"]["entitlement"],
        "app:custom:admin"
    );
    assert_eq!(
        issue_body["jit_privilege"]["requested_by"],
        "security-admin"
    );
    assert_eq!(issue_body["jit_privilege"]["approved_by"], "security-admin");
    assert_eq!(
        issue_body["jit_privilege"]["constraints_json"]["ticket"],
        "INC-1"
    );
    assert_eq!(issue_body["jit_privilege"]["revoked"], false);

    let stored = repo
        .list_iga_jit_privilege_grants("test", Some("user-1"))
        .await
        .expect("list stored IGA JIT privilege grants failed");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].id, grant_id);

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/iga/v1/jit-privileges?subject=user-1")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body = json(list_response).await;
    assert_eq!(list_body["jit_privileges"].as_array().unwrap().len(), 1);
    assert_eq!(list_body["jit_privileges"][0]["id"], grant_id);

    let revoke_response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/iga/v1/jit-privileges/{grant_id}/revoke"))
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(r#"{"reason":"Work complete"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoke_response.status(), StatusCode::OK);
    let revoke_body = json(revoke_response).await;
    assert_eq!(revoke_body["revoked"], true);
    let stored = repo
        .list_iga_jit_privilege_grants("test", Some("user-1"))
        .await
        .expect("list stored IGA JIT privilege grants after revoke failed");
    assert!(stored[0].revoked);
}

#[tokio::test]
async fn certification_routes_record_attestations_and_export_iga_evidence() {
    let (app, repo, session_id) = setup_with_repo().await;
    let entitlement = serde_json::json!({
        "id": "app:custom:admin",
        "display_name": "Custom administrator",
        "owner": "security-admin",
        "risk_level": "critical",
        "conflicting_entitlements": [],
        "max_duration_seconds": 900,
        "active": true
    });
    let entitlement_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/entitlements")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(entitlement.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(entitlement_response.status(), StatusCode::OK);

    let manager_certification = serde_json::json!({
        "certification_type": "manager",
        "campaign_id": "review-1",
        "subject": "user-1",
        "entitlement": "app:custom:admin",
        "certifier": "manager-1",
        "decision": "certify",
        "reason": "User still needs access",
        "evidence_json": {"manager_chain": ["manager-1"]}
    });
    let manager_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/certifications")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(manager_certification.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(manager_response.status(), StatusCode::OK);
    let manager_body = json(manager_response).await;
    assert_eq!(
        manager_body["certification"]["certification_type"],
        "manager"
    );
    assert_eq!(manager_body["certification"]["decision"], "certify");

    let wrong_owner_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/certifications")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{
                        "certification_type":"application_owner",
                        "subject":"user-1",
                        "entitlement":"app:custom:admin",
                        "certifier":"not-owner",
                        "decision":"certify"
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_owner_response.status(), StatusCode::OK);
    let wrong_owner_body = json(wrong_owner_response).await;
    assert_eq!(
        wrong_owner_body["certification"]["certifier"],
        "security-admin"
    );

    let owned_entitlement = serde_json::json!({
        "id": "app:owned:admin",
        "display_name": "Owned administrator",
        "owner": "security-admin",
        "risk_level": "critical",
        "conflicting_entitlements": [],
        "max_duration_seconds": 900,
        "active": true
    });
    let owned_entitlement_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/entitlements")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(owned_entitlement.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(owned_entitlement_response.status(), StatusCode::OK);

    let app_owner_certification = serde_json::json!({
        "certification_type": "application_owner",
        "subject": "user-1",
        "entitlement": "app:owned:admin",
        "decision": "certify",
        "evidence_json": {"application": "custom"}
    });
    let app_owner_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/certifications")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(app_owner_certification.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(app_owner_response.status(), StatusCode::OK);

    let privileged_attestation = serde_json::json!({
        "certification_type": "privileged_role",
        "subject": "user-1",
        "entitlement": "app:custom:admin",
        "certifier": "security-admin",
        "decision": "exception",
        "reason": "Break-glass coverage",
        "evidence_json": {"privileged": true}
    });
    let privileged_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/certifications")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(privileged_attestation.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(privileged_response.status(), StatusCode::OK);

    let manager_list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/iga/v1/certifications?certification_type=manager")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(manager_list_response.status(), StatusCode::OK);
    let manager_list = json(manager_list_response).await;
    assert_eq!(manager_list["certifications"].as_array().unwrap().len(), 1);

    let stored = repo
        .list_iga_certifications("test", None)
        .await
        .expect("list stored IGA certifications failed");
    assert_eq!(stored.len(), 4);

    let evidence_response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/iga/v1/evidence")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(evidence_response.status(), StatusCode::OK);
    let evidence = json(evidence_response).await;
    assert_eq!(evidence["schema_version"], "qid.iga.evidence.v1");
    assert_eq!(evidence["tenant_id"], "test");
    assert_eq!(evidence["certifications"].as_array().unwrap().len(), 4);
    assert!(evidence["generated_at_epoch_seconds"].as_u64().is_some());
}

#[tokio::test]
async fn finding_routes_detect_resolve_and_export_sod_conflicts_from_grants() {
    let (app, repo, session_id) = setup_with_repo().await;
    let now = qid_core::util::now_seconds();
    for (id, entitlement) in [
        ("finding-grant-admin", "app:erp:admin"),
        ("finding-grant-audit", "app:erp:audit"),
    ] {
        repo.store_iga_access_grant(&IgaAccessGrantRecord {
            id: id.to_string(),
            tenant_id: "test".to_string(),
            request_id: format!("{id}-request"),
            subject: "user-conflicted".to_string(),
            entitlement: entitlement.to_string(),
            granted_at_epoch_seconds: now,
            expires_at_epoch_seconds: Some(now + 3600),
            approval_ids: vec![format!("{id}-approval")],
            revoked: false,
        })
        .await
        .expect("store finding source grant failed");
    }
    let payload = serde_json::json!({
        "dormant_threshold_seconds": 100
    });
    let detect_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/findings/detect")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(detect_response.status(), StatusCode::OK);
    let detect_body = json(detect_response).await;
    assert_eq!(detect_body["findings"].as_array().unwrap().len(), 2);
    let finding_id = detect_body["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["finding_type"] == "sod_conflict")
        .and_then(|finding| finding["id"].as_str())
        .unwrap()
        .to_string();

    let stored = repo
        .list_iga_findings("test", None)
        .await
        .expect("list stored IGA findings failed");
    assert_eq!(stored.len(), 2);
    assert!(
        stored
            .iter()
            .any(|finding| finding.subject == "user-conflicted")
    );

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/iga/v1/findings?finding_type=sod_conflict")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body = json(list_response).await;
    assert_eq!(list_body["findings"].as_array().unwrap().len(), 2);
    assert_eq!(list_body["findings"][0]["subject"], "user-conflicted");

    let resolve_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/iga/v1/findings/{finding_id}/resolve"))
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(r#"{}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resolve_response.status(), StatusCode::OK);
    let resolved = repo
        .list_iga_findings("test", Some("sod_conflict"))
        .await
        .expect("list resolved IGA findings failed");
    assert!(resolved.iter().any(|finding| finding.resolved));

    let evidence_response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/iga/v1/evidence")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(evidence_response.status(), StatusCode::OK);
    let evidence = json(evidence_response).await;
    assert_eq!(evidence["findings"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn approval_validation_route_reports_missing_and_rejected_approvals() {
    let (app, _, session_id) = setup_with_repo().await;
    let eval_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/access-requests")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{
                        "subject":"user-1",
                        "entitlement":"app:erp:admin",
                        "requested_duration_seconds":3600
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(eval_response.status(), StatusCode::OK);
    let eval_body = json(eval_response).await;
    let request_id = eval_body["id"].as_str().unwrap();
    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "issue_grant": true,
        "approvals": [
            {
                "id": "approval-rejected",
                "request_id": request_id,
                "approver": "security-admin",
                "decision": "rejected",
                "approved_at_epoch_seconds": now,
                "expires_at_epoch_seconds": now + 300,
                "reason": "rejected by security"
            }
        ]
    });

    let response = app
        .clone()
        .oneshot(request_with_headers(
            Method::POST,
            "/iga/v1/access-requests/approvals/validate",
            payload,
            &session_id,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    assert_eq!(body["validation"]["valid"], false);
    assert_eq!(body["validation"]["missing_approvers"][0], "finance-ops");
    assert_eq!(
        body["validation"]["rejected_approvers"][0],
        "security-admin"
    );
    assert!(body["grant"].is_null());
}

#[tokio::test]
async fn access_review_route_builds_persists_lists_and_closes_campaign() {
    let (app, repo, session_id) = setup_with_repo().await;
    let now = qid_core::util::now_seconds();
    for (id, subject, entitlement) in [
        ("review-campaign-grant-1", "user-1", "app:erp:admin"),
        ("review-campaign-grant-2", "user-1", "app:erp:audit"),
        ("review-campaign-grant-3", "user-2", "app:erp:read"),
    ] {
        repo.store_iga_access_grant(&IgaAccessGrantRecord {
            id: id.to_string(),
            tenant_id: "test".to_string(),
            request_id: format!("{id}-request"),
            subject: subject.to_string(),
            entitlement: entitlement.to_string(),
            granted_at_epoch_seconds: now,
            expires_at_epoch_seconds: Some(now + 3600),
            approval_ids: vec![format!("{id}-approval")],
            revoked: false,
        })
        .await
        .expect("store review campaign source grant failed");
    }
    repo.store_iga_finding(&IgaFindingRecord {
        id: "review-orphan-user-1".to_string(),
        tenant_id: "test".to_string(),
        finding_type: "orphaned_service_account".to_string(),
        subject: "user-1".to_string(),
        severity: "high".to_string(),
        evidence_json: serde_json::json!({"source":"test"}),
        detected_at_epoch_seconds: now,
        resolved: false,
    })
    .await
    .expect("store review campaign source finding failed");
    let payload = serde_json::json!({
        "reviewer": "auditor-1",
        "assignments": {
            "user-1": ["app:erp:admin", "app:erp:audit"],
            "user-2": ["app:erp:read"]
        },
        "dormant_subjects": ["user-2"],
        "orphan_subjects": ["user-1"],
        "due_in_seconds": 86400
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/access-reviews")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    let campaign_id = body["id"].as_str().unwrap();
    assert_eq!(body["tenant_id"], "test");
    assert_eq!(body["reviewer"], "security-admin");
    assert_eq!(body["status"], "open");
    assert_eq!(body["subjects"].as_array().unwrap().len(), 2);
    assert_eq!(body["subjects"][0]["subject"], "user-1");
    assert_eq!(body["subjects"][0]["recommendation"], "revoke");

    let stored = repo
        .get_iga_access_review_campaign("test", campaign_id)
        .await
        .expect("get stored IGA access review campaign failed")
        .expect("stored IGA access review campaign missing");
    assert_eq!(stored.tenant_id, "test");
    assert_eq!(stored.reviewer, "security-admin");
    assert_eq!(stored.status, "open");
    assert_eq!(stored.subjects_json.as_array().unwrap().len(), 2);

    let grant_now = qid_core::util::now_seconds();
    repo.store_iga_access_grant(&IgaAccessGrantRecord {
        id: "review-grant-1".to_string(),
        tenant_id: "test".to_string(),
        request_id: "review-request-1".to_string(),
        subject: "user-1".to_string(),
        entitlement: "app:erp:admin".to_string(),
        granted_at_epoch_seconds: grant_now,
        expires_at_epoch_seconds: Some(grant_now + 3600),
        approval_ids: vec!["review-approval-1".to_string()],
        revoked: false,
    })
    .await
    .expect("store review remediation grant failed");

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/iga/v1/access-reviews")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body = json(list_response).await;
    assert_eq!(list_body["tenant_id"], "test");
    assert_eq!(list_body["campaigns"].as_array().unwrap().len(), 1);
    assert_eq!(list_body["campaigns"][0]["id"], campaign_id);

    let decision_payload = serde_json::json!({
        "subject": "user-1",
        "decision": "revoke",
        "reason": "Orphaned owner"
    });
    let decision_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/iga/v1/access-reviews/{campaign_id}/decisions"))
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(decision_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(decision_response.status(), StatusCode::OK);
    let decision_body = json(decision_response).await;
    let decision_id = decision_body["decision"]["id"].as_str().unwrap();
    assert_eq!(decision_body["tenant_id"], "test");
    assert_eq!(decision_body["decision"]["campaign_id"], campaign_id);
    assert_eq!(decision_body["decision"]["subject"], "user-1");
    assert_eq!(decision_body["decision"]["decision"], "revoke");
    let revoked_ids = decision_body["revoked_grants"].as_array().unwrap();
    assert!(revoked_ids.iter().any(|id| id == "review-campaign-grant-1"));
    assert!(revoked_ids.iter().any(|id| id == "review-campaign-grant-2"));
    assert!(revoked_ids.iter().any(|id| id == "review-grant-1"));

    let stored_decisions = repo
        .list_iga_access_review_decisions("test", campaign_id)
        .await
        .expect("list stored IGA access review decisions failed");
    assert_eq!(stored_decisions.len(), 1);
    assert_eq!(stored_decisions[0].id, decision_id);
    let revoked_grants = repo
        .list_iga_access_grants("test", Some("user-1"))
        .await
        .expect("list review remediation grants failed");
    assert_eq!(revoked_grants.len(), 3);
    assert!(
        revoked_grants
            .iter()
            .filter(|grant| grant.revoked)
            .all(|grant| matches!(
                grant.entitlement.as_str(),
                "app:erp:admin" | "app:erp:audit"
            ))
    );

    let decisions_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/iga/v1/access-reviews/{campaign_id}/decisions"))
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(decisions_response.status(), StatusCode::OK);
    let decisions_body = json(decisions_response).await;
    assert_eq!(decisions_body["campaign_id"], campaign_id);
    assert_eq!(decisions_body["decisions"].as_array().unwrap().len(), 1);
    assert_eq!(decisions_body["decisions"][0]["id"], decision_id);

    let close_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/iga/v1/access-reviews/{campaign_id}/close"))
                .header("content-type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    serde_json::json!({"tenant_id": "test"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(close_response.status(), StatusCode::OK);
    let close_body = json(close_response).await;
    assert_eq!(close_body["status"], "closed");

    let closed = repo
        .get_iga_access_review_campaign("test", campaign_id)
        .await
        .expect("get closed IGA access review campaign failed")
        .expect("closed IGA access review campaign missing");
    assert_eq!(closed.status, "closed");

    let late_decision_response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/iga/v1/access-reviews/{campaign_id}/decisions"))
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{
                        "subject":"user-2",
                        "reviewer":"auditor-1",
                        "decision":"certify"
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(late_decision_response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn validate_approvals_rejects_forged_evaluation_in_body() {
    let (app, _, session_id) = setup_with_repo().await;
    let eval_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/access-requests")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{
                        "subject":"user-1",
                        "entitlement":"app:erp:admin",
                        "requested_duration_seconds":3600
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(eval_response.status(), StatusCode::OK);
    let eval_body = json(eval_response).await;
    let request_id = eval_body["id"].as_str().unwrap();
    let now = qid_core::util::now_seconds();
    let forged_payload = serde_json::json!({
        "evaluation": {
            "request_id": request_id,
            "subject": "attacker",
            "entitlement": "app:erp:audit",
            "status": "approval_required",
            "approval_steps": [{"approver": "attacker-approver", "reason": "forged"}],
            "violations": [],
            "expires_at_epoch_seconds": now + 3600
        },
        "actor": "attacker",
        "issue_grant": true,
        "approvals": [
            {
                "id": "forged-approval",
                "request_id": request_id,
                "approver": "attacker-approver",
                "decision": "approved",
                "approved_at_epoch_seconds": now,
                "expires_at_epoch_seconds": now + 300,
                "reason": "forged"
            }
        ]
    });

    let response = app
        .clone()
        .oneshot(request_with_headers(
            Method::POST,
            "/iga/v1/access-requests/approvals/validate",
            forged_payload,
            &session_id,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    assert_eq!(body["validation"]["valid"], false);
    assert!(
        body["validation"]["missing_approvers"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("finance-ops")),
        "stored evaluation must be used, not forged body: missing_approvers={:?}",
        body["validation"]["missing_approvers"]
    );
    assert!(body["grant"].is_null());
}

#[tokio::test]
async fn validate_approvals_rejects_self_approval_sod_violation() {
    let (app, _, session_id) = setup_with_repo().await;
    let eval_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/access-requests")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{
                        "subject":"user-1",
                        "entitlement":"app:erp:admin",
                        "requested_duration_seconds":3600
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(eval_response.status(), StatusCode::OK);
    let eval_body = json(eval_response).await;
    let request_id = eval_body["id"].as_str().unwrap();

    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "issue_grant": true,
        "approvals": [
            {
                "id": "self-approval",
                "request_id": request_id,
                "approver": "user-1",
                "decision": "approved",
                "approved_at_epoch_seconds": now,
                "expires_at_epoch_seconds": now + 300,
                "reason": "self approval attempt"
            },
            {
                "id": "owner-approval",
                "request_id": request_id,
                "approver": "finance-ops",
                "decision": "approved",
                "approved_at_epoch_seconds": now,
                "expires_at_epoch_seconds": now + 300,
                "reason": "owner approved"
            },
            {
                "id": "security-approval",
                "request_id": request_id,
                "approver": "security-admin",
                "decision": "approved",
                "approved_at_epoch_seconds": now,
                "expires_at_epoch_seconds": now + 300,
                "reason": "security approved"
            }
        ]
    });

    let response = app
        .clone()
        .oneshot(request_with_headers(
            Method::POST,
            "/iga/v1/access-requests/approvals/validate",
            payload,
            &session_id,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    assert_eq!(body["validation"]["valid"], false);
    assert!(
        body["validation"]["missing_approvers"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("finance-ops")),
        "client supplied self-approval must be ignored: body={body:?}"
    );
    assert!(body["grant"].is_null());
}

#[tokio::test]
async fn validate_approvals_rejects_request_not_in_approval_required_status() {
    let (app, _, session_id) = setup_with_repo().await;
    let eval_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/access-requests")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{"subject":"user-1","entitlement":"app:erp:read"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(eval_response.status(), StatusCode::OK);
    let eval_body = json(eval_response).await;
    assert_eq!(eval_body["status"], "auto_approved");
    let request_id = eval_body["id"].as_str().unwrap();

    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "issue_grant": true,
        "approvals": [
            {
                "id": "unnecessary-approval",
                "request_id": request_id,
                "approver": "finance-ops",
                "decision": "approved",
                "approved_at_epoch_seconds": now,
                "expires_at_epoch_seconds": now + 300
            }
        ]
    });

    let response = app
        .clone()
        .oneshot(request_with_headers(
            Method::POST,
            "/iga/v1/access-requests/approvals/validate",
            payload,
            &session_id,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json(response).await;
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("auto_approved"),
        "expected error about auto_approved status, got: {:?}",
        body
    );
}

#[tokio::test]
async fn validate_approvals_rejects_missing_admin_headers() {
    let (app, _, session_id) = setup_with_repo().await;
    let payload = serde_json::json!({
        "issue_grant": false,
        "approvals": []
    });

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/access-requests/approvals/validate")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        response.status() == StatusCode::BAD_REQUEST
            || response.status() == StatusCode::UNAUTHORIZED,
        "expected 4xx for missing admin auth, got {}",
        response.status()
    );
}

#[tokio::test]
async fn validate_approvals_rejects_insufficient_admin_role() {
    let (app, _, _session_id) = setup_with_repo().await;
    let payload = serde_json::json!({
        "issue_grant": false,
        "approvals": []
    });

    // Send request without admin session header - should be rejected
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/access-requests/approvals/validate")
                .header("Content-Type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        response.status() == StatusCode::BAD_REQUEST
            || response.status() == StatusCode::UNAUTHORIZED,
        "expected 4xx for missing admin auth, got {}",
        response.status()
    );
}

#[tokio::test]
async fn validate_approvals_is_idempotent_and_prevents_double_issuance() {
    let (app, repo, session_id) = setup_with_repo().await;
    let eval_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/access-requests")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{
                        "subject":"user-1",
                        "entitlement":"app:erp:admin",
                        "requested_duration_seconds":3600
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(eval_response.status(), StatusCode::OK);
    let eval_body = json(eval_response).await;
    let request_id = eval_body["id"].as_str().unwrap();
    store_iga_approval(&repo, request_id, "finance-ops", "approved").await;

    let now = qid_core::util::now_seconds();
    let payload = serde_json::json!({
        "issue_grant": true,
        "approvals": [
            {
                "id": "dup-approval-owner",
                "request_id": request_id,
                "approver": "finance-ops",
                "decision": "approved",
                "approved_at_epoch_seconds": now,
                "expires_at_epoch_seconds": now + 300
            },
            {
                "id": "dup-approval-security",
                "request_id": request_id,
                "approver": "security-admin",
                "decision": "approved",
                "approved_at_epoch_seconds": now,
                "expires_at_epoch_seconds": now + 300
            }
        ]
    });

    let first_response = app
        .clone()
        .oneshot(request_with_headers(
            Method::POST,
            "/iga/v1/access-requests/approvals/validate",
            payload.clone(),
            &session_id,
        ))
        .await
        .unwrap();
    assert_eq!(first_response.status(), StatusCode::OK);
    let first_body = json(first_response).await;
    assert_eq!(first_body["validation"]["valid"], true);
    assert!(
        first_body["grant"].is_object(),
        "first call should issue a grant"
    );

    let second_response = app
        .clone()
        .oneshot(request_with_headers(
            Method::POST,
            "/iga/v1/access-requests/approvals/validate",
            payload,
            &session_id,
        ))
        .await
        .unwrap();
    assert_eq!(second_response.status(), StatusCode::OK);
    let second_body = json(second_response).await;
    assert_eq!(second_body["validation"]["valid"], true);
    assert!(
        second_body["grant"].is_null(),
        "second call must not issue a duplicate grant: grant={:?}",
        second_body["grant"]
    );
    assert_eq!(
        second_body["grants"].as_array().unwrap().len(),
        0,
        "second call must return empty grants list"
    );

    let grants = repo
        .list_iga_access_grants("test", Some("user-1"))
        .await
        .expect("list grants failed");
    assert_eq!(grants.len(), 1, "only one grant must exist");
}
