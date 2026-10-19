mod common;

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use common::{
    ADMIN_SESSION_ID_HEADER, json, post_json, post_raw, request_with_headers,
    seed_default_erp_catalog, setup_app, store_iga_approval,
};
use qid_core::models::{
    IgaAccessGrantRecord, IgaAccessRequestRecord, IgaApprovalRecord, IgaFindingRecord,
};
use qid_storage::{FileRepository, prelude::*};
use std::sync::Arc;
use tower::ServiceExt;

async fn setup_with_repo() -> (Router, Arc<FileRepository>, String) {
    setup_app("qid-iga", Some("test"), "security-admin").await
}

async fn store_approved_jit_source_request(
    repo: &FileRepository,
    request_id: &str,
    expires_at_epoch_seconds: Option<u64>,
    approved_at_epoch_seconds: Option<u64>,
) {
    let now = qid_core::util::now_seconds();
    let created_at_epoch_seconds = expires_at_epoch_seconds
        .filter(|expires_at| *expires_at <= now)
        .map_or(now, |expires_at| expires_at.saturating_sub(2));
    repo.store_iga_access_request(&IgaAccessRequestRecord {
        id: request_id.to_string(),
        tenant_id: "test".to_string(),
        subject: "user-1".to_string(),
        entitlement: "app:custom:admin".to_string(),
        reason: Some("Emergency fix".to_string()),
        status: "approved".to_string(),
        approval_steps_json: serde_json::json!([
            {"approver":"security-admin","reason":"owner_approval_required"}
        ]),
        violations_json: serde_json::json!([]),
        package_entitlement_ids_json: serde_json::json!([]),
        expires_at_epoch_seconds,
        created_at_epoch_seconds,
    })
    .await
    .expect("store JIT source access request failed");
    repo.store_iga_approval(&IgaApprovalRecord {
        id: format!("stored-security-admin-{request_id}"),
        tenant_id: "test".to_string(),
        request_id: request_id.to_string(),
        approver: "security-admin".to_string(),
        decision: "approved".to_string(),
        approved_at_epoch_seconds: approved_at_epoch_seconds.unwrap_or(now),
        expires_at_epoch_seconds: None,
        reason: Some("stored approval".to_string()),
    })
    .await
    .expect("store JIT approval failed");
}

#[tokio::test]
async fn access_request_route_evaluates_catalog_duration_and_approval_steps() {
    let (app, repo, session_id) = setup_with_repo().await;
    seed_default_erp_catalog(&repo, "test").await;
    let body = post_raw(
        app.clone(),
        "/iga/v1/access-requests",
        r#"{
                        "subject":"user-1",
                        "entitlement":"app:erp:admin",
                        "current_entitlements":[],
                        "requested_duration_seconds":3600,
                        "reason":"temporary admin"
                    }"#,
        &session_id,
    )
    .await;
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
    let body = post_raw(
        app.clone(),
        "/iga/v1/access-requests",
        r#"{
                        "subject":"user-1",
                        "entitlement":"app:unknown"
                    }"#,
        &session_id,
    )
    .await;
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
    let create_body = post_json(
        app.clone(),
        "/iga/v1/entitlements",
        entitlement,
        &session_id,
    )
    .await;
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

    let evaluation = post_raw(
        app.clone(),
        "/iga/v1/access-requests",
        r#"{
                        "subject":"user-1",
                        "entitlement":"app:custom:admin",
                        "requested_duration_seconds":3600
                    }"#,
        &session_id,
    )
    .await;
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

async fn seed_conflicting_erp_pair(app: &Router, session_id: &str) {
    for (id, conflicts) in [
        ("app:erp:admin", vec!["app:erp:audit"]),
        ("app:erp:audit", vec!["app:erp:admin"]),
    ] {
        post_json(
            app.clone(),
            "/iga/v1/entitlements",
            serde_json::json!({
                "id": id,
                "display_name": id,
                "owner": "security-admin",
                "risk_level": "high",
                "conflicting_entitlements": conflicts,
                "max_duration_seconds": 30 * 24 * 60 * 60,
                "active": true
            }),
            session_id,
        )
        .await;
    }
}

async fn create_package_and_request(
    app: &Router,
    session_id: &str,
    package: serde_json::Value,
    subject: &str,
) -> serde_json::Value {
    let package_id = package["id"].clone();
    post_json(app.clone(), "/iga/v1/access-packages", package, session_id).await;
    post_json(
        app.clone(),
        "/iga/v1/access-requests",
        serde_json::json!({
            "subject": subject,
            "access_package_id": package_id,
            "reason": "package request",
        }),
        session_id,
    )
    .await
}

#[tokio::test]
async fn access_package_request_rejects_conflicting_members_in_any_order() {
    for entitlement_ids in [
        vec!["app:erp:admin", "app:erp:audit"],
        vec!["app:erp:audit", "app:erp:admin"],
    ] {
        let (app, _repo, session_id) = setup_with_repo().await;
        seed_conflicting_erp_pair(&app, &session_id).await;
        let body = create_package_and_request(
            &app,
            &session_id,
            serde_json::json!({
                "id": "pkg-conflicting",
                "display_name": "Conflicting package",
                "owner": "security-admin",
                "entitlement_ids": entitlement_ids,
                "max_duration_seconds": 1800,
                "active": true
            }),
            "user-1",
        )
        .await;
        assert_eq!(body["status"], "rejected", "order: {entitlement_ids:?}");
        let violations = body["violations"].as_array().unwrap();
        assert!(
            violations
                .iter()
                .any(|v| v.as_str().unwrap_or_default().contains("sod_conflict")),
            "conflicting package must surface an SoD violation, got {violations:?}"
        );
    }
}

#[tokio::test]
async fn empty_or_fully_deactivated_catalog_rejects_as_unknown() {
    let (app, _repo, session_id) = setup_with_repo().await;
    let request = |entitlement: &str| {
        serde_json::json!({
            "subject": "user-1",
            "entitlement": entitlement,
            "requested_duration_seconds": 3600,
            "reason": "catalog authority probe"
        })
    };
    // No configured entitlements: nothing is known, nothing is granted.
    let body = post_json(
        app.clone(),
        "/iga/v1/access-requests",
        request("app:erp:admin"),
        &session_id,
    )
    .await;
    assert_eq!(body["status"], "rejected");
    assert!(
        body["violations"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("unknown_entitlement"))
    );

    // A configured entitlement authorizes evaluation.
    post_json(
        app.clone(),
        "/iga/v1/entitlements",
        serde_json::json!({
            "id": "app:custom:ops",
            "display_name": "Operations",
            "owner": "security-admin",
            "risk_level": "low",
            "max_duration_seconds": 3600,
            "active": true
        }),
        &session_id,
    )
    .await;
    let body = post_json(
        app.clone(),
        "/iga/v1/access-requests",
        request("app:custom:ops"),
        &session_id,
    )
    .await;
    assert_eq!(body["status"], "auto_approved");

    // Deactivating the final entitlement restores fail-closed unknown.
    post_json(
        app.clone(),
        "/iga/v1/entitlements",
        serde_json::json!({
            "id": "app:custom:ops",
            "display_name": "Operations",
            "owner": "security-admin",
            "risk_level": "low",
            "max_duration_seconds": 3600,
            "active": false
        }),
        &session_id,
    )
    .await;
    let body = post_json(
        app,
        "/iga/v1/access-requests",
        request("app:custom:ops"),
        &session_id,
    )
    .await;
    assert_eq!(body["status"], "rejected");
    assert!(
        body["violations"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("unknown_entitlement"))
    );
}

#[tokio::test]
async fn revoke_certification_removes_packaged_member_access() {
    let (app, repo, session_id) = setup_with_repo().await;
    seed_conflicting_erp_pair(&app, &session_id).await;
    let body = create_package_and_request(
        &app,
        &session_id,
        serde_json::json!({
            "id": "pkg-admin-only",
            "display_name": "Admin only",
            "owner": "security-admin",
            "entitlement_ids": ["app:erp:admin"],
            "max_duration_seconds": 1800,
            "active": true
        }),
        "user-1",
    )
    .await;
    let request_id = body["id"].as_str().unwrap().to_string();
    let now = qid_core::util::now_seconds();
    let approvals: Vec<serde_json::Value> = ["cert-approval-owner", "cert-approval-security"]
        .iter()
        .map(|id| {
            serde_json::json!({
                "id": id,
                "request_id": request_id,
                "approver": "security-admin",
                "decision": "approved",
                "approved_at_epoch_seconds": now,
                "expires_at_epoch_seconds": now + 300
            })
        })
        .collect();
    let validation_body = post_json(
        app.clone(),
        "/iga/v1/access-requests/approvals/validate",
        serde_json::json!({"issue_grant": true, "approvals": approvals}),
        &session_id,
    )
    .await;
    assert_eq!(validation_body["validation"]["valid"], true);
    let grant_id = validation_body["grants"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let active_grant = repo
        .list_iga_access_grants("test", Some("user-1"))
        .await
        .unwrap()
        .into_iter()
        .find(|grant| grant.id == grant_id)
        .unwrap();
    assert!(!active_grant.revoked);

    let invalid_response = app
        .clone()
        .oneshot(request_with_headers(
            Method::POST,
            "/iga/v1/certifications",
            serde_json::json!({
                "certification_type": "manager",
                "campaign_id": "review-1",
                "subject": "user-1",
                "entitlement": "app:erp:admin",
                "decision": "revoke",
                "evidence_json": []
            }),
            &session_id,
        ))
        .await
        .unwrap();
    assert_eq!(invalid_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json(invalid_response).await["error"],
        "certification_invalid"
    );

    let unchanged_grant = repo
        .list_iga_access_grants("test", Some("user-1"))
        .await
        .unwrap()
        .into_iter()
        .find(|grant| grant.id == grant_id)
        .unwrap();
    assert!(!unchanged_grant.revoked);
    assert!(
        repo.list_iga_certifications("test", None)
            .await
            .unwrap()
            .is_empty()
    );

    // Revoking the member via certification revokes the packaged grant.
    let cert_body = post_json(
        app.clone(),
        "/iga/v1/certifications",
        serde_json::json!({
            "certification_type": "manager",
            "campaign_id": "review-1",
            "subject": "user-1",
            "entitlement": "app:erp:admin",
            "decision": "revoke",
            "reason": "no longer required"
        }),
        &session_id,
    )
    .await;
    let revoked = cert_body["revoked_grants"].as_array().unwrap();
    assert!(revoked.contains(&serde_json::json!(grant_id)));
    let grant = repo
        .list_iga_access_grants("test", Some("user-1"))
        .await
        .unwrap()
        .into_iter()
        .find(|grant| grant.id == grant_id)
        .unwrap();
    assert!(grant.revoked);

    // Effective access is gone: the conflicting audit request is no longer blocked.
    let conflict_body = post_json(
        app.clone(),
        "/iga/v1/access-requests",
        serde_json::json!({
            "subject": "user-1",
            "entitlement": "app:erp:audit",
            "requested_duration_seconds": 3600
        }),
        &session_id,
    )
    .await;
    assert_ne!(conflict_body["status"], "rejected");
}

#[tokio::test]
async fn package_issuance_refuses_drifted_package_definition() {
    let (app, repo, session_id) = setup_with_repo().await;
    for (id, owner) in [("app:custom:a", "owner-a"), ("app:custom:b", "owner-b")] {
        post_json(
            app.clone(),
            "/iga/v1/entitlements",
            serde_json::json!({
                "id": id,
                "display_name": id,
                "owner": owner,
                "risk_level": "medium",
                "conflicting_entitlements": [],
                "max_duration_seconds": 3600,
                "active": true
            }),
            &session_id,
        )
        .await;
    }
    let package = |members: Vec<&str>| {
        serde_json::json!({
            "id": "pkg-drift",
            "display_name": "Drifting package",
            "owner": "security-admin",
            "entitlement_ids": members,
            "max_duration_seconds": 1800,
            "active": true
        })
    };
    let body =
        create_package_and_request(&app, &session_id, package(vec!["app:custom:a"]), "user-1")
            .await;
    let request_id = body["id"].as_str().unwrap().to_string();
    assert_eq!(body["status"], "approval_required");

    // Edit the package after the request: the added member was never evaluated.
    post_json(
        app.clone(),
        "/iga/v1/access-packages",
        package(vec!["app:custom:a", "app:custom:b"]),
        &session_id,
    )
    .await;
    let now = qid_core::util::now_seconds();
    let response = app
        .oneshot(request_with_headers(
            Method::POST,
            "/iga/v1/access-requests/approvals/validate",
            serde_json::json!({
                "request_id": request_id,
                "issue_grant": true,
                "approvals": [
                    {
                        "id": "drift-approval",
                        "request_id": request_id,
                        "approver": "security-admin",
                        "decision": "approved",
                        "approved_at_epoch_seconds": now,
                        "expires_at_epoch_seconds": now + 300
                    }
                ]
            }),
            &session_id,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json(response).await;
    assert_eq!(body["error"], "access_package_changed");
    let grants = repo
        .list_iga_access_grants("test", Some("user-1"))
        .await
        .unwrap();
    assert!(grants.is_empty(), "drifted package must issue no grants");
}

#[tokio::test]
async fn package_grant_batch_issues_complete_set_or_repairs_partial_revoked_set() {
    for partial in [false, true] {
        let (app, repo, session_id) = setup_with_repo().await;
        for id in ["app:custom:a", "app:custom:b"] {
            post_json(
                app.clone(),
                "/iga/v1/entitlements",
                serde_json::json!({
                    "id": id, "display_name": id, "owner": "security-admin",
                    "risk_level": "medium", "max_duration_seconds": 3600, "active": true
                }),
                &session_id,
            )
            .await;
        }
        let body = create_package_and_request(
            &app,
            &session_id,
            serde_json::json!({
                "id": "pkg-retry", "display_name": "Retry package", "owner": "security-admin",
                "entitlement_ids": ["app:custom:a", "app:custom:b"],
                "max_duration_seconds": 1800, "active": true
            }),
            "user-1",
        )
        .await;
        assert_eq!(body["status"], "approval_required");
        let request_id = body["id"].as_str().unwrap();
        let now = qid_core::util::now_seconds();
        let incumbent = IgaAccessGrantRecord {
            id: "legacy-member".into(),
            tenant_id: "test".into(),
            request_id: request_id.into(),
            subject: "user-1".into(),
            entitlement: "app:custom:a".into(),
            granted_at_epoch_seconds: now - 100,
            expires_at_epoch_seconds: Some(now - 50),
            approval_ids: vec!["legacy-approval".into()],
            revoked: true,
        };
        if partial {
            // Simulate a legacy per-member write followed by failure, then a
            // certification revocation before retry. Neither may be undone.
            repo.store_iga_access_grant(&incumbent).await.unwrap();
        }
        let issued = post_json(
            app.clone(),
            "/iga/v1/access-requests/approvals/validate",
            serde_json::json!({
                "request_id": request_id, "issue_grant": true,
                "approvals": [{
                    "id": "retry-approval",
                    "request_id": request_id, "approver": "security-admin",
                    "decision": "approved", "approved_at_epoch_seconds": now,
                    "expires_at_epoch_seconds": now + 300
                }]
            }),
            &session_id,
        )
        .await;
        assert_eq!(issued["validation"]["valid"], true);
        let grants = issued["grants"].as_array().unwrap();
        assert_eq!(grants.len(), if partial { 1 } else { 2 });
        assert_eq!(issued["grant"], grants[0]);
        if partial {
            assert_eq!(grants[0]["entitlement"], "app:custom:b");
        }
        for grant in grants {
            let expiry = grant["expires_at_epoch_seconds"].as_u64().unwrap();
            assert_eq!(expiry, body["expires_at_epoch_seconds"].as_u64().unwrap());
        }
        let stored = repo
            .list_iga_access_grants("test", Some("user-1"))
            .await
            .unwrap();
        assert_eq!(stored.len(), 2);
        if partial {
            assert_eq!(
                stored.iter().find(|grant| grant.id == incumbent.id),
                Some(&incumbent)
            );
        }
        assert_eq!(
            repo.get_iga_access_request("test", request_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            "approved"
        );
        assert_eq!(
            repo.list_iga_approvals("test", request_id)
                .await
                .unwrap()
                .len(),
            1
        );
        let replay = post_json(
            app.clone(),
            "/iga/v1/access-requests/approvals/validate",
            serde_json::json!({"request_id": request_id, "issue_grant": true}),
            &session_id,
        )
        .await;
        assert_eq!(replay["validation"]["valid"], true);
        assert_eq!(replay["grants"], serde_json::json!([]));
        assert!(replay["grant"].is_null());
        assert_eq!(
            repo.list_iga_access_grants("test", Some("user-1"))
                .await
                .unwrap(),
            stored
        );
    }
}

#[tokio::test]
async fn package_member_grant_feeds_later_sod_checks_and_review() {
    let (app, _repo, session_id) = setup_with_repo().await;
    seed_conflicting_erp_pair(&app, &session_id).await;
    let body = create_package_and_request(
        &app,
        &session_id,
        serde_json::json!({
            "id": "pkg-audit-only",
            "display_name": "Audit only",
            "owner": "security-admin",
            "entitlement_ids": ["app:erp:audit"],
            "max_duration_seconds": 1800,
            "active": true
        }),
        "user-1",
    )
    .await;
    let request_id = body["id"].as_str().unwrap().to_string();

    // High-risk audit needs owner plus security approval; entitlement owners
    // pin to the creating admin, so both steps name security-admin.
    let now = qid_core::util::now_seconds();
    let approvals: Vec<serde_json::Value> = ["package-approval-owner", "package-approval-security"]
        .iter()
        .map(|id| {
            serde_json::json!({
                "id": id,
                "request_id": request_id,
                "approver": "security-admin",
                "decision": "approved",
                "approved_at_epoch_seconds": now,
                "expires_at_epoch_seconds": now + 300
            })
        })
        .collect();
    let validation_body = post_json(
        app.clone(),
        "/iga/v1/access-requests/approvals/validate",
        serde_json::json!({"issue_grant": true, "approvals": approvals}),
        &session_id,
    )
    .await;
    assert_eq!(validation_body["validation"]["valid"], true);
    let grants_json = validation_body["grants"].as_array().unwrap();
    assert_eq!(grants_json.len(), 1);
    assert_eq!(grants_json[0]["entitlement"], "app:erp:audit");

    // A later standalone admin request must see the packaged audit grant.
    let conflict_body = post_json(
        app.clone(),
        "/iga/v1/access-requests",
        serde_json::json!({
            "subject": "user-1",
            "entitlement": "app:erp:admin",
            "requested_duration_seconds": 3600,
            "reason": "admin after audit package"
        }),
        &session_id,
    )
    .await;
    assert_eq!(conflict_body["status"], "rejected");
    let violations = conflict_body["violations"].as_array().unwrap();
    assert!(
        violations.contains(&serde_json::json!("sod_conflict:app:erp:audit")),
        "packaged audit grant must trip later SoD checks, got {violations:?}"
    );

    // Access review resolves the packaged member, not an opaque marker.
    let review_body = post_json(
        app,
        "/iga/v1/access-reviews",
        serde_json::json!({}),
        &session_id,
    )
    .await;
    let subjects = review_body["subjects"].as_array().unwrap();
    let user_subject = subjects
        .iter()
        .find(|subject| subject["subject"] == "user-1")
        .expect("review must include the packaged subject");
    assert!(
        user_subject["entitlements"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("app:erp:audit")),
        "review must list the packaged member entitlement, got {user_subject:?}"
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
    let create_body = post_json(app.clone(), "/iga/v1/access-packages", package, &session_id).await;
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
    seed_default_erp_catalog(&repo, "test").await;
    let evaluation = post_raw(
        app.clone(),
        "/iga/v1/access-requests",
        r#"{
                        "subject":"user-1",
                        "entitlement":"app:erp:admin",
                        "requested_duration_seconds":3600
                    }"#,
        &session_id,
    )
    .await;
    let request_id = evaluation["id"].as_str().unwrap();
    store_iga_approval(&repo, "test", request_id, "finance-ops", "approved").await;
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

    let body = post_json(
        app.clone(),
        "/iga/v1/access-requests/approvals/validate",
        payload,
        &session_id,
    )
    .await;
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

    let request_body = post_raw(
        app.clone(),
        "/iga/v1/access-requests",
        r#"{
                        "subject":"user-1",
                        "access_package_id":"pkg-custom-ops",
                        "requested_duration_seconds":3600,
                        "reason":"temporary operations"
                    }"#,
        &session_id,
    )
    .await;
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
    store_iga_approval(&repo, "test", request_id, "security-admin", "approved").await;

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
    let validation_body = post_json(
        app.clone(),
        "/iga/v1/access-requests/approvals/validate",
        validation_payload,
        &session_id,
    )
    .await;
    assert_eq!(validation_body["validation"]["valid"], true);
    let grants_json = validation_body["grants"].as_array().unwrap();
    assert_eq!(grants_json.len(), 2);
    let mut grant_entitlements: Vec<&str> = grants_json
        .iter()
        .map(|grant| grant["entitlement"].as_str().unwrap())
        .collect();
    grant_entitlements.sort();
    assert_eq!(
        grant_entitlements,
        vec!["app:custom:admin", "app:custom:read"]
    );

    let grants = repo
        .list_iga_access_grants("test", Some("user-1"))
        .await
        .expect("list package grants failed");
    assert_eq!(grants.len(), 2);
    let mut stored_entitlements: Vec<&str> = grants
        .iter()
        .map(|grant| grant.entitlement.as_str())
        .collect();
    stored_entitlements.sort();
    assert_eq!(
        stored_entitlements,
        vec!["app:custom:admin", "app:custom:read"]
    );
    assert!(grants.iter().all(|grant| grant.request_id == request_id));
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
    store_approved_jit_source_request(&repo, "jit-request-1", None, None).await;

    let issue_body = post_raw(
        app.clone(),
        "/iga/v1/jit-privileges",
        r#"{
                        "request_id":"jit-request-1",
                        "subject":"user-1",
                        "entitlement":"app:custom:admin",
                        "reason":"Emergency fix",
                        "duration_seconds":300,
                        "constraints_json":{"ticket":"INC-1"}
                    }"#,
        &session_id,
    )
    .await;
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
    assert_eq!(
        issue_body["jit_privilege"]["expires_at_epoch_seconds"]
            .as_u64()
            .unwrap(),
        issue_body["jit_privilege"]["issued_at_epoch_seconds"]
            .as_u64()
            .unwrap()
            + 300
    );

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
        .clone()
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

    let expired_at = qid_core::util::now_seconds() - 1;
    store_approved_jit_source_request(
        &repo,
        "jit-request-expired",
        Some(expired_at),
        Some(expired_at - 1),
    )
    .await;
    let expired_response = app
        .clone()
        .oneshot(request_with_headers(
            Method::POST,
            "/iga/v1/jit-privileges",
            serde_json::json!({
                "request_id": "jit-request-expired",
                "subject": "user-1",
                "entitlement": "app:custom:admin",
                "reason": "Emergency fix",
                "duration_seconds": 300
            }),
            &session_id,
        ))
        .await
        .unwrap();
    assert_eq!(expired_response.status(), StatusCode::BAD_REQUEST);
    let stored = repo
        .list_iga_jit_privilege_grants("test", Some("user-1"))
        .await
        .expect("list stored IGA JIT grants after expired request failed");
    assert_eq!(stored.len(), 1);

    let near_expiry = qid_core::util::now_seconds() + 240;
    store_approved_jit_source_request(&repo, "jit-request-near-expiry", Some(near_expiry), None)
        .await;
    let near_expiry_body = post_json(
        app,
        "/iga/v1/jit-privileges",
        serde_json::json!({
            "request_id": "jit-request-near-expiry",
            "subject": "user-1",
            "entitlement": "app:custom:admin",
            "reason": "Emergency fix",
            "duration_seconds": 300
        }),
        &session_id,
    )
    .await;
    assert_eq!(
        near_expiry_body["jit_privilege"]["expires_at_epoch_seconds"],
        near_expiry
    );
    let stored = repo
        .list_iga_jit_privilege_grants("test", Some("user-1"))
        .await
        .expect("list stored IGA JIT grants after near-expiry request failed");
    assert_eq!(stored.len(), 2);
    assert!(
        stored
            .iter()
            .any(|grant| grant.expires_at_epoch_seconds == near_expiry)
    );
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
    let manager_body = post_json(
        app.clone(),
        "/iga/v1/certifications",
        manager_certification,
        &session_id,
    )
    .await;
    assert_eq!(
        manager_body["certification"]["certification_type"],
        "manager"
    );
    assert_eq!(manager_body["certification"]["decision"], "certify");

    let wrong_owner_body = post_raw(
        app.clone(),
        "/iga/v1/certifications",
        r#"{
                        "certification_type":"application_owner",
                        "subject":"user-1",
                        "entitlement":"app:custom:admin",
                        "certifier":"not-owner",
                        "decision":"certify"
                    }"#,
        &session_id,
    )
    .await;
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
async fn finding_routes_reject_foreign_admin_tenant_scope() {
    let (app, _repo, session_id) = setup_with_repo().await;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/iga/v1/findings?tenant_id=other")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn finding_routes_detect_resolve_and_export_sod_conflicts_from_grants() {
    let (app, repo, session_id) = setup_with_repo().await;
    seed_default_erp_catalog(&repo, "test").await;
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
    let payload = serde_json::json!({});
    let detect_body = post_json(app.clone(), "/iga/v1/findings/detect", payload, &session_id).await;
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
    let (app, repo, session_id) = setup_with_repo().await;
    seed_default_erp_catalog(&repo, "test").await;
    let eval_body = post_raw(
        app.clone(),
        "/iga/v1/access-requests",
        r#"{
                        "subject":"user-1",
                        "entitlement":"app:erp:admin",
                        "requested_duration_seconds":3600
                    }"#,
        &session_id,
    )
    .await;
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

    let body = post_json(
        app.clone(),
        "/iga/v1/access-requests/approvals/validate",
        payload,
        &session_id,
    )
    .await;
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
    // Spoofed evidence must not leak into the campaign: assignments and
    // dormant/orphan subjects are repository-derived, unknown fields ignored.
    let payload = serde_json::json!({
        "reviewer": "auditor-1",
        "assignments": {
            "ghost-user": ["app:erp:admin"]
        },
        "dormant_subjects": ["ghost-user"],
        "orphan_subjects": ["ghost-user"],
        "due_in_seconds": 86400
    });

    let body = post_json(app.clone(), "/iga/v1/access-reviews", payload, &session_id).await;
    let campaign_id = body["id"].as_str().unwrap();
    assert_eq!(body["tenant_id"], "test");
    assert_eq!(body["reviewer"], "security-admin");
    assert_eq!(body["status"], "open");
    assert_eq!(body["subjects"].as_array().unwrap().len(), 2);
    assert_eq!(body["subjects"][0]["subject"], "user-1");
    assert_eq!(body["subjects"][0]["recommendation"], "revoke");
    assert!(
        body["subjects"]
            .as_array()
            .unwrap()
            .iter()
            .all(|subject| subject["subject"] != "ghost-user"),
        "spoofed assignments must not create campaign subjects"
    );

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
    let (app, repo, session_id) = setup_with_repo().await;
    seed_default_erp_catalog(&repo, "test").await;
    let eval_body = post_raw(
        app.clone(),
        "/iga/v1/access-requests",
        r#"{
                        "subject":"user-1",
                        "entitlement":"app:erp:admin",
                        "requested_duration_seconds":3600
                    }"#,
        &session_id,
    )
    .await;
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

    let body = post_json(
        app.clone(),
        "/iga/v1/access-requests/approvals/validate",
        forged_payload,
        &session_id,
    )
    .await;
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
    let (app, repo, session_id) = setup_with_repo().await;
    seed_default_erp_catalog(&repo, "test").await;
    let eval_body = post_raw(
        app.clone(),
        "/iga/v1/access-requests",
        r#"{
                        "subject":"user-1",
                        "entitlement":"app:erp:admin",
                        "requested_duration_seconds":3600
                    }"#,
        &session_id,
    )
    .await;
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

    let body = post_json(
        app.clone(),
        "/iga/v1/access-requests/approvals/validate",
        payload,
        &session_id,
    )
    .await;
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
    let (app, repo, session_id) = setup_with_repo().await;
    seed_default_erp_catalog(&repo, "test").await;
    let eval_body = post_raw(
        app.clone(),
        "/iga/v1/access-requests",
        r#"{"subject":"user-1","entitlement":"app:erp:read"}"#,
        &session_id,
    )
    .await;
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
    seed_default_erp_catalog(&repo, "test").await;
    let eval_body = post_raw(
        app.clone(),
        "/iga/v1/access-requests",
        r#"{
                        "subject":"user-1",
                        "entitlement":"app:erp:admin",
                        "requested_duration_seconds":3600
                    }"#,
        &session_id,
    )
    .await;
    let request_id = eval_body["id"].as_str().unwrap();
    store_iga_approval(&repo, "test", request_id, "finance-ops", "approved").await;

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

    let second_body = post_json(
        app.clone(),
        "/iga/v1/access-requests/approvals/validate",
        payload,
        &session_id,
    )
    .await;
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

#[tokio::test]
async fn access_request_route_rejects_unrepresentable_duration() {
    let (app, _repo, session_id) = setup_with_repo().await;
    let entitlement = serde_json::json!({
        "id": "app:test:overflow",
        "display_name": "Overflow probe",
        "owner": "test",
        "risk_level": "low",
        "conflicting_entitlements": [],
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
    let body = post_raw(
        app.clone(),
        "/iga/v1/access-requests",
        r#"{
                        "subject":"user-1",
                        "entitlement":"app:test:overflow",
                        "current_entitlements":[],
                        "requested_duration_seconds":18446744073709551615,
                        "reason":"unbounded grant"
                    }"#,
        &session_id,
    )
    .await;
    assert_eq!(body["status"], "rejected");
    assert!(
        body["violations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|violation| violation == "duration_overflow")
    );
    assert!(body["expires_at_epoch_seconds"].is_null());
}

#[tokio::test]
async fn access_review_route_rejects_unrepresentable_due_time() {
    let (app, _repo, session_id) = setup_with_repo().await;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/access-reviews")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(
                    r#"{"reviewer":"auditor-1","due_in_seconds":18446744073709551615}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn access_review_revoke_decision_retry_converges_without_new_effects() {
    let (app, repo, session_id) = setup_with_repo().await;
    let now = qid_core::util::now_seconds();
    repo.store_iga_access_grant(&IgaAccessGrantRecord {
        id: "retry-grant-1".to_string(),
        tenant_id: "test".to_string(),
        request_id: "retry-request-1".to_string(),
        subject: "user-9".to_string(),
        entitlement: "app:erp:read".to_string(),
        granted_at_epoch_seconds: now,
        expires_at_epoch_seconds: Some(now + 3600),
        approval_ids: vec![],
        revoked: false,
    })
    .await
    .expect("store retry grant failed");

    let campaign_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/iga/v1/access-reviews")
                .header("Content-Type", "application/json")
                .header(ADMIN_SESSION_ID_HEADER, &session_id)
                .body(Body::from(r#"{"reviewer":"auditor-1"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(campaign_response.status(), StatusCode::OK);
    let campaign_body = json(campaign_response).await;
    let campaign_id = campaign_body["id"].as_str().unwrap().to_string();

    let decide = |app: Router| {
        let campaign_id = campaign_id.clone();
        let session_id = session_id.clone();
        async move {
            app.oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/iga/v1/access-reviews/{campaign_id}/decisions"))
                    .header("Content-Type", "application/json")
                    .header(ADMIN_SESSION_ID_HEADER, &session_id)
                    .body(Body::from(
                        r#"{"subject":"user-9","decision":"revoke","reason":"retry probe"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };

    let first = decide(app.clone()).await;
    assert_eq!(first.status(), StatusCode::OK);
    let first_body = json(first).await;
    assert_eq!(first_body["decision"]["decision"], "revoke");
    assert_eq!(
        first_body["revoked_grants"].as_array().unwrap().len(),
        1,
        "first revoke applies the effect before recording"
    );

    // Retrying the same revoke must be a harmless no-op on grants while still
    // recording the (duplicate) decision: effects-first keeps retries safe.
    let second = decide(app.clone()).await;
    assert_eq!(second.status(), StatusCode::OK);
    let second_body = json(second).await;
    assert!(
        second_body["revoked_grants"].as_array().unwrap().is_empty(),
        "retry must find no active grants left to revoke"
    );

    let grants = repo
        .list_iga_access_grants("test", Some("user-9"))
        .await
        .expect("list retry grants failed");
    assert_eq!(grants.len(), 1);
    assert!(grants[0].revoked);
}
