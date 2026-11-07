mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use qid_core::{
    config::OAuthResourceServerConfig, models::AccessToken, state::SharedState, test_helpers,
    util::now_seconds,
};
use qid_crypto::LocalSigner;
use qid_storage::{FileRepository, prelude::*};
use std::sync::Arc;
use tower::ServiceExt;

const AUDIENCE: &str = "api://iga";
const SCOPE: &str = "qid_iga_access_request";

#[tokio::test]
async fn bearer_access_requests_require_the_realm_audience_and_exact_scope_before_storage() {
    // Explicit stored tokens also cover empty audiences, which normal issuance
    // replaces with a client audience. A resource is never an audience substitute.
    for (name, configured, audiences, scopes, allowed) in [
        ("valid", true, vec![AUDIENCE], vec![SCOPE], true),
        (
            "multi-audience",
            true,
            vec!["api://other", AUDIENCE],
            vec!["openid", SCOPE],
            true,
        ),
        ("unconfigured", false, vec![AUDIENCE], vec![SCOPE], false),
        ("missing-audience", true, vec![], vec![SCOPE], false),
        (
            "wrong-audience",
            true,
            vec!["api://other"],
            vec![SCOPE],
            false,
        ),
        (
            "audience-prefix",
            true,
            vec!["api://iga/other"],
            vec![SCOPE],
            false,
        ),
        ("missing-scope", true, vec![AUDIENCE], vec![], false),
        (
            "wrong-scope",
            true,
            vec![AUDIENCE],
            vec!["qid_identity"],
            false,
        ),
        (
            "scope-prefix",
            true,
            vec![AUDIENCE],
            vec!["qid_iga_access_request_extra"],
            false,
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let repo = Arc::new(
            FileRepository::new(dir.path().join("store.json").to_str().unwrap())
                .await
                .unwrap(),
        );
        repo.migrate().await.unwrap();
        repo.create_realm(
            &"test".into(),
            &"test".into(),
            "https://id.example.com",
            None,
        )
        .await
        .unwrap();
        common::seed_default_erp_catalog(&repo, "test").await;
        let mut config = test_helpers::test_config();
        config.realms[0].tenant_id = Some("test".into());
        config.realms[0].protocols.oauth.resource_servers = vec![OAuthResourceServerConfig {
            audience: AUDIENCE.into(),
            resources: vec![],
            scopes: vec![SCOPE.into()],
            introspection_client_ids: vec![],
            require_sender_constraint: false,
            high_risk: false,
        }];
        config.realms[0].protocols.iga.access_request_audience =
            configured.then(|| AUDIENCE.into());
        let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
        let state = Arc::new(
            SharedState::new(config, repo.clone(), signer, serde_json::json!({})).unwrap(),
        );
        let jti = ulid::Ulid::new().to_string();
        let record: AccessToken = serde_json::from_value(serde_json::json!({
            "jti": jti, "family_id": null, "user_id": "user-1",
            "client_id": "iga-client", "realm_id": "test", "scopes": scopes,
            "audience": audiences, "resource": [AUDIENCE], "token_format": "opaque",
            "expires_at": now_seconds() + 300, "issued_at": now_seconds(), "revoked": false
        }))
        .unwrap();
        repo.create_access_token(&record).await.unwrap();
        let app = qid_iga::iga_routes().with_state(state);
        let response = app.oneshot(Request::builder()
            .method("POST").uri("/iga/v1/access-requests")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", qid_oauth::endpoints::encode_opaque_access_token(&jti)))
            .body(Body::from(serde_json::json!({
                "subject": "user-1", "entitlement": "app:erp:admin", "requested_duration_seconds": 3600
            }).to_string())).unwrap()).await.unwrap();
        assert_eq!(
            response.status(),
            if allowed {
                StatusCode::OK
            } else {
                StatusCode::UNAUTHORIZED
            },
            "{name}"
        );
        let body = common::json(response).await;
        let stored = repo.list_iga_access_requests("test").await.unwrap();
        if allowed {
            assert_eq!(body["status"], "approval_required", "{name}");
            assert_eq!(stored.len(), 1, "{name}");
            assert_eq!(stored[0].id, body["id"].as_str().unwrap(), "{name}");
            assert_eq!(stored[0].subject, "user-1");
            assert_eq!(stored[0].approval_steps_json.as_array().unwrap().len(), 2);
        } else {
            assert!(
                body["error"]
                    .as_str()
                    .unwrap()
                    .contains("configured IGA audience"),
                "{name}: {body}"
            );
            assert!(stored.is_empty(), "denied request persisted: {name}");
        }
        // All repository owners are dropped before the temp directory, including
        // on Windows; each table case has a fresh isolated store.
        drop(repo);
    }
}
