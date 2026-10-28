//! Caller coverage; atomic owner changes remain covered by storage contracts.
use super::*;
use crate::test_support::{sign_test_document, test_sp_cert_body};
use axum::{body::Body, http::Request};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use qid_core::{config::SamlServiceProviderConfig, test_helpers::test_config};
use tower::ServiceExt;

#[tokio::test]
async fn logout_routes_preserve_same_realm_and_ignore_foreign_or_missing_sessions() {
    let directory = tempfile::tempdir().unwrap();
    let repo = Arc::new(
        qid_storage::FileRepository::new(directory.path().join("store.json").to_str().unwrap())
            .await
            .unwrap(),
    );
    let mut config = test_config();
    config.realms[0].protocols.saml.enabled = true;
    config.realms[0].protocols.saml.service_providers = vec![SamlServiceProviderConfig {
        entity_id: "https://sp.example.com".into(),
        signing_certificates: vec![test_sp_cert_body()],
        ..Default::default()
    }];
    let state = Arc::new(
        SharedState::new(
            config,
            repo.clone(),
            Arc::new(super::tests::TestSigner),
            serde_json::json!({}),
        )
        .unwrap(),
    );
    let cookie_name = state
        .realm("test")
        .unwrap()
        .browser_session
        .cookie_name
        .clone();
    let app = saml_routes().with_state(state);
    let now = qid_core::util::now_seconds();
    for (id, realm) in [
        ("sp-local", "test"),
        ("browser-local", "test"),
        ("foreign", "other"),
    ] {
        repo.create_session(&Session {
            id: id.into(),
            realm_id: realm.into(),
            user_id: "user".into(),
            auth_time: now,
            acr: None,
            amr: vec!["pwd".into()],
            idle_expires_at: now + 600,
            absolute_expires_at: now + 600,
            revoked: false,
            created_at: now,
            cnf: None,
        })
        .await
        .unwrap();
    }
    let foreign_before = serde_json::to_value(repo.get_session("foreign").await.unwrap()).unwrap();
    let signed = sign_test_document(
        r#"<p:LogoutRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" ID="_logout" Version="2.0" IssueInstant="2026-10-28T00:00:00Z" Destination="https://id.example.com/saml/test/slo"><s:Issuer>https://sp.example.com</s:Issuer><!--SIGNATURE--><s:NameID>user</s:NameID><p:SessionIndex>sp-local</p:SessionIndex><p:SessionIndex>foreign</p:SessionIndex><p:SessionIndex>missing</p:SessionIndex></p:LogoutRequest>"#,
        "_logout",
    );
    let encoded = STANDARD.encode(signed);
    // Repeating SP logout still reports the matched session even on Ok(false).
    for _ in 0..2 {
        let request = Request::builder()
            .method("POST")
            .uri("/saml/test/slo")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "SAMLRequest={}",
                urlencoding::encode(&encoded)
            )))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 32_768)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["result"], "logout_received");
        assert_eq!(json["revoked_sessions"], serde_json::json!(["sp-local"]));
        assert!(repo.get_session("sp-local").await.unwrap().unwrap().revoked);
    }

    for (id, expected) in [
        ("foreign", StatusCode::UNAUTHORIZED),
        ("missing", StatusCode::UNAUTHORIZED),
        ("browser-local", StatusCode::OK),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/saml/test/slo/initiate")
                    .header(header::COOKIE, format!("{cookie_name}={id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        let body = axum::body::to_bytes(response.into_body(), 32_768)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if expected == StatusCode::OK {
            assert_eq!(json["result"], "logged_out");
            assert_eq!(json["session_id"], id);
            assert_eq!(json["user_id"], "user");
        } else {
            assert_eq!(json["error"], "saml_logout_required");
        }
    }
    assert!(
        repo.get_session("browser-local")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    assert_eq!(
        serde_json::to_value(repo.get_session("foreign").await.unwrap()).unwrap(),
        foreign_before,
    );
    assert!(repo.get_session("missing").await.unwrap().is_none());
}
