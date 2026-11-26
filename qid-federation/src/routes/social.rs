use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use qid_core::state::SharedState;
use qid_storage::prelude::*;
use std::sync::Arc;

use crate::{HomeRealmDiscoveryRequest, InboundProviderKind, verify_inbound_idp_token};

use super::oidc::{exchange_code_for_tokens, extract_claims_from_oidc_response};
use super::{
    OidcCallbackQuery, broker_login_plan_error_response, exec_broker_login_plan, plan_broker_login,
    providers_from_config, transaction, verify_authorization_response_issuer,
};

pub async fn social_login_callback<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path((realm, provider_name)): Path<(String, String)>,
    Query(params): Query<OidcCallbackQuery>,
    headers: HeaderMap,
) -> Response {
    // Spend the browser-bound proof before token exchange, lookups or writes.
    let proof = match transaction::verify(
        &state,
        &headers,
        &realm,
        params.state.as_deref(),
        Some(&provider_name),
    ) {
        Ok(proof) => proof,
        Err(error) => return error.into_response(),
    };

    let realm_config = match state.config.realms.iter().find(|r| r.id == realm) {
        Some(cfg) => cfg,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "realm_not_found"})),
            )
                .into_response();
        }
    };

    if !realm_config.protocols.federation.enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "federation_disabled"})),
        )
            .into_response();
    }

    let providers = providers_from_config(&realm_config.protocols.federation.inbound_providers);

    // The verified proof, not the callback path alias, selects the provider.
    let provider_id = proof.provider.as_str();
    let provider = match providers
        .iter()
        .find(|p| p.id == provider_id && p.enabled && p.kind == InboundProviderKind::Social)
    {
        Some(p) => p.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "provider_not_found",
                    "message": format!("provider {provider_id} is not an enabled social provider")
                })),
            )
                .into_response();
        }
    };
    let path_is_canonical = provider_name == provider.id;
    if !path_is_canonical
        && !provider
            .social_provider
            .as_deref()
            .is_some_and(|alias| alias.eq_ignore_ascii_case(&provider_name))
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "social_provider_mismatch",
                "message": format!("provider {provider_id} does not match callback {provider_name}")
            })),
        )
            .into_response();
    }

    // Several enabled providers can share one social alias; a canonical id path
    // binds the response when they do, before any credential lookup or exchange.
    let ambiguous_target = providers
        .iter()
        .filter(|p| {
            p.enabled
                && p.social_provider
                    .as_deref()
                    .is_some_and(|alias| alias.eq_ignore_ascii_case(&provider_name))
        })
        .count()
        > 1;
    if let Err(error) = verify_authorization_response_issuer(
        params.iss.as_deref(),
        &provider.issuer,
        ambiguous_target && !path_is_canonical,
    ) {
        return error.into_response();
    }

    let request = HomeRealmDiscoveryRequest {
        login_hint: None,
        domain: None,
        idp_hint: Some(provider.id.clone()),
        social_provider: None,
    };

    let client_id = match &provider.client_id {
        Some(cid) => cid,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "client_id_not_configured"})),
            )
                .into_response();
        }
    };
    let client_secret = match &provider.client_secret {
        Some(cs) => cs,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "client_secret_not_configured"})),
            )
                .into_response();
        }
    };
    let token_url = match &provider.token_url {
        Some(tu) => tu.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "token_url_not_configured"})),
            )
                .into_response();
        }
    };

    let redirect_uri = format!(
        "{}/federation/{}/social/{}/callback",
        state.plan.public_base_url.trim_end_matches('/'),
        urlencoding::encode(&realm),
        urlencoding::encode(&provider_name),
    );

    let token_resp = match exchange_code_for_tokens(
        &token_url,
        client_id,
        client_secret,
        &params.code,
        &redirect_uri,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(
                    serde_json::json!({"error": "token_exchange_failed", "message": e.to_string()}),
                ),
            )
                .into_response();
        }
    };

    // Verify ID token signature before accepting claims
    if let Some(id_token) = token_resp.get("id_token").and_then(|v| v.as_str()) {
        let client_id_str = client_id.as_str();
        if let Err(e) =
            verify_inbound_idp_token(id_token, &provider, &provider.issuer, client_id_str)
        {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "id_token_verification_failed", "message": e.to_string()})),
            )
                .into_response();
        }
    }

    let claims = match extract_claims_from_oidc_response(
        &token_resp,
        provider.userinfo_url.as_deref(),
        &provider.issuer,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "claim_extraction_failed", "message": e.to_string()})),
            )
                .into_response();
        }
    };

    let login_plan = match plan_broker_login(
        state.repo.as_ref(),
        &realm,
        &provider.id,
        &providers,
        &request,
        &claims,
    )
    .await
    {
        Ok(plan) => plan,
        Err(error) => return broker_login_plan_error_response(error),
    };

    let local_user_id = exec_broker_login_plan(
        state.repo.as_ref(),
        &realm,
        &provider.id,
        &claims,
        &login_plan,
    )
    .await;

    match local_user_id {
        Ok(uid) => Json(serde_json::json!({
            "status": "linked",
            "provider": provider.id,
            "claims": claims,
            "local_user_id": uid,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "login_plan_execution_failed", "message": e.to_string()})),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, header};
    use http_body_util::BodyExt;
    use qid_core::tenant::RealmId;
    use serde_json::Value;

    use super::super::transaction::test_support as tx_test;

    fn callback_headers(cookie: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(cookie) = cookie {
            headers.insert(header::COOKIE, cookie.parse().unwrap());
        }
        headers
    }

    async fn callback(
        state: &Arc<SharedState<qid_storage::FileRepository>>,
        provider_name: &str,
        proof: Option<&str>,
        cookie: Option<&str>,
    ) -> (StatusCode, Value) {
        callback_with_iss(state, provider_name, proof, cookie, None).await
    }

    async fn callback_with_iss(
        state: &Arc<SharedState<qid_storage::FileRepository>>,
        provider_name: &str,
        proof: Option<&str>,
        cookie: Option<&str>,
        issuer: Option<&str>,
    ) -> (StatusCode, Value) {
        let response = social_login_callback(
            State(state.clone()),
            Path(("test".to_string(), provider_name.to_string())),
            Query(OidcCallbackQuery {
                code: "provider-code".to_string(),
                state: proof.map(str::to_string),
                iss: issuer.map(str::to_string),
            }),
            callback_headers(cookie),
        )
        .await;
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn social_callback_completes_with_a_valid_transaction_and_spends_it() {
        let (base_url, server) = tx_test::provider_stub().await;
        let fixture = tx_test::fixture("corp-social", "social", &base_url).await;
        let (proof, cookie) =
            tx_test::issue_transaction(&fixture.state, "test", "corp-social").await;

        let (status, body) = callback(&fixture.state, "google", Some(&proof), Some(&cookie)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "linked");
        assert_eq!(body["provider"], "corp-social");

        let realm = RealmId("test".to_string());
        assert_eq!(fixture.repo.list_users(&realm).await.unwrap().len(), 1);
        assert!(
            fixture
                .repo
                .get_ciam_identity_link_by_external_subject(&realm, "corp-social", "user-123")
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            fixture
                .repo
                .list_audit_events(Some(&realm), 100)
                .await
                .unwrap()
                .len(),
            2
        );

        let (status, body) = callback(&fixture.state, "google", Some(&proof), Some(&cookie)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_transaction");
        assert_eq!(fixture.repo.list_users(&realm).await.unwrap().len(), 1);

        server.abort();
    }

    #[tokio::test]
    async fn social_callback_rejects_proof_failures_before_identity_effects() {
        let (base_url, server) = tx_test::provider_stub().await;
        let fixture =
            tx_test::fixture_with_providers(&["corp-social", "other-social"], "social", &base_url)
                .await;
        let (proof, cookie) =
            tx_test::issue_transaction(&fixture.state, "test", "corp-social").await;
        let (other_proof, other_cookie) =
            tx_test::issue_transaction(&fixture.state, "test", "other-social").await;

        let cases: Vec<(Option<&str>, Option<&str>, &str)> = vec![
            (None, Some(&cookie), "invalid_transaction"),
            (Some(""), Some(&cookie), "invalid_transaction"),
            (Some(&proof), None, "invalid_transaction"),
            (
                Some(&proof),
                Some("__Host-qid-federation-tx=foreign-secret"),
                "invalid_transaction",
            ),
            (
                Some(&other_proof),
                Some(&other_cookie),
                "invalid_transaction",
            ),
        ];
        for (proof, cookie, expected_error) in cases {
            let (status, body) = callback(&fixture.state, "google", proof, cookie).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(body["error"], expected_error);
        }
        tx_test::assert_no_identity_effects(&fixture, "corp-social").await;
        tx_test::assert_no_identity_effects(&fixture, "other-social").await;

        server.abort();
    }

    #[tokio::test]
    async fn social_callback_uses_transaction_provider_when_providers_share_an_alias() {
        let (base_url, server) = tx_test::provider_stub().await;
        let fixture = tx_test::fixture_with_social_alias_and_issuers(
            &["corp-social", "other-social"],
            "google",
            &[
                "https://corp-social.example",
                "https://other-social.example",
            ],
            &base_url,
        )
        .await;
        let realm = RealmId("test".to_string());

        // The transaction names the unconfigured provider: fail before exchange.
        let (proof, cookie) =
            tx_test::issue_transaction(&fixture.state, "test", "other-social").await;
        let (status, body) = callback_with_iss(
            &fixture.state,
            "google",
            Some(&proof),
            Some(&cookie),
            Some("https://other-social.example"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "client_id_not_configured");
        tx_test::assert_no_identity_effects(&fixture, "corp-social").await;
        tx_test::assert_no_identity_effects(&fixture, "other-social").await;

        // The transaction names the configured provider: complete against it.
        let (proof, cookie) =
            tx_test::issue_transaction(&fixture.state, "test", "corp-social").await;
        let (status, body) = callback_with_iss(
            &fixture.state,
            "google",
            Some(&proof),
            Some(&cookie),
            Some("https://corp-social.example"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["provider"], "corp-social");
        assert_eq!(fixture.repo.list_users(&realm).await.unwrap().len(), 1);
        assert!(
            fixture
                .repo
                .get_ciam_identity_link_by_external_subject(&realm, "corp-social", "user-123")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            fixture
                .repo
                .get_ciam_identity_link_by_external_subject(&realm, "other-social", "user-123")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            fixture
                .repo
                .list_audit_events(Some(&realm), 100)
                .await
                .unwrap()
                .len(),
            2
        );

        server.abort();
    }

    #[tokio::test]
    async fn social_callback_requires_matching_issuer_for_a_shared_alias() {
        let (base_url, server) = tx_test::provider_stub().await;
        let fixture = tx_test::fixture_with_social_alias(
            &["corp-social", "other-social"],
            "google",
            &base_url,
        )
        .await;

        for (issuer, message) in [
            (None, "authorization response issuer required"),
            (
                Some("https://other.example"),
                "authorization response issuer mismatch",
            ),
        ] {
            let (proof, cookie) =
                tx_test::issue_transaction(&fixture.state, "test", "corp-social").await;
            let (status, body) = callback_with_iss(
                &fixture.state,
                "google",
                Some(&proof),
                Some(&cookie),
                issuer,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(body["error"].as_str().unwrap().contains(message), "{body}");
        }
        tx_test::assert_no_identity_effects(&fixture, "corp-social").await;
        tx_test::assert_no_identity_effects(&fixture, "other-social").await;

        server.abort();
    }

    #[tokio::test]
    async fn social_callback_accepts_canonical_provider_id_path() {
        let (base_url, server) = tx_test::provider_stub().await;
        let fixture =
            tx_test::fixture_with_social_alias(&["corp-social"], "google", &base_url).await;
        let (proof, cookie) =
            tx_test::issue_transaction(&fixture.state, "test", "corp-social").await;

        // The canonical id is an alternative to the configured alias in the path.
        let (status, body) =
            callback(&fixture.state, "corp-social", Some(&proof), Some(&cookie)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["provider"], "corp-social");
        let realm = RealmId("test".to_string());
        assert_eq!(fixture.repo.list_users(&realm).await.unwrap().len(), 1);
        assert!(
            fixture
                .repo
                .get_ciam_identity_link_by_external_subject(&realm, "corp-social", "user-123")
                .await
                .unwrap()
                .is_some()
        );

        server.abort();
    }

    #[tokio::test]
    async fn social_callback_shared_alias_without_issuer_rejects_alias_path() {
        let (base_url, server) = tx_test::provider_stub().await;
        let fixture = tx_test::fixture_with_social_alias(
            &["corp-social", "other-social"],
            "google",
            &base_url,
        )
        .await;
        let (proof, cookie) =
            tx_test::issue_transaction(&fixture.state, "test", "corp-social").await;

        let (status, body) = callback(&fixture.state, "google", Some(&proof), Some(&cookie)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("authorization response issuer required"),
            "{body}"
        );
        tx_test::assert_no_identity_effects(&fixture, "corp-social").await;
        tx_test::assert_no_identity_effects(&fixture, "other-social").await;

        server.abort();
    }

    #[tokio::test]
    async fn social_callback_shared_alias_without_issuer_completes_via_canonical_id_path() {
        let (base_url, server) = tx_test::provider_stub().await;
        let fixture = tx_test::fixture_with_social_alias(
            &["corp-social", "other-social"],
            "google",
            &base_url,
        )
        .await;
        let (proof, cookie) =
            tx_test::issue_transaction(&fixture.state, "test", "corp-social").await;

        let (status, body) =
            callback(&fixture.state, "corp-social", Some(&proof), Some(&cookie)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["provider"], "corp-social");
        let realm = RealmId("test".to_string());
        assert_eq!(fixture.repo.list_users(&realm).await.unwrap().len(), 1);
        assert!(
            fixture
                .repo
                .get_ciam_identity_link_by_external_subject(&realm, "corp-social", "user-123")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            fixture
                .repo
                .get_ciam_identity_link_by_external_subject(&realm, "other-social", "user-123")
                .await
                .unwrap()
                .is_none()
        );

        server.abort();
    }
}
