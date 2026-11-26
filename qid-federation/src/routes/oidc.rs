use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use qid_core::{QidError, state::SharedState};
use qid_storage::prelude::*;
use std::sync::Arc;

use crate::{
    ExternalIdentityClaims, HomeRealmDiscoveryRequest, InboundProviderKind,
    verify_inbound_idp_token,
};

use super::{
    OidcCallbackQuery, authorization_response_iss_supported, broker_login_plan_error_response,
    exec_broker_login_plan, plan_broker_login, providers_from_config, transaction,
    verify_authorization_response_issuer,
};

/// Exchange an authorization code for tokens at the external provider's token endpoint.
pub async fn exchange_code_for_tokens(
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<serde_json::Value, QidError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|error| QidError::Internal {
            message: format!("OIDC HTTP client initialization failed: {error}"),
        })?;
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("client_secret", client_secret),
    ];
    let resp = client
        .post(token_url)
        .form(&params)
        .send()
        .await
        .map_err(|e| QidError::BadRequest {
            message: format!("token exchange request failed: {e}"),
        })?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.map_err(|e| QidError::BadRequest {
        message: format!("token exchange response parse failed: {e}"),
    })?;
    if !status.is_success() {
        return Err(QidError::BadRequest {
            message: format!(
                "token exchange returned {status}: {}",
                body.get("error_description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown error")
            ),
        });
    }
    Ok(body)
}

/// Fetch user claims from the userinfo endpoint using an access token.
pub async fn fetch_userinfo(
    userinfo_url: &str,
    access_token: &str,
) -> Result<serde_json::Value, QidError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|error| QidError::Internal {
            message: format!("OIDC HTTP client initialization failed: {error}"),
        })?;
    let resp = client
        .get(userinfo_url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| QidError::BadRequest {
            message: format!("userinfo request failed: {e}"),
        })?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.map_err(|e| QidError::BadRequest {
        message: format!("userinfo response parse failed: {e}"),
    })?;
    if !status.is_success() {
        return Err(QidError::BadRequest {
            message: format!("userinfo returned {status}"),
        });
    }
    Ok(body)
}

/// Extract ExternalIdentityClaims from an OIDC token response.
/// Tries the ID token first, falls back to the userinfo endpoint.
pub async fn extract_claims_from_oidc_response(
    token_response: &serde_json::Value,
    userinfo_url: Option<&str>,
    expected_issuer: &str,
) -> Result<ExternalIdentityClaims, QidError> {
    // Try to decode ID token first (JWT without signature verification for
    // claim extraction — the provider is already trusted by configuration).
    if let Some(id_token) = token_response.get("id_token").and_then(|v| v.as_str()) {
        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() == 3
            && let Ok(payload) = util::decode_base64url(parts[1])
            && let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&payload)
        {
            let sub = extract_oidc_subject(&claims, "ID token")?;
            let mut map = std::collections::BTreeMap::new();
            if let Some(obj) = claims.as_object() {
                for (k, v) in obj {
                    map.insert(k.clone(), v.clone());
                }
            }
            return Ok(ExternalIdentityClaims {
                issuer: expected_issuer.to_string(),
                subject: sub,
                claims: map,
            });
        }
    }

    // Fallback: use access token to call userinfo
    let access_token = token_response
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| QidError::BadRequest {
            message: "token response missing access_token".to_string(),
        })?;

    let userinfo_url = userinfo_url.ok_or_else(|| QidError::BadRequest {
        message: "userinfo_url required when ID token is not available".to_string(),
    })?;

    let userinfo = fetch_userinfo(userinfo_url, access_token).await?;
    let sub = extract_oidc_subject(&userinfo, "userinfo")?;
    let mut map = std::collections::BTreeMap::new();
    if let Some(obj) = userinfo.as_object() {
        for (k, v) in obj {
            map.insert(k.clone(), v.clone());
        }
    }
    Ok(ExternalIdentityClaims {
        issuer: expected_issuer.to_string(),
        subject: sub,
        claims: map,
    })
}

/// Require a non-empty string subject before any link lookup or persistence.
/// Missing, non-string, and empty `sub` values fail closed instead of
/// collapsing distinct provider responses onto one shared identity.
fn extract_oidc_subject(source: &serde_json::Value, context: &str) -> Result<String, QidError> {
    match source.get("sub").and_then(|v| v.as_str()) {
        Some(sub) if !sub.is_empty() => Ok(sub.to_string()),
        _ => Err(QidError::BadRequest {
            message: format!("OIDC {context} subject (sub) must be a non-empty string"),
        }),
    }
}

mod util {
    /// Decode a URL-safe base64 string without padding validation.
    pub fn decode_base64url(input: &str) -> Result<Vec<u8>, ()> {
        use base64::Engine;
        let padded = match input.len() % 4 {
            2 => format!("{input}=="),
            3 => format!("{input}="),
            _ => input.to_string(),
        };
        base64::engine::general_purpose::URL_SAFE
            .decode(padded.as_bytes())
            .map_err(|_| ())
    }
}

/// Shared callback: the verified proof selects the provider.
pub async fn oidc_inbound_callback<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    Query(params): Query<OidcCallbackQuery>,
    headers: HeaderMap,
) -> Response {
    oidc_inbound_callback_inner(state, realm, params, headers, None).await
}

/// Provider-specific callback: the path is an alternative issuer binding for
/// upstreams that omit the front-channel `iss`.
pub async fn oidc_inbound_callback_for_provider<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path((realm, provider)): Path<(String, String)>,
    Query(params): Query<OidcCallbackQuery>,
    headers: HeaderMap,
) -> Response {
    oidc_inbound_callback_inner(state, realm, params, headers, Some(&provider)).await
}

async fn oidc_inbound_callback_inner<R: Repository>(
    state: Arc<SharedState<R>>,
    realm: String,
    params: OidcCallbackQuery,
    headers: HeaderMap,
    path_provider: Option<&str>,
) -> Response {
    // Spend the browser-bound proof before token exchange, lookups or writes.
    let proof = match transaction::verify(&state, &headers, &realm, params.state.as_deref(), None) {
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

    // The verified proof, not the raw state parameter, selects the provider.
    let provider_id = proof.provider.as_str();
    let provider = match providers.iter().find(|p| p.id == provider_id && p.enabled) {
        Some(p) => p.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "provider_not_found",
                    "message": format!("provider {provider_id} not found")
                })),
            )
                .into_response();
        }
    };

    // Bind the upstream response to the provider selected by the verified proof
    // before any credential lookup, exchange, claim extraction or identity write.
    if let Some(path) = path_provider.filter(|path| *path != provider.id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "provider_mismatch",
                "message": format!("provider {provider_id} does not match callback {path}")
            })),
        )
            .into_response();
    }
    let ambiguous_target = providers
        .iter()
        .filter(|p| p.enabled && p.kind == InboundProviderKind::Oidc)
        .count()
        > 1;
    let supported = authorization_response_iss_supported(
        &realm_config.protocols.federation.inbound_providers,
        &provider.id,
    );
    if let Err(error) = verify_authorization_response_issuer(
        params.iss.as_deref(),
        &provider.issuer,
        // A matching provider-specific path binds the response when `iss` is absent.
        ambiguous_target && path_provider.is_none(),
        supported,
    ) {
        return error.into_response();
    }

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

    let callback_path = match path_provider {
        Some(provider) => format!("oidc/{}", urlencoding::encode(provider)),
        None => "oidc".to_string(),
    };
    let redirect_uri = format!(
        "{}/federation/{}/{}/callback",
        state.plan.public_base_url.trim_end_matches('/'),
        urlencoding::encode(&realm),
        callback_path
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
        &HomeRealmDiscoveryRequest {
            login_hint: None,
            domain: None,
            idp_hint: Some(provider.id.clone()),
            social_provider: None,
        },
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
            "provider_kind": provider.kind.as_str(),
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
        proof: Option<&str>,
        cookie: Option<&str>,
    ) -> (StatusCode, Value) {
        callback_with_iss(state, proof, cookie, None).await
    }

    async fn callback_with_iss(
        state: &Arc<SharedState<qid_storage::FileRepository>>,
        proof: Option<&str>,
        cookie: Option<&str>,
        issuer: Option<&str>,
    ) -> (StatusCode, Value) {
        let response = oidc_inbound_callback(
            State(state.clone()),
            Path("test".to_string()),
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

    /// Drive the registered route so the new callback path is covered too.
    async fn routed_callback(
        state: &Arc<SharedState<qid_storage::FileRepository>>,
        path: &str,
        proof: Option<&str>,
        cookie: Option<&str>,
        issuer: Option<&str>,
    ) -> (StatusCode, Value) {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;

        let mut uri = format!("/federation/test{path}?code=provider-code");
        if let Some(proof) = proof {
            uri.push_str(&format!("&state={}", urlencoding::encode(proof)));
        }
        if let Some(issuer) = issuer {
            uri.push_str(&format!("&iss={}", urlencoding::encode(issuer)));
        }
        let mut request = Request::builder().uri(uri);
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        let app = super::super::federation_routes::<qid_storage::FileRepository>()
            .with_state(state.clone());
        let response = app
            .oneshot(request.body(Body::empty()).expect("request"))
            .await
            .expect("route response");
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn oidc_callback_completes_with_a_valid_transaction_and_spends_it() {
        let (base_url, server) = tx_test::provider_stub().await;
        let fixture = tx_test::fixture("corp-oidc", "oidc", &base_url).await;
        let (proof, cookie) = tx_test::issue_transaction(&fixture.state, "test", "corp-oidc").await;

        let (status, body) = callback(&fixture.state, Some(&proof), Some(&cookie)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "linked");
        assert_eq!(body["provider"], "corp-oidc");

        let realm = RealmId("test".to_string());
        let users = fixture.repo.list_users(&realm).await.unwrap();
        assert_eq!(users.len(), 1);
        assert!(
            fixture
                .repo
                .get_ciam_identity_link_by_external_subject(&realm, "corp-oidc", "user-123")
                .await
                .unwrap()
                .is_some()
        );
        let audit = fixture
            .repo
            .list_audit_events(Some(&realm), 100)
            .await
            .unwrap();
        assert_eq!(audit.len(), 2);

        let (status, body) = callback(&fixture.state, Some(&proof), Some(&cookie)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_transaction");
        assert_eq!(fixture.repo.list_users(&realm).await.unwrap().len(), 1);
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
    async fn oidc_callback_rejects_proof_failures_before_identity_effects() {
        let (base_url, server) = tx_test::provider_stub().await;
        let fixture =
            tx_test::fixture_with_providers(&["corp-oidc", "other-oidc"], "oidc", &base_url).await;
        let (proof, cookie) = tx_test::issue_transaction(&fixture.state, "test", "corp-oidc").await;
        let (other_proof, other_cookie) =
            tx_test::issue_transaction(&fixture.state, "test", "other-oidc").await;

        struct ProofCase<'a> {
            proof: Option<&'a str>,
            cookie: Option<&'a str>,
            issuer: Option<&'a str>,
            expected_error: &'a str,
        }
        let cases = [
            ProofCase {
                proof: None,
                cookie: Some(&cookie),
                issuer: None,
                expected_error: "invalid_transaction",
            },
            ProofCase {
                proof: Some(""),
                cookie: Some(&cookie),
                issuer: None,
                expected_error: "invalid_transaction",
            },
            ProofCase {
                proof: Some(&proof),
                cookie: None,
                issuer: None,
                expected_error: "invalid_transaction",
            },
            ProofCase {
                proof: Some(&proof),
                cookie: Some("__Host-qid-federation-tx=foreign-secret"),
                issuer: None,
                expected_error: "invalid_transaction",
            },
            // A valid proof for another configured provider selects that provider,
            // whose missing client configuration stops the exchange before writes.
            ProofCase {
                proof: Some(&other_proof),
                cookie: Some(&other_cookie),
                issuer: Some("https://provider.example.com"),
                expected_error: "client_id_not_configured",
            },
        ];
        for case in cases {
            let (status, body) =
                callback_with_iss(&fixture.state, case.proof, case.cookie, case.issuer).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(body["error"], case.expected_error);
        }
        tx_test::assert_no_identity_effects(&fixture, "corp-oidc").await;
        tx_test::assert_no_identity_effects(&fixture, "other-oidc").await;

        server.abort();
    }

    #[tokio::test]
    async fn oidc_callback_rejects_issuer_mismatch_before_identity_effects() {
        let (base_url, server) = tx_test::provider_stub().await;
        let fixture = tx_test::fixture("corp-oidc", "oidc", &base_url).await;
        let (proof, cookie) = tx_test::issue_transaction(&fixture.state, "test", "corp-oidc").await;

        let (status, body) = callback_with_iss(
            &fixture.state,
            Some(&proof),
            Some(&cookie),
            Some("https://other.example"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("authorization response issuer mismatch"),
            "{body}"
        );
        tx_test::assert_no_identity_effects(&fixture, "corp-oidc").await;

        // A fresh proof with the exact configured issuer still completes.
        let (proof, cookie) = tx_test::issue_transaction(&fixture.state, "test", "corp-oidc").await;
        let (status, body) = callback_with_iss(
            &fixture.state,
            Some(&proof),
            Some(&cookie),
            Some("https://provider.example.com"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["provider"], "corp-oidc");

        server.abort();
    }

    #[tokio::test]
    async fn oidc_callback_requires_iss_for_provider_advertising_rfc9207() {
        let (base_url, server) = tx_test::provider_stub().await;
        let fixture =
            tx_test::fixture_with_issuer_support("corp-oidc", "oidc", &base_url, true).await;

        let (proof, cookie) = tx_test::issue_transaction(&fixture.state, "test", "corp-oidc").await;
        let (status, body) =
            callback_with_iss(&fixture.state, Some(&proof), Some(&cookie), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("authorization response issuer required by provider configuration"),
            "{body}"
        );
        tx_test::assert_no_identity_effects(&fixture, "corp-oidc").await;

        let (proof, cookie) = tx_test::issue_transaction(&fixture.state, "test", "corp-oidc").await;
        let (status, body) = callback_with_iss(
            &fixture.state,
            Some(&proof),
            Some(&cookie),
            Some("https://provider.example.com"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["provider"], "corp-oidc");
        let realm = RealmId("test".to_string());
        assert_eq!(fixture.repo.list_users(&realm).await.unwrap().len(), 1);
        assert!(
            fixture
                .repo
                .get_ciam_identity_link_by_external_subject(&realm, "corp-oidc", "user-123")
                .await
                .unwrap()
                .is_some()
        );

        server.abort();
    }

    #[tokio::test]
    async fn oidc_callback_requires_matching_issuer_for_a_shared_target() {
        let (base_url, server) = tx_test::provider_stub().await;
        let fixture = tx_test::fixture_with_issuers(
            &["corp-oidc", "other-oidc"],
            &["https://corp.example", "https://other.example"],
            "oidc",
            &base_url,
        )
        .await;

        let (proof, cookie) = tx_test::issue_transaction(&fixture.state, "test", "corp-oidc").await;
        let (status, body) = callback(&fixture.state, Some(&proof), Some(&cookie)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("authorization response issuer required"),
            "{body}"
        );
        tx_test::assert_no_identity_effects(&fixture, "corp-oidc").await;
        tx_test::assert_no_identity_effects(&fixture, "other-oidc").await;

        // Another provider's issuer is not accepted for the selected provider.
        let (proof, cookie) = tx_test::issue_transaction(&fixture.state, "test", "corp-oidc").await;
        let (status, body) = callback_with_iss(
            &fixture.state,
            Some(&proof),
            Some(&cookie),
            Some("https://other.example"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("authorization response issuer mismatch"),
            "{body}"
        );
        tx_test::assert_no_identity_effects(&fixture, "corp-oidc").await;

        // The selected provider's issuer binds correctly and completes.
        let (proof, cookie) = tx_test::issue_transaction(&fixture.state, "test", "corp-oidc").await;
        let (status, body) = callback_with_iss(
            &fixture.state,
            Some(&proof),
            Some(&cookie),
            Some("https://corp.example"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["provider"], "corp-oidc");

        server.abort();
    }

    #[tokio::test]
    async fn oidc_callback_shared_target_without_issuer_is_rejected_before_exchange() {
        let (base_url, server) = tx_test::provider_stub().await;
        let fixture = tx_test::fixture_with_issuers(
            &["corp-oidc", "other-oidc"],
            &["https://corp.example", "https://other.example"],
            "oidc",
            &base_url,
        )
        .await;
        let (proof, cookie) = tx_test::issue_transaction(&fixture.state, "test", "corp-oidc").await;

        let (status, body) = routed_callback(
            &fixture.state,
            "/oidc/callback",
            Some(&proof),
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("authorization response issuer required"),
            "{body}"
        );
        tx_test::assert_no_identity_effects(&fixture, "corp-oidc").await;
        tx_test::assert_no_identity_effects(&fixture, "other-oidc").await;

        server.abort();
    }

    #[tokio::test]
    async fn oidc_callback_provider_path_without_issuer_completes_for_selected_provider() {
        let (base_url, server) = tx_test::provider_stub().await;
        let fixture = tx_test::fixture_with_issuers(
            &["corp-oidc", "other-oidc"],
            &["https://corp.example", "https://other.example"],
            "oidc",
            &base_url,
        )
        .await;
        let (proof, cookie) = tx_test::issue_transaction(&fixture.state, "test", "corp-oidc").await;

        let (status, body) = routed_callback(
            &fixture.state,
            "/oidc/corp-oidc/callback",
            Some(&proof),
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "linked");
        assert_eq!(body["provider"], "corp-oidc");

        let realm = qid_core::tenant::RealmId("test".to_string());
        assert_eq!(fixture.repo.list_users(&realm).await.unwrap().len(), 1);
        assert!(
            fixture
                .repo
                .get_ciam_identity_link_by_external_subject(&realm, "corp-oidc", "user-123")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            fixture
                .repo
                .get_ciam_identity_link_by_external_subject(&realm, "other-oidc", "user-123")
                .await
                .unwrap()
                .is_none()
        );

        server.abort();
    }

    #[tokio::test]
    async fn oidc_callback_provider_path_for_another_provider_rejects_before_exchange() {
        let (base_url, server) = tx_test::provider_stub().await;
        let fixture = tx_test::fixture_with_issuers(
            &["corp-oidc", "other-oidc"],
            &["https://corp.example", "https://other.example"],
            "oidc",
            &base_url,
        )
        .await;
        let (proof, cookie) = tx_test::issue_transaction(&fixture.state, "test", "corp-oidc").await;

        let (status, body) = routed_callback(
            &fixture.state,
            "/oidc/other-oidc/callback",
            Some(&proof),
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "provider_mismatch");
        tx_test::assert_no_identity_effects(&fixture, "corp-oidc").await;
        tx_test::assert_no_identity_effects(&fixture, "other-oidc").await;

        // A matching path still requires an exact issuer when one is supplied.
        let (proof, cookie) = tx_test::issue_transaction(&fixture.state, "test", "corp-oidc").await;
        let (status, body) = routed_callback(
            &fixture.state,
            "/oidc/corp-oidc/callback",
            Some(&proof),
            Some(&cookie),
            Some("https://other.example"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("authorization response issuer mismatch"),
            "{body}"
        );
        tx_test::assert_no_identity_effects(&fixture, "corp-oidc").await;

        server.abort();
    }

    fn id_token_response(sub_json: &str) -> serde_json::Value {
        use base64::Engine;
        let body = if sub_json.is_empty() {
            "\"iss\":\"https://provider.example.com\"".to_string()
        } else {
            format!("\"iss\":\"https://provider.example.com\",{sub_json}")
        };
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{{{body}}}"));
        serde_json::json!({ "id_token": format!("header.{payload}.signature") })
    }

    #[tokio::test]
    async fn oidc_rejects_missing_non_string_and_empty_subjects() {
        for (name, sub_json) in [
            ("missing", ""),
            ("non-string", "\"sub\":123"),
            ("empty", "\"sub\":\"\""),
        ] {
            let response = id_token_response(sub_json);
            let err =
                extract_claims_from_oidc_response(&response, None, "https://provider.example.com")
                    .await
                    .unwrap_err();
            assert!(
                err.message().contains("subject (sub)"),
                "{name} subject must fail closed"
            );
        }
    }

    #[tokio::test]
    async fn oidc_accepts_valid_subject() {
        let response = id_token_response("\"sub\":\"user-123\"");
        let claims =
            extract_claims_from_oidc_response(&response, None, "https://provider.example.com")
                .await
                .expect("valid subject must extract");
        assert_eq!(claims.subject, "user-123");
    }
}
