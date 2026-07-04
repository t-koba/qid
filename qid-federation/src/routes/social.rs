use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use qid_core::state::SharedState;
use qid_storage::prelude::*;
use std::sync::Arc;

use crate::{
    HomeRealmDiscoveryRequest, plan_inbound_login, route_inbound_provider, verify_inbound_idp_token,
};

use super::oidc::{exchange_code_for_tokens, extract_claims_from_oidc_response};
use super::{OidcCallbackQuery, exec_broker_login_plan, load_broker_links, providers_from_config};

pub async fn social_login_callback<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path((realm, provider_name)): Path<(String, String)>,
    Query(params): Query<OidcCallbackQuery>,
) -> Response {
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

    let request = HomeRealmDiscoveryRequest {
        login_hint: None,
        domain: None,
        idp_hint: None,
        social_provider: Some(provider_name.clone()),
    };

    let route = match route_inbound_provider(&providers, &request) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "provider_routing_failed", "message": e.to_string()})),
            )
                .into_response();
        }
    };

    let provider = match providers.iter().find(|p| p.id == route.provider_id) {
        Some(p) => p.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "provider_not_found"})),
            )
                .into_response();
        }
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

    let links = load_broker_links(state.repo.as_ref(), &realm, &provider.id, &claims).await;

    let login_plan = match plan_inbound_login(&providers, &request, &claims, &links) {
        Ok(plan) => plan,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "login_plan_failed", "message": e.to_string()})),
            )
                .into_response();
        }
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
