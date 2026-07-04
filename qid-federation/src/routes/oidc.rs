use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use qid_core::{QidError, state::SharedState};
use qid_storage::prelude::*;
use std::sync::Arc;

use crate::{
    ExternalIdentityClaims, HomeRealmDiscoveryRequest, plan_inbound_login, verify_inbound_idp_token,
};

use super::{OidcCallbackQuery, exec_broker_login_plan, load_broker_links, providers_from_config};

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
        .expect("reqwest client build");
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
        .expect("reqwest client build");
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
            let sub = claims
                .get("sub")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
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
    let sub = userinfo
        .get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
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

pub async fn oidc_inbound_callback<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
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

    // Use state parameter to identify the provider
    let provider_id = params.state.as_deref().unwrap_or("");
    let provider = match providers.iter().find(|p| p.id == provider_id) {
        Some(p) => p.clone(),
        None => {
            let msg = if provider_id.is_empty() {
                "no provider identifier in state parameter".to_string()
            } else {
                format!("provider {provider_id} not found")
            };
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "provider_not_found", "message": msg})),
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
        "{}/federation/{}/oidc/callback",
        state.plan.public_base_url.trim_end_matches('/'),
        urlencoding::encode(&realm)
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

    let login_plan = match plan_inbound_login(
        &providers,
        &HomeRealmDiscoveryRequest {
            login_hint: None,
            domain: None,
            idp_hint: Some(provider.id.clone()),
            social_provider: None,
        },
        &claims,
        &links,
    ) {
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
