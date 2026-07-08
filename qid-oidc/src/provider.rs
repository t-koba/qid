//! OIDC Provider core logic.

use base64::Engine;

use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Redirect, Response},
};
use qid_core::{
    error::{QidError, QidResult},
    jwt::JwtClaims,
    models::{AuthorizationCode, Client},
    state::SharedState,
    tenant::RealmId,
};
use qid_crypto::{Jwk, jwt::verify_jwt_signature_with_jwk};

use qid_session::{auth::Authenticator, session_is_active};
use qid_storage::prelude::*;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    pub request: Option<String>,
    pub client_id: Option<String>,
    pub response_type: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub response_mode: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub resource: Option<String>,
    pub authorization_details: Option<serde_json::Value>,
    pub nonce: Option<String>,
    pub prompt: Option<String>,
    pub request_uri: Option<String>,
    pub max_age: Option<u64>,
    /// OIDC acr_values parameter (space-separated list of ACR values).
    pub acr_values: Option<String>,
    /// OIDC claims parameter (JSON). Used to extract essential acr.
    pub claims: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuthorizeParameters {
    client_id: String,
    response_type: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    response_mode: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    resource: Option<String>,
    authorization_details: Option<serde_json::Value>,
    nonce: Option<String>,
    prompt: Option<String>,
    /// DPoP proof JWT (RFC 9449) extracted from the `DPoP` HTTP
    /// header on the original authorization request. Carried
    /// through the call chain so the JARM response can embed the
    /// matching `apv` JWK thumbprint per FAPI 2.0 Message Signing.
    #[serde(default)]
    pub dpop_proof: Option<String>,
    request_uri: Option<String>,
    max_age: Option<u64>,
    acr_values: Option<String>,
    claims: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub email: String,
    pub password: String,
}

/// Handle GET /oauth2/authorize by rendering a login challenge.
pub async fn authorize_get<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Query(req): Query<AuthorizeRequest>,
) -> Response {
    let dpop_proof = headers
        .get("dpop")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    match resolve_and_validate_authorize_request(&state, &req, false).await {
        Ok((mut resolved, client)) => {
            resolved.dpop_proof = dpop_proof;
            if !prompt_requires_login(resolved.prompt.as_deref()) {
                match authorize_with_browser_session(&state, &headers, &mut resolved, &client).await
                {
                    Ok(Some(response)) => {
                        if let Some(request_uri) = resolved.request_uri.as_deref()
                            && let Err(e) = state.repo.mark_par_request_used(request_uri).await
                        {
                            return qid_http::error_response(e);
                        }
                        return response;
                    }
                    Ok(None) => {}
                    Err(e) => return qid_http::error_response(e),
                }
            }
            login_challenge_response(resolved)
        }
        Err(e) => qid_http::error_response(e),
    }
}

async fn authorize_with_browser_session<R: Repository>(
    state: &SharedState<R>,
    headers: &HeaderMap,
    resolved: &mut AuthorizeParameters,
    client: &Client,
) -> QidResult<Option<Response>> {
    let realm = state
        .realm(&client.realm_id)
        .ok_or_else(|| QidError::NotFound {
            resource: format!("realm {}", client.realm_id),
        })?;
    let Some(session_id) = headers
        .get(header::COOKIE)
        .and_then(|cookie| cookie.to_str().ok())
        .and_then(|cookie| parse_cookie(cookie, &realm.browser_session.cookie_name))
    else {
        return Ok(None);
    };

    let Some(session) = state.repo.get_session(&session_id).await? else {
        return Ok(None);
    };
    let now = qid_core::util::now_seconds();
    if session.realm_id != client.realm_id || !session_is_active(&session, now) {
        return Ok(None);
    }
    // max_age: re-authenticate if session exceeds the requested max age
    if let Some(max_age) = resolved.max_age
        && (max_age == 0 || session.auth_time + max_age <= now)
    {
        return Ok(None);
    }
    let Some(user) = state.repo.get_user_by_id(&session.user_id).await? else {
        return Ok(None);
    };

    if let Some(request_uri) = &resolved.request_uri {
        state.repo.mark_par_request_used(request_uri).await?;
    }

    let auth_result = qid_session::auth::AuthResult {
        user,
        acr: session
            .acr
            .clone()
            .unwrap_or_else(|| "urn:qid:acr:password".to_string()),
        amr: if session.amr.is_empty() {
            vec!["pwd".to_string()]
        } else {
            session.amr.clone()
        },
    };
    let code =
        issue_authorization_code(state, client, &auth_result, session.auth_time, resolved).await?;
    Ok(Some(
        authorization_response_redirect(
            state,
            resolved,
            client,
            &code,
            resolved.dpop_proof.as_deref(),
        )
        .await?,
    ))
}

fn login_challenge_response(resolved: AuthorizeParameters) -> Response {
    let mut body = serde_json::json!({
        "challenge": "login_required",
        "client_id": resolved.client_id,
        "redirect_uri": resolved.redirect_uri,
    });
    if let Some(state_param) = resolved.state {
        body["state"] = serde_json::Value::String(state_param);
    }
    (axum::http::StatusCode::OK, axum::Json(body)).into_response()
}

fn prompt_requires_login(prompt: Option<&str>) -> bool {
    prompt
        .map(|prompt| {
            prompt
                .split_ascii_whitespace()
                .any(|value| value == "login")
        })
        .unwrap_or(false)
}

fn parse_cookie(cookie_header: &str, name: &str) -> Option<String> {
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some((key, value)) = pair.split_once('=')
            && key.trim() == name
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// Handle POST /oauth2/authorize by accepting credentials and redirecting.
pub async fn authorize_post<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Query(req): Query<AuthorizeRequest>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let dpop_proof = headers
        .get("dpop")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let (mut resolved, client) =
        match resolve_and_validate_authorize_request(&state, &req, true).await {
            Ok(result) => result,
            Err(e) => return qid_http::error_response(e),
        };
    resolved.dpop_proof = dpop_proof;

    let authenticator = Authenticator::new(state.repo.clone());
    let auth_result = match authenticator
        .authenticate_password(
            &RealmId::from(client.realm_id.clone()),
            &form.email,
            &form.password,
        )
        .await
    {
        Ok(a) => a,
        Err(_) => {
            return authorization_error_response(
                &state,
                &resolved,
                &client,
                "access_denied",
                "invalid credentials",
            );
        }
    };

    // Check acr_values / essential acr claim against the session ACR
    let session_acr = auth_result.acr.as_str();
    if let Some(ref acr_values) = resolved.acr_values {
        let requested: Vec<&str> = acr_values.split_whitespace().collect();
        if !requested.is_empty() && !requested.contains(&session_acr) {
            let msg = format!(
                "requested acr_values {acr_values} does not match session ACR {session_acr}"
            );
            return authorization_error_response(
                &state,
                &resolved,
                &client,
                "unmet_authentication_requirements",
                &msg,
            );
        }
    }
    // Check claims parameter for essential acr
    if let Some(ref claims_json) = resolved.claims
        && let Ok(claims_value) = serde_json::from_str::<serde_json::Value>(claims_json)
        && let Some(acr_claim) = claims_value.pointer("/id_token/acr")
    {
        let essential = acr_claim
            .get("essential")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if essential && let Some(values) = acr_claim.get("values").and_then(|v| v.as_array()) {
            let values_str: Vec<&str> = values.iter().filter_map(|v| v.as_str()).collect();
            if !values_str.is_empty() && !values_str.contains(&session_acr) {
                let msg = format!(
                    "essential acr claim requires values {:?}, session ACR is {session_acr}",
                    values_str
                );
                return authorization_error_response(
                    &state,
                    &resolved,
                    &client,
                    "unmet_authentication_requirements",
                    &msg,
                );
            }
        }
    }

    let auth_time = qid_core::util::now_seconds();
    let code =
        match issue_authorization_code(&state, &client, &auth_result, auth_time, &resolved).await {
            Ok(c) => c,
            Err(e) => return qid_http::error_response(e),
        };

    match authorization_response_redirect(
        &state,
        &resolved,
        &client,
        &code,
        resolved.dpop_proof.as_deref(),
    )
    .await
    {
        Ok(response) => response,
        Err(e) => qid_http::error_response(e),
    }
}

async fn resolve_and_validate_authorize_request<R: Repository>(
    state: &SharedState<R>,
    req: &AuthorizeRequest,
    consume_par: bool,
) -> QidResult<(AuthorizeParameters, Client)> {
    let resolved = resolve_authorize_request(state, req, consume_par).await?;
    let client = validate_authorize_request(state, &resolved).await?;
    Ok((resolved, client))
}

async fn resolve_authorize_request<R: Repository>(
    state: &SharedState<R>,
    req: &AuthorizeRequest,
    consume_par: bool,
) -> QidResult<AuthorizeParameters> {
    let mut merged = AuthorizeParameters {
        client_id: req.client_id.clone().unwrap_or_default(),
        response_type: req.response_type.clone().unwrap_or_default(),
        redirect_uri: req.redirect_uri.clone().unwrap_or_default(),
        scope: req.scope.clone(),
        state: req.state.clone(),
        response_mode: req.response_mode.clone(),
        code_challenge: req.code_challenge.clone(),
        code_challenge_method: req.code_challenge_method.clone(),
        resource: req.resource.clone(),
        authorization_details: req.authorization_details.clone(),
        nonce: req.nonce.clone(),
        prompt: req.prompt.clone(),
        request_uri: req.request_uri.clone(),
        max_age: req.max_age,
        acr_values: req.acr_values.clone(),
        claims: req.claims.clone(),
        dpop_proof: None,
    };

    if let Some(request_object) = req.request.as_deref() {
        merge_request_object(state, &mut merged, request_object).await?;
    }

    // FAPI 2.0 Security Profile §5.2.3: when the realm requires a signed
    // request object, the request must carry the `request` parameter (or a
    // `request_uri` referencing a previously-pushed JAR) before the merged
    // parameters are accepted.
    if req.request.is_none()
        && req.request_uri.is_none()
        && realm_requires_signed_request_object(state, &req.client_id).await?
    {
        return Err(QidError::BadRequest {
            message: "signed request object is required for this realm".to_string(),
        });
    }

    if req.request_uri.is_none() {
        let realm_id = merged.client_id.as_str();
        let realm_config = state.config.realms.iter().find(|candidate| {
            candidate
                .protocols
                .oauth
                .resource_servers
                .iter()
                .any(|rs| rs.audience == realm_id)
                || candidate
                    .protocols
                    .oauth
                    .require_pushed_authorization_requests
        });
        if realm_config.is_some_and(|c| c.protocols.oauth.require_pushed_authorization_requests) {
            return Err(QidError::BadRequest {
                message: "pushed authorization request is required for this server".to_string(),
            });
        }
        require_authorize_fields(&merged)?;
        return Ok(merged);
    }
    let request_uri = req
        .request_uri
        .as_deref()
        .ok_or_else(|| QidError::BadRequest {
            message: "missing request_uri".to_string(),
        })?;
    if !request_uri.starts_with("urn:ietf:params:oauth:request_uri:") {
        return Err(QidError::BadRequest {
            message: "invalid request_uri".to_string(),
        });
    }
    let par = state
        .repo
        .get_par_request(request_uri)
        .await?
        .ok_or_else(|| QidError::Unauthorized {
            message: "unknown request_uri".to_string(),
        })?;
    let now = qid_core::util::now_seconds();
    if par.used {
        return Err(QidError::Unauthorized {
            message: "request_uri already used".to_string(),
        });
    }
    if par.expires_at <= now {
        return Err(QidError::Unauthorized {
            message: "request_uri expired".to_string(),
        });
    }
    let par_params: AuthorizeRequest =
        serde_json::from_value(par.params_json).map_err(|e| QidError::BadRequest {
            message: format!("invalid PAR payload: {e}"),
        })?;
    if let Some(request_object) = par_params.request.as_deref() {
        merge_request_object(state, &mut merged, request_object).await?;
    }
    merge_authorize_param(&mut merged.client_id, par_params.client_id, "client_id")?;
    merge_authorize_param(
        &mut merged.response_type,
        par_params.response_type,
        "response_type",
    )?;
    merge_authorize_param(
        &mut merged.redirect_uri,
        par_params.redirect_uri,
        "redirect_uri",
    )?;
    merge_optional_authorize_param(&mut merged.scope, par_params.scope, "scope")?;
    merge_optional_authorize_param(&mut merged.state, par_params.state, "state")?;
    merge_optional_authorize_param(
        &mut merged.response_mode,
        par_params.response_mode,
        "response_mode",
    )?;
    merge_optional_authorize_param(
        &mut merged.code_challenge,
        par_params.code_challenge,
        "code_challenge",
    )?;
    merge_optional_authorize_param(
        &mut merged.code_challenge_method,
        par_params.code_challenge_method,
        "code_challenge_method",
    )?;
    merge_optional_authorize_param(&mut merged.resource, par_params.resource, "resource")?;
    merge_optional_json_authorize_param(
        &mut merged.authorization_details,
        par_params.authorization_details,
        "authorization_details",
    )?;
    merge_optional_authorize_param(&mut merged.nonce, par_params.nonce, "nonce")?;
    merge_optional_authorize_param(&mut merged.prompt, par_params.prompt, "prompt")?;

    if merged.client_id != par.client_id {
        return Err(QidError::Unauthorized {
            message: "request_uri client mismatch".to_string(),
        });
    }

    require_authorize_fields(&merged)?;
    if consume_par {
        state.repo.mark_par_request_used(request_uri).await?;
    }
    Ok(merged)
}

async fn merge_request_object<R: Repository>(
    state: &SharedState<R>,
    merged: &mut AuthorizeParameters,
    request_object: &str,
) -> QidResult<()> {
    let header =
        jsonwebtoken::decode_header(request_object).map_err(|e| QidError::Unauthorized {
            message: format!("invalid request object header: {e}"),
        })?;
    let alg_name = match header.alg {
        jsonwebtoken::Algorithm::HS256 => "HS256",
        jsonwebtoken::Algorithm::HS384 => "HS384",
        jsonwebtoken::Algorithm::HS512 => "HS512",
        jsonwebtoken::Algorithm::RS256 => "RS256",
        jsonwebtoken::Algorithm::RS384 => "RS384",
        jsonwebtoken::Algorithm::RS512 => "RS512",
        jsonwebtoken::Algorithm::ES256 => "ES256",
        jsonwebtoken::Algorithm::ES384 => "ES384",
        jsonwebtoken::Algorithm::PS256 => "PS256",
        jsonwebtoken::Algorithm::PS384 => "PS384",
        jsonwebtoken::Algorithm::PS512 => "PS512",
        jsonwebtoken::Algorithm::EdDSA => "EdDSA",
    };
    let payload = parse_request_object_payload(request_object)?;
    let client = find_request_object_client(state, &payload).await?;
    enforce_allowed_request_object_alg(state, &client.realm_id, alg_name)?;
    verify_request_object_signature(request_object, &header, &client, alg_name)?;
    validate_request_object_audience(state, &client.realm_id, &payload)?;
    validate_request_object_registered_claims(&payload, &client.client_id)?;
    validate_request_object_time(&payload)?;
    if let Some(client_id) = request_object_string(&payload, "client_id")
        .or_else(|| request_object_string(&payload, "sub"))
        .or_else(|| request_object_string(&payload, "iss"))
    {
        merge_authorize_param(&mut merged.client_id, Some(client_id), "client_id")?;
    }
    merge_authorize_param(
        &mut merged.response_type,
        request_object_string(&payload, "response_type"),
        "response_type",
    )?;
    merge_authorize_param(
        &mut merged.redirect_uri,
        request_object_string(&payload, "redirect_uri"),
        "redirect_uri",
    )?;
    merge_optional_authorize_param(
        &mut merged.scope,
        request_object_string(&payload, "scope"),
        "scope",
    )?;
    merge_optional_authorize_param(
        &mut merged.state,
        request_object_string(&payload, "state"),
        "state",
    )?;
    merge_optional_authorize_param(
        &mut merged.response_mode,
        request_object_string(&payload, "response_mode"),
        "response_mode",
    )?;
    merge_optional_authorize_param(
        &mut merged.code_challenge,
        request_object_string(&payload, "code_challenge"),
        "code_challenge",
    )?;
    merge_optional_authorize_param(
        &mut merged.code_challenge_method,
        request_object_string(&payload, "code_challenge_method"),
        "code_challenge_method",
    )?;
    merge_optional_authorize_param(
        &mut merged.resource,
        request_object_string(&payload, "resource"),
        "resource",
    )?;
    merge_optional_json_authorize_param(
        &mut merged.authorization_details,
        payload.get("authorization_details").cloned(),
        "authorization_details",
    )?;
    merge_optional_authorize_param(
        &mut merged.nonce,
        request_object_string(&payload, "nonce"),
        "nonce",
    )?;
    merge_optional_authorize_param(
        &mut merged.prompt,
        request_object_string(&payload, "prompt"),
        "prompt",
    )?;
    if let Some(max_age) = payload.get("max_age").and_then(|v| v.as_u64()) {
        if merged.max_age.is_none_or(|existing| existing == max_age) {
            merged.max_age = Some(max_age);
        } else {
            return Err(QidError::BadRequest {
                message: "max_age conflicts with request_uri payload".to_string(),
            });
        }
    }
    Ok(())
}

fn request_object_string(claims: &serde_json::Value, name: &str) -> Option<String> {
    claims
        .get(name)
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
}

fn parse_request_object_payload(request_object: &str) -> QidResult<serde_json::Value> {
    let parts: Vec<&str> = request_object.split('.').collect();
    if parts.len() != 3 {
        return Err(QidError::Unauthorized {
            message: "invalid request object format".to_string(),
        });
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| QidError::Unauthorized {
            message: format!("invalid request object payload encoding: {e}"),
        })?;
    serde_json::from_slice(&payload).map_err(|e| QidError::Unauthorized {
        message: format!("invalid request object payload: {e}"),
    })
}

async fn find_request_object_client<R: Repository>(
    state: &SharedState<R>,
    claims: &serde_json::Value,
) -> QidResult<Client> {
    let client_id = request_object_string(claims, "client_id")
        .or_else(|| request_object_string(claims, "sub"))
        .or_else(|| request_object_string(claims, "iss"))
        .ok_or_else(|| QidError::Unauthorized {
            message: "request object missing client identity".to_string(),
        })?;
    let mut candidates = Vec::new();
    for realm in &state.config.realms {
        if let Some(client) = state
            .repo
            .get_client_by_client_id(&RealmId(realm.id.clone()), &client_id)
            .await?
        {
            candidates.push(client);
        }
    }
    let mut matching_audience: Vec<Client> = candidates
        .iter()
        .filter(|client| request_object_audience_matches_realm(state, &client.realm_id, claims))
        .cloned()
        .collect();
    if matching_audience.len() == 1 {
        return Ok(matching_audience.remove(0));
    }
    if candidates.len() == 1 && matching_audience.is_empty() {
        tracing::warn!(client_id = %client_id, "request object audience mismatch");
        return Err(QidError::Unauthorized {
            message: "invalid request object".to_string(),
        });
    }
    if candidates.is_empty() {
        tracing::warn!(client_id = %client_id, "request object client is not registered");
        return Err(QidError::Unauthorized {
            message: "invalid request object".to_string(),
        });
    }
    tracing::warn!(client_id = %client_id, "request object client realm is ambiguous");
    Err(QidError::Unauthorized {
        message: "invalid request object".to_string(),
    })
}

fn verify_request_object_signature(
    request_object: &str,
    header: &jsonwebtoken::Header,
    client: &Client,
    alg: &str,
) -> QidResult<()> {
    let kid = header.kid.as_deref();
    let keys = client
        .jwks
        .get("keys")
        .and_then(|value| value.as_array())
        .ok_or_else(|| QidError::Unauthorized {
            message: "request object client jwks is missing keys".to_string(),
        })?;
    if keys.is_empty() {
        return Err(QidError::Unauthorized {
            message: "request object client jwks has no keys".to_string(),
        });
    }
    let candidates: Vec<&serde_json::Value> = keys
        .iter()
        .filter(|key| {
            kid.is_none_or(|expected_kid| {
                key.get("kid").and_then(|value| value.as_str()) == Some(expected_kid)
            })
        })
        .collect();
    if candidates.is_empty() {
        tracing::warn!(client_id = %client.client_id, kid = ?kid, "request object kid is not registered for client");
        return Err(QidError::Unauthorized {
            message: "invalid request object".to_string(),
        });
    }
    let mut last_error = None;
    for candidate in candidates {
        let mut jwk_value = candidate.clone();
        if let Some(object) = jwk_value.as_object_mut() {
            object
                .entry("kid".to_string())
                .or_insert_with(|| serde_json::Value::String(String::new()));
        }
        let jwk: Jwk = match serde_json::from_value(jwk_value) {
            Ok(jwk) => jwk,
            Err(err) => {
                last_error = Some(format!("registered request object JWK is invalid: {err}"));
                continue;
            }
        };
        if jwk.alg.as_deref().is_some_and(|jwk_alg| jwk_alg != alg) {
            last_error =
                Some("registered request object JWK alg does not match JWT alg".to_string());
            continue;
        }
        match verify_jwt_signature_with_jwk(request_object, &jwk, alg) {
            Ok(()) => return Ok(()),
            Err(err) => last_error = Some(err.message().to_string()),
        }
    }
    Err(QidError::Unauthorized {
        message: format!(
            "request object signature verification failed: {}",
            last_error.unwrap_or_else(|| "no usable client key".to_string())
        ),
    })
}

fn validate_request_object_registered_claims(
    claims: &serde_json::Value,
    client_id: &str,
) -> QidResult<()> {
    for claim in ["client_id", "iss", "sub"] {
        if let Some(value) = request_object_string(claims, claim)
            && value != client_id
        {
            return Err(QidError::Unauthorized {
                message: format!("request object {claim} mismatch"),
            });
        }
    }
    Ok(())
}

fn validate_request_object_time(claims: &serde_json::Value) -> QidResult<()> {
    let now = qid_core::util::now_seconds();
    if let Some(exp) = claims.get("exp").and_then(|value| value.as_u64())
        && exp <= now
    {
        return Err(QidError::Unauthorized {
            message: "request object expired".to_string(),
        });
    }
    if let Some(nbf) = claims.get("nbf").and_then(|value| value.as_u64())
        && nbf > now
    {
        return Err(QidError::Unauthorized {
            message: "request object is not yet valid".to_string(),
        });
    }
    Ok(())
}

async fn realm_requires_signed_request_object<R: Repository>(
    state: &SharedState<R>,
    client_id: &Option<String>,
) -> QidResult<bool> {
    let Some(client_id) = client_id
        .as_deref()
        .filter(|client_id| !client_id.is_empty())
    else {
        return Ok(false);
    };
    let client = find_client_across_realms(state, client_id).await?;
    Ok(state
        .config
        .realms
        .iter()
        .find(|realm| realm.id == client.realm_id)
        .is_some_and(|realm| {
            realm.protocols.oidc.enabled
                && realm
                    .protocols
                    .oidc
                    .authorization_code
                    .require_signed_request_object
        }))
}

fn validate_request_object_audience<R: Repository>(
    state: &SharedState<R>,
    realm_id: &str,
    claims: &serde_json::Value,
) -> QidResult<()> {
    if request_object_audience_matches_realm(state, realm_id, claims) {
        return Ok(());
    }
    tracing::warn!(realm = %realm_id, "request object audience mismatch");
    Err(QidError::Unauthorized {
        message: "invalid request object".to_string(),
    })
}

fn request_object_audience_matches_realm<R: Repository>(
    state: &SharedState<R>,
    realm_id: &str,
    claims: &serde_json::Value,
) -> bool {
    let Some(realm) = state.plan.realms.iter().find(|realm| realm.id == realm_id) else {
        return false;
    };
    let issuer = realm.issuer.as_str();
    let authorize_endpoint = format!("{}{}", issuer.trim_end_matches('/'), state.paths.authorize);
    match claims.get("aud") {
        Some(serde_json::Value::String(aud)) => aud == issuer || aud == &authorize_endpoint,
        Some(serde_json::Value::Array(values)) => values.iter().any(|aud| {
            aud.as_str()
                .is_some_and(|aud| aud == issuer || aud == authorize_endpoint)
        }),
        _ => false,
    }
}

fn enforce_allowed_request_object_alg<R: Repository>(
    state: &SharedState<R>,
    realm_id: &str,
    alg: &str,
) -> QidResult<()> {
    let allowed: Vec<String> = state
        .config
        .realms
        .iter()
        .filter(|realm| realm.id == realm_id)
        .flat_map(|realm| {
            realm
                .protocols
                .oidc
                .authorization_code
                .request_object_signing_alg_values
                .clone()
        })
        .collect();
    if allowed.iter().any(|value| value == alg) {
        Ok(())
    } else {
        Err(QidError::Unauthorized {
            message: format!("request object signing algorithm '{alg}' is not allowed"),
        })
    }
}

fn merge_optional_json_authorize_param(
    target: &mut Option<serde_json::Value>,
    source: Option<serde_json::Value>,
    name: &str,
) -> QidResult<()> {
    let Some(source) = source else {
        return Ok(());
    };
    match target {
        Some(current) if current != &source => Err(QidError::BadRequest {
            message: format!("{name} conflicts with request_uri payload"),
        }),
        Some(_) => Ok(()),
        None => {
            *target = Some(source);
            Ok(())
        }
    }
}

fn require_authorize_fields(req: &AuthorizeParameters) -> QidResult<()> {
    if req.client_id.is_empty() {
        return Err(QidError::BadRequest {
            message: "client_id required".to_string(),
        });
    }
    if req.response_type.is_empty() {
        return Err(QidError::BadRequest {
            message: "response_type required".to_string(),
        });
    }
    if req.redirect_uri.is_empty() {
        return Err(QidError::BadRequest {
            message: "redirect_uri required".to_string(),
        });
    }
    Ok(())
}

fn merge_authorize_param(target: &mut String, source: Option<String>, name: &str) -> QidResult<()> {
    let Some(source) = source else {
        return Ok(());
    };
    if target.is_empty() {
        *target = source;
        return Ok(());
    }
    if target != &source {
        return Err(QidError::BadRequest {
            message: format!("{name} conflicts with request_uri payload"),
        });
    }
    Ok(())
}

fn merge_optional_authorize_param(
    target: &mut Option<String>,
    source: Option<String>,
    name: &str,
) -> QidResult<()> {
    let Some(source) = source else {
        return Ok(());
    };
    match target {
        Some(current) if current != &source => Err(QidError::BadRequest {
            message: format!("{name} conflicts with request_uri payload"),
        }),
        Some(_) => Ok(()),
        None => {
            *target = Some(source);
            Ok(())
        }
    }
}

async fn validate_authorize_request<R: Repository>(
    state: &SharedState<R>,
    req: &AuthorizeParameters,
) -> QidResult<Client> {
    let client = find_client_across_realms(state, &req.client_id).await?;

    let oidc = state
        .config
        .realms
        .iter()
        .find(|r| r.id == client.realm_id)
        .map(|realm| &realm.protocols.oidc)
        .ok_or_else(|| {
            tracing::warn!(realm = %client.realm_id, "client references missing realm");
            QidError::Config {
                message: "authorization request is not available".to_string(),
            }
        })?;
    if !oidc.enabled || !oidc.authorization_code.enabled {
        return Err(QidError::BadRequest {
            message: "OIDC authorization code flow is disabled".to_string(),
        });
    }

    if req.response_type != "code" {
        return Err(QidError::BadRequest {
            message: "unsupported response_type".to_string(),
        });
    }
    if !matches!(
        req.response_mode.as_deref(),
        None | Some("query") | Some("form_post") | Some("jwt")
    ) {
        return Err(QidError::BadRequest {
            message: "unsupported response_mode".to_string(),
        });
    }
    let oauth = state
        .config
        .realms
        .iter()
        .find(|r| r.id == client.realm_id)
        .map(|realm| &realm.protocols.oauth)
        .ok_or_else(|| {
            tracing::warn!(realm = %client.realm_id, "client references missing realm");
            QidError::Config {
                message: "authorization request is not available".to_string(),
            }
        })?;
    if oauth.jarm.enabled && req.response_mode.as_deref() != Some("jwt") {
        return Err(QidError::BadRequest {
            message: "JARM response_mode=jwt is required".to_string(),
        });
    }

    if !client.redirect_uris.contains(&req.redirect_uri) {
        tracing::warn!(
            client_id = %client.client_id,
            realm = %client.realm_id,
            "authorization request redirect_uri is not registered"
        );
        return Err(QidError::Unauthorized {
            message: "authorization request is not allowed".to_string(),
        });
    }

    if !client
        .grant_types
        .contains(&"authorization_code".to_string())
    {
        return Err(QidError::Unauthorized {
            message: "grant type not allowed".to_string(),
        });
    }

    let realm = state
        .realm(&client.realm_id)
        .ok_or_else(|| QidError::NotFound {
            resource: format!("realm {}", client.realm_id),
        })?;
    if realm.pkce_required
        && (req.code_challenge.as_deref().unwrap_or("").is_empty()
            || req.code_challenge_method.as_deref() != Some("S256"))
    {
        return Err(QidError::BadRequest {
            message: "S256 PKCE is required".to_string(),
        });
    }
    if let Some(details) = &req.authorization_details {
        qid_core::oauth::validate_authorization_details(details)?;
    }

    Ok(client)
}

async fn find_client_across_realms<R: Repository>(
    state: &SharedState<R>,
    client_id: &str,
) -> QidResult<Client> {
    let mut found = None;
    for realm_config in &state.config.realms {
        if let Some(client) = state
            .repo
            .get_client_by_client_id(&RealmId::from(realm_config.id.clone()), client_id)
            .await?
        {
            if found.is_some() {
                tracing::warn!(client_id = %client_id, "authorization request client realm is ambiguous");
                return Err(QidError::Unauthorized {
                    message: "authorization request is not allowed".to_string(),
                });
            }
            found = Some(client);
        }
    }
    found.ok_or_else(|| {
        tracing::warn!(client_id = %client_id, "authorization request client is unknown");
        QidError::Unauthorized {
            message: "authorization request is not allowed".to_string(),
        }
    })
}

async fn issue_authorization_code<R: Repository>(
    state: &SharedState<R>,
    client: &Client,
    auth_result: &qid_session::auth::AuthResult,
    auth_time: u64,
    req: &AuthorizeParameters,
) -> QidResult<String> {
    let code = generate_code();
    let code_hash = qid_core::util::sha256_base64url(&code);

    let ttl = state
        .realm(&client.realm_id)
        .map(|r| r.token_ttl.auth_code_ttl_seconds)
        .unwrap_or(600);

    let auth_code = AuthorizationCode {
        code_hash,
        client_id: client.client_id.clone(),
        user_id: auth_result.user.id.clone(),
        realm_id: client.realm_id.clone(),
        redirect_uri: req.redirect_uri.clone(),
        state: req.state.clone(),
        nonce: req.nonce.clone(),
        auth_time: Some(auth_time),
        acr: Some(auth_result.acr.clone()),
        amr: auth_result.amr.clone(),
        code_challenge: req.code_challenge.clone(),
        code_challenge_method: req.code_challenge_method.clone(),
        scopes: req
            .scope
            .as_deref()
            .map(|s| s.split(' ').map(String::from).collect())
            .unwrap_or_else(|| {
                let default_scope = state
                    .realm(&client.realm_id)
                    .map(|r| r.oidc_default_scope.clone())
                    .unwrap_or_else(|| "openid".to_string());
                vec![default_scope]
            }),
        resource: req.resource.iter().cloned().collect(),
        authorization_details: req.authorization_details.clone(),
        expires_at: qid_core::util::now_seconds() + ttl,
        used: false,
        created_at: qid_core::util::now_seconds(),
    };

    state.repo.create_authorization_code(&auth_code).await?;
    Ok(code)
}

fn generate_code() -> String {
    format!("ac_{}", ulid::Ulid::new())
}

fn form_post_response(redirect_uri: &str, params: &[(&str, &str)]) -> Response {
    let fields: String = params
        .iter()
        .map(|(k, v)| format!(r#"<input type="hidden" name="{k}" value="{v}" />"#))
        .collect();
    let html = format!(
        r#"<!doctype html><html><body><form method="POST" action="{redirect_uri}">{fields}</form><script>document.forms[0].submit();</script></body></html>"#
    );
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response()
}

fn form_post_error(
    redirect_uri: &str,
    state: Option<&str>,
    error: &str,
    description: &str,
) -> Response {
    let mut params = vec![("error", error), ("error_description", description)];
    if let Some(s) = state {
        params.push(("state", s));
    }
    form_post_response(redirect_uri, &params)
}

fn authorization_error_response<R: Repository>(
    state: &SharedState<R>,
    req: &AuthorizeParameters,
    client: &Client,
    error: &str,
    description: &str,
) -> Response {
    if req.response_mode.as_deref() == Some("jwt") {
        match sign_jarm_response(
            state,
            req,
            client,
            vec![
                (
                    "error".to_string(),
                    serde_json::Value::String(error.to_string()),
                ),
                (
                    "error_description".to_string(),
                    serde_json::Value::String(description.to_string()),
                ),
            ],
        ) {
            Ok((issuer, response)) => {
                let redirect_url = format!(
                    "{}?response={}&iss={}",
                    req.redirect_uri,
                    urlencoding::encode(&response),
                    urlencoding::encode(&issuer)
                );
                return Redirect::temporary(&redirect_url).into_response();
            }
            Err(e) => return qid_http::error_response(e),
        }
    }
    if req.response_mode.as_deref() == Some("form_post") {
        return form_post_error(&req.redirect_uri, req.state.as_deref(), error, description);
    }
    qid_http::redirect_error(&req.redirect_uri, req.state.as_deref(), error, description)
}

fn sign_jarm_response<R: Repository>(
    state: &SharedState<R>,
    req: &AuthorizeParameters,
    client: &Client,
    entries: Vec<(String, serde_json::Value)>,
) -> QidResult<(String, String)> {
    let issuer = state
        .realm(&client.realm_id)
        .map(|realm| realm.issuer.clone())
        .unwrap_or_else(|| state.plan.public_base_url.clone());
    let now = qid_core::util::now_seconds();
    let mut extra = HashMap::new();
    for (key, value) in entries {
        extra.insert(key, value);
    }
    if let Some(state_param) = &req.state {
        extra.insert(
            "state".to_string(),
            serde_json::Value::String(state_param.clone()),
        );
    }
    let response = state
        .signer
        .sign(&JwtClaims {
            iss: Some(issuer.clone()),
            sub: None,
            aud: Some(req.client_id.clone()),
            exp: Some((now + 60) as usize),
            nbf: Some(now as usize),
            iat: Some(now as usize),
            jti: Some(format!("jarm_{}", ulid::Ulid::new())),
            extra,
        })
        .map_err(|e| QidError::Crypto {
            message: format!("failed to sign authorization response: {e}"),
        })?;
    Ok((issuer, response))
}

async fn authorization_response_redirect<R: Repository>(
    state: &SharedState<R>,
    req: &AuthorizeParameters,
    client: &Client,
    code: &str,
    dpop_header: Option<&str>,
) -> QidResult<Response> {
    if req.response_mode.as_deref() == Some("jwt") {
        let mut entries = vec![(
            "code".to_string(),
            serde_json::Value::String(code.to_string()),
        )];
        // FAPI 2.0 Message Signing: when the client sent a DPoP key (or
        // any other key bound to the request), embed the JWK thumbprint in
        // the JARM response under the `apv` claim so the client can verify
        // the response was produced for the same key. The DPoP header is
        // propagated by the caller (authorize_get / authorize_post) so
        // apv resolution works for both flows.
        if let Some(apv) = dpop_apv_for_request(state, req, dpop_header).await {
            entries.push(("apv".to_string(), serde_json::Value::String(apv)));
        }
        let (issuer, response) = sign_jarm_response(state, req, client, entries)?;
        // RFC 9207 §2.1: a JARM response MUST include the `iss` parameter on
        // the redirect when the client did not suppress it. We always include
        // it because the OP advertises `authorization_response_iss_parameter_supported`.
        let redirect_url = format!(
            "{}?response={}&iss={}",
            req.redirect_uri,
            urlencoding::encode(&response),
            urlencoding::encode(&issuer)
        );
        return Ok(Redirect::temporary(&redirect_url).into_response());
    }

    let issuer = state
        .realm(&client.realm_id)
        .map(|realm| realm.issuer.clone())
        .unwrap_or_else(|| state.plan.public_base_url.clone());

    if req.response_mode.as_deref() == Some("form_post") {
        let mut params = vec![("code", code), ("iss", &issuer)];
        if let Some(state) = &req.state {
            params.push(("state", state));
        }
        return Ok(form_post_response(&req.redirect_uri, &params));
    }

    let mut redirect_url = format!("{}?code={}", req.redirect_uri, urlencoding::encode(code));
    // RFC 9207 §2.1: include the issuer identifier in the redirect when the
    // client supports it.
    redirect_url.push_str(&format!("&iss={}", urlencoding::encode(&issuer)));
    if let Some(state_param) = &req.state {
        redirect_url.push_str(&format!("&state={}", urlencoding::encode(state_param)));
    }
    Ok(Redirect::temporary(&redirect_url).into_response())
}

/// Look up the DPoP JWK thumbprint associated with the in-flight
/// authorization request so it can be embedded in the JARM `apv` claim.
///
/// FAPI 2.0 Message Signing requires the JARM response to carry an
/// `apv` claim whose value is the SHA-256 JWK thumbprint of the
/// DPoP key bound to the request. The binding ensures the client can
/// prove the response was produced for the same key that signed the
/// original authorization request.
///
/// We resolve the DPoP key from two sources, in priority order:
///   1. The `DPoP` HTTP header on the in-flight authorization request
///      (per RFC 9449 §9). When present, the JWK embedded in the
///      proof is used directly.
///   2. The first `jwk` entry in the registered client metadata
///      (used as a static fallback for clients that bind a key once
///      at registration time and never re-enroll).
async fn dpop_apv_for_request<R: Repository>(
    state: &SharedState<R>,
    req: &AuthorizeParameters,
    dpop_header: Option<&str>,
) -> Option<String> {
    if let Some(proof) = dpop_header
        && let Some(jwt_thumbprint) = extract_dpop_jkt_from_proof(proof)
    {
        return Some(jwt_thumbprint);
    }
    let client = find_client_across_realms_for_apv(state, &req.client_id).await?;
    if let Some(jwks) = client.jwks.as_object()
        && let Some(keys) = jwks.get("keys").and_then(|v| v.as_array())
    {
        for key in keys {
            if let Some(thumbprint) = jwk_thumbprint(key) {
                return Some(thumbprint);
            }
        }
    }
    None
}

async fn find_client_across_realms_for_apv<R: Repository>(
    state: &SharedState<R>,
    client_id: &str,
) -> Option<qid_core::models::Client> {
    for realm_config in &state.config.realms {
        if let Ok(Some(client)) = state
            .repo
            .get_client_by_client_id(&RealmId::from(realm_config.id.clone()), client_id)
            .await
        {
            return Some(client);
        }
    }
    None
}

fn extract_dpop_jkt_from_proof(proof: &str) -> Option<String> {
    use qid_oauth::dpop::dpop_jkt_from_proof;
    dpop_jkt_from_proof(proof).ok()
}

fn jwk_thumbprint(key: &serde_json::Value) -> Option<String> {
    use sha2::{Digest, Sha256};
    let kty = key.get("kty")?.as_str()?;
    let mut members: BTreeMap<&str, String> = BTreeMap::new();
    members.insert("kty", kty.to_string());
    match kty {
        "EC" => {
            for member in ["crv", "x", "y"] {
                if let Some(v) = key.get(member).and_then(|v| v.as_str()) {
                    members.insert(member, v.to_string());
                } else {
                    return None;
                }
            }
        }
        "RSA" => {
            for member in ["e", "n"] {
                if let Some(v) = key.get(member).and_then(|v| v.as_str()) {
                    members.insert(member, v.to_string());
                } else {
                    return None;
                }
            }
        }
        "OKP" => {
            for member in ["crv", "x"] {
                if let Some(v) = key.get(member).and_then(|v| v.as_str()) {
                    members.insert(member, v.to_string());
                } else {
                    return None;
                }
            }
        }
        _ => return None,
    }
    let canonical = serde_json::to_string(&members).ok()?;
    let digest = Sha256::digest(canonical.as_bytes());
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
}
