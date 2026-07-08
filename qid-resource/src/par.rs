//! qid-resource par module.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::Engine;
use qid_core::{QidError, state::SharedState, tenant::RealmId};
use qid_crypto::{Jwk, jwt::verify_jwt_signature_with_jwk};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use qid_core::models::ParRequest;

//
// PAR (Pushed Authorization Request)
//

#[derive(Debug, Serialize, Deserialize)]
pub struct ParRequestParams {
    request: Option<String>,
    response_type: Option<String>,
    client_id: String,
    #[serde(default, skip_serializing)]
    client_secret: Option<String>,
    #[serde(default, skip_serializing)]
    client_assertion: Option<String>,
    #[serde(default, skip_serializing)]
    client_assertion_type: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    response_mode: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    authorization_details: Option<serde_json::Value>,
}

pub async fn push_authorization_request<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<ParRequestParams>,
) -> Response {
    if let Some(details) = &req.authorization_details
        && let Err(e) = qid_core::oauth::validate_authorization_details(details)
    {
        return qid_http::error_response(e);
    }
    let client = match authenticate_par_client(&state, &headers, &req).await {
        Ok(client) => client,
        Err(e) => return qid_http::error_response(e),
    };
    let realm_config = match state
        .config
        .realms
        .iter()
        .find(|realm| realm.id == client.realm_id)
    {
        Some(realm) => realm,
        None => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("realm {}", client.realm_id),
            });
        }
    };
    if !realm_config.protocols.oauth.par.enabled {
        return qid_http::error_response(QidError::BadRequest {
            message: "PAR is disabled for client realm".to_string(),
        });
    }
    if realm_config
        .protocols
        .oidc
        .authorization_code
        .require_signed_request_object
        && req.request.as_deref().unwrap_or("").trim().is_empty()
    {
        return qid_http::error_response(QidError::BadRequest {
            message: "signed request object is required for PAR".to_string(),
        });
    }
    let params_json = serde_json::to_value(&req).unwrap_or(serde_json::Value::Null);
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", ulid::Ulid::new());
    let now = qid_core::util::now_seconds();
    let ttl_seconds = state
        .realm(&client.realm_id)
        .map(|realm| realm.token_ttl.par_request_ttl_seconds)
        .unwrap_or_else(|| qid_core::config::TokenTtlConfig::default().par_request_ttl_seconds);
    let par_req = ParRequest {
        request_uri: request_uri.clone(),
        client_id: req.client_id,
        realm_id: client.realm_id,
        params_json,
        expires_at: now + ttl_seconds,
        used: false,
        created_at: now,
    };
    match state.repo.store_par_request(&par_req).await {
        Ok(()) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "request_uri": request_uri,
                "expires_in": ttl_seconds,
            })),
        )
            .into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

async fn authenticate_par_client<R: Repository>(
    state: &SharedState<R>,
    headers: &HeaderMap,
    req: &ParRequestParams,
) -> qid_core::error::QidResult<qid_core::models::Client> {
    let basic_auth = extract_basic_client_auth(headers);
    let assertion_client_id = match req.client_assertion.as_deref() {
        Some(assertion) => Some(extract_assertion_client_id(assertion)?),
        None => None,
    };
    let client_id = assertion_client_id
        .as_deref()
        .or(basic_auth.as_ref().map(|(client_id, _)| client_id.as_str()))
        .or(Some(req.client_id.as_str()))
        .unwrap_or("");
    if client_id != req.client_id {
        return Err(QidError::Unauthorized {
            message: "PAR client authentication does not match request client_id".to_string(),
        });
    }
    if basic_auth.is_some() && (req.client_secret.is_some() || req.client_assertion.is_some()) {
        return Err(QidError::Unauthorized {
            message: "multiple PAR client authentication methods are not allowed".to_string(),
        });
    }
    if req.client_secret.is_some() && req.client_assertion.is_some() {
        return Err(QidError::Unauthorized {
            message: "multiple PAR client authentication methods are not allowed".to_string(),
        });
    }
    let mut found = None;
    for realm in &state.config.realms {
        if let Some(client) = state
            .repo
            .get_client_by_client_id(&RealmId::from(realm.id.clone()), client_id)
            .await?
        {
            if found.is_some() {
                return Err(QidError::Unauthorized {
                    message: "PAR client realm is ambiguous".to_string(),
                });
            }
            found = Some(client);
        }
    }
    let client = found.ok_or_else(|| QidError::Unauthorized {
        message: "unknown PAR client".to_string(),
    })?;
    match client.token_endpoint_auth_method.as_str() {
        "client_secret_basic" => {
            let Some((_, secret)) = basic_auth else {
                return Err(QidError::Unauthorized {
                    message: "PAR requires client_secret_basic authentication".to_string(),
                });
            };
            verify_par_client_secret(&client, Some(secret.as_str()))?;
        }
        "client_secret_post" => {
            verify_par_client_secret(&client, req.client_secret.as_deref())?;
        }
        "private_key_jwt" => {
            let assertion =
                req.client_assertion
                    .as_deref()
                    .ok_or_else(|| QidError::Unauthorized {
                        message: "PAR requires client_assertion".to_string(),
                    })?;
            let assertion_type = req
                .client_assertion_type
                .as_deref()
                .unwrap_or("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            if assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
                return Err(QidError::Unauthorized {
                    message: "unsupported PAR client_assertion_type".to_string(),
                });
            }
            verify_par_private_key_jwt(state, &client, assertion)?;
        }
        "tls_client_auth" | "self_signed_tls_client_auth" => {
            let presented_thumbprint = extract_par_mtls_x5t_s256(headers, state)?;
            verify_par_mtls_thumbprint(&client, presented_thumbprint.as_deref())?;
        }
        other => {
            return Err(QidError::Unauthorized {
                message: format!("PAR client authentication method is not supported: {other}"),
            });
        }
    }
    Ok(client)
}

fn verify_par_client_secret(
    client: &qid_core::models::Client,
    presented_secret: Option<&str>,
) -> qid_core::error::QidResult<()> {
    let presented_secret = presented_secret.ok_or_else(|| QidError::Unauthorized {
        message: "PAR client_secret is required".to_string(),
    })?;
    let expected_hash =
        client
            .client_secret_hash
            .as_deref()
            .ok_or_else(|| QidError::Unauthorized {
                message: "PAR client secret is not configured".to_string(),
            })?;
    let presented_hash = qid_core::util::client_secret_hash(presented_secret);
    if !qid_core::util::constant_time_eq(expected_hash, &presented_hash) {
        return Err(QidError::Unauthorized {
            message: "invalid PAR client credentials".to_string(),
        });
    }
    Ok(())
}

fn extract_par_mtls_x5t_s256<R: Repository>(
    headers: &HeaderMap,
    state: &SharedState<R>,
) -> qid_core::error::QidResult<Option<String>> {
    let token = bearer_header(
        headers,
        header::HeaderName::from_static("x-qid-pep-adapter-authorization"),
    )
    .ok_or_else(|| QidError::Unauthorized {
        message: "PAR mTLS requires authenticated PEP mTLS metadata".to_string(),
    })?;
    let mut authenticated_thumbprint = None;
    for adapter in state
        .config
        .realms
        .iter()
        .flat_map(|realm| realm.pep_registrations.registrations.iter())
    {
        let Some(audience) = adapter.audience.as_deref() else {
            continue;
        };
        if let Ok(decoded) = state.signer.decode_with_aud(token, audience)
            && decoded.claims.sub.as_deref() == Some(adapter.name.as_str())
        {
            authenticated_thumbprint = decoded
                .claims
                .extra
                .get("x5t#S256")
                .or_else(|| decoded.claims.extra.get("x5t_s256"))
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string);
            break;
        }
    }
    let Some(bound_thumbprint) = authenticated_thumbprint else {
        return Err(QidError::Unauthorized {
            message: "invalid or unbound PEP mTLS metadata adapter authentication".to_string(),
        });
    };
    let x5t_s256 = headers
        .get(header::HeaderName::from_static("x-qid-mtls-x5t-s256"))
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| QidError::Unauthorized {
            message: "authenticated PEP mTLS metadata is missing x5t#S256".to_string(),
        })?;
    if x5t_s256 != bound_thumbprint {
        return Err(QidError::Unauthorized {
            message: "PEP mTLS metadata thumbprint does not match adapter assertion".to_string(),
        });
    }
    Ok(Some(x5t_s256.to_string()))
}

fn bearer_header(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    let value = headers.get(name)?.to_str().ok()?.trim();
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty() && !token.contains(' ')).then_some(token)
}

fn verify_par_mtls_thumbprint(
    client: &qid_core::models::Client,
    presented_thumbprint: Option<&str>,
) -> qid_core::error::QidResult<()> {
    let presented_thumbprint = presented_thumbprint.ok_or_else(|| QidError::Unauthorized {
        message: "PAR mTLS client certificate is required".to_string(),
    })?;
    if client.mtls_certificate_thumbprints.is_empty() {
        return Err(QidError::Unauthorized {
            message: "PAR mTLS certificate thumbprint is not configured".to_string(),
        });
    }
    if !client
        .mtls_certificate_thumbprints
        .iter()
        .any(|expected| qid_core::util::constant_time_eq(expected, presented_thumbprint))
    {
        return Err(QidError::Unauthorized {
            message: "PAR mTLS certificate thumbprint is not allowed".to_string(),
        });
    }
    Ok(())
}

fn verify_par_private_key_jwt<R: Repository>(
    state: &SharedState<R>,
    client: &qid_core::models::Client,
    assertion: &str,
) -> qid_core::error::QidResult<()> {
    let (header, payload) = parse_jwt_unverified(assertion)?;
    verify_registered_jwk_signature(assertion, &header, &client.jwks, "client_assertion")?;
    for claim in ["iss", "sub"] {
        let value = payload
            .get(claim)
            .and_then(|value| value.as_str())
            .ok_or_else(|| QidError::Unauthorized {
                message: format!("PAR client_assertion missing {claim} claim"),
            })?;
        if value != client.client_id {
            return Err(QidError::Unauthorized {
                message: format!("PAR client_assertion {claim} mismatch"),
            });
        }
    }
    let par_url = format!(
        "{}{}",
        state.plan.public_base_url.trim_end_matches('/'),
        state.paths.par
    );
    if !audience_matches(payload.get("aud"), &par_url) {
        return Err(QidError::Unauthorized {
            message: "PAR client_assertion audience mismatch".to_string(),
        });
    }
    let now = qid_core::util::now_seconds();
    let exp = payload
        .get("exp")
        .and_then(|value| value.as_u64())
        .ok_or_else(|| QidError::Unauthorized {
            message: "PAR client_assertion missing exp claim".to_string(),
        })?;
    if exp <= now {
        return Err(QidError::Unauthorized {
            message: "PAR client_assertion has expired".to_string(),
        });
    }
    let jti = payload
        .get("jti")
        .and_then(|value| value.as_str())
        .ok_or_else(|| QidError::Unauthorized {
            message: "PAR client_assertion missing jti claim".to_string(),
        })?;
    state.assertion_replay_cache.record_jti(jti, now, now)?;
    Ok(())
}

fn extract_assertion_client_id(assertion: &str) -> qid_core::error::QidResult<String> {
    let (_, payload) = parse_jwt_unverified(assertion)?;
    payload
        .get("iss")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| QidError::Unauthorized {
            message: "PAR client_assertion missing iss claim".to_string(),
        })
}

fn parse_jwt_unverified(
    token: &str,
) -> qid_core::error::QidResult<(serde_json::Value, serde_json::Value)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(QidError::Unauthorized {
            message: "invalid JWT format".to_string(),
        });
    }
    let header = decode_jwt_part(parts[0], "header")?;
    let payload = decode_jwt_part(parts[1], "payload")?;
    Ok((header, payload))
}

fn decode_jwt_part(part: &str, name: &str) -> qid_core::error::QidResult<serde_json::Value> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|e| QidError::Unauthorized {
            message: format!("invalid JWT {name} encoding: {e}"),
        })?;
    serde_json::from_slice(&bytes).map_err(|e| QidError::Unauthorized {
        message: format!("invalid JWT {name}: {e}"),
    })
}

fn verify_registered_jwk_signature(
    token: &str,
    header: &serde_json::Value,
    jwks: &serde_json::Value,
    label: &str,
) -> qid_core::error::QidResult<()> {
    let alg = header
        .get("alg")
        .and_then(|value| value.as_str())
        .ok_or_else(|| QidError::Unauthorized {
            message: format!("{label} missing alg header"),
        })?;
    if !matches!(alg, "ES256" | "EdDSA" | "RS256") {
        return Err(QidError::Unauthorized {
            message: format!("{label} alg is not supported: {alg}"),
        });
    }
    let kid = header.get("kid").and_then(|value| value.as_str());
    let keys = jwks
        .get("keys")
        .and_then(|value| value.as_array())
        .ok_or_else(|| QidError::Unauthorized {
            message: format!("{label} client jwks is missing keys"),
        })?;
    let candidates: Vec<&serde_json::Value> = keys
        .iter()
        .filter(|key| {
            kid.is_none_or(|expected| {
                key.get("kid").and_then(|value| value.as_str()) == Some(expected)
            })
        })
        .collect();
    if candidates.is_empty() {
        return Err(QidError::Unauthorized {
            message: format!("{label} kid is not registered for client"),
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
                last_error = Some(format!("registered client JWK is invalid: {err}"));
                continue;
            }
        };
        if jwk.alg.as_deref().is_some_and(|jwk_alg| jwk_alg != alg) {
            last_error = Some("registered client JWK alg does not match JWT alg".to_string());
            continue;
        }
        match verify_jwt_signature_with_jwk(token, &jwk, alg) {
            Ok(()) => return Ok(()),
            Err(err) => last_error = Some(err.message().to_string()),
        }
    }
    Err(QidError::Unauthorized {
        message: format!(
            "{label} signature verification failed: {}",
            last_error.unwrap_or_else(|| "no usable client key".to_string())
        ),
    })
}

fn audience_matches(aud: Option<&serde_json::Value>, expected: &str) -> bool {
    match aud {
        Some(serde_json::Value::String(value)) => value == expected,
        Some(serde_json::Value::Array(values)) => {
            values.iter().any(|value| value.as_str() == Some(expected))
        }
        _ => false,
    }
}

fn extract_basic_client_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (client_id, secret) = decoded.split_once(':')?;
    Some((client_id.to_string(), secret.to_string()))
}
