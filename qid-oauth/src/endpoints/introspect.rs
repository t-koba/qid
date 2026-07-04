//! OAuth 2.0 token introspection endpoint.

use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, Method},
    response::{IntoResponse, Response},
};
use qid_core::{
    config::{OAuthResourceServerConfig, RealmConfig},
    error::{QidError, QidResult},
    jwt::JwtClaims,
    models::{Client, ClientType, TokenFormat},
    state::SharedState,
    tenant::RealmId,
};
use qid_storage::prelude::*;
use std::sync::Arc;

use super::{
    IntrospectRequest, IntrospectResponse, decode_opaque_access_token, extract_basic_client_auth,
    verify_client_secret,
};

#[derive(Debug, Clone)]
pub struct DecodedAccessToken {
    pub user_id: String,
    pub client_id: String,
    pub realm_id: String,
    pub exp: u64,
    pub scope: String,
    pub cnf: Option<serde_json::Value>,
    pub aud: Vec<String>,
    pub resource: Vec<String>,
    pub auth_time: Option<u64>,
    pub acr: Option<String>,
    pub amr: Vec<String>,
    pub nonce: Option<String>,
    pub token_format: TokenFormat,
    pub act: Option<serde_json::Value>,
}

pub fn enforce_sender_constrained_access_token<R: Repository>(
    state: &SharedState<R>,
    headers: &HeaderMap,
    method: &Method,
    htu: &str,
    access_token: &str,
    decoded: &DecodedAccessToken,
) -> QidResult<()> {
    let Some(cnf) = decoded.cnf.as_ref() else {
        return Ok(());
    };
    let dpop_jkt = cnf.get("jkt").and_then(serde_json::Value::as_str);
    let mtls_x5t = cnf
        .get("x5t#S256")
        .or_else(|| cnf.get("x5t_s256"))
        .and_then(serde_json::Value::as_str);
    if dpop_jkt.is_none() && mtls_x5t.is_none() {
        return Err(QidError::Unauthorized {
            message: "sender-constrained access token has unsupported cnf claim".to_string(),
        });
    }
    if let Some(expected_jkt) = dpop_jkt {
        let proof = headers
            .get("dpop")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| QidError::Unauthorized {
                message: "sender-constrained access token requires DPoP proof".to_string(),
            })?;
        let proof_token = crate::dpop::extract_dpop_jkt(proof)?;
        crate::dpop::validate_dpop_proof(
            &state.dpop_state,
            &proof_token,
            method.as_str(),
            htu,
            None,
            state.signer.as_ref(),
        )?;
        crate::dpop::validate_dpop_ath(&proof_token, access_token)?;
        let presented_jkt = crate::dpop::dpop_jkt_from_proof(&proof_token)?;
        if presented_jkt != expected_jkt {
            return Err(QidError::Unauthorized {
                message: "DPoP proof key does not match access token cnf".to_string(),
            });
        }
        return Ok(());
    }
    if let Some(expected_x5t) = mtls_x5t {
        let presented = crate::mtls::extract_mtls_x5t_s256(headers, state)?.ok_or_else(|| {
            QidError::Unauthorized {
                message: "sender-constrained access token requires mTLS thumbprint".to_string(),
            }
        })?;
        if presented != expected_x5t {
            return Err(QidError::Unauthorized {
                message: "mTLS thumbprint does not match access token cnf".to_string(),
            });
        }
    }
    Ok(())
}

pub fn extract_bearer_token(headers: &HeaderMap) -> QidResult<&str> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| QidError::Unauthorized {
            message: "bearer access token is required".to_string(),
        })?
        .trim();
    let Some((scheme, token)) = value.split_once(' ') else {
        return Err(QidError::Unauthorized {
            message: "Authorization header must use the Bearer scheme".to_string(),
        });
    };
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(QidError::Unauthorized {
            message: "Authorization header must use the Bearer scheme".to_string(),
        });
    }
    let token = token.trim();
    if token.is_empty() || token.contains(' ') {
        return Err(QidError::Unauthorized {
            message: "Bearer access token is malformed".to_string(),
        });
    }
    Ok(token)
}

pub async fn introspect<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Form(req): Form<IntrospectRequest>,
) -> Response {
    if !state
        .config
        .realms
        .iter()
        .any(|realm| realm.protocols.oauth.introspection.enabled)
    {
        return qid_http::error_response(QidError::BadRequest {
            message: "introspection is disabled".to_string(),
        });
    }

    let result = decode_access_token(&state, &req.token).await;
    match result {
        Ok(mut decoded) => {
            let Some(realm) = state
                .config
                .realms
                .iter()
                .find(|realm| realm.id == decoded.realm_id)
            else {
                return inactive_response();
            };
            let introspection = &realm.protocols.oauth.introspection;
            if !introspection.enabled {
                return qid_http::error_response(QidError::BadRequest {
                    message: "introspection is disabled for token realm".to_string(),
                });
            }
            if req.response_format.as_deref() == Some("jwt") && !introspection.jwt_response {
                return qid_http::error_response(QidError::BadRequest {
                    message: "jwt introspection response is disabled".to_string(),
                });
            }
            let caller = if !realm.protocols.oauth.resource_servers.is_empty() {
                match authenticate_introspection_client(&state, &headers, &req, &decoded.realm_id)
                    .await
                {
                    Ok(caller) => Some(caller),
                    Err(e) => return qid_http::error_response(e),
                }
            } else {
                None
            };
            if !realm.protocols.oauth.resource_servers.is_empty() {
                let caller = caller.as_ref().expect("caller is authenticated");
                let Some(server) = select_introspection_resource_server(realm, &req, &decoded)
                else {
                    return inactive_response();
                };
                if !server
                    .introspection_client_ids
                    .iter()
                    .any(|client_id| client_id == &caller.client_id)
                {
                    return qid_http::error_response(QidError::Unauthorized {
                        message: "client is not allowed to introspect this resource server"
                            .to_string(),
                    });
                }
                if !token_targets_resource_server(&decoded, server) {
                    return inactive_response();
                }
                if !filter_decoded_for_resource_server(&mut decoded, server) {
                    return inactive_response();
                }
            }
            let token_introspection = if req.response_format.as_deref() == Some("jwt") {
                sign_introspection_response(
                    &state,
                    &decoded,
                    caller.as_ref().map(|caller| caller.client_id.as_str()),
                )
                .ok()
            } else {
                None
            };
            active_response(decoded, token_introspection)
        }
        Err(_) => inactive_response(),
    }
}

#[derive(Debug, Clone)]
struct IntrospectionCaller {
    client_id: String,
}

async fn authenticate_introspection_client<R: Repository>(
    state: &SharedState<R>,
    headers: &HeaderMap,
    req: &IntrospectRequest,
    realm_id: &str,
) -> QidResult<IntrospectionCaller> {
    let basic_client_auth = extract_basic_client_auth(headers);
    let (client_id, presented_secret, used_auth_method) = match basic_client_auth.as_ref() {
        Some(auth) => (
            auth.client_id.as_str(),
            Some(auth.client_secret.as_str()),
            "client_secret_basic",
        ),
        None => (
            req.client_id
                .as_deref()
                .ok_or_else(|| QidError::Unauthorized {
                    message: "client_id is required for introspection".to_string(),
                })?,
            req.client_secret.as_deref(),
            "client_secret_post",
        ),
    };
    if req.client_secret.is_some() && used_auth_method == "client_secret_basic" {
        return Err(QidError::Unauthorized {
            message: "multiple client authentication methods are not allowed".to_string(),
        });
    }
    let client = state
        .repo
        .get_client_by_client_id(&RealmId::from(realm_id.to_string()), client_id)
        .await?
        .ok_or_else(|| QidError::Unauthorized {
            message: "unknown introspection client for token realm".to_string(),
        })?;
    verify_introspection_client_secret(&client, used_auth_method, presented_secret)?;
    Ok(IntrospectionCaller {
        client_id: client.client_id,
    })
}

fn verify_introspection_client_secret(
    client: &Client,
    used_auth_method: &str,
    presented_secret: Option<&str>,
) -> QidResult<()> {
    if client.client_type != ClientType::Confidential {
        return Err(QidError::Unauthorized {
            message: "introspection client must be confidential".to_string(),
        });
    }
    if client.token_endpoint_auth_method != used_auth_method {
        return Err(QidError::Unauthorized {
            message: format!(
                "introspection client must authenticate with {}",
                client.token_endpoint_auth_method
            ),
        });
    }
    if !matches!(
        used_auth_method,
        "client_secret_basic" | "client_secret_post"
    ) {
        return Err(QidError::Unauthorized {
            message: "introspection client authentication method is not supported".to_string(),
        });
    }
    verify_client_secret(client, presented_secret)
}

fn select_introspection_resource_server<'a>(
    realm: &'a RealmConfig,
    req: &IntrospectRequest,
    decoded: &DecodedAccessToken,
) -> Option<&'a OAuthResourceServerConfig> {
    let servers = &realm.protocols.oauth.resource_servers;
    match (req.audience.as_deref(), req.resource.as_deref()) {
        (Some(audience), Some(resource)) => servers.iter().find(|server| {
            server.audience == audience && server.resources.iter().any(|value| value == resource)
        }),
        (Some(audience), None) => servers.iter().find(|server| server.audience == audience),
        (None, Some(resource)) => servers
            .iter()
            .find(|server| server.resources.iter().any(|value| value == resource)),
        (None, None) => {
            let mut matching = servers
                .iter()
                .filter(|server| token_targets_resource_server(decoded, server));
            let selected = matching.next()?;
            if matching.next().is_some() {
                None
            } else {
                Some(selected)
            }
        }
    }
}

fn token_targets_resource_server(
    decoded: &DecodedAccessToken,
    server: &OAuthResourceServerConfig,
) -> bool {
    decoded
        .aud
        .iter()
        .any(|audience| audience == &server.audience)
        || decoded
            .resource
            .iter()
            .any(|resource| server.resources.iter().any(|value| value == resource))
}

fn filter_decoded_for_resource_server(
    decoded: &mut DecodedAccessToken,
    server: &OAuthResourceServerConfig,
) -> bool {
    decoded.aud = decoded
        .aud
        .iter()
        .filter(|audience| *audience == &server.audience)
        .cloned()
        .collect();
    decoded.resource = decoded
        .resource
        .iter()
        .filter(|resource| server.resources.iter().any(|value| value == *resource))
        .cloned()
        .collect();
    if !server.scopes.is_empty() {
        let filtered_scopes = decoded
            .scope
            .split_whitespace()
            .filter(|scope| server.scopes.iter().any(|allowed| allowed == *scope))
            .collect::<Vec<_>>();
        if filtered_scopes.is_empty() {
            return false;
        }
        decoded.scope = filtered_scopes.join(" ");
    }
    true
}

fn active_response(decoded: DecodedAccessToken, token_introspection: Option<String>) -> Response {
    Json(IntrospectResponse {
        active: true,
        sub: Some(decoded.user_id),
        client_id: Some(decoded.client_id),
        exp: Some(decoded.exp),
        scope: Some(decoded.scope),
        cnf: decoded.cnf,
        aud: optional_vec(decoded.aud),
        resource: optional_vec(decoded.resource),
        auth_time: decoded.auth_time,
        acr: decoded.acr,
        amr: optional_vec(decoded.amr),
        nonce: decoded.nonce,
        token_format: Some(decoded.token_format),
        act: decoded.act,
        token_introspection,
    })
    .into_response()
}

fn inactive_response() -> Response {
    Json(IntrospectResponse {
        active: false,
        sub: None,
        client_id: None,
        exp: None,
        scope: None,
        cnf: None,
        aud: None,
        resource: None,
        auth_time: None,
        acr: None,
        amr: None,
        nonce: None,
        token_format: None,
        act: None,
        token_introspection: None,
    })
    .into_response()
}

fn sign_introspection_response<R: Repository>(
    state: &SharedState<R>,
    decoded: &DecodedAccessToken,
    audience: Option<&str>,
) -> QidResult<String> {
    let now = qid_core::util::now_seconds();
    let issuer = state
        .realm(&decoded.realm_id)
        .map(|r| r.issuer.clone())
        .unwrap_or_else(|| state.plan.public_base_url.clone());
    let mut extra = std::collections::HashMap::new();
    extra.insert("active".to_string(), serde_json::Value::Bool(true));
    extra.insert(
        "client_id".to_string(),
        serde_json::Value::String(decoded.client_id.clone()),
    );
    extra.insert(
        "scope".to_string(),
        serde_json::Value::String(decoded.scope.clone()),
    );
    if let Some(cnf) = &decoded.cnf {
        extra.insert("cnf".to_string(), cnf.clone());
    }
    if !decoded.resource.is_empty() {
        extra.insert("resource".to_string(), serde_json::json!(decoded.resource));
    }
    if let Some(auth_time) = decoded.auth_time {
        extra.insert("auth_time".to_string(), serde_json::json!(auth_time));
    }
    if let Some(acr) = &decoded.acr {
        extra.insert("acr".to_string(), serde_json::json!(acr));
    }
    if !decoded.amr.is_empty() {
        extra.insert("amr".to_string(), serde_json::json!(decoded.amr));
    }
    if let Some(nonce) = &decoded.nonce {
        extra.insert("nonce".to_string(), serde_json::json!(nonce));
    }
    if let Some(act) = &decoded.act {
        extra.insert("act".to_string(), act.clone());
    }
    extra.insert(
        "token_format".to_string(),
        serde_json::json!(decoded.token_format),
    );
    let claims = JwtClaims {
        iss: Some(issuer),
        sub: Some(decoded.user_id.clone()),
        aud: Some(audience.unwrap_or(&decoded.client_id).to_string()),
        exp: Some(decoded.exp as usize),
        nbf: Some(now as usize),
        iat: Some(now as usize),
        jti: Some(format!("itr_{}", ulid::Ulid::new())),
        extra,
    };
    state.signer.sign(&claims).map_err(|e| QidError::Crypto {
        message: format!("failed to sign introspection response: {e}"),
    })
}

pub async fn decode_access_token<R: Repository>(
    state: &SharedState<R>,
    token: &str,
) -> QidResult<DecodedAccessToken> {
    let mut act = None;
    let jti = if let Some(jti) = decode_opaque_access_token(token) {
        jti.to_string()
    } else {
        let data = state
            .signer
            .decode_signature_only(token)
            .map_err(|e| QidError::Crypto {
                message: format!("failed to decode token: {e}"),
            })?;
        act = data.claims.extra.get("act").cloned();
        data.claims.jti.ok_or_else(|| QidError::Crypto {
            message: "token missing jti".to_string(),
        })?
    };

    let record =
        state
            .repo
            .get_access_token(&jti)
            .await?
            .ok_or_else(|| QidError::Unauthorized {
                message: "token not found".to_string(),
            })?;

    if record.revoked || record.expires_at <= qid_core::util::now_seconds() {
        return Err(QidError::Unauthorized {
            message: "token expired or revoked".to_string(),
        });
    }

    Ok(DecodedAccessToken {
        user_id: record.user_id,
        client_id: record.client_id,
        realm_id: record.realm_id,
        exp: record.expires_at,
        scope: record.scopes.join(" "),
        cnf: record.cnf,
        aud: record.audience,
        resource: record.resource,
        auth_time: record.auth_time,
        acr: record.acr,
        amr: record.amr,
        nonce: record.nonce,
        token_format: record.token_format,
        act,
    })
}

fn optional_vec<T>(value: Vec<T>) -> Option<Vec<T>> {
    if value.is_empty() { None } else { Some(value) }
}
