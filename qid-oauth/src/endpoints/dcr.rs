use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use qid_core::{
    error::{QidError, QidResult},
    jwt::JwtClaims,
    models::{Client, ClientType},
    state::SharedState,
    tenant::RealmId,
};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::{extract_basic_client_auth, oauth_feature_enabled, verify_client_secret};

#[derive(Debug, Deserialize)]
pub struct DynamicClientRegistrationRequest {
    pub client_id: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub mtls_certificate_thumbprints: Vec<String>,
    #[serde(default = "qid_core::models::default_client_jwks")]
    pub jwks: serde_json::Value,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub client_uri: Option<String>,
    #[serde(default)]
    pub logo_uri: Option<String>,
    #[serde(default)]
    pub contacts: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub default_max_age: Option<u64>,
    #[serde(default)]
    pub require_auth_time: bool,
    #[serde(default)]
    pub sector_identifier_uri: Option<String>,
    #[serde(default)]
    pub subject_type: Option<String>,
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub frontchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub backchannel_client_notification_endpoint: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DynamicClientRegistrationResponse {
    pub client_id: String,
    pub client_id_issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_client_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub mtls_certificate_thumbprints: Vec<String>,
    pub jwks: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_max_age: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_auth_time: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sector_identifier_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_client_notification_endpoint: Option<String>,
}

#[derive(Debug)]
struct DynamicClientMetadata {
    client_type: ClientType,
    auth_method: String,
    grant_types: Vec<String>,
}

pub async fn dynamic_client_registration<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<DynamicClientRegistrationRequest>,
) -> Response {
    let realm = match extract_bearer_token(&headers) {
        Some(token) if !token.is_empty() => {
            let data = match state.signer.decode_signature_only(token) {
                Ok(data) => data,
                Err(_) => {
                    return qid_http::error_response(QidError::Unauthorized {
                        message: "invalid initial access token".to_string(),
                    });
                }
            };
            // Validate the initial access token claims.
            let now = qid_core::util::now_seconds() as usize;
            if let Some(exp) = data.claims.exp {
                if exp <= now {
                    return qid_http::error_response(QidError::Unauthorized {
                        message: "initial access token has expired".to_string(),
                    });
                }
            } else {
                return qid_http::error_response(QidError::Unauthorized {
                    message: "initial access token must have an exp claim".to_string(),
                });
            }
            if let Some(nbf) = data.claims.nbf
                && nbf > now + 60
            {
                return qid_http::error_response(QidError::Unauthorized {
                    message: "initial access token is not yet valid".to_string(),
                });
            }
            // The aud claim must match the DCR endpoint.
            let dcr_issuer = data.claims.iss.as_deref().unwrap_or("");
            let dcr_url = format!(
                "{}{}",
                dcr_issuer.trim_end_matches('/'),
                state.paths.dynamic_client_registration
            );
            if let Some(aud) = &data.claims.aud {
                if *aud != dcr_url {
                    return qid_http::error_response(QidError::Unauthorized {
                        message: "initial access token audience mismatch".to_string(),
                    });
                }
            } else {
                return qid_http::error_response(QidError::Unauthorized {
                    message: "initial access token must have an aud claim".to_string(),
                });
            }
            let issuer = data.claims.iss.as_deref().unwrap_or("");
            let realm = match state.plan.realms.iter().find(|r| r.issuer == issuer) {
                Some(r) => r,
                None => {
                    return qid_http::error_response(QidError::Unauthorized {
                        message: "invalid initial access token issuer".to_string(),
                    });
                }
            };
            if !oauth_feature_enabled(&state, &realm.id, |oauth| {
                oauth.dynamic_client_registration.enabled
            }) {
                return qid_http::error_response(QidError::BadRequest {
                    message: "dynamic client registration is disabled".to_string(),
                });
            }
            realm
        }
        _ => {
            let mut open_realms = state.config.realms.iter().filter(|realm| {
                realm.protocols.oauth.dynamic_client_registration.enabled
                    && realm
                        .protocols
                        .oauth
                        .dynamic_client_registration
                        .allow_open_registration
            });
            let Some(open_realm) = open_realms.next() else {
                if !state
                    .config
                    .realms
                    .iter()
                    .any(|realm| realm.protocols.oauth.dynamic_client_registration.enabled)
                {
                    return qid_http::error_response(QidError::BadRequest {
                        message: "dynamic client registration is disabled".to_string(),
                    });
                }
                return qid_http::error_response(QidError::Unauthorized {
                    message: "initial access token is required for dynamic client registration"
                        .to_string(),
                });
            };
            if open_realms.next().is_some() {
                return qid_http::error_response(QidError::Unauthorized {
                    message:
                        "initial access token is required when multiple realms allow open registration"
                            .to_string(),
                });
            }
            match state.realm(&open_realm.id) {
                Some(realm) => realm,
                None => {
                    return qid_http::error_response(QidError::Config {
                        message: format!("realm {} is not available at runtime", open_realm.id),
                    });
                }
            }
        }
    };
    let metadata = match validate_dynamic_client_metadata(&req) {
        Ok(metadata) => metadata,
        Err(e) => return qid_http::error_response(e),
    };
    let client_id = req
        .client_id
        .clone()
        .unwrap_or_else(|| format!("client_{}", ulid::Ulid::new()));
    let generated_secret = (metadata.client_type == ClientType::Confidential
        && matches!(
            metadata.auth_method.as_str(),
            "client_secret_basic" | "client_secret_post"
        ))
    .then(|| format!("secret_{}", ulid::Ulid::new()));
    let client = Client {
        id: format!("cl_{}", ulid::Ulid::new()),
        realm_id: realm.id.clone(),
        client_id: client_id.clone(),
        client_type: metadata.client_type,
        token_endpoint_auth_method: metadata.auth_method.clone(),
        client_secret_hash: generated_secret
            .as_deref()
            .map(qid_core::util::client_secret_hash),
        mtls_certificate_thumbprints: req.mtls_certificate_thumbprints.clone(),
        jwks: req.jwks.clone(),
        redirect_uris: req.redirect_uris.clone(),
        grant_types: metadata.grant_types.clone(),
        client_name: req.client_name.clone(),
        client_uri: req.client_uri.clone(),
        logo_uri: req.logo_uri.clone(),
        contacts: req.contacts.clone(),
        post_logout_redirect_uris: req.post_logout_redirect_uris.clone(),
        default_max_age: req.default_max_age,
        require_auth_time: req.require_auth_time,
        sector_identifier_uri: req.sector_identifier_uri.clone(),
        subject_type: req.subject_type.clone(),
        backchannel_logout_uri: req.backchannel_logout_uri.clone(),
        frontchannel_logout_uri: req.frontchannel_logout_uri.clone(),
        backchannel_client_notification_endpoint: req
            .backchannel_client_notification_endpoint
            .clone(),
    };
    match state.repo.create_client(&client).await {
        Ok(()) => match build_dynamic_client_registration_response(
            &state,
            &realm.issuer,
            DynamicClientRegistrationResponseInput {
                client_id,
                client_secret: generated_secret,
                redirect_uris: req.redirect_uris,
                grant_types: metadata.grant_types,
                token_endpoint_auth_method: metadata.auth_method,
                mtls_certificate_thumbprints: req.mtls_certificate_thumbprints,
                jwks: req.jwks,
                client_name: req.client_name,
                client_uri: req.client_uri,
                logo_uri: req.logo_uri,
                contacts: req.contacts,
                post_logout_redirect_uris: req.post_logout_redirect_uris,
                default_max_age: req.default_max_age,
                require_auth_time: req.require_auth_time,
                sector_identifier_uri: req.sector_identifier_uri,
                subject_type: req.subject_type,
                backchannel_client_notification_endpoint: req
                    .backchannel_client_notification_endpoint
                    .clone(),
            },
        ) {
            Ok(response) => Json(response).into_response(),
            Err(e) => qid_http::error_response(e),
        },
        Err(e) => qid_http::error_response(e),
    }
}

struct DynamicClientRegistrationResponseInput {
    client_id: String,
    client_secret: Option<String>,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    token_endpoint_auth_method: String,
    mtls_certificate_thumbprints: Vec<String>,
    jwks: serde_json::Value,
    client_name: Option<String>,
    client_uri: Option<String>,
    logo_uri: Option<String>,
    contacts: Vec<String>,
    post_logout_redirect_uris: Vec<String>,
    default_max_age: Option<u64>,
    require_auth_time: bool,
    sector_identifier_uri: Option<String>,
    subject_type: Option<String>,
    backchannel_client_notification_endpoint: Option<String>,
}

fn build_dynamic_client_registration_response<R: Repository>(
    state: &SharedState<R>,
    issuer: &str,
    input: DynamicClientRegistrationResponseInput,
) -> QidResult<DynamicClientRegistrationResponse> {
    let registration_client_uri = dcr_registration_client_uri(state, &input.client_id);
    let registration_access_token = sign_dcr_registration_access_token(
        state,
        issuer,
        &input.client_id,
        &registration_client_uri,
    )?;
    Ok(DynamicClientRegistrationResponse {
        client_id: input.client_id,
        client_id_issued_at: qid_core::util::now_seconds(),
        registration_access_token: Some(registration_access_token),
        registration_client_uri: Some(registration_client_uri),
        client_secret: input.client_secret,
        redirect_uris: input.redirect_uris,
        grant_types: input.grant_types,
        token_endpoint_auth_method: input.token_endpoint_auth_method,
        mtls_certificate_thumbprints: input.mtls_certificate_thumbprints,
        jwks: input.jwks,
        client_name: input.client_name,
        client_uri: input.client_uri,
        logo_uri: input.logo_uri,
        contacts: input.contacts,
        post_logout_redirect_uris: input.post_logout_redirect_uris,
        default_max_age: input.default_max_age,
        require_auth_time: Some(input.require_auth_time),
        sector_identifier_uri: input.sector_identifier_uri,
        subject_type: input.subject_type,
        backchannel_client_notification_endpoint: input.backchannel_client_notification_endpoint,
    })
}

fn dcr_registration_client_uri<R: Repository>(state: &SharedState<R>, client_id: &str) -> String {
    let base = state.plan.public_base_url.trim_end_matches('/');
    let path = state
        .paths
        .dynamic_client_registration_management
        .replace(":client_id", client_id);
    format!("{base}{path}")
}

fn sign_dcr_registration_access_token<R: Repository>(
    state: &SharedState<R>,
    issuer: &str,
    client_id: &str,
    registration_client_uri: &str,
) -> QidResult<String> {
    let now = qid_core::util::now_seconds();
    let claims = JwtClaims {
        iss: Some(issuer.to_string()),
        sub: Some(client_id.to_string()),
        aud: Some(registration_client_uri.to_string()),
        exp: Some((now + 3600) as usize),
        nbf: Some(now as usize),
        iat: Some(now as usize),
        jti: Some(format!("rat_{}", ulid::Ulid::new())),
        extra: std::collections::HashMap::new(),
    };
    state.signer.sign(&claims).map_err(|e| QidError::Crypto {
        message: format!("failed to sign DCR registration access token: {e}"),
    })
}

fn validate_dynamic_client_metadata(
    req: &DynamicClientRegistrationRequest,
) -> QidResult<DynamicClientMetadata> {
    for redirect_uri in &req.redirect_uris {
        let parsed = url::Url::parse(redirect_uri).map_err(|_| QidError::BadRequest {
            message: format!("redirect_uri {redirect_uri} is not a valid URL"),
        })?;
        let host = parsed.host_str().unwrap_or("");
        let scheme = parsed.scheme();
        let is_localhost = host == "localhost"
            || host == "127.0.0.1"
            || host == "::1"
            || host.starts_with("127.")
            || host == "[::1]";
        if scheme != "https" && !(scheme == "http" && is_localhost) {
            return Err(QidError::BadRequest {
                message: format!("redirect_uri {redirect_uri} has no scheme"),
            });
        }
    }
    let auth_method = req
        .token_endpoint_auth_method
        .clone()
        .unwrap_or_else(|| "client_secret_basic".to_string());
    if !matches!(
        auth_method.as_str(),
        "none"
            | "client_secret_basic"
            | "client_secret_post"
            | "private_key_jwt"
            | "tls_client_auth"
            | "self_signed_tls_client_auth"
    ) {
        return Err(QidError::BadRequest {
            message: "unsupported token_endpoint_auth_method".to_string(),
        });
    }
    let client_type = if auth_method == "none" {
        ClientType::Public
    } else {
        ClientType::Confidential
    };
    let grant_types = if req.grant_types.is_empty() {
        vec!["authorization_code".to_string()]
    } else {
        req.grant_types.clone()
    };
    if grant_types
        .iter()
        .any(|g| g == "implicit" || g == "password")
    {
        return Err(QidError::BadRequest {
            message: "implicit and password grants are forbidden for new clients".to_string(),
        });
    }
    if client_type == ClientType::Public && grant_types.iter().any(|g| g == "client_credentials") {
        return Err(QidError::BadRequest {
            message: "public clients cannot use client_credentials".to_string(),
        });
    }
    if matches!(
        auth_method.as_str(),
        "tls_client_auth" | "self_signed_tls_client_auth"
    ) && req.mtls_certificate_thumbprints.is_empty()
    {
        return Err(QidError::BadRequest {
            message: "mTLS clients require mtls_certificate_thumbprints".to_string(),
        });
    }
    if auth_method == "private_key_jwt" {
        validate_client_jwks(&req.jwks)?;
    }
    Ok(DynamicClientMetadata {
        client_type,
        auth_method,
        grant_types,
    })
}

fn validate_client_jwks(jwks: &serde_json::Value) -> QidResult<()> {
    let keys = jwks
        .get("keys")
        .and_then(|value| value.as_array())
        .ok_or_else(|| QidError::BadRequest {
            message: "private_key_jwt clients require jwks.keys".to_string(),
        })?;
    if keys.is_empty() {
        return Err(QidError::BadRequest {
            message: "private_key_jwt clients require at least one JWK".to_string(),
        });
    }
    for (idx, key) in keys.iter().enumerate() {
        let object = key.as_object().ok_or_else(|| QidError::BadRequest {
            message: format!("jwks.keys[{idx}] must be an object"),
        })?;
        match object.get("kty").and_then(|value| value.as_str()) {
            Some("RSA") => {
                let n_bits = object
                    .get("n")
                    .and_then(|v| v.as_str())
                    .map(rsa_modulus_bit_len)
                    .transpose()?
                    .unwrap_or(0);
                if n_bits < 2048 {
                    return Err(QidError::BadRequest {
                        message: format!(
                            "jwks.keys[{idx}] RSA key size {n_bits} is too small, minimum 2048 bits"
                        ),
                    });
                }
            }
            Some("EC") => match object.get("crv").and_then(|v| v.as_str()) {
                Some("P-256" | "P-384" | "P-521") => {}
                Some(other) => {
                    return Err(QidError::BadRequest {
                        message: format!(
                            "jwks.keys[{idx}] EC curve {other} is unsupported, minimum P-256"
                        ),
                    });
                }
                None => {
                    return Err(QidError::BadRequest {
                        message: format!("jwks.keys[{idx}] EC missing crv"),
                    });
                }
            },
            Some("OKP") => {}
            Some(other) => {
                return Err(QidError::BadRequest {
                    message: format!("jwks.keys[{idx}].kty is unsupported: {other}"),
                });
            }
            None => {
                return Err(QidError::BadRequest {
                    message: format!("jwks.keys[{idx}] missing kty"),
                });
            }
        }
    }
    Ok(())
}

fn rsa_modulus_bit_len(encoded: &str) -> QidResult<usize> {
    let modulus = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|err| QidError::BadRequest {
            message: format!("RSA JWK modulus is not valid base64url: {err}"),
        })?;
    let first_non_zero = modulus
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(modulus.len());
    let significant = &modulus[first_non_zero..];
    let Some(first) = significant.first() else {
        return Ok(0);
    };
    Ok((significant.len() - 1) * 8 + (8 - first.leading_zeros() as usize))
}

async fn authenticate_dcr_management_client<R: Repository>(
    state: &SharedState<R>,
    headers: &HeaderMap,
    realm_id: &str,
    client_id: &str,
) -> QidResult<Client> {
    if let Some(token) = extract_bearer_token(headers) {
        validate_dcr_registration_access_token(state, token, client_id)?;
        return state
            .repo
            .get_client_by_client_id(&RealmId::from(realm_id.to_string()), client_id)
            .await?
            .ok_or_else(|| QidError::Unauthorized {
                message: "unknown client".to_string(),
            });
    }
    let basic_client_auth =
        extract_basic_client_auth(headers).ok_or_else(|| QidError::Unauthorized {
            message: "DCR management requires client authentication".to_string(),
        })?;
    if basic_client_auth.client_id != client_id {
        return Err(QidError::Unauthorized {
            message: "DCR management client_id must match path".to_string(),
        });
    }
    let client = state
        .repo
        .get_client_by_client_id(&RealmId::from(realm_id.to_string()), client_id)
        .await?
        .ok_or_else(|| QidError::Unauthorized {
            message: "unknown client".to_string(),
        })?;
    if client.client_type != ClientType::Confidential {
        return Err(QidError::Unauthorized {
            message: "DCR management requires a confidential client".to_string(),
        });
    }
    verify_client_secret(&client, Some(basic_client_auth.client_secret.as_str()))?;
    Ok(client)
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    super::extract_bearer_token(headers).ok()
}

fn validate_dcr_registration_access_token<R: Repository>(
    state: &SharedState<R>,
    token: &str,
    client_id: &str,
) -> QidResult<()> {
    let claims = state
        .signer
        .decode_signature_only(token)
        .map_err(|e| QidError::Unauthorized {
            message: format!("invalid registration access token: {e}"),
        })?;
    let claims = claims.claims;
    if claims.sub.as_deref() != Some(client_id) {
        return Err(QidError::Unauthorized {
            message: "registration access token subject mismatch".to_string(),
        });
    }
    let expected_audience = dcr_registration_client_uri(state, client_id);
    if claims.aud.as_deref() != Some(expected_audience.as_str()) {
        return Err(QidError::Unauthorized {
            message: "registration access token audience mismatch".to_string(),
        });
    }
    let now = qid_core::util::now_seconds();
    if claims.exp.is_none_or(|exp| exp as u64 <= now) {
        return Err(QidError::Unauthorized {
            message: "registration access token expired".to_string(),
        });
    }
    if claims.nbf.is_some_and(|nbf| nbf as u64 > now + 60) {
        return Err(QidError::Unauthorized {
            message: "registration access token is not yet valid".to_string(),
        });
    }
    Ok(())
}

pub async fn dynamic_client_registration_get<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> Response {
    let (realm_id, issuer) = match find_client_across_realms(&state, &client_id).await {
        Ok(c) => {
            let realm = state.realm(&c.realm_id).ok_or_else(|| QidError::NotFound {
                resource: format!("realm {}", c.realm_id),
            });
            match realm {
                Ok(r) => (c.realm_id.clone(), r.issuer.clone()),
                Err(e) => return qid_http::error_response(e),
            }
        }
        Err(_) => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("client {client_id}"),
            });
        }
    };
    if !oauth_feature_enabled(&state, &realm_id, |oauth| {
        oauth.dynamic_client_registration.enabled
    }) {
        return qid_http::error_response(QidError::BadRequest {
            message: "dynamic client registration is disabled".to_string(),
        });
    }
    if let Err(e) =
        authenticate_dcr_management_client(&state, &headers, &realm_id, &client_id).await
    {
        return qid_http::error_response(e);
    }
    match state
        .repo
        .get_client_by_client_id(&RealmId::from(realm_id), &client_id)
        .await
    {
        Ok(Some(client)) => match build_dynamic_client_registration_response(
            &state,
            &issuer,
            DynamicClientRegistrationResponseInput {
                client_id: client.client_id.clone(),
                client_secret: None,
                redirect_uris: client.redirect_uris,
                grant_types: client.grant_types,
                token_endpoint_auth_method: client.token_endpoint_auth_method,
                mtls_certificate_thumbprints: client.mtls_certificate_thumbprints,
                jwks: client.jwks,
                client_name: client.client_name,
                client_uri: client.client_uri,
                logo_uri: client.logo_uri,
                contacts: client.contacts,
                post_logout_redirect_uris: client.post_logout_redirect_uris,
                default_max_age: client.default_max_age,
                require_auth_time: client.require_auth_time,
                sector_identifier_uri: client.sector_identifier_uri,
                subject_type: client.subject_type,
                backchannel_client_notification_endpoint: client
                    .backchannel_client_notification_endpoint,
            },
        ) {
            Ok(response) => Json(response).into_response(),
            Err(e) => qid_http::error_response(e),
        },
        Ok(None) => qid_http::error_response(QidError::NotFound {
            resource: format!("client {client_id}"),
        }),
        Err(e) => qid_http::error_response(e),
    }
}

pub async fn dynamic_client_registration_update<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
    Json(req): Json<DynamicClientRegistrationRequest>,
) -> Response {
    if req
        .client_id
        .as_deref()
        .is_some_and(|body_client_id| body_client_id != client_id)
    {
        return qid_http::error_response(QidError::BadRequest {
            message: "client_id in request body must match management path".to_string(),
        });
    }
    let metadata = match validate_dynamic_client_metadata(&req) {
        Ok(metadata) => metadata,
        Err(e) => return qid_http::error_response(e),
    };
    let (realm_id, issuer) = match find_client_across_realms(&state, &client_id).await {
        Ok(c) => {
            let realm = state.realm(&c.realm_id).ok_or_else(|| QidError::NotFound {
                resource: format!("realm {}", c.realm_id),
            });
            match realm {
                Ok(r) => (c.realm_id.clone(), r.issuer.clone()),
                Err(e) => return qid_http::error_response(e),
            }
        }
        Err(_) => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("client {client_id}"),
            });
        }
    };
    if !oauth_feature_enabled(&state, &realm_id, |oauth| {
        oauth.dynamic_client_registration.enabled
    }) {
        return qid_http::error_response(QidError::BadRequest {
            message: "dynamic client registration is disabled".to_string(),
        });
    }
    if let Err(e) =
        authenticate_dcr_management_client(&state, &headers, &realm_id, &client_id).await
    {
        return qid_http::error_response(e);
    }
    let existing = match state
        .repo
        .get_client_by_client_id(&RealmId::from(realm_id.clone()), &client_id)
        .await
    {
        Ok(Some(client)) => client,
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("client {client_id}"),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };
    let generated_secret = (metadata.client_type == ClientType::Confidential
        && matches!(
            metadata.auth_method.as_str(),
            "client_secret_basic" | "client_secret_post"
        )
        && existing.client_secret_hash.is_none())
    .then(|| format!("secret_{}", ulid::Ulid::new()));
    let client_secret_hash = if metadata.client_type == ClientType::Confidential
        && matches!(
            metadata.auth_method.as_str(),
            "client_secret_basic" | "client_secret_post"
        ) {
        generated_secret
            .as_deref()
            .map(qid_core::util::client_secret_hash)
            .or(existing.client_secret_hash)
    } else {
        None
    };
    let updated = Client {
        id: existing.id,
        realm_id,
        client_id: existing.client_id,
        client_type: metadata.client_type,
        token_endpoint_auth_method: metadata.auth_method.clone(),
        client_secret_hash,
        mtls_certificate_thumbprints: req.mtls_certificate_thumbprints.clone(),
        jwks: req.jwks.clone(),
        redirect_uris: req.redirect_uris.clone(),
        grant_types: metadata.grant_types.clone(),
        client_name: req.client_name.clone(),
        client_uri: req.client_uri.clone(),
        logo_uri: req.logo_uri.clone(),
        contacts: req.contacts.clone(),
        post_logout_redirect_uris: req.post_logout_redirect_uris.clone(),
        default_max_age: req.default_max_age,
        require_auth_time: req.require_auth_time,
        sector_identifier_uri: req.sector_identifier_uri.clone(),
        subject_type: req.subject_type.clone(),
        backchannel_logout_uri: req.backchannel_logout_uri.clone(),
        frontchannel_logout_uri: req.frontchannel_logout_uri.clone(),
        backchannel_client_notification_endpoint: req
            .backchannel_client_notification_endpoint
            .clone(),
    };
    match state.repo.update_client(&updated).await {
        Ok(()) => match build_dynamic_client_registration_response(
            &state,
            &issuer,
            DynamicClientRegistrationResponseInput {
                client_id,
                client_secret: generated_secret,
                redirect_uris: req.redirect_uris,
                grant_types: metadata.grant_types,
                token_endpoint_auth_method: metadata.auth_method,
                mtls_certificate_thumbprints: req.mtls_certificate_thumbprints,
                jwks: req.jwks,
                client_name: req.client_name,
                client_uri: req.client_uri,
                logo_uri: req.logo_uri,
                contacts: req.contacts,
                post_logout_redirect_uris: req.post_logout_redirect_uris,
                default_max_age: req.default_max_age,
                require_auth_time: req.require_auth_time,
                sector_identifier_uri: req.sector_identifier_uri,
                subject_type: req.subject_type,
                backchannel_client_notification_endpoint: req
                    .backchannel_client_notification_endpoint
                    .clone(),
            },
        ) {
            Ok(response) => Json(response).into_response(),
            Err(e) => qid_http::error_response(e),
        },
        Err(e) => qid_http::error_response(e),
    }
}

pub async fn dynamic_client_registration_delete<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> Response {
    let realm_id = match find_client_across_realms(&state, &client_id).await {
        Ok(c) => c.realm_id,
        Err(_) => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("client {client_id}"),
            });
        }
    };
    if !oauth_feature_enabled(&state, &realm_id, |oauth| {
        oauth.dynamic_client_registration.enabled
    }) {
        return qid_http::error_response(QidError::BadRequest {
            message: "dynamic client registration is disabled".to_string(),
        });
    }
    if let Err(e) =
        authenticate_dcr_management_client(&state, &headers, &realm_id, &client_id).await
    {
        return qid_http::error_response(e);
    }
    let client = match state
        .repo
        .get_client_by_client_id(&RealmId::from(realm_id), &client_id)
        .await
    {
        Ok(Some(client)) => client,
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("client {client_id}"),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };
    match state.repo.delete_client(&client.id).await {
        Ok(()) => axum::http::StatusCode::NO_CONTENT.into_response(),
        Err(e) => qid_http::error_response(e),
    }
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
                return Err(QidError::Unauthorized {
                    message: "client realm is ambiguous".to_string(),
                });
            }
            found = Some(client);
        }
    }
    found.ok_or_else(|| QidError::Unauthorized {
        message: "unknown client".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dcr_rejects_rsa_jwk_by_actual_modulus_bits() {
        let weak_modulus = URL_SAFE_NO_PAD.encode([0x7fu8; 192]);
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "n": weak_modulus,
                "e": "AQAB"
            }]
        });
        let err = validate_client_jwks(&jwks).unwrap_err();
        assert!(err.to_string().contains("1535"));
    }

    #[test]
    fn dcr_accepts_rsa_jwk_with_2048_bit_modulus() {
        let mut modulus = vec![0u8; 256];
        modulus[0] = 0x80;
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "n": URL_SAFE_NO_PAD.encode(modulus),
                "e": "AQAB"
            }]
        });
        validate_client_jwks(&jwks).unwrap();
    }
}
