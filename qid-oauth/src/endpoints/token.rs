use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use base64::Engine;
use qid_core::{
    error::{QidError, QidResult},
    models::{Client, ClientType, User},
    state::SharedState,
    tenant::RealmId,
};
use qid_crypto::{Jwk, jwt::verify_jwt_signature_with_jwk};
use qid_storage::prelude::*;
use serde_json::Map;
use std::sync::Arc;

use super::{
    TokenIssueClaims, TokenRequest, TokenResponse, access_token_type_for_cnf,
    authorization_code_grant, ciba_grant, client_credentials_grant, decode_access_token,
    device_code_grant, issue_access_token, refresh_token_grant,
};

pub async fn token<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Form(req): Form<TokenRequest>,
) -> Response {
    let dpop_header = headers
        .get("dpop")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let should_challenge_dpop_nonce = dpop_header.is_some()
        && state
            .config
            .realms
            .iter()
            .any(|realm| realm.protocols.oauth.dpop.nonce);
    let basic_client_auth = extract_basic_client_auth(&headers);
    let mtls_x5t_s256 = if state
        .config
        .realms
        .iter()
        .any(|realm| realm.protocols.oauth.mtls.enabled)
    {
        match crate::mtls::extract_mtls_x5t_s256(&headers, &state) {
            Ok(value) => value,
            Err(e) => return qid_http::error_response(e),
        }
    } else {
        None
    };
    match handle_token(&state, &req, dpop_header, mtls_x5t_s256, basic_client_auth).await {
        Ok(resp) => Json(resp).into_response(),
        Err(e) if should_challenge_dpop_nonce => token_error_with_fresh_dpop_nonce(&state, e),
        Err(e) => qid_http::error_response(e),
    }
}

async fn handle_token<R: Repository>(
    state: &SharedState<R>,
    req: &TokenRequest,
    dpop_header: Option<String>,
    mtls_x5t_s256: Option<String>,
    basic_client_auth: Option<BasicClientAuth>,
) -> QidResult<TokenResponse> {
    let assertion_client_id = if let Some(ref assertion) = req.client_assertion {
        let assertion_type = req
            .client_assertion_type
            .as_deref()
            .unwrap_or("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        if assertion_type == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
            let client_id = crate::dpop::extract_client_id_from_assertion(assertion)?;
            Some(client_id)
        } else {
            None
        }
    } else {
        None
    };

    let effective_client_id = assertion_client_id
        .as_deref()
        .or(basic_client_auth
            .as_ref()
            .map(|auth| auth.client_id.as_str()))
        .or(req.client_id.as_deref())
        .unwrap_or("");
    let inferred_client_id =
        if effective_client_id.is_empty() && req.grant_type == "authorization_code" {
            infer_authorization_code_client_id(state, req).await?
        } else {
            None
        };
    let effective_client_id = assertion_client_id
        .as_deref()
        .or(basic_client_auth
            .as_ref()
            .map(|auth| auth.client_id.as_str()))
        .or(req.client_id.as_deref())
        .or(inferred_client_id.as_deref())
        .unwrap_or("");
    let used_auth_method = if assertion_client_id.is_some() {
        "private_key_jwt"
    } else if mtls_x5t_s256.is_some() {
        "tls_client_auth"
    } else if basic_client_auth.is_some() {
        "client_secret_basic"
    } else if req.client_secret.is_some() {
        "client_secret_post"
    } else {
        "none"
    };

    if effective_client_id.is_empty() {
        return Err(QidError::BadRequest {
            message: "client_id required".to_string(),
        });
    }
    if !is_supported_grant_type(&req.grant_type) {
        return Err(QidError::BadRequest {
            message: "unsupported grant_type".to_string(),
        });
    }
    let client = find_client_across_realms(state, effective_client_id).await?;
    let realm_config = oauth_realm_config(state, &client.realm_id)?;
    let dpop_jkt = if let Some(ref dpop) = dpop_header {
        if !realm_config.protocols.oauth.dpop.enabled {
            return Err(QidError::BadRequest {
                message: "DPoP is disabled for client realm".to_string(),
            });
        }
        let token = crate::dpop::extract_dpop_jkt(dpop)?;
        let htu = state.plan.public_base_url.trim_end_matches('/').to_string();
        let htu = format!("{htu}{}", state.paths.token);
        crate::dpop::validate_dpop_proof(
            &state.dpop_state,
            &token,
            "POST",
            &htu,
            required_dpop_nonce_for_realm(realm_config, &token)?.as_deref(),
            state.signer.as_ref(),
        )?;
        Some(crate::dpop::dpop_jkt_from_proof(&token)?)
    } else {
        None
    };
    if mtls_x5t_s256.is_some() && !realm_config.protocols.oauth.mtls.enabled {
        return Err(QidError::BadRequest {
            message: "mTLS is disabled for client realm".to_string(),
        });
    }
    let mut cnf_claims = Map::new();
    if let Some(jkt) = &dpop_jkt {
        cnf_claims.insert("jkt".to_string(), serde_json::Value::String(jkt.clone()));
    }
    if let Some(x5t) = &mtls_x5t_s256 {
        cnf_claims.insert(
            "x5t#S256".to_string(),
            serde_json::Value::String(x5t.clone()),
        );
    }
    let cnf = (!cnf_claims.is_empty()).then_some(serde_json::Value::Object(cnf_claims));

    validate_client_auth_method(
        state,
        req,
        &client,
        used_auth_method,
        basic_client_auth.as_ref(),
        mtls_x5t_s256.as_deref(),
    )
    .await?;

    let result = match req.grant_type.as_str() {
        "authorization_code" => authorization_code_grant(state, req, &client, cnf.as_ref()).await,
        "client_credentials" => {
            client_credentials_grant(state, req, effective_client_id, cnf.as_ref()).await
        }
        "refresh_token" => refresh_token_grant(state, req, cnf.as_ref()).await,
        "urn:ietf:params:oauth:grant-type:token-exchange" => {
            advanced_subject_grant(state, req, &client, "token-exchange", cnf.as_ref()).await
        }
        "urn:ietf:params:oauth:grant-type:jwt-bearer" => {
            advanced_subject_grant(state, req, &client, "jwt-bearer", cnf.as_ref()).await
        }
        "urn:ietf:params:oauth:grant-type:saml2-bearer" => {
            advanced_subject_grant(state, req, &client, "saml2-bearer", cnf.as_ref()).await
        }
        "urn:ietf:params:oauth:grant-type:device_code" => {
            device_code_grant(state, req, cnf.as_ref()).await
        }
        "urn:openid:params:grant-type:ciba" => ciba_grant(state, req, cnf.as_ref()).await,
        _ => Err(QidError::BadRequest {
            message: "unsupported grant_type".to_string(),
        }),
    };
    if result.is_ok() {
        metrics::counter!("qid_token_issued_total", "grant_type" => metric_grant_type_label(&req.grant_type))
            .increment(1);
    }
    result
}

fn metric_grant_type_label(grant_type: &str) -> &'static str {
    match grant_type {
        "authorization_code" => "authorization_code",
        "client_credentials" => "client_credentials",
        "refresh_token" => "refresh_token",
        "urn:ietf:params:oauth:grant-type:token-exchange" => "token_exchange",
        "urn:ietf:params:oauth:grant-type:jwt-bearer" => "jwt_bearer",
        "urn:ietf:params:oauth:grant-type:saml2-bearer" => "saml2_bearer",
        "urn:ietf:params:oauth:grant-type:device_code" => "device_code",
        "urn:openid:params:grant-type:ciba" => "ciba",
        _ => "other",
    }
}

fn is_supported_grant_type(grant_type: &str) -> bool {
    matches!(
        grant_type,
        "authorization_code"
            | "client_credentials"
            | "refresh_token"
            | "urn:ietf:params:oauth:grant-type:token-exchange"
            | "urn:ietf:params:oauth:grant-type:jwt-bearer"
            | "urn:ietf:params:oauth:grant-type:saml2-bearer"
            | "urn:ietf:params:oauth:grant-type:device_code"
            | "urn:openid:params:grant-type:ciba"
    )
}

fn required_dpop_nonce_for_realm(
    realm: &qid_core::config::RealmConfig,
    dpop_proof: &str,
) -> QidResult<Option<String>> {
    if !realm.protocols.oauth.dpop.nonce {
        return Ok(None);
    }
    let nonce =
        crate::dpop::dpop_nonce_from_proof(dpop_proof)?.ok_or_else(|| QidError::BadRequest {
            message: "DPoP proof nonce is required".to_string(),
        })?;
    Ok(Some(nonce))
}

fn token_error_with_fresh_dpop_nonce<R: Repository>(
    state: &SharedState<R>,
    err: QidError,
) -> Response {
    let nonce = state
        .dpop_state
        .issue_nonce(qid_core::util::now_seconds())
        .ok();
    qid_http::dpop_nonce_error_response(err, nonce.as_deref())
}

async fn advanced_subject_grant<R: Repository>(
    state: &SharedState<R>,
    req: &TokenRequest,
    client: &Client,
    grant_name: &str,
    cnf: Option<&serde_json::Value>,
) -> QidResult<TokenResponse> {
    if req
        .requested_token_type
        .as_deref()
        .is_some_and(|token_type| token_type != "urn:ietf:params:oauth:token-type:access_token")
    {
        return Err(QidError::BadRequest {
            message: "only access_token requested_token_type is supported".to_string(),
        });
    }
    let subject_material = match grant_name {
        "token-exchange" => req
            .subject_token
            .as_deref()
            .ok_or_else(|| QidError::BadRequest {
                message: "subject_token required for token exchange".to_string(),
            })?,
        "jwt-bearer" | "saml2-bearer" => {
            req.assertion
                .as_deref()
                .ok_or_else(|| QidError::BadRequest {
                    message: "assertion required".to_string(),
                })?
        }
        _ => {
            return Err(QidError::BadRequest {
                message: format!("unsupported advanced grant: {grant_name}"),
            });
        }
    };
    let realm = state
        .realm(&client.realm_id)
        .ok_or_else(|| QidError::Config {
            message: format!("realm {} not found for client", client.realm_id),
        })?;
    let mut subject_user = User {
        id: format!(
            "{}:{}",
            grant_name,
            qid_core::util::sha256_base64url(subject_material)
        ),
        realm_id: client.realm_id.clone(),
        email: None,
        email_verified: false,
        display_name: Some(grant_name.to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    let mut inherited_cnf = None;
    let mut inherited_auth_time = Some(qid_core::util::now_seconds());
    let mut inherited_acr = None;
    let mut inherited_amr = Vec::new();
    let mut actor_claim = None;
    if grant_name == "token-exchange" {
        let subject_token_type =
            req.subject_token_type
                .as_deref()
                .ok_or_else(|| QidError::BadRequest {
                    message: "subject_token_type required for token exchange".to_string(),
                })?;
        match subject_token_type {
            "urn:ietf:params:oauth:token-type:access_token" => {
                let decoded = decode_access_token(state, subject_material).await?;
                subject_user = User {
                    id: decoded.user_id,
                    realm_id: realm.id.clone(),
                    email: None,
                    email_verified: false,
                    display_name: Some("token-exchange subject".to_string()),
                    failed_login_attempts: 0,
                    locked_until: None,
                    org: None,
                };
                inherited_cnf = decoded.cnf;
                inherited_auth_time = decoded.auth_time;
                inherited_acr = decoded.acr;
                inherited_amr = decoded.amr;
            }
            "urn:ietf:params:oauth:token-type:jwt" => {
                let assertion =
                    validate_jwt_bearer_assertion(state, client, &realm.issuer, subject_material)?;
                subject_user = User {
                    id: assertion.subject,
                    realm_id: realm.id.clone(),
                    email: None,
                    email_verified: false,
                    display_name: assertion
                        .issuer
                        .map(|iss| format!("token-exchange subject from {iss}")),
                    failed_login_attempts: 0,
                    locked_until: None,
                    org: None,
                };
                inherited_cnf = assertion.cnf;
                inherited_auth_time = assertion.auth_time;
                inherited_acr = assertion.acr;
                inherited_amr = assertion.amr;
            }
            "urn:ietf:params:oauth:token-type:saml2" => {
                let decrypted =
                    decrypt_encrypted_saml_assertion(state, &realm.id, subject_material)?;
                let assertion = qid_saml::validate_saml_bearer_assertion(
                    &decrypted,
                    &token_endpoint_url_for_realm(state, &realm.id),
                    qid_core::util::now_seconds(),
                    realm.saml_clock_skew_seconds,
                )?;
                subject_user = User {
                    id: assertion.subject,
                    realm_id: realm.id.clone(),
                    email: None,
                    email_verified: false,
                    display_name: Some(format!("token-exchange subject from {}", assertion.issuer)),
                    failed_login_attempts: 0,
                    locked_until: None,
                    org: None,
                };
                inherited_auth_time = assertion.auth_time;
                inherited_acr =
                    Some("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified".to_string());
                inherited_amr = vec!["saml".to_string()];
            }
            _ => {
                return Err(QidError::BadRequest {
                    message: format!("unsupported subject_token_type: {subject_token_type}"),
                });
            }
        }
        actor_claim = validate_token_exchange_actor(state, req, &realm.id).await?;
    }
    if grant_name == "jwt-bearer" {
        if req
            .subject_token_type
            .as_deref()
            .is_some_and(|token_type| token_type != "urn:ietf:params:oauth:token-type:jwt")
        {
            return Err(QidError::BadRequest {
                message: "only jwt subject_token_type is supported for jwt bearer".to_string(),
            });
        }
        let assertion =
            validate_jwt_bearer_assertion(state, client, &realm.issuer, subject_material)?;
        subject_user = User {
            id: assertion.subject,
            realm_id: realm.id.clone(),
            email: None,
            email_verified: false,
            display_name: assertion
                .issuer
                .map(|iss| format!("jwt-bearer subject from {iss}")),
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        };
        inherited_cnf = assertion.cnf;
        inherited_auth_time = assertion.auth_time;
        inherited_acr = assertion.acr;
        inherited_amr = assertion.amr;
    }
    if grant_name == "saml2-bearer" {
        if req
            .subject_token_type
            .as_deref()
            .is_some_and(|token_type| token_type != "urn:ietf:params:oauth:token-type:saml2")
        {
            return Err(QidError::BadRequest {
                message: "only saml2 subject_token_type is supported for saml2 bearer".to_string(),
            });
        }
        let decrypted = decrypt_encrypted_saml_assertion(state, &realm.id, subject_material)?;
        let assertion = qid_saml::validate_saml_bearer_assertion(
            &decrypted,
            &token_endpoint_url_for_realm(state, &realm.id),
            qid_core::util::now_seconds(),
            realm.saml_clock_skew_seconds,
        )?;
        subject_user = User {
            id: assertion.subject,
            realm_id: realm.id.clone(),
            email: None,
            email_verified: false,
            display_name: Some(format!("saml2-bearer subject from {}", assertion.issuer)),
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        };
        inherited_auth_time = assertion.auth_time;
        inherited_acr = Some("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified".to_string());
        inherited_amr = vec!["saml".to_string()];
    }
    let scopes = req
        .scope
        .as_deref()
        .map(|s| s.split(' ').map(String::from).collect::<Vec<_>>())
        .unwrap_or_else(|| vec![realm.oauth_default_scope.clone()]);
    let resources = req.resource.iter().cloned().collect::<Vec<_>>();
    if let Some(details) = &req.authorization_details {
        qid_core::oauth::validate_authorization_details(details)?;
    }
    let audiences = req
        .audience
        .as_deref()
        .map(|value| {
            value
                .split(' ')
                .filter(|part| !part.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let token_cnf = cnf.or(inherited_cnf.as_ref());
    let realm_config = state
        .config
        .realms
        .iter()
        .find(|candidate| candidate.id == realm.id)
        .ok_or_else(|| QidError::NotFound {
            resource: format!("realm {}", realm.id),
        })?;
    let audiences = qid_core::oauth::resolve_token_audience(
        realm_config,
        &audiences,
        &resources,
        &scopes,
        token_cnf,
    )?;
    let (access_token, expires_in) = issue_access_token(
        state,
        &realm.issuer,
        &subject_user,
        &client.client_id,
        &realm.id,
        &scopes,
        TokenIssueClaims {
            audience: Some(&audiences),
            resource: Some(&resources),
            authorization_details: req.authorization_details.as_ref(),
            cnf: token_cnf,
            auth_time: inherited_auth_time,
            acr: inherited_acr.as_deref(),
            amr: Some(&inherited_amr),
            nonce: None,
            act: actor_claim.as_ref(),
            authorization_code: None,
            access_token: None,
        },
    )
    .await?;
    Ok(TokenResponse {
        access_token,
        token_type: access_token_type_for_cnf(token_cnf).to_string(),
        expires_in,
        refresh_token: None,
        id_token: None,
        scope: Some(scopes.join(" ")),
        issued_token_type: (grant_name == "token-exchange")
            .then(|| "urn:ietf:params:oauth:token-type:access_token".to_string()),
    })
}

async fn validate_token_exchange_actor<R: Repository>(
    state: &SharedState<R>,
    req: &TokenRequest,
    realm_id: &str,
) -> QidResult<Option<serde_json::Value>> {
    let Some(actor_token) = req.actor_token.as_deref() else {
        if req.actor_token_type.is_some() {
            return Err(QidError::BadRequest {
                message: "actor_token required when actor_token_type is present".to_string(),
            });
        }
        return Ok(None);
    };
    let actor_token_type = req
        .actor_token_type
        .as_deref()
        .ok_or_else(|| QidError::BadRequest {
            message: "actor_token_type required when actor_token is present".to_string(),
        })?;
    match actor_token_type {
        "urn:ietf:params:oauth:token-type:access_token" => {
            let decoded = decode_access_token(state, actor_token).await?;
            Ok(Some(serde_json::json!({
                "sub": decoded.user_id,
                "client_id": decoded.client_id,
                "scope": decoded.scope
            })))
        }
        "urn:ietf:params:oauth:token-type:jwt" => {
            let _ = actor_token;
            Err(QidError::Unauthorized {
                message: "external actor JWT token exchange requires configured issuer, JWKS, and audience trust".to_string(),
            })
        }
        "urn:ietf:params:oauth:token-type:saml2" => {
            let decrypted = decrypt_encrypted_saml_assertion(state, realm_id, actor_token)?;
            let realm = state.realm(realm_id).ok_or_else(|| QidError::Config {
                message: format!("realm {realm_id} not found for actor token"),
            })?;
            let assertion = qid_saml::validate_saml_bearer_assertion(
                &decrypted,
                &token_endpoint_url_for_realm(state, realm_id),
                qid_core::util::now_seconds(),
                realm.saml_clock_skew_seconds,
            )?;
            Ok(Some(serde_json::json!({
                "sub": assertion.subject,
                "iss": assertion.issuer,
            })))
        }
        _ => Err(QidError::BadRequest {
            message: format!("unsupported actor_token_type: {actor_token_type}"),
        }),
    }
}

struct ValidatedJwtBearerAssertion {
    subject: String,
    issuer: Option<String>,
    auth_time: Option<u64>,
    acr: Option<String>,
    amr: Vec<String>,
    cnf: Option<serde_json::Value>,
}

fn validate_jwt_bearer_assertion<R: Repository>(
    state: &SharedState<R>,
    client: &Client,
    issuer: &str,
    assertion: &str,
) -> QidResult<ValidatedJwtBearerAssertion> {
    let (header, claims) = parse_jwt_unverified(assertion)?;
    verify_registered_jwk_signature(assertion, &header, &client.jwks, "jwt bearer assertion")?;
    let assertion_issuer =
        json_string_claim(&claims, "iss").ok_or_else(|| QidError::Unauthorized {
            message: "jwt bearer assertion missing iss claim".to_string(),
        })?;
    if assertion_issuer != client.client_id {
        return Err(QidError::Unauthorized {
            message: "jwt bearer assertion issuer is not a registered client".to_string(),
        });
    }
    let subject = json_string_claim(&claims, "sub")
        .filter(|sub| !sub.trim().is_empty())
        .ok_or_else(|| QidError::Unauthorized {
            message: "jwt bearer assertion missing sub claim".to_string(),
        })?;
    let token_url = format!("{}{}", issuer.trim_end_matches('/'), state.paths.token);
    if !json_audience_matches(claims.get("aud"), &token_url) {
        return Err(QidError::Unauthorized {
            message: "jwt bearer assertion audience mismatch".to_string(),
        });
    }
    let now = qid_core::util::now_seconds();
    let exp = claims
        .get("exp")
        .and_then(|value| value.as_u64())
        .ok_or_else(|| QidError::Unauthorized {
            message: "jwt bearer assertion missing exp claim".to_string(),
        })?;
    if exp <= now {
        return Err(QidError::Unauthorized {
            message: "jwt bearer assertion has expired".to_string(),
        });
    }
    if let Some(nbf) = claims.get("nbf").and_then(|value| value.as_u64())
        && nbf > now + 60
    {
        return Err(QidError::Unauthorized {
            message: "jwt bearer assertion is not yet valid".to_string(),
        });
    }
    if let Some(iat) = claims.get("iat").and_then(|value| value.as_u64())
        && iat > now + 60
    {
        return Err(QidError::Unauthorized {
            message: "jwt bearer assertion iat is in the future".to_string(),
        });
    }
    let jti = json_string_claim(&claims, "jti").ok_or_else(|| QidError::Unauthorized {
        message: "jwt bearer assertion missing jti claim".to_string(),
    })?;
    state.assertion_replay_cache.record_jti(&jti, now, now)?;
    let acr = claims
        .get("acr")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    let amr = claims
        .get("amr")
        .and_then(|value| value.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let cnf = claims.get("cnf").cloned();
    Ok(ValidatedJwtBearerAssertion {
        subject,
        issuer: Some(assertion_issuer),
        auth_time: claims
            .get("iat")
            .and_then(|value| value.as_u64())
            .or(Some(now)),
        acr,
        amr,
        cnf,
    })
}

fn parse_jwt_unverified(token: &str) -> QidResult<(serde_json::Value, serde_json::Value)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(QidError::Unauthorized {
            message: "invalid JWT format".to_string(),
        });
    }
    let header = decode_jwt_json(parts[0], "header")?;
    let payload = decode_jwt_json(parts[1], "payload")?;
    Ok((header, payload))
}

fn decode_jwt_json(part: &str, name: &str) -> QidResult<serde_json::Value> {
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
) -> QidResult<()> {
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

fn json_string_claim(claims: &serde_json::Value, name: &str) -> Option<String> {
    claims
        .get(name)
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
}

fn json_audience_matches(aud: Option<&serde_json::Value>, expected: &str) -> bool {
    match aud {
        Some(serde_json::Value::String(value)) => value == expected,
        Some(serde_json::Value::Array(values)) => {
            values.iter().any(|value| value.as_str() == Some(expected))
        }
        _ => false,
    }
}

#[derive(Debug)]
pub(crate) struct BasicClientAuth {
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
}

pub(crate) fn extract_basic_client_auth(headers: &HeaderMap) -> Option<BasicClientAuth> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    text.split_once(':').map(|(id, secret)| BasicClientAuth {
        client_id: id.to_string(),
        client_secret: secret.to_string(),
    })
}

pub(crate) fn verify_client_secret(
    client: &Client,
    presented_secret: Option<&str>,
) -> QidResult<()> {
    let presented_secret = presented_secret.ok_or_else(|| QidError::Unauthorized {
        message: "client_secret is required".to_string(),
    })?;
    if presented_secret.is_empty() {
        return Err(QidError::Unauthorized {
            message: "client_secret is required".to_string(),
        });
    }
    let expected_hash =
        client
            .client_secret_hash
            .as_deref()
            .ok_or_else(|| QidError::Unauthorized {
                message: "client secret is not configured".to_string(),
            })?;
    let presented_hash = qid_core::util::client_secret_hash(presented_secret);
    if !qid_core::util::constant_time_eq(expected_hash, &presented_hash) {
        return Err(QidError::Unauthorized {
            message: "invalid client_secret".to_string(),
        });
    }
    Ok(())
}

fn verify_mtls_thumbprint(client: &Client, presented_thumbprint: Option<&str>) -> QidResult<()> {
    let presented_thumbprint = presented_thumbprint.ok_or_else(|| QidError::Unauthorized {
        message: "mTLS client certificate is required".to_string(),
    })?;
    if client.mtls_certificate_thumbprints.is_empty() {
        return Err(QidError::Unauthorized {
            message: "mTLS certificate thumbprint is not configured".to_string(),
        });
    }
    if !client
        .mtls_certificate_thumbprints
        .iter()
        .any(|expected| qid_core::util::constant_time_eq(expected, presented_thumbprint))
    {
        return Err(QidError::Unauthorized {
            message: "mTLS certificate thumbprint is not allowed".to_string(),
        });
    }
    Ok(())
}

async fn validate_client_auth_method<R: Repository>(
    state: &SharedState<R>,
    req: &TokenRequest,
    client: &Client,
    used_auth_method: &str,
    basic_client_auth: Option<&BasicClientAuth>,
    mtls_x5t_s256: Option<&str>,
) -> QidResult<()> {
    if client.client_id.is_empty() {
        return Err(QidError::BadRequest {
            message: "client_id required".to_string(),
        });
    }

    if !client
        .grant_types
        .iter()
        .any(|grant| grant == &req.grant_type)
    {
        return Err(QidError::Unauthorized {
            message: "grant type not allowed for client".to_string(),
        });
    }
    if req.client_secret.is_some() && used_auth_method == "client_secret_basic" {
        return Err(QidError::Unauthorized {
            message: "multiple client authentication methods are not allowed".to_string(),
        });
    }
    if req.client_assertion.is_some() && used_auth_method != "private_key_jwt" {
        return Err(QidError::Unauthorized {
            message: "invalid client assertion authentication".to_string(),
        });
    }

    match client.client_type {
        ClientType::Public => {
            if client.token_endpoint_auth_method != "none" || used_auth_method != "none" {
                return Err(QidError::Unauthorized {
                    message: "public client must not use confidential authentication".to_string(),
                });
            }
        }
        ClientType::Confidential => {
            let expected = client.token_endpoint_auth_method.as_str();
            let mtls_auth_matches =
                matches!(expected, "tls_client_auth" | "self_signed_tls_client_auth")
                    && used_auth_method == "tls_client_auth";
            if expected != used_auth_method && !mtls_auth_matches {
                return Err(QidError::Unauthorized {
                    message: format!("confidential client must authenticate with {expected}"),
                });
            }
            if matches!(expected, "client_secret_basic" | "client_secret_post") {
                let presented_secret = if expected == "client_secret_basic" {
                    basic_client_auth.map(|auth| auth.client_secret.as_str())
                } else {
                    req.client_secret.as_deref()
                };
                verify_client_secret(client, presented_secret)?;
            }
            if matches!(expected, "tls_client_auth" | "self_signed_tls_client_auth") {
                verify_mtls_thumbprint(client, mtls_x5t_s256)?;
            }
            if expected == "private_key_jwt" {
                if !oauth_realm_config(state, &client.realm_id)?
                    .protocols
                    .oauth
                    .private_key_jwt
                    .enabled
                {
                    return Err(QidError::BadRequest {
                        message: "private_key_jwt is disabled for client realm".to_string(),
                    });
                }
                let assertion =
                    req.client_assertion
                        .as_deref()
                        .ok_or_else(|| QidError::Unauthorized {
                            message: "client_assertion is required".to_string(),
                        })?;
                crate::dpop::extract_private_key_jwt(
                    assertion,
                    &client.client_id,
                    &token_endpoint_url_for_realm(state, &client.realm_id),
                    &client.jwks,
                    &state.assertion_replay_cache,
                )?;
            }
        }
    }

    Ok(())
}

fn token_endpoint_url_for_realm<R: Repository>(state: &SharedState<R>, realm_id: &str) -> String {
    let issuer = state
        .realm(realm_id)
        .map(|r| r.issuer.clone().trim_end_matches('/').to_string())
        .unwrap_or_else(|| state.plan.public_base_url.trim_end_matches('/').to_string());
    format!("{issuer}{}", state.paths.token)
}

fn oauth_realm_config<'a, R: Repository>(
    state: &'a SharedState<R>,
    realm_id: &str,
) -> QidResult<&'a qid_core::config::RealmConfig> {
    state
        .config
        .realms
        .iter()
        .find(|realm| realm.id == realm_id)
        .ok_or_else(|| QidError::Config {
            message: format!("realm {realm_id} not found for OAuth client"),
        })
}

/// Decrypt an encrypted SAML assertion if the XML contains
/// `<saml:EncryptedAssertion>`.  Returns the original XML if it is
/// not encrypted.
fn decrypt_encrypted_saml_assertion<R: Repository>(
    state: &SharedState<R>,
    realm_id: &str,
    xml: &str,
) -> QidResult<String> {
    if !xml.contains("EncryptedAssertion") {
        return Ok(xml.to_string());
    }
    let realm_config = state
        .config
        .realms
        .iter()
        .find(|realm| realm.id == realm_id)
        .ok_or_else(|| QidError::Config {
            message: format!("realm {realm_id} not configured for SAML decryption"),
        })?;
    let key_path = realm_config
        .protocols
        .saml
        .idp_encryption_key_pem_path
        .as_deref()
        .ok_or_else(|| QidError::Config {
            message: "SAML encrypted assertion requires idp_encryption_key_pem_path".to_string(),
        })?;
    let key_pem = std::fs::read(key_path).map_err(|e| QidError::Config {
        message: format!("failed to read IdP encryption key at {key_path}: {e}"),
    })?;
    qid_saml::decrypt_saml_response(xml, &key_pem)
}

async fn infer_authorization_code_client_id<R: Repository>(
    state: &SharedState<R>,
    req: &TokenRequest,
) -> QidResult<Option<String>> {
    let Some(code) = req.code.as_deref() else {
        return Ok(None);
    };
    let code_hash = qid_core::util::sha256_base64url(code);
    Ok(state
        .repo
        .get_authorization_code(&code_hash)
        .await?
        .map(|code| code.client_id))
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
