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
    oauth::is_supported_grant_type,
    state::SharedState,
};
use qid_crypto::{Jwk, jwk::matching_jwk_candidates, jwt::verify_jwt_signature_with_jwk};
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
    let mtls_x5t_s256 =
        super::error_response_or_return!(super::extract_mtls_client_thumbprint(&state, &headers));
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
    let assertion_client_id = client_assertion_client_id(
        req.client_assertion.as_deref(),
        req.client_assertion_type.as_deref(),
    )?;
    let credentials = ClientCredentials {
        client_assertion: req.client_assertion.as_deref(),
        asserted_client_id: assertion_client_id.as_deref(),
        basic: basic_client_auth.as_ref(),
        form_client_secret: req.client_secret.as_deref(),
        mtls_x5t_s256: mtls_x5t_s256.as_deref(),
    };
    let presented_client_id = credentials.routed_client_id(req.client_id.as_deref());
    let inferred_client_id =
        if presented_client_id.unwrap_or("").is_empty() && req.grant_type == "authorization_code" {
            infer_authorization_code_client_id(state, req).await?
        } else {
            None
        };
    let effective_client_id = presented_client_id
        .or(inferred_client_id.as_deref())
        .unwrap_or("");
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
    let client = super::find_client_across_realms(state, effective_client_id).await?;
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
    let exchange_proof = ExchangeProof {
        dpop_jkt: dpop_jkt.as_deref(),
        mtls_x5t_s256: mtls_x5t_s256.as_deref(),
    };

    validate_client_auth_method(state, req, &client, &credentials)?;

    // A supplied form client_id is untrusted routing: when it disagrees with
    // the authenticated client (Basic or private_key_jwt take precedence
    // over the form), fail before any device/CIBA grant is consumed, so one
    // confidential client cannot redeem another client's grant by naming it.
    if matches!(
        req.grant_type.as_str(),
        "urn:ietf:params:oauth:grant-type:device_code" | "urn:openid:params:grant-type:ciba"
    ) {
        reject_client_id_mismatch(&client.client_id, req.client_id.as_deref())?;
    }

    let metric_start = std::time::Instant::now();
    let metric_grant_type = metric_grant_type_label(&req.grant_type);
    let metric_realm = client.realm_id.clone();
    let result = match req.grant_type.as_str() {
        "authorization_code" => authorization_code_grant(state, req, &client, cnf.as_ref()).await,
        "client_credentials" => client_credentials_grant(state, req, &client, cnf.as_ref()).await,
        "refresh_token" => refresh_token_grant(state, req, &client, cnf.as_ref()).await,
        "urn:ietf:params:oauth:grant-type:token-exchange" => {
            advanced_subject_grant(
                state,
                req,
                &client,
                "token-exchange",
                cnf.as_ref(),
                exchange_proof,
            )
            .await
        }
        "urn:ietf:params:oauth:grant-type:jwt-bearer" => {
            advanced_subject_grant(
                state,
                req,
                &client,
                "jwt-bearer",
                cnf.as_ref(),
                exchange_proof,
            )
            .await
        }
        "urn:ietf:params:oauth:grant-type:saml2-bearer" => {
            advanced_subject_grant(
                state,
                req,
                &client,
                "saml2-bearer",
                cnf.as_ref(),
                exchange_proof,
            )
            .await
        }
        "urn:ietf:params:oauth:grant-type:device_code" => {
            device_code_grant(state, req, cnf.as_ref()).await
        }
        "urn:openid:params:grant-type:ciba" => ciba_grant(state, req, cnf.as_ref()).await,
        _ => Err(QidError::BadRequest {
            message: "unsupported grant_type".to_string(),
        }),
    };
    metrics::histogram!(
        "qid_token_issue_duration_seconds",
        "grant_type" => metric_grant_type,
        "realm" => metric_realm.clone()
    )
    .record(metric_start.elapsed().as_secs_f64());
    if result.is_ok() {
        metrics::counter!(
            "qid_token_issued_total",
            "grant_type" => metric_grant_type,
            "realm" => metric_realm
        )
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

fn required_dpop_nonce_for_realm(
    realm: &qid_core::config::RealmConfig,
    dpop_proof: &str,
) -> QidResult<Option<String>> {
    if !realm.protocols.oauth.dpop.nonce {
        return Ok(None);
    }
    let nonce =
        crate::dpop::dpop_nonce_from_proof(dpop_proof)?.ok_or_else(|| QidError::DpopNonce {
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

fn oauth_saml_subject_id(
    realm_id: &str,
    assertion: &qid_saml::SamlBearerAssertion,
) -> QidResult<String> {
    const UNSPECIFIED_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
    let name_id = &assertion.name_id;
    let format = name_id.format.as_deref().unwrap_or(UNSPECIFIED_FORMAT);
    let tuple = serde_json::to_vec(&(
        realm_id,
        &assertion.issuer,
        &name_id.value,
        format,
        &name_id.name_qualifier,
        &name_id.sp_name_qualifier,
        &name_id.sp_provided_id,
    ))
    .map_err(|error| QidError::Internal {
        message: format!("failed to serialize SAML OAuth identity tuple: {error}"),
    })?;
    let mut encoded = b"qid:oauth:saml-subject:v2\0".to_vec();
    encoded.extend_from_slice(&tuple);
    Ok(format!(
        "saml2:v2:{}",
        qid_core::util::sha256_base64url(encoded)
    ))
}

fn oauth_jwt_subject_id(realm_id: &str, issuer: &str, subject: &str) -> String {
    let tuple = serde_json::json!([realm_id, issuer, subject]).to_string();
    let mut encoded = b"qid:oauth:jwt-subject:v1\0".to_vec();
    encoded.extend_from_slice(tuple.as_bytes());
    format!("jwt:v1:{}", qid_core::util::sha256_base64url(encoded))
}

/// Sender proofs presented by the token-exchange request itself.
#[derive(Clone, Copy)]
struct ExchangeProof<'a> {
    dpop_jkt: Option<&'a str>,
    mtls_x5t_s256: Option<&'a str>,
}

/// qid token-exchange policy: a constrained subject may be exchanged only
/// when the exchange proves every sender constraint the subject carries.
/// Unknown or malformed `cnf` members fail closed; an unconstrained subject
/// may acquire a fresh proof. This is not a general RFC 8693 requirement.
fn validate_exchange_sender_constraint(
    inherited_cnf: Option<&serde_json::Value>,
    proof: ExchangeProof<'_>,
) -> QidResult<()> {
    let Some(cnf) = inherited_cnf else {
        return Ok(());
    };
    let Some(members) = cnf.as_object() else {
        return Err(QidError::Unauthorized {
            message: "subject_token cnf must be an object".to_string(),
        });
    };
    if members.is_empty() {
        return Err(QidError::Unauthorized {
            message: "subject_token cnf has no supported sender constraint".to_string(),
        });
    }
    for (member, expected) in members {
        let (presented, proof_name) = match member.as_str() {
            "jkt" => (proof.dpop_jkt, "DPoP proof jkt"),
            "x5t#S256" => (proof.mtls_x5t_s256, "mTLS certificate thumbprint"),
            _ => {
                return Err(QidError::Unauthorized {
                    message: format!("unsupported subject_token cnf member: {member}"),
                });
            }
        };
        let expected = expected.as_str().ok_or_else(|| QidError::Unauthorized {
            message: format!("invalid subject_token cnf member: {member}"),
        })?;
        let presented = presented.ok_or_else(|| QidError::Unauthorized {
            message: format!("token exchange requires matching {proof_name} for subject_token cnf"),
        })?;
        if presented != expected {
            return Err(QidError::Unauthorized {
                message: format!("token exchange {proof_name} does not match subject_token cnf"),
            });
        }
    }
    Ok(())
}

async fn advanced_subject_grant<R: Repository>(
    state: &SharedState<R>,
    req: &TokenRequest,
    client: &Client,
    grant_name: &str,
    cnf: Option<&serde_json::Value>,
    proof: ExchangeProof<'_>,
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
    let realm_config = state
        .config
        .realms
        .iter()
        .find(|candidate| candidate.id == realm.id)
        .ok_or_else(|| QidError::NotFound {
            resource: format!("realm {}", realm.id),
        })?;
    let mut subject_token_scopes: Option<Vec<String>> = None;
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
    let mut inherited_auth_time = None;
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
                if decoded.realm_id != realm.id {
                    return Err(QidError::BadRequest {
                        message: "subject_token realm does not match client realm".to_string(),
                    });
                }
                if decoded.client_id != client.client_id
                    && !decoded.aud.iter().any(|audience| {
                        realm_config
                            .protocols
                            .oauth
                            .resource_servers
                            .iter()
                            .any(|server| audience == &server.audience)
                    })
                {
                    return Err(QidError::BadRequest {
                        message: "subject_token is not owned by the exchange client or targeted to a registered resource server".to_string(),
                    });
                }
                subject_token_scopes = Some(
                    decoded
                        .scope
                        .split_whitespace()
                        .map(str::to_owned)
                        .collect(),
                );
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
                let assertion = validate_jwt_bearer_assertion(
                    state,
                    client,
                    &realm.issuer,
                    subject_material,
                    qid_core::util::now_seconds(),
                )?;
                subject_user = User {
                    id: oauth_jwt_subject_id(&realm.id, &assertion.issuer, &assertion.subject),
                    realm_id: realm.id.clone(),
                    email: None,
                    email_verified: false,
                    display_name: Some(format!("token-exchange subject from {}", assertion.issuer)),
                    failed_login_attempts: 0,
                    locked_until: None,
                    org: None,
                };
                inherited_cnf = assertion.cnf;
            }
            "urn:ietf:params:oauth:token-type:saml2" => {
                let decrypted =
                    decrypt_encrypted_saml_assertion(state, &realm.id, subject_material)?;
                let assertion = validate_oauth_saml_bearer_assertion(
                    state,
                    &realm.id,
                    &decrypted,
                    &token_endpoint_url_for_realm(state, &realm.id),
                    realm.saml_clock_skew_seconds,
                )?;
                subject_user = User {
                    id: oauth_saml_subject_id(&realm.id, &assertion)?,
                    realm_id: realm.id.clone(),
                    email: None,
                    email_verified: false,
                    display_name: Some(format!("token-exchange subject from {}", assertion.issuer)),
                    failed_login_attempts: 0,
                    locked_until: None,
                    org: None,
                };
                // External SAML authentication class, not a qid-issued ACR;
                // no qid step-up or risk predicate matches it.
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
        validate_exchange_sender_constraint(inherited_cnf.as_ref(), proof)?;
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
        let assertion = validate_jwt_bearer_assertion(
            state,
            client,
            &realm.issuer,
            subject_material,
            qid_core::util::now_seconds(),
        )?;
        subject_user = User {
            id: oauth_jwt_subject_id(&realm.id, &assertion.issuer, &assertion.subject),
            realm_id: realm.id.clone(),
            email: None,
            email_verified: false,
            display_name: Some(format!("jwt-bearer subject from {}", assertion.issuer)),
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        };
        inherited_cnf = assertion.cnf;
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
        let assertion = validate_oauth_saml_bearer_assertion(
            state,
            &realm.id,
            &decrypted,
            &token_endpoint_url_for_realm(state, &realm.id),
            realm.saml_clock_skew_seconds,
        )?;
        subject_user = User {
            id: oauth_saml_subject_id(&realm.id, &assertion)?,
            realm_id: realm.id.clone(),
            email: None,
            email_verified: false,
            display_name: Some(format!("saml2-bearer subject from {}", assertion.issuer)),
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        };
        // External SAML authentication class, not a qid-issued ACR; no qid
        // step-up or risk predicate matches it.
        inherited_auth_time = assertion.auth_time;
        inherited_acr = Some("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified".to_string());
        inherited_amr = vec!["saml".to_string()];
    }
    let requested_scopes = req
        .scope
        .as_deref()
        .map(|s| s.split(' ').map(String::from).collect::<Vec<_>>());
    let scopes = match (subject_token_scopes.as_ref(), requested_scopes) {
        (Some(subject_scopes), Some(requested)) => {
            if requested
                .iter()
                .any(|scope| !subject_scopes.contains(scope))
            {
                return Err(QidError::BadRequest {
                    message: "requested scope is outside subject_token scopes".to_string(),
                });
            }
            requested
        }
        (Some(subject_scopes), None) => subject_scopes.clone(),
        (None, Some(requested)) => requested,
        (None, None) => vec![realm.oauth_default_scope.clone()],
    };
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
            access_expires_at: None,
            session_id: None,
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
            if decoded.realm_id != realm_id {
                return Err(QidError::BadRequest {
                    message: "actor_token realm does not match client realm".to_string(),
                });
            }
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
            let assertion = validate_oauth_saml_bearer_assertion(
                state,
                realm_id,
                &decrypted,
                &token_endpoint_url_for_realm(state, realm_id),
                realm.saml_clock_skew_seconds,
            )?;
            let subject_id = oauth_saml_subject_id(realm_id, &assertion)?;
            Ok(Some(serde_json::json!({
                "sub": subject_id,
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
    issuer: String,
    cnf: Option<serde_json::Value>,
}

fn validate_jwt_bearer_assertion<R: Repository>(
    state: &SharedState<R>,
    client: &Client,
    issuer: &str,
    assertion: &str,
    now: u64,
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
    state.assertion_replay_cache.record_assertion_jti(
        qid_core::cache::ASSERTION_SCOPE_OAUTH_JWT_BEARER,
        &client.client_id,
        &jti,
        exp,
        now,
        "jwt bearer assertion jti already used (replay detected)",
    )?;
    let cnf = claims.get("cnf").cloned();
    Ok(ValidatedJwtBearerAssertion {
        subject,
        issuer: assertion_issuer,
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
    let candidates = matching_jwk_candidates(keys, kid);
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

/// Certificate metadata is collected only when a realm enables mTLS; the
/// client's own realm is enforced with its authentication method.
pub(crate) fn extract_mtls_client_thumbprint<R: Repository>(
    state: &SharedState<R>,
    headers: &HeaderMap,
) -> QidResult<Option<String>> {
    if state
        .config
        .realms
        .iter()
        .any(|realm| realm.protocols.oauth.mtls.enabled)
    {
        crate::mtls::extract_mtls_x5t_s256(headers, state)
    } else {
        Ok(None)
    }
}

/// Credentials presented at a client-authenticated OAuth endpoint. Both the
/// token endpoint and device authorization resolve the same precedence here;
/// grant-specific checks stay at their endpoints.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClientCredentials<'a> {
    pub(crate) client_assertion: Option<&'a str>,
    pub(crate) asserted_client_id: Option<&'a str>,
    pub(crate) basic: Option<&'a BasicClientAuth>,
    pub(crate) form_client_secret: Option<&'a str>,
    pub(crate) mtls_x5t_s256: Option<&'a str>,
}

impl<'a> ClientCredentials<'a> {
    /// A JWT assertion outranks Basic, which outranks the form `client_id`.
    pub(crate) fn routed_client_id(&self, form_client_id: Option<&'a str>) -> Option<&'a str> {
        self.asserted_client_id
            .or_else(|| self.basic.map(|auth| auth.client_id.as_str()))
            .or(form_client_id)
    }

    /// A trusted certificate binds an issued token but does not replace the
    /// client's configured client-authentication method.
    pub(crate) fn used_auth_method<'c>(&self, client: &'c Client) -> &'c str {
        if self.asserted_client_id.is_some() {
            "private_key_jwt"
        } else if self.basic.is_some() {
            "client_secret_basic"
        } else if self.form_client_secret.is_some() {
            "client_secret_post"
        } else if self.mtls_x5t_s256.is_some()
            && matches!(
                client.token_endpoint_auth_method.as_str(),
                "tls_client_auth" | "self_signed_tls_client_auth"
            )
        {
            client.token_endpoint_auth_method.as_str()
        } else {
            "none"
        }
    }
}

pub(crate) fn client_assertion_client_id(
    assertion: Option<&str>,
    assertion_type: Option<&str>,
) -> QidResult<Option<String>> {
    const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    let Some(assertion) = assertion else {
        return Ok(None);
    };
    if assertion_type.unwrap_or(JWT_BEARER) != JWT_BEARER {
        return Ok(None);
    }
    Ok(Some(crate::dpop::extract_client_id_from_assertion(
        assertion,
    )?))
}

/// A stronger credential identifies the client; the form `client_id` is only
/// routing data and must not redirect its grant or authorization request.
pub(crate) fn reject_client_id_mismatch(
    authenticated_client_id: &str,
    form_client_id: Option<&str>,
) -> QidResult<()> {
    if form_client_id.is_some_and(|form| form != authenticated_client_id) {
        return Err(QidError::Unauthorized {
            message: "authenticated client does not match request client_id".to_string(),
        });
    }
    Ok(())
}

/// Verify the method a client is registered for at either OAuth endpoint.
pub(crate) fn validate_client_authentication<R: Repository>(
    state: &SharedState<R>,
    client: &Client,
    credentials: &ClientCredentials<'_>,
) -> QidResult<()> {
    let used_auth_method = credentials.used_auth_method(client);
    let realm_config = oauth_realm_config(state, &client.realm_id)?;
    if credentials.mtls_x5t_s256.is_some() && !realm_config.protocols.oauth.mtls.enabled {
        return Err(QidError::BadRequest {
            message: "mTLS is disabled for client realm".to_string(),
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
            if expected != used_auth_method {
                return Err(QidError::Unauthorized {
                    message: format!("confidential client must authenticate with {expected}"),
                });
            }
            if matches!(expected, "client_secret_basic" | "client_secret_post") {
                let presented_secret = if expected == "client_secret_basic" {
                    credentials.basic.map(|auth| auth.client_secret.as_str())
                } else {
                    credentials.form_client_secret
                };
                verify_client_secret(client, presented_secret)?;
            }
            if matches!(expected, "tls_client_auth" | "self_signed_tls_client_auth") {
                verify_mtls_thumbprint(client, credentials.mtls_x5t_s256)?;
            }
            if expected == "private_key_jwt" {
                if !realm_config.protocols.oauth.private_key_jwt.enabled {
                    return Err(QidError::BadRequest {
                        message: "private_key_jwt is disabled for client realm".to_string(),
                    });
                }
                let assertion =
                    credentials
                        .client_assertion
                        .ok_or_else(|| QidError::Unauthorized {
                            message: "client_assertion is required".to_string(),
                        })?;
                crate::dpop::extract_private_key_jwt(
                    assertion,
                    &client.client_id,
                    &realm_config.issuer,
                    &client.jwks,
                    &state.assertion_replay_cache,
                )?;
            }
        }
    }
    Ok(())
}

pub(crate) fn verify_mtls_thumbprint(
    client: &Client,
    presented_thumbprint: Option<&str>,
) -> QidResult<()> {
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

fn validate_client_auth_method<R: Repository>(
    state: &SharedState<R>,
    req: &TokenRequest,
    client: &Client,
    credentials: &ClientCredentials<'_>,
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
    let used_auth_method = credentials.used_auth_method(client);
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
    validate_client_authentication(state, client, credentials)
}

/// Validate OAuth SAML inputs only against the issuer-bound inbound federation trust
/// configured for this realm. The verifier never uses assertion KeyInfo as trust.
fn validate_oauth_saml_bearer_assertion<R: Repository>(
    state: &SharedState<R>,
    realm_id: &str,
    xml: &str,
    expected_audience: &str,
    clock_skew_seconds: u64,
) -> QidResult<qid_saml::SamlBearerAssertion> {
    let realm_config = oauth_realm_config(state, realm_id)?;
    let federation = &realm_config.protocols.federation;
    if !federation.enabled {
        return Err(QidError::Unauthorized {
            message: "OAuth SAML assertions require enabled inbound federation trust".into(),
        });
    }

    let providers = federation.inbound_providers.iter().filter(|provider| {
        provider.enabled
            && provider.kind == "saml"
            && !provider.saml_signing_certificates.is_empty()
    });
    let mut attempted = false;
    let mut last_error = None;
    for provider in providers {
        attempted = true;
        match qid_saml::validate_saml_bearer_assertion(
            xml,
            expected_audience,
            qid_core::util::now_seconds(),
            clock_skew_seconds,
            &provider.saml_signing_certificates,
        ) {
            Ok(assertion) if assertion.issuer == provider.issuer => {
                state.assertion_replay_cache.record_replay_key(
                    &format!(
                        "oauth-saml:{}:{}:{}",
                        realm_id, provider.issuer, assertion.assertion_id
                    ),
                    assertion.expires_at.saturating_add(clock_skew_seconds),
                    qid_core::util::now_seconds(),
                    "SAML assertion ID already used (replay detected)",
                )?;
                return Ok(assertion);
            }
            Ok(_) => {
                last_error = Some(QidError::Unauthorized {
                    message: "verified SAML assertion issuer does not match configured provider"
                        .into(),
                });
            }
            Err(error) => last_error = Some(error),
        }
    }
    if !attempted {
        return Err(QidError::Unauthorized {
            message: "no enabled inbound SAML provider with signing certificates is configured"
                .into(),
        });
    }
    Err(last_error.unwrap_or_else(|| QidError::Unauthorized {
        message: "SAML assertion does not match configured inbound provider trust".into(),
    }))
}

fn token_endpoint_url_for_realm<R: Repository>(state: &SharedState<R>, realm_id: &str) -> String {
    let issuer = state
        .realm(realm_id)
        .map(|r| r.issuer.clone().trim_end_matches('/').to_string())
        .unwrap_or_else(|| state.plan.public_base_url.trim_end_matches('/').to_string());
    format!("{issuer}{}", state.paths.token)
}

pub(super) fn oauth_realm_config<'a, R: Repository>(
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

#[cfg(test)]
mod client_auth_tests {
    use super::*;

    fn client_with_method(method: &str) -> Client {
        serde_json::from_value(serde_json::json!({
            "id": "client-id",
            "realm_id": "realm",
            "client_id": "client",
            "client_type": "confidential",
            "token_endpoint_auth_method": method,
            "redirect_uris": [],
            "grant_types": [],
        }))
        .unwrap()
    }

    #[test]
    fn credential_precedence_and_method_resolution_are_shared() {
        let basic = BasicClientAuth {
            client_id: "basic-client".to_string(),
            client_secret: "secret".to_string(),
        };
        let mtls_client = client_with_method("tls_client_auth");
        let all = ClientCredentials {
            client_assertion: Some("assertion"),
            asserted_client_id: Some("jwt-client"),
            basic: Some(&basic),
            form_client_secret: Some("form-secret"),
            mtls_x5t_s256: Some("thumbprint"),
        };
        assert_eq!(
            all.routed_client_id(Some("form-client")),
            Some("jwt-client")
        );
        assert_eq!(all.used_auth_method(&mtls_client), "private_key_jwt");

        let without_assertion = ClientCredentials {
            asserted_client_id: None,
            ..all
        };
        assert_eq!(
            without_assertion.routed_client_id(Some("form-client")),
            Some("basic-client")
        );
        assert_eq!(
            without_assertion.used_auth_method(&mtls_client),
            "client_secret_basic"
        );

        let without_basic = ClientCredentials {
            basic: None,
            ..without_assertion
        };
        assert_eq!(
            without_basic.routed_client_id(Some("form-client")),
            Some("form-client")
        );
        assert_eq!(
            without_basic.used_auth_method(&client_with_method("client_secret_post")),
            "client_secret_post"
        );

        let certificate_only = ClientCredentials {
            form_client_secret: None,
            ..without_basic
        };
        assert_eq!(
            certificate_only.used_auth_method(&mtls_client),
            "tls_client_auth"
        );
        // A certificate binds a token but never replaces a different method.
        assert_eq!(
            certificate_only.used_auth_method(&client_with_method("client_secret_basic")),
            "none"
        );
    }

    #[test]
    fn stronger_credential_must_match_routed_client_id() {
        assert!(reject_client_id_mismatch("client", None).is_ok());
        assert!(reject_client_id_mismatch("client", Some("client")).is_ok());
        let error = reject_client_id_mismatch("client", Some("other")).unwrap_err();
        assert_eq!(
            error.message(),
            "unauthorized: authenticated client does not match request client_id"
        );
    }

    #[test]
    fn shared_mtls_verifier_requires_a_registered_thumbprint() {
        let mut client = client_with_method("tls_client_auth");
        client.mtls_certificate_thumbprints = vec!["registered".to_string()];
        assert!(verify_mtls_thumbprint(&client, Some("registered")).is_ok());
        assert_eq!(
            verify_mtls_thumbprint(&client, None).unwrap_err().message(),
            "unauthorized: mTLS client certificate is required"
        );
        assert_eq!(
            verify_mtls_thumbprint(&client, Some("other"))
                .unwrap_err()
                .message(),
            "unauthorized: mTLS certificate thumbprint is not allowed"
        );
        client.mtls_certificate_thumbprints.clear();
        assert_eq!(
            verify_mtls_thumbprint(&client, Some("registered"))
                .unwrap_err()
                .message(),
            "unauthorized: mTLS certificate thumbprint is not configured"
        );
    }
}

#[cfg(test)]
mod saml_subject_id_tests {
    use super::oauth_saml_subject_id;

    #[test]
    fn realm_scoping() -> Result<(), Box<dyn std::error::Error>> {
        let assertion: qid_saml::SamlBearerAssertion =
            serde_json::from_str(include_str!("../../tests/data/saml-subject.json"))?;
        assert_ne!(
            oauth_saml_subject_id("realm-a", &assertion)?,
            oauth_saml_subject_id("realm-b", &assertion)?
        );
        Ok(())
    }
}
