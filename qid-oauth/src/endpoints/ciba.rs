use axum::{
    Form, Json,
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use qid_core::web::JsonObject;
use qid_core::{
    config::CibaMode,
    error::{QidError, QidResult},
    models::{BackchannelAuthenticationGrant, ClientType},
    state::SharedState,
    tenant::RealmId,
};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::{
    TokenIssueClaims, TokenRequest, TokenResponse, access_token_type_for_cnf, issue_id_token,
    issue_token_pair, oauth_feature_enabled, verify_client_secret,
};

#[derive(Debug, Deserialize)]
pub struct BackchannelAuthenticationRequest {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
    pub resource: Option<String>,
    pub login_hint: String,
    pub binding_message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BackchannelAuthenticationResponse {
    pub auth_req_id: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Debug, Deserialize)]
pub struct BackchannelAuthenticationApprovalRequest {
    pub auth_req_id: String,
    pub user_id: String,
}

#[derive(Debug, Serialize)]
pub struct BackchannelAuthenticationApprovalResponse {
    pub approved: bool,
}

#[derive(Debug, Deserialize)]
pub struct BackchannelAuthenticationContextQuery {
    pub auth_req_id: String,
}

#[derive(Debug, Serialize)]
pub struct BackchannelAuthenticationContextResponse {
    pub client_id: String,
    pub scopes: Vec<String>,
    pub resource: Vec<String>,
    pub audience: Vec<String>,
}

pub async fn backchannel_authentication<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Form(req): Form<BackchannelAuthenticationRequest>,
) -> Response {
    match create_backchannel_authentication_grant(&state, req).await {
        Ok(resp) => Json(resp).into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

async fn create_backchannel_authentication_grant<R: Repository>(
    state: &SharedState<R>,
    req: BackchannelAuthenticationRequest,
) -> QidResult<BackchannelAuthenticationResponse> {
    let client = super::find_client_across_realms_with_messages(
        state,
        &req.client_id,
        "CIBA client realm is ambiguous",
        "unknown client",
    )
    .await?;
    let realm = state
        .realm(&client.realm_id)
        .ok_or_else(|| QidError::Config {
            message: format!("realm {} not found for CIBA client", client.realm_id),
        })?;
    let ciba_enabled = state
        .config
        .realms
        .iter()
        .find(|candidate| candidate.id == realm.id)
        .is_some_and(|candidate| candidate.protocols.oauth.ciba.enabled);
    if !ciba_enabled {
        return Err(QidError::BadRequest {
            message: "CIBA is disabled".to_string(),
        });
    }
    if client.client_type != ClientType::Confidential {
        return Err(QidError::Unauthorized {
            message: "CIBA requires a confidential client".to_string(),
        });
    }
    if !client
        .grant_types
        .iter()
        .any(|grant| grant == "urn:openid:params:grant-type:ciba")
    {
        return Err(QidError::Unauthorized {
            message: "CIBA grant not allowed for client".to_string(),
        });
    }
    if client.token_endpoint_auth_method != "client_secret_post" {
        return Err(QidError::Unauthorized {
            message: "CIBA client must authenticate with client_secret_post".to_string(),
        });
    }
    verify_client_secret(&client, req.client_secret.as_deref())?;
    let user = state
        .repo
        .get_user_by_email(&RealmId::from(realm.id.clone()), &req.login_hint)
        .await?
        .ok_or_else(|| QidError::Unauthorized {
            message: "unknown login_hint".to_string(),
        })?;
    let auth_req_id = format!("ciba_{}", ulid::Ulid::new());
    let now = qid_core::util::now_seconds();
    let scopes = req
        .scope
        .as_deref()
        .unwrap_or(realm.oidc_default_scope.as_str())
        .split(' ')
        .map(String::from)
        .collect::<Vec<_>>();
    let resource = req.resource.iter().cloned().collect::<Vec<_>>();
    let realm_config = super::token::oauth_realm_config(state, &realm.id);
    let audience =
        qid_core::oauth::resolve_authorization_audience(realm_config?, &[], &resource, &scopes)?;
    let grant = BackchannelAuthenticationGrant {
        auth_req_id_hash: qid_core::util::sha256_base64url(&auth_req_id),
        client_id: req.client_id,
        realm_id: realm.id.clone(),
        login_hint: req.login_hint,
        binding_message: req.binding_message,
        scopes,
        resource,
        audience,
        user_id: Some(user.id),
        expires_at: now + 600,
        approved_at: None,
        consumed: false,
        last_poll_at: None,
        poll_interval_seconds: 5,
        created_at: now,
    };
    state
        .repo
        .store_backchannel_authentication_grant(&grant)
        .await?;
    Ok(BackchannelAuthenticationResponse {
        auth_req_id,
        expires_in: 600,
        interval: 5,
    })
}

fn extract_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let cookie = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for pair in cookie.split(';') {
        let mut parts = pair.splitn(2, '=');
        if parts.next()?.trim() == name {
            return Some(parts.next()?.trim());
        }
    }
    None
}

pub async fn backchannel_authentication_approve<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    JsonObject(req): JsonObject<BackchannelAuthenticationApprovalRequest>,
) -> Response {
    let auth_req_id_hash = qid_core::util::sha256_base64url(&req.auth_req_id);
    let grant = match super::error_response_or_return!(
        state
            .repo
            .get_backchannel_authentication_grant(&auth_req_id_hash)
            .await
    ) {
        Some(grant) => grant,
        None => {
            return qid_http::error_response(QidError::NotFound {
                resource: "backchannel authentication grant".to_string(),
            });
        }
    };
    if grant.user_id.as_deref() != Some(req.user_id.as_str()) {
        return qid_http::error_response(QidError::Unauthorized {
            message: "approval subject does not match login_hint".to_string(),
        });
    }
    if let Err(error) = authorize_ciba_browser_session(&state, &headers, &grant, &req.user_id).await
    {
        return qid_http::error_response(error);
    }
    super::error_response_or_return!(
        state
            .repo
            .approve_backchannel_authentication_grant(
                &auth_req_id_hash,
                &req.user_id,
                qid_core::util::now_seconds(),
            )
            .await
    );
    // In Ping mode, notify the client's backchannel notification endpoint asynchronously.
    let ciba_mode = state
        .config
        .realms
        .iter()
        .find(|candidate| candidate.id == grant.realm_id)
        .map(|candidate| candidate.protocols.oauth.ciba.mode)
        .unwrap_or(CibaMode::Poll);
    if ciba_mode == CibaMode::Ping
        && let Ok(Some(client)) = state
            .repo
            .get_client_by_client_id(&RealmId::from(grant.realm_id.clone()), &grant.client_id)
            .await
        && let Some(notification_endpoint) = &client.backchannel_client_notification_endpoint
    {
        let auth_req_id = req.auth_req_id.clone();
        let endpoint = notification_endpoint.clone();
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let payload = serde_json::json!({ "auth_req_id": auth_req_id });
            match client
                .post(&endpoint)
                .json(&payload)
                .timeout(std::time::Duration::from_secs(10))
                .send()
                .await
            {
                Ok(response) => {
                    if !response.status().is_success() {
                        tracing::warn!(
                            "CIBA ping notification to {} returned {}",
                            endpoint,
                            response.status()
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("CIBA ping notification to {} failed: {e}", endpoint);
                }
            }
        });
    }
    Json(BackchannelAuthenticationApprovalResponse { approved: true }).into_response()
}

async fn authorize_ciba_browser_session<R: Repository>(
    state: &SharedState<R>,
    headers: &HeaderMap,
    grant: &BackchannelAuthenticationGrant,
    approval_user_id: &str,
) -> QidResult<()> {
    let user = state
        .repo
        .get_user_by_id(approval_user_id)
        .await?
        .ok_or_else(|| QidError::NotFound {
            resource: "user".to_string(),
        })?;
    if user.realm_id != grant.realm_id {
        return Err(QidError::Unauthorized {
            message: "approval user realm does not match CIBA grant".to_string(),
        });
    }
    // Require a live browser session whose user and realm match the grant.
    let realm_cfg = state.plan.realms.iter().find(|r| r.id == grant.realm_id);
    let Some(realm_cfg) = realm_cfg else {
        return Err(QidError::Config {
            message: format!("realm '{}' not found for CIBA grant", grant.realm_id),
        });
    };
    let cookie_name = &realm_cfg.browser_session.cookie_name;
    let Some(session_id) = extract_cookie(headers, cookie_name) else {
        return Err(QidError::Unauthorized {
            message: "authentication required: missing session cookie".to_string(),
        });
    };
    let session =
        state
            .repo
            .get_session(session_id)
            .await?
            .ok_or_else(|| QidError::Unauthorized {
                message: "invalid or expired session".to_string(),
            })?;
    if !qid_session::browser::session_is_active(&session, qid_core::util::now_seconds()) {
        return Err(QidError::Unauthorized {
            message: "session is no longer active".to_string(),
        });
    }
    if session.user_id != approval_user_id {
        return Err(QidError::Unauthorized {
            message: "session user does not match approval user".to_string(),
        });
    }
    if session.realm_id != grant.realm_id {
        return Err(QidError::Unauthorized {
            message: "session realm does not match CIBA grant".to_string(),
        });
    }
    Ok(())
}

/// Read-only approval context for the CIBA approval path. It returns the
/// immutable stored target before approval and never mutates the grant.
pub async fn backchannel_authentication_context<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Query(query): Query<BackchannelAuthenticationContextQuery>,
) -> Response {
    let auth_req_id_hash = qid_core::util::sha256_base64url(&query.auth_req_id);
    let grant = match state
        .repo
        .get_backchannel_authentication_grant(&auth_req_id_hash)
        .await
    {
        Ok(Some(grant)) => grant,
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: "backchannel authentication grant".to_string(),
            });
        }
        Err(error) => return qid_http::error_response(error),
    };
    if grant.expires_at <= qid_core::util::now_seconds() || grant.consumed {
        return qid_http::error_response(QidError::NotFound {
            resource: "backchannel authentication grant".to_string(),
        });
    }
    let Some(approval_user_id) = grant.user_id.clone() else {
        return qid_http::error_response(QidError::Unauthorized {
            message: "approval subject does not match login_hint".to_string(),
        });
    };
    if let Err(error) =
        authorize_ciba_browser_session(&state, &headers, &grant, &approval_user_id).await
    {
        return qid_http::error_response(error);
    }
    Json(BackchannelAuthenticationContextResponse {
        client_id: grant.client_id.clone(),
        scopes: grant.scopes.clone(),
        resource: grant.resource.clone(),
        audience: grant.audience.clone(),
    })
    .into_response()
}

pub(crate) async fn ciba_grant<R: Repository>(
    state: &SharedState<R>,
    req: &TokenRequest,
    cnf: Option<&serde_json::Value>,
) -> QidResult<TokenResponse> {
    let auth_req_id = req
        .auth_req_id
        .as_deref()
        .ok_or_else(|| QidError::BadRequest {
            message: "auth_req_id required".to_string(),
        })?;
    let auth_req_id_hash = qid_core::util::sha256_base64url(auth_req_id);
    let grant = state
        .repo
        .get_backchannel_authentication_grant(&auth_req_id_hash)
        .await?
        .ok_or_else(|| QidError::Unauthorized {
            message: "invalid auth_req_id".to_string(),
        })?;
    let now = qid_core::util::now_seconds();
    if grant.expires_at <= now {
        return Err(QidError::Unauthorized {
            message: "expired_token".to_string(),
        });
    }
    if grant.consumed {
        return Err(QidError::Unauthorized {
            message: "invalid auth_req_id".to_string(),
        });
    }
    if req.client_id.as_deref() != Some(grant.client_id.as_str()) {
        return Err(QidError::Unauthorized {
            message: "client_id does not match auth_req_id".to_string(),
        });
    }
    if grant.approved_at.is_none() {
        enforce_ciba_poll_interval(state, &auth_req_id_hash, &grant, now).await?;
        return Err(QidError::Unauthorized {
            message: "authorization_pending".to_string(),
        });
    }
    let user_id = grant
        .user_id
        .clone()
        .ok_or_else(|| QidError::Unauthorized {
            message: "authorization_pending".to_string(),
        })?;
    let user = state
        .repo
        .get_user_by_id(&user_id)
        .await?
        .ok_or_else(|| QidError::NotFound {
            resource: "user".to_string(),
        })?;
    if user.realm_id != grant.realm_id {
        return Err(QidError::Unauthorized {
            message: "CIBA grant user realm mismatch".to_string(),
        });
    }
    let realm = state.require_realm(&grant.realm_id)?;
    if !oauth_feature_enabled(state, &grant.realm_id, |oauth| oauth.ciba.enabled) {
        return Err(QidError::BadRequest {
            message: "CIBA is disabled".to_string(),
        });
    }
    let realm_config = super::token::oauth_realm_config(state, &grant.realm_id)?;
    let scopes = super::validate_grant_target(
        realm_config,
        req,
        &grant.client_id,
        &grant.resource,
        &grant.audience,
        &grant.scopes,
        cnf,
    )?;
    state
        .repo
        .consume_backchannel_authentication_grant(&auth_req_id_hash)
        .await?;
    let ciba_amr = vec!["ciba".to_string()];
    let pair = issue_token_pair(
        state,
        &realm.issuer,
        &user,
        &grant.client_id,
        &grant.realm_id,
        &scopes,
        TokenIssueClaims {
            audience: Some(&grant.audience),
            resource: Some(&grant.resource),
            authorization_details: None,
            cnf,
            auth_time: grant.approved_at,
            acr: Some("urn:qid:acr:ciba"),
            amr: Some(&ciba_amr),
            nonce: None,
            act: None,
            authorization_code: None,
            access_token: None,
            access_expires_at: None,
            session_id: None,
        },
    )
    .await?;
    let client = state
        .repo
        .get_client_by_client_id(&RealmId::from(grant.realm_id.clone()), &grant.client_id)
        .await?
        .ok_or_else(|| QidError::NotFound {
            resource: format!("client {}", grant.client_id),
        })?;
    let sub_override = if client.subject_type.as_deref() == Some("pairwise") {
        Some(qid_core::compute_pairwise_sub(
            &user.id,
            &qid_core::sector_identifier_for_client(&client),
            &realm.issuer,
        ))
    } else {
        None
    };

    Ok(TokenResponse {
        access_token: pair.access_token,
        token_type: access_token_type_for_cnf(cnf).to_string(),
        expires_in: pair.expires_in,
        refresh_token: Some(pair.refresh_token),
        id_token: Some(issue_id_token(
            state,
            &realm.issuer,
            &user,
            &grant.client_id,
            &grant.realm_id,
            &scopes,
            TokenIssueClaims {
                audience: None,
                resource: None,
                authorization_details: None,
                cnf,
                auth_time: grant.approved_at,
                acr: Some("urn:qid:acr:ciba"),
                amr: Some(&ciba_amr),
                nonce: None,
                act: None,
                authorization_code: None,
                access_token: None,
                access_expires_at: None,
                session_id: None,
            },
            sub_override.as_deref(),
        )?),
        scope: Some(scopes.join(" ")),
        issued_token_type: None,
    })
}

async fn enforce_ciba_poll_interval<R: Repository>(
    state: &SharedState<R>,
    auth_req_id_hash: &str,
    grant: &BackchannelAuthenticationGrant,
    now: u64,
) -> QidResult<()> {
    let next_interval = if let Some(last_poll_at) = grant.last_poll_at {
        let earliest_next_poll = last_poll_at.saturating_add(grant.poll_interval_seconds);
        if now < earliest_next_poll {
            grant.poll_interval_seconds.saturating_add(5)
        } else {
            grant.poll_interval_seconds
        }
    } else {
        grant.poll_interval_seconds
    };
    state
        .repo
        .record_backchannel_authentication_poll(auth_req_id_hash, now, next_interval)
        .await?;
    if grant
        .last_poll_at
        .is_some_and(|last_poll_at| now < last_poll_at.saturating_add(grant.poll_interval_seconds))
    {
        return Err(QidError::Unauthorized {
            message: "slow_down".to_string(),
        });
    }
    Ok(())
}
