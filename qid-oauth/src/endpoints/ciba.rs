use axum::{
    Form, Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use qid_core::{
    config::CibaMode,
    error::{QidError, QidResult},
    models::{BackchannelAuthenticationGrant, Client, ClientType},
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
    let client = find_ciba_client(state, &req.client_id).await?;
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
        .map(|s| s.split(' ').map(String::from).collect::<Vec<_>>())
        .unwrap_or_else(|| vec![realm.oidc_default_scope.clone()]);
    let grant = BackchannelAuthenticationGrant {
        auth_req_id_hash: qid_core::util::sha256_base64url(&auth_req_id),
        client_id: req.client_id,
        realm_id: realm.id.clone(),
        login_hint: req.login_hint,
        binding_message: req.binding_message,
        scopes,
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

async fn find_ciba_client<R: Repository>(
    state: &SharedState<R>,
    client_id: &str,
) -> QidResult<Client> {
    let mut found = None;
    for realm in &state.config.realms {
        if let Some(client) = state
            .repo
            .get_client_by_client_id(&RealmId::from(realm.id.clone()), client_id)
            .await?
        {
            if found.is_some() {
                return Err(QidError::Unauthorized {
                    message: "CIBA client realm is ambiguous".to_string(),
                });
            }
            found = Some(client);
        }
    }
    found.ok_or_else(|| QidError::Unauthorized {
        message: "unknown client".to_string(),
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
    Json(req): Json<BackchannelAuthenticationApprovalRequest>,
) -> Response {
    let auth_req_id_hash = qid_core::util::sha256_base64url(&req.auth_req_id);
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
        Err(e) => return qid_http::error_response(e),
    };
    if grant.user_id.as_deref() != Some(req.user_id.as_str()) {
        return qid_http::error_response(QidError::Unauthorized {
            message: "approval subject does not match login_hint".to_string(),
        });
    }
    match state.repo.get_user_by_id(&req.user_id).await {
        Ok(Some(user)) => {
            if user.realm_id != grant.realm_id {
                return qid_http::error_response(QidError::Unauthorized {
                    message: "approval user realm does not match CIBA grant".to_string(),
                });
            }
        }
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: "user".to_string(),
            });
        }
        Err(e) => return qid_http::error_response(e),
    }
    // Require an active session for CIBA approval.
    let realm_cfg = state.plan.realms.iter().find(|r| r.id == grant.realm_id);
    let Some(realm_cfg) = realm_cfg else {
        return qid_http::error_response(QidError::Config {
            message: format!("realm '{}' not found for CIBA grant", grant.realm_id),
        });
    };
    let cookie_name = &realm_cfg.browser_session.cookie_name;
    if let Some(session_id) = extract_cookie(&headers, cookie_name) {
        match state.repo.get_session(session_id).await {
            Ok(Some(session)) => {
                if !qid_session::browser::session_is_active(&session, qid_core::util::now_seconds())
                {
                    return qid_http::error_response(QidError::Unauthorized {
                        message: "session is no longer active".to_string(),
                    });
                }
                if session.user_id != req.user_id {
                    return qid_http::error_response(QidError::Unauthorized {
                        message: "session user does not match approval user".to_string(),
                    });
                }
                if session.realm_id != grant.realm_id {
                    return qid_http::error_response(QidError::Unauthorized {
                        message: "session realm does not match CIBA grant".to_string(),
                    });
                }
            }
            Ok(None) => {
                return qid_http::error_response(QidError::Unauthorized {
                    message: "invalid or expired session".to_string(),
                });
            }
            Err(e) => return qid_http::error_response(e),
        }
    } else {
        return qid_http::error_response(QidError::Unauthorized {
            message: "authentication required: missing session cookie".to_string(),
        });
    }
    match state
        .repo
        .approve_backchannel_authentication_grant(
            &auth_req_id_hash,
            &req.user_id,
            qid_core::util::now_seconds(),
        )
        .await
    {
        Ok(()) => {}
        Err(e) => return qid_http::error_response(e),
    }
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
    let realm = state
        .realm(&grant.realm_id)
        .ok_or_else(|| QidError::NotFound {
            resource: format!("realm {}", grant.realm_id),
        })?;
    if !oauth_feature_enabled(state, &grant.realm_id, |oauth| oauth.ciba.enabled) {
        return Err(QidError::BadRequest {
            message: "CIBA is disabled".to_string(),
        });
    }
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
        &grant.scopes,
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
            &grant.scopes,
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
            },
            sub_override.as_deref(),
        )?),
        scope: Some(grant.scopes.join(" ")),
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
