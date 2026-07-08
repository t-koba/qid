use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use qid_core::{
    error::{QidError, QidResult},
    models::{Client, DeviceAuthorizationGrant},
    state::SharedState,
    tenant::RealmId,
};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::{
    TokenIssueClaims, TokenRequest, TokenResponse, access_token_type_for_cnf, issue_token_pair,
    oauth_feature_enabled,
};

#[derive(Debug, Deserialize)]
pub struct DeviceAuthorizationRequest {
    pub client_id: String,
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Debug, Deserialize)]
pub struct DeviceAuthorizationApprovalRequest {
    pub user_code: String,
}

#[derive(Debug, Serialize)]
pub struct DeviceAuthorizationApprovalResponse {
    pub approved: bool,
    pub user_code: String,
}

pub async fn device_authorization<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Form(req): Form<DeviceAuthorizationRequest>,
) -> Response {
    let client = match find_device_authorization_client(&state, &req.client_id).await {
        Ok(client) => client,
        Err(e) => return qid_http::error_response(e),
    };
    let realm = match state.realm(&client.realm_id) {
        Some(realm) => realm,
        None => {
            return qid_http::error_response(QidError::Config {
                message: format!("realm {} not found for device client", client.realm_id),
            });
        }
    };
    if !oauth_feature_enabled(&state, &realm.id, |oauth| {
        oauth.device_authorization.enabled
    }) {
        return qid_http::error_response(QidError::BadRequest {
            message: "device authorization is disabled".to_string(),
        });
    }
    if !client
        .grant_types
        .iter()
        .any(|grant| grant == "urn:ietf:params:oauth:grant-type:device_code")
    {
        return qid_http::error_response(QidError::Unauthorized {
            message: "device grant not allowed for client".to_string(),
        });
    }
    let code = ulid::Ulid::new().to_string();
    let user_code = format!("QID-{}", &code[10..23]);
    let base = state.plan.public_base_url.trim_end_matches('/');
    let verification_uri = format!("{base}{}", state.paths.device_authorization);
    let verification_uri_complete = format!("{verification_uri}?user_code={user_code}");
    let scope = req
        .scope
        .as_deref()
        .map(|s| s.split(' ').map(String::from).collect::<Vec<_>>())
        .unwrap_or_else(|| vec![realm.oauth_default_scope.clone()]);
    let device_code = format!("dc_{code}");
    let now = qid_core::util::now_seconds();
    let ttl_seconds = state
        .realm(&client.realm_id)
        .map(|realm| realm.token_ttl.device_code_ttl_seconds)
        .unwrap_or_else(|| qid_core::config::TokenTtlConfig::default().device_code_ttl_seconds);
    let grant = DeviceAuthorizationGrant {
        device_code_hash: qid_core::util::sha256_base64url(&device_code),
        user_code: user_code.clone(),
        client_id: req.client_id,
        realm_id: realm.id.clone(),
        scopes: scope,
        user_id: None,
        expires_at: now + ttl_seconds,
        approved_at: None,
        consumed: false,
        last_poll_at: None,
        poll_interval_seconds: 5,
        created_at: now,
    };
    if let Err(e) = state.repo.store_device_authorization_grant(&grant).await {
        return qid_http::error_response(e);
    }
    Json(DeviceAuthorizationResponse {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete,
        expires_in: ttl_seconds,
        interval: 5,
    })
    .into_response()
}

async fn find_device_authorization_client<R: Repository>(
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
                    message: "device authorization client realm is ambiguous".to_string(),
                });
            }
            found = Some(client);
        }
    }
    found.ok_or_else(|| QidError::Unauthorized {
        message: "unknown client".to_string(),
    })
}

pub async fn device_authorization_approve<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<DeviceAuthorizationApprovalRequest>,
) -> Response {
    if !state.config.realms.iter().any(|realm| {
        oauth_feature_enabled(&state, &realm.id, |oauth| {
            oauth.device_authorization.enabled
        })
    }) {
        return qid_http::error_response(QidError::BadRequest {
            message: "device authorization is disabled".to_string(),
        });
    }
    match approve_device_authorization(&state, &req, &headers).await {
        Ok(()) => Json(DeviceAuthorizationApprovalResponse {
            approved: true,
            user_code: req.user_code,
        })
        .into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

async fn approve_device_authorization<R: Repository>(
    state: &SharedState<R>,
    req: &DeviceAuthorizationApprovalRequest,
    headers: &HeaderMap,
) -> QidResult<()> {
    let grant = state
        .repo
        .get_device_authorization_grant_by_user_code(&req.user_code)
        .await?
        .ok_or_else(|| QidError::NotFound {
            resource: "device authorization grant".to_string(),
        })?;

    let realm_cfg = state
        .realm(&grant.realm_id)
        .ok_or_else(|| QidError::Config {
            message: format!("realm {} not found", grant.realm_id),
        })?;

    let cookie_name = &realm_cfg.browser_session.cookie_name;
    let session_id =
        extract_cookie(headers, cookie_name).ok_or_else(|| QidError::Unauthorized {
            message: "authentication required: missing session cookie".to_string(),
        })?;

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

    let user_id = session.user_id;
    let user = state
        .repo
        .get_user_by_id(&user_id)
        .await?
        .ok_or_else(|| QidError::NotFound {
            resource: "user".to_string(),
        })?;

    if user.realm_id != grant.realm_id {
        return Err(QidError::Unauthorized {
            message: "approval subject does not belong to the same realm as the device authorization grant"
                .to_string(),
        });
    }

    state
        .repo
        .approve_device_authorization_grant(&req.user_code, &user_id, qid_core::util::now_seconds())
        .await
}

fn extract_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let cookie_str = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in cookie_str.split(';') {
        let pair = pair.trim();
        if let Some((key, value)) = pair.split_once('=')
            && key.trim() == name
        {
            return Some(value.trim());
        }
    }
    None
}

pub(crate) async fn device_code_grant<R: Repository>(
    state: &SharedState<R>,
    req: &TokenRequest,
    cnf: Option<&serde_json::Value>,
) -> QidResult<TokenResponse> {
    let device_code = req
        .device_code
        .as_deref()
        .ok_or_else(|| QidError::BadRequest {
            message: "device_code required".to_string(),
        })?;
    let device_code_hash = qid_core::util::sha256_base64url(device_code);
    let grant = state
        .repo
        .get_device_authorization_grant(&device_code_hash)
        .await?
        .ok_or_else(|| QidError::Unauthorized {
            message: "invalid device_code".to_string(),
        })?;
    let now = qid_core::util::now_seconds();
    if grant.expires_at <= now {
        return Err(QidError::Unauthorized {
            message: "expired_token".to_string(),
        });
    }
    if grant.consumed {
        return Err(QidError::Unauthorized {
            message: "invalid device_code".to_string(),
        });
    }
    if req.client_id.as_deref() != Some(grant.client_id.as_str()) {
        return Err(QidError::Unauthorized {
            message: "client_id does not match device_code".to_string(),
        });
    }
    if grant.user_id.is_none() {
        enforce_device_poll_interval(state, &device_code_hash, &grant, now).await?;
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
            message: "user realm does not match device authorization grant realm".to_string(),
        });
    }
    let realm = state
        .realm(&grant.realm_id)
        .ok_or_else(|| QidError::NotFound {
            resource: format!("realm {}", grant.realm_id),
        })?;
    if !oauth_feature_enabled(state, &grant.realm_id, |oauth| {
        oauth.device_authorization.enabled
    }) {
        return Err(QidError::BadRequest {
            message: "device authorization is disabled".to_string(),
        });
    }
    state
        .repo
        .consume_device_authorization_grant(&device_code_hash)
        .await?;
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
            auth_time: Some(now),
            acr: None,
            amr: None,
            nonce: None,
            act: None,
            authorization_code: None,
            access_token: None,
        },
    )
    .await?;
    Ok(TokenResponse {
        access_token: pair.access_token,
        token_type: access_token_type_for_cnf(cnf).to_string(),
        expires_in: pair.expires_in,
        refresh_token: Some(pair.refresh_token),
        id_token: None,
        scope: Some(grant.scopes.join(" ")),
        issued_token_type: None,
    })
}

const MAX_POLL_INTERVAL_SECONDS: u64 = 60;

async fn enforce_device_poll_interval<R: Repository>(
    state: &SharedState<R>,
    device_code_hash: &str,
    grant: &DeviceAuthorizationGrant,
    now: u64,
) -> QidResult<()> {
    let next_interval = if let Some(last_poll_at) = grant.last_poll_at {
        let earliest_next_poll = last_poll_at.saturating_add(grant.poll_interval_seconds);
        if now < earliest_next_poll {
            grant
                .poll_interval_seconds
                .saturating_add(5)
                .min(MAX_POLL_INTERVAL_SECONDS)
        } else {
            grant.poll_interval_seconds
        }
    } else {
        grant.poll_interval_seconds
    };
    state
        .repo
        .record_device_authorization_poll(device_code_hash, now, next_interval)
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
