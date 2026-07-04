//! WebAuthn handlers.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use qid_core::{error::QidError, state::SharedState, tenant::RealmId};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::{build_webauthn_service, extract_cookie};
use crate::browser::SessionManager;
use crate::webauthn::{WebAuthnState, webauthn_state_key};

use axum::Extension;
use rand::RngCore;
use sha2::Digest;

#[derive(Debug, Deserialize)]
pub struct WebAuthnStartRequest {
    email: String,
    display_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WebAuthnStartResponse {
    challenge: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct WebAuthnFinishRequest {
    user_id: String,
    response: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct WebAuthnAuthStartRequest {
    email: String,
}

#[derive(Debug, Deserialize)]
pub struct WebAuthnAuthFinishRequest {
    email: String,
    response: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct WebAuthnDiscoverableStartResponse {
    ceremony_id: String,
    challenge: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct WebAuthnDiscoverableFinishRequest {
    ceremony_id: String,
    response: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct WebAuthnDiscoverableFinishResponse {
    session: String,
    user: DiscoverableUserResponse,
}

#[derive(Debug, Serialize)]
pub struct DiscoverableUserResponse {
    id: String,
    email: Option<String>,
}

pub async fn webauthn_register_start<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Extension(webauthn_state): Extension<Arc<WebAuthnState>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Json(req): Json<WebAuthnStartRequest>,
) -> Response {
    let webauthn = match build_webauthn_service(&state, &realm) {
        Ok(w) => w,
        Err(e) => return qid_http::error_response(e),
    };

    let user = match state
        .repo
        .get_user_by_email(&RealmId(realm.clone()), &req.email)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("user with email {}", req.email),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };
    let session_user_id =
        match require_webauthn_registration_session(&state, &realm, &headers).await {
            Ok(user_id) => user_id,
            Err(response) => return response,
        };
    if user.realm_id != realm || user.id != session_user_id {
        return qid_http::error_response(QidError::Unauthorized {
            message: "session user does not match WebAuthn registration user".to_string(),
        });
    }

    let display_name = req.display_name.as_deref().unwrap_or(&req.email);
    let state_key = webauthn_state_key(&realm, &user.id);
    match webauthn.start_registration(
        &webauthn_state,
        &state_key,
        &user.id,
        &req.email,
        display_name,
    ) {
        Ok(challenge) => {
            let body = Json(WebAuthnStartResponse { challenge });
            (StatusCode::OK, body).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub async fn webauthn_register_finish<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Extension(webauthn_state): Extension<Arc<WebAuthnState>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Json(req): Json<WebAuthnFinishRequest>,
) -> Response {
    let session_user_id =
        match require_webauthn_registration_session(&state, &realm, &headers).await {
            Ok(user_id) => user_id,
            Err(response) => return response,
        };
    if session_user_id != req.user_id {
        return qid_http::error_response(QidError::Unauthorized {
            message: "session user does not match WebAuthn registration user".to_string(),
        });
    }
    let user = match state.repo.get_user_by_id(&req.user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("user {}", req.user_id),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };
    if user.realm_id != realm {
        return qid_http::error_response(QidError::Unauthorized {
            message: "WebAuthn registration user does not belong to request realm".to_string(),
        });
    }

    let state_key = webauthn_state_key(&realm, &user.id);
    let webauthn = match build_webauthn_service(&state, &realm) {
        Ok(w) => w,
        Err(e) => return qid_http::error_response(e),
    };

    match webauthn.finish_registration(&webauthn_state, &state_key, &user.id, req.response) {
        Ok(cred) => {
            metrics::counter!("qid_webauthn_ceremonies_total", "ceremony" => "register")
                .increment(1);
            if let Err(e) = state.repo.store_webauthn_credential(&cred).await {
                return qid_http::error_response(e);
            }
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "credential_id": cred.id })),
            )
                .into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

async fn require_webauthn_registration_session<R: Repository>(
    state: &Arc<SharedState<R>>,
    realm: &str,
    headers: &HeaderMap,
) -> Result<String, Response> {
    let realm_config = state.realm(realm).ok_or_else(|| {
        qid_http::error_response(QidError::NotFound {
            resource: format!("realm {realm}"),
        })
    })?;
    let cookie_name = &realm_config.browser_session.cookie_name;
    let session_id = extract_cookie(headers, cookie_name).ok_or_else(|| {
        qid_http::error_response(QidError::Unauthorized {
            message: "missing session cookie".to_string(),
        })
    })?;
    let manager = SessionManager::new(
        state.repo.clone(),
        realm_config.browser_session.idle_timeout_minutes,
        realm_config.browser_session.absolute_timeout_hours,
    );
    let session = manager
        .get(&session_id)
        .await
        .map_err(qid_http::error_response)?
        .ok_or_else(|| {
            qid_http::error_response(QidError::Unauthorized {
                message: "invalid or expired session".to_string(),
            })
        })?;
    if session.realm_id != realm {
        return Err(qid_http::error_response(QidError::Unauthorized {
            message: "session realm does not match request realm".to_string(),
        }));
    }
    Ok(session.user_id)
}

pub async fn webauthn_auth_start<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Extension(webauthn_state): Extension<Arc<WebAuthnState>>,
    Path(realm): Path<String>,
    Json(req): Json<WebAuthnAuthStartRequest>,
) -> Response {
    let user = match state
        .repo
        .get_user_by_email(&RealmId(realm.clone()), &req.email)
        .await
    {
        Ok(user) => user,
        Err(e) => return qid_http::error_response(e),
    };

    let webauthn = match build_webauthn_service(&state, &realm) {
        Ok(w) => w,
        Err(e) => return qid_http::error_response(e),
    };

    let (user_id, creds) = match user {
        Some(user) => {
            let creds = match state.repo.get_webauthn_credentials(&user.id).await {
                Ok(c) => c,
                Err(e) => return qid_http::error_response(e),
            };
            (user.id, creds)
        }
        None => (
            format!(
                "unknown:{}",
                qid_core::util::sha256_base64url(format!("{}:{}", realm, req.email))
            ),
            Vec::new(),
        ),
    };

    let passkeys: Vec<_> = creds
        .iter()
        .filter_map(|c| serde_json::from_slice::<webauthn_rs::prelude::Passkey>(&c.public_key).ok())
        .collect();

    let state_key = webauthn_state_key(&realm, &user_id);
    match webauthn.start_authentication(&webauthn_state, &state_key, &passkeys) {
        Ok(challenge) => {
            let body = Json(WebAuthnStartResponse { challenge });
            (StatusCode::OK, body).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub async fn webauthn_auth_finish<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Extension(webauthn_state): Extension<Arc<WebAuthnState>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Json(req): Json<WebAuthnAuthFinishRequest>,
) -> Response {
    let realm_config = match state.realm(&realm) {
        Some(r) => r,
        None => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("realm {}", realm),
            });
        }
    };

    let webauthn = match build_webauthn_service(&state, &realm) {
        Ok(w) => w,
        Err(e) => return qid_http::error_response(e),
    };

    let user = match state
        .repo
        .get_user_by_email(&RealmId(realm.clone()), &req.email)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("user with email {}", req.email),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };

    let state_key = webauthn_state_key(&realm, &user.id);
    let auth_result =
        match webauthn.finish_authentication(&webauthn_state, &state_key, req.response) {
            Ok(r) => {
                metrics::counter!("qid_webauthn_ceremonies_total", "ceremony" => "authenticate")
                    .increment(1);
                r
            }
            Err(e) => return qid_http::error_response(e),
        };

    // Verify signCount monotonicity (credential cloning detection)
    let creds = match state.repo.get_webauthn_credentials(&user.id).await {
        Ok(c) => c,
        Err(e) => return qid_http::error_response(e),
    };
    let used_cred_id = auth_result.cred_id();
    if let Some(cred) = creds
        .iter()
        .find(|c| c.credential_id.as_slice() == used_cred_id.as_ref())
    {
        let new_counter = auth_result.counter() as u64;
        // WebAuthn L3 §6.1.1: authenticators that do not implement a
        // signature counter always return 0.  Allow 0→0 transitions.
        if (new_counter != 0 || cred.counter != 0) && new_counter <= cred.counter {
            return qid_http::error_response(QidError::Crypto {
                message: "credential cloning detected: signCount did not increase".to_string(),
            });
        }
        if let Err(e) = state
            .repo
            .update_webauthn_credential_counter(&cred.id, new_counter)
            .await
        {
            return qid_http::error_response(e);
        }
    }

    let session_config = &realm_config.browser_session;
    let old_session_id = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie_str| {
            cookie_str.split(';').find_map(|pair| {
                let pair = pair.trim();
                pair.split_once('=').and_then(|(key, value)| {
                    if key.trim() == session_config.cookie_name {
                        Some(value.trim().to_string())
                    } else {
                        None
                    }
                })
            })
        });
    let manager = SessionManager::new(
        state.repo.clone(),
        session_config.idle_timeout_minutes,
        session_config.absolute_timeout_hours,
    );

    let session = match manager
        .create_with_regeneration(
            &realm,
            &user.id,
            "phr",                                   // ACR = phishing-resistant
            &["phr".to_string(), "hwk".to_string()], // AMR
            old_session_id.as_deref(),
        )
        .await
    {
        Ok(s) => s,
        Err(e) => return qid_http::error_response(e),
    };

    let cookie_value = format!(
        "{}={}; HttpOnly; Secure; Path=/; SameSite={}",
        session_config.cookie_name, session.id, session_config.same_site,
    );

    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, cookie_value.parse().unwrap());

    let body = Json(serde_json::json!({
        "session": session.id,
        "user": {
            "id": user.id,
            "email": user.email,
        }
    }));

    (headers, body).into_response()
}

pub async fn webauthn_discoverable_auth_start<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Extension(webauthn_state): Extension<Arc<WebAuthnState>>,
    Path(realm): Path<String>,
) -> Response {
    let _realm_config = match state.realm(&realm) {
        Some(r) => r,
        None => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("realm {}", realm),
            });
        }
    };

    let webauthn = match build_webauthn_service(&state, &realm) {
        Ok(w) => w,
        Err(e) => return qid_http::error_response(e),
    };

    let ceremony_id = format!("disc_{:016x}", rand::thread_rng().next_u64());
    let ceremony_key = format!("{}:{}", realm, ceremony_id);

    match webauthn.start_discoverable_authentication(&webauthn_state, &ceremony_key) {
        Ok(challenge) => {
            let body = Json(WebAuthnDiscoverableStartResponse {
                ceremony_id,
                challenge,
            });
            (StatusCode::OK, body).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub async fn webauthn_discoverable_auth_finish<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Extension(webauthn_state): Extension<Arc<WebAuthnState>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Json(req): Json<WebAuthnDiscoverableFinishRequest>,
) -> Response {
    let realm_config = match state.realm(&realm) {
        Some(r) => r,
        None => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("realm {}", realm),
            });
        }
    };

    let webauthn = match build_webauthn_service(&state, &realm) {
        Ok(w) => w,
        Err(e) => return qid_http::error_response(e),
    };

    let ceremony_key = format!("{}:{}", realm, req.ceremony_id);

    let (user_uuid, _cred_id) = match webauthn.identify_discoverable_authentication(&req.response) {
        Ok(r) => r,
        Err(e) => return qid_http::error_response(e),
    };

    let user_hash = sha2::Sha256::digest(user_uuid.as_bytes());
    let users = match state.repo.list_users(&RealmId(realm.clone())).await {
        Ok(u) => u,
        Err(e) => return qid_http::error_response(e),
    };

    let matched_user = users.into_iter().find(|u| {
        let expected = sha2::Sha256::digest(u.id.as_bytes());
        expected[..16] == user_hash[..16]
    });

    let user = match matched_user {
        Some(u) => u,
        None => {
            return qid_http::error_response(QidError::NotFound {
                resource: "user matching discoverable credential".to_string(),
            });
        }
    };

    let creds = match state.repo.get_webauthn_credentials(&user.id).await {
        Ok(c) => c,
        Err(e) => return qid_http::error_response(e),
    };

    let passkeys: Vec<webauthn_rs::prelude::Passkey> = creds
        .iter()
        .filter_map(|c| serde_json::from_slice::<webauthn_rs::prelude::Passkey>(&c.public_key).ok())
        .collect();

    let auth_result = match webauthn.finish_discoverable_authentication(
        &webauthn_state,
        &ceremony_key,
        req.response,
        &passkeys,
    ) {
        Ok(r) => {
            metrics::counter!("qid_webauthn_ceremonies_total", "ceremony" => "authenticate")
                .increment(1);
            r
        }
        Err(e) => return qid_http::error_response(e),
    };

    // Verify signCount monotonicity (credential cloning detection)
    let used_cred_id = auth_result.cred_id();
    if let Some(cred) = creds
        .iter()
        .find(|c| c.credential_id.as_slice() == used_cred_id.as_ref())
    {
        let new_counter = auth_result.counter() as u64;
        // WebAuthn L3 §6.1.1: authenticators that do not implement a
        // signature counter always return 0.  Allow 0→0 transitions.
        if (new_counter != 0 || cred.counter != 0) && new_counter <= cred.counter {
            return qid_http::error_response(QidError::Crypto {
                message: "credential cloning detected: signCount did not increase".to_string(),
            });
        }
        if let Err(e) = state
            .repo
            .update_webauthn_credential_counter(&cred.id, new_counter)
            .await
        {
            return qid_http::error_response(e);
        }
    }

    let session_config = &realm_config.browser_session;
    let old_session_id = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie_str| {
            cookie_str.split(';').find_map(|pair| {
                let pair = pair.trim();
                pair.split_once('=').and_then(|(key, value)| {
                    if key.trim() == session_config.cookie_name {
                        Some(value.trim().to_string())
                    } else {
                        None
                    }
                })
            })
        });
    let manager = SessionManager::new(
        state.repo.clone(),
        session_config.idle_timeout_minutes,
        session_config.absolute_timeout_hours,
    );

    let session = match manager
        .create_with_regeneration(
            &realm,
            &user.id,
            "phr",
            &["phr".to_string(), "hwk".to_string()],
            old_session_id.as_deref(),
        )
        .await
    {
        Ok(s) => s,
        Err(e) => return qid_http::error_response(e),
    };

    let cookie_value = format!(
        "{}={}; HttpOnly; Secure; Path=/; SameSite={}",
        session_config.cookie_name, session.id, session_config.same_site,
    );

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::SET_COOKIE, cookie_value.parse().unwrap());

    let body = Json(WebAuthnDiscoverableFinishResponse {
        session: session.id,
        user: DiscoverableUserResponse {
            id: user.id.clone(),
            email: user.email.clone(),
        },
    });

    (resp_headers, body).into_response()
}
