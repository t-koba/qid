use axum::{
    Extension, Router,
    http::{HeaderMap, HeaderValue, header},
    routing::post,
};
use qid_core::{
    config::{BrowserSessionConfig, ServerPaths},
    error::QidError,
    models::Session,
    plan::RuntimeRealm,
    state::SharedState,
};

use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use url::Url;

use crate::auth::Authenticator;
use crate::browser::SessionManager;
use crate::password_limit::PasswordAttemptLimiter;
use crate::webauthn::{WebAuthnService, WebAuthnState};

pub(crate) fn set_session_cookie(
    headers: &mut HeaderMap,
    config: &BrowserSessionConfig,
    session_id: &str,
    error_context: &str,
) -> Result<(), QidError> {
    let value = format!(
        "{}={}; HttpOnly; Secure; Path=/; SameSite={}",
        config.cookie_name, session_id, config.same_site,
    );
    let value = HeaderValue::from_str(&value).map_err(|error| QidError::Internal {
        message: format!("{error_context}: {error}"),
    })?;
    headers.insert(header::SET_COOKIE, value);
    Ok(())
}

/// The session routes with a password admission limiter of their own.
///
/// The limiter is fresh for every router, so a test that builds a router
/// does not share its counts with another test.
pub fn auth_routes<R: Repository>(paths: &ServerPaths) -> Router<Arc<SharedState<R>>> {
    auth_routes_with_password_attempt_limiter(paths, Arc::new(PasswordAttemptLimiter::new()))
}

/// The session routes with the password admission limiter the caller owns.
///
/// A deployment that serves the session routes and the OIDC authorization
/// endpoint from one process passes one limiter to both, so the two
/// password login paths enforce the same admission numbers.
pub fn auth_routes_with_password_attempt_limiter<R: Repository>(
    paths: &ServerPaths,
    limiter: Arc<PasswordAttemptLimiter>,
) -> Router<Arc<SharedState<R>>> {
    Router::new()
        .route(&paths.auth_password, post(password_auth::<R>))
        .route(&paths.auth_session_refresh, post(session_refresh::<R>))
        .route(&paths.auth_session_revoke, post(session_revoke::<R>))
        .route(
            &paths.auth_webauthn_start,
            post(webauthn_register_start::<R>),
        )
        .route(
            &paths.auth_webauthn_finish,
            post(webauthn_register_finish::<R>),
        )
        .route(
            &paths.auth_webauthn_auth_start,
            post(webauthn_auth_start::<R>),
        )
        .route(
            &paths.auth_webauthn_auth_finish,
            post(webauthn_auth_finish::<R>),
        )
        .route(
            &paths.auth_webauthn_discoverable_start,
            post(webauthn_discoverable_auth_start::<R>),
        )
        .route(
            &paths.auth_webauthn_discoverable_finish,
            post(webauthn_discoverable_auth_finish::<R>),
        )
        .layer(Extension(WebAuthnState::new()))
        .layer(Extension(limiter))
}

pub(crate) fn build_webauthn_service<R: Repository>(
    state: &Arc<SharedState<R>>,
    realm: &str,
) -> Result<WebAuthnService, QidError> {
    let realm_config = state.require_realm(realm)?;
    let passkey_config = &realm_config.passkeys;
    if !passkey_config.enabled {
        return Err(QidError::BadRequest {
            message: "WebAuthn is not enabled for this realm".to_string(),
        });
    }
    let rp_id = passkey_config.rp_id.clone().unwrap_or_else(|| {
        Url::parse(&realm_config.issuer)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_default()
    });
    let rp_origin = passkey_config.rp_origin.clone().unwrap_or_else(|| {
        Url::parse(&realm_config.issuer)
            .ok()
            .map(|u| {
                let origin = format!("{}://{}", u.scheme(), u.host_str().unwrap_or("localhost"),);
                if let Some(port) = u.port() {
                    format!("{}:{}", origin, port)
                } else {
                    origin
                }
            })
            .unwrap_or_else(|| "https://localhost".to_string())
    });
    let rp_name = &passkey_config.rp_name;
    WebAuthnService::new(&rp_id, rp_name, &rp_origin)
}

#[derive(Debug, Deserialize)]
pub struct PasswordAuthRequest {
    email: String,
    password: String,
}

#[derive(Debug, Serialize)]
pub struct PasswordAuthResponse {
    session: String,
    user: UserResponse,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    id: String,
    email: String,
}

mod password;
mod session;
mod webauthn;

pub(crate) use password::password_auth;
pub(crate) use session::{session_refresh, session_revoke};
pub(crate) use webauthn::{
    webauthn_auth_finish, webauthn_auth_start, webauthn_discoverable_auth_finish,
    webauthn_discoverable_auth_start, webauthn_register_finish, webauthn_register_start,
};

pub(crate) fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
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

pub(crate) struct BrowserSessionContext<'a, R: Repository> {
    pub(crate) realm_config: &'a RuntimeRealm,
    pub(crate) session_id: String,
    pub(crate) session: Session,
    pub(crate) manager: SessionManager<R>,
}

pub(crate) async fn load_browser_session<'a, R: Repository>(
    state: &'a Arc<SharedState<R>>,
    realm: &str,
    headers: &HeaderMap,
) -> Result<BrowserSessionContext<'a, R>, axum::response::Response> {
    let realm_config = state
        .require_realm(realm)
        .map_err(qid_http::error_response)?;
    let session_id = extract_cookie(headers, &realm_config.browser_session.cookie_name)
        .ok_or_else(|| {
            qid_http::error_response(QidError::Unauthorized {
                message: "missing session cookie".to_string(),
            })
        })?;
    let manager = SessionManager::from_browser_session_config(
        state.repo.clone(),
        &realm_config.browser_session,
    );
    let session = match manager.get(&session_id).await {
        Ok(Some(session)) => session,
        _ => {
            return Err(qid_http::error_response(QidError::Unauthorized {
                message: "invalid or expired session".to_string(),
            }));
        }
    };
    if session.realm_id != realm {
        return Err(qid_http::error_response(QidError::Unauthorized {
            message: "session realm does not match request realm".to_string(),
        }));
    }

    Ok(BrowserSessionContext {
        realm_config,
        session_id,
        session,
        manager,
    })
}
