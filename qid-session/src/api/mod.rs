use axum::{
    Extension, Router,
    http::{HeaderMap, header},
    routing::post,
};
use qid_core::{config::ServerPaths, error::QidError, state::SharedState};

use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use url::Url;

use self::email_magic_api::email_magic_routes;
use self::push_api::push_routes;
use crate::auth::Authenticator;
use crate::webauthn::{WebAuthnService, WebAuthnState};

pub fn auth_routes<R: Repository>(paths: &ServerPaths) -> Router<Arc<SharedState<R>>> {
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
}

pub fn auth_routes_with_push<R: Repository>(paths: &ServerPaths) -> Router<Arc<SharedState<R>>> {
    auth_routes::<R>(paths)
        .merge(push_routes::<R>())
        .merge(email_magic_routes::<R>(paths))
}

pub(crate) fn build_webauthn_service<R: Repository>(
    state: &Arc<SharedState<R>>,
    realm: &str,
) -> Result<WebAuthnService, QidError> {
    let realm_config = state.realm(realm).ok_or_else(|| QidError::NotFound {
        resource: format!("realm {}", realm),
    })?;
    let passkey_config = &realm_config.passkeys;
    if !passkey_config.enabled {
        return Err(QidError::BadRequest {
            message: "WebAuthn is not enabled for this realm".to_string(),
        });
    }
    if let Some(attestation) = passkey_config.attestation.as_deref()
        && !matches!(attestation, "none")
    {
        return Err(QidError::Config {
            message: "WebAuthn attestation and FIDO Metadata policy are not connected to the registration ceremony".to_string(),
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

mod email_magic_api;
mod password;
mod push_api;
mod session;
mod webauthn;

pub(crate) use password::password_auth;
pub(crate) use session::{session_refresh, session_revoke};
pub(crate) use webauthn::{
    webauthn_auth_finish, webauthn_auth_start, webauthn_discoverable_auth_finish,
    webauthn_discoverable_auth_start, webauthn_register_finish, webauthn_register_start,
};

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
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
