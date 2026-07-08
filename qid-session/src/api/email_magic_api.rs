use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use qid_core::{config::ServerPaths, error::QidError, state::SharedState, tenant::RealmId};
use qid_http::ratelimit::{RateLimitConfig, RateLimiter};
use qid_mfa::email_magic::{
    EmailMagicLinkConfig, EmailMagicLinkSent, create_email_magic_link_challenge,
    verify_email_magic_link,
};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::browser::SessionManager;

/// Global rate limiter for email magic link.
static EMAIL_MAGIC_RATE_LIMITER: std::sync::LazyLock<RateLimiter> =
    std::sync::LazyLock::new(|| {
        RateLimiter::new(RateLimitConfig {
            max_per_user: 3,
            max_per_ip: 10,
            max_per_asn: 30,
            max_per_device: 5,
            max_per_tenant: 50,
            window_seconds: 300,
        })
    });

pub fn email_magic_routes<R: Repository>(_paths: &ServerPaths) -> Router<Arc<SharedState<R>>> {
    Router::new()
        .route(
            &_paths.auth_email_magic_link_send,
            post(email_magic_link_send::<R>),
        )
        .route(
            &_paths.auth_email_magic_link_verify,
            post(email_magic_link_verify::<R>),
        )
}

#[derive(Debug, Deserialize)]
struct EmailMagicLinkSendRequest {
    email: String,
    redirect_to: Option<String>,
}

#[derive(Debug, Serialize)]
struct EmailMagicLinkSendResponse {
    challenge_id: String,
    email: String,
    expires_at: u64,
}

#[derive(Debug, Deserialize)]
struct EmailMagicLinkVerifyRequest {
    challenge_id: String,
    token: String,
}

async fn email_magic_link_send<R: Repository>(
    Path(realm): Path<String>,
    State(state): State<Arc<SharedState<R>>>,
    _headers: HeaderMap,
    Json(req): Json<EmailMagicLinkSendRequest>,
) -> Response {
    // Do not trust forwarded IP headers unless an authenticated edge has normalized them.
    let client_ip: Option<String> = None;
    if !EMAIL_MAGIC_RATE_LIMITER.check(
        Some(&req.email),
        client_ip.as_deref(),
        None,
        None,
        Some(&realm),
    ) {
        metrics::counter!("qid_authn_rate_limited_total", "method" => "email_magic_link")
            .increment(1);
        return qid_http::error_response(QidError::TooManyRequests {
            message: "too many email requests, please wait and try again".to_string(),
        });
    }

    let _realm_config = match state.realm(&realm) {
        Some(cfg) => cfg,
        None => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("realm {}", realm),
            });
        }
    };

    let realm_id = RealmId(realm);
    let user = match state.repo.get_user_by_email(&realm_id, &req.email).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("user {}", req.email),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };

    let config = EmailMagicLinkConfig::default();
    let sent: EmailMagicLinkSent =
        create_email_magic_link_challenge(&user.id, &req.email, &config, req.redirect_to);

    let resp = EmailMagicLinkSendResponse {
        challenge_id: sent.challenge_id,
        email: sent.email,
        expires_at: sent.expires_at,
    };

    (StatusCode::OK, Json(resp)).into_response()
}

async fn email_magic_link_verify<R: Repository>(
    Path(realm): Path<String>,
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<EmailMagicLinkVerifyRequest>,
) -> Response {
    let challenge = match verify_email_magic_link(&req.challenge_id, &req.token) {
        Ok(c) => c,
        Err(e) => return qid_http::error_response(e),
    };

    let user = match state.repo.get_user_by_id(&challenge.user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("user {}", challenge.user_id),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };

    if user.realm_id != realm {
        return qid_http::error_response(QidError::BadRequest {
            message: "realm mismatch".to_string(),
        });
    }

    let realm_config = match state.realm(&realm) {
        Some(cfg) => cfg,
        None => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("realm {}", realm),
            });
        }
    };

    let authenticator = crate::auth::Authenticator::new(state.repo.clone());
    let _auth_result = match authenticator.authenticate_email_magic_link(&user).await {
        Ok(r) => r,
        Err(e) => return qid_http::error_response(e),
    };

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
            "urn:qid:acr:email_magic_link",
            &["email_magic_link".to_string()],
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
    let cookie_value = match HeaderValue::from_str(&cookie_value) {
        Ok(value) => value,
        Err(err) => {
            return qid_http::error_response(QidError::Internal {
                message: format!("failed to build session cookie header: {err}"),
            });
        }
    };
    headers.insert(header::SET_COOKIE, cookie_value);

    let body = Json(serde_json::json!({
        "status": "verified",
        "session": session.id,
        "user_id": user.id,
        "email": challenge.email,
        "acr": _auth_result.acr,
        "amr": _auth_result.amr,
        "redirect_to": challenge.redirect_to,
    }));

    (headers, body).into_response()
}
