//! Password authentication handler.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use qid_core::{error::QidError, state::SharedState, tenant::RealmId};
use qid_http::ratelimit::{RateLimitConfig, RateLimiter};
use qid_storage::prelude::*;
use std::sync::Arc;

use super::{Authenticator, PasswordAuthRequest, PasswordAuthResponse, UserResponse};
use crate::browser::SessionManager;

/// Global rate limiter for password authentication.
static PASSWORD_RATE_LIMITER: std::sync::LazyLock<RateLimiter> = std::sync::LazyLock::new(|| {
    RateLimiter::new(RateLimitConfig {
        max_per_user: 5,
        max_per_ip: 20,
        max_per_asn: 50,
        max_per_device: 10,
        max_per_tenant: 100,
        window_seconds: 300,
    })
});

pub async fn password_auth<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Json(req): Json<PasswordAuthRequest>,
) -> Response {
    let realm_config = match state.realm(&realm) {
        Some(r) => r,
        None => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("realm {}", realm),
            });
        }
    };

    if realm_config.passwordless_only {
        return qid_http::error_response(QidError::Unauthorized {
            message: "password authentication is disabled for this realm".to_string(),
        });
    }

    // Rate limiting: multi-axis (user, tenant). Do not trust forwarded IP headers here.
    let client_ip: Option<String> = None;
    if !PASSWORD_RATE_LIMITER.check(
        Some(&req.email),
        client_ip.as_deref(),
        None, // device_id: not available at password auth stage
        None, // asn: not available
        Some(&realm),
    ) {
        metrics::counter!("qid_authn_rate_limited_total", "method" => "password").increment(1);
        return qid_http::error_response(QidError::TooManyRequests {
            message: "too many login attempts, please wait and try again".to_string(),
        });
    }

    let authenticator = Authenticator::new(state.repo.clone());
    metrics::counter!("qid_authn_attempts_total", "method" => "password").increment(1);
    let auth_result = match authenticator
        .authenticate_password(&RealmId(realm.clone()), &req.email, &req.password)
        .await
    {
        Ok(r) => {
            metrics::counter!("qid_authn_success_total", "method" => "password").increment(1);
            // Reset rate limit on successful login
            PASSWORD_RATE_LIMITER.reset_user(&req.email);
            r
        }
        Err(e) => {
            metrics::counter!("qid_authn_failures_total", "method" => "password").increment(1);
            return qid_http::error_response(e);
        }
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
            &auth_result.user.id,
            &auth_result.acr,
            &auth_result.amr,
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

    let body = Json(PasswordAuthResponse {
        session: session.id,
        user: UserResponse {
            id: auth_result.user.id,
            email: auth_result.user.email.unwrap_or_default(),
        },
    });

    (headers, body).into_response()
}
