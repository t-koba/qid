use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use qid_core::{config::ServerPaths, error::QidError, models::TotpCredential, state::SharedState};
use qid_crypto::totp::TotpVerifier;
use qid_mfa::verify_totp_at_with_step;
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::browser::SessionManager;

pub fn totp_routes<R: Repository>(_paths: &ServerPaths) -> Router<Arc<SharedState<R>>> {
    Router::new()
        .route("/api/v1/:realm/auth/totp/enroll", post(totp_enroll::<R>))
        .route("/api/v1/:realm/auth/totp/verify", post(totp_verify::<R>))
        .route(
            "/api/v1/:realm/auth/totp/authenticate",
            post(totp_authenticate::<R>),
        )
}

#[derive(Debug, Serialize)]
struct TotpEnrollResponse {
    secret: String,
    qrcode_url: String,
}

#[derive(Debug, Deserialize)]
struct TotpVerifyRequest {
    code: String,
}

#[derive(Debug, Serialize)]
struct TotpVerifyResponse {
    status: String,
}

#[derive(Debug, Deserialize)]
struct TotpAuthenticateRequest {
    user_id: String,
    code: String,
}

#[derive(Debug, Serialize)]
struct TotpAuthenticateResponse {
    session_id: String,
    user: TotpUserResponse,
}

#[derive(Debug, Serialize)]
struct TotpUserResponse {
    id: String,
    email: Option<String>,
}

async fn totp_enroll<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Response {
    let realm_config = match state.realm(&realm) {
        Some(r) => r,
        None => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("realm {}", realm),
            });
        }
    };

    let cookie_name = &realm_config.browser_session.cookie_name;
    let session_id = match extract_cookie(&headers, cookie_name) {
        Some(id) => id,
        None => {
            return qid_http::error_response(QidError::Unauthorized {
                message: "missing session cookie".to_string(),
            });
        }
    };

    let manager = SessionManager::new(
        state.repo.clone(),
        realm_config.browser_session.idle_timeout_minutes,
        realm_config.browser_session.absolute_timeout_hours,
    );

    let session = match manager.get(&session_id).await {
        Ok(Some(s)) => s,
        _ => {
            return qid_http::error_response(QidError::Unauthorized {
                message: "invalid or expired session".to_string(),
            });
        }
    };
    if session.realm_id != realm {
        return qid_http::error_response(QidError::Unauthorized {
            message: "session realm does not match request realm".to_string(),
        });
    }

    let user = match state.repo.get_user_by_id(&session.user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("user {}", session.user_id),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };
    if user.realm_id != realm {
        return qid_http::error_response(QidError::Unauthorized {
            message: "session user does not belong to request realm".to_string(),
        });
    }

    let secret = TotpVerifier::generate_secret();
    let verifier = TotpVerifier::default();

    let cred = TotpCredential {
        id: ulid::Ulid::new().to_string(),
        user_id: session.user_id.clone(),
        secret: secret.clone(),
        algorithm: "SHA1".to_string(),
        digits: verifier.digits,
        period: verifier.period,
        enabled: false,
        last_used_step: None,
        created_at: qid_core::util::now_seconds(),
    };

    if let Err(e) = state.repo.store_totp_credential(&cred).await {
        return qid_http::error_response(e);
    }

    let email = user.email.as_deref().unwrap_or(&session.user_id);
    let qrcode_url = build_totp_qrcode_url(&realm_config.issuer, email, &secret, &verifier);

    let body = Json(TotpEnrollResponse { secret, qrcode_url });
    (StatusCode::OK, body).into_response()
}

async fn totp_verify<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Json(req): Json<TotpVerifyRequest>,
) -> Response {
    let realm_config = match state.realm(&realm) {
        Some(r) => r,
        None => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("realm {}", realm),
            });
        }
    };

    let cookie_name = &realm_config.browser_session.cookie_name;
    let session_id = match extract_cookie(&headers, cookie_name) {
        Some(id) => id,
        None => {
            return qid_http::error_response(QidError::Unauthorized {
                message: "missing session cookie".to_string(),
            });
        }
    };

    let manager = SessionManager::new(
        state.repo.clone(),
        realm_config.browser_session.idle_timeout_minutes,
        realm_config.browser_session.absolute_timeout_hours,
    );

    let session = match manager.get(&session_id).await {
        Ok(Some(s)) => s,
        _ => {
            return qid_http::error_response(QidError::Unauthorized {
                message: "invalid or expired session".to_string(),
            });
        }
    };
    if session.realm_id != realm {
        return qid_http::error_response(QidError::Unauthorized {
            message: "session realm does not match request realm".to_string(),
        });
    }

    let mut cred = match state.repo.get_totp_credential(&session.user_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("totp credential for user {}", session.user_id),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };

    // Replay prevention and code verification are performed atomically in
    // `verify_totp_at_with_step`, which is the single source of truth for
    // TOTP boundary checking.
    let now = qid_core::util::now_seconds();
    let current_step = match verify_totp_at_with_step(&cred, &req.code, now) {
        Ok(Some(step)) => step,
        Ok(None) => {
            return qid_http::error_response(QidError::BadRequest {
                message: "invalid or already-used TOTP code".to_string(),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };

    cred.enabled = true;
    cred.last_used_step = Some(current_step);
    if let Err(e) = state.repo.store_totp_credential(&cred).await {
        return qid_http::error_response(e);
    }

    let body = Json(TotpVerifyResponse {
        status: "verified".to_string(),
    });
    (StatusCode::OK, body).into_response()
}

async fn totp_authenticate<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Json(req): Json<TotpAuthenticateRequest>,
) -> Response {
    let realm_config = match state.realm(&realm) {
        Some(r) => r,
        None => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("realm {}", realm),
            });
        }
    };

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
            message: "TOTP user does not belong to request realm".to_string(),
        });
    }

    let cred = match state.repo.get_totp_credential(&user.id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("totp credential for user {}", user.id),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };

    if !cred.enabled {
        return qid_http::error_response(QidError::BadRequest {
            message: "TOTP not enabled for this user".to_string(),
        });
    }

    // Replay prevention and code verification are performed atomically in
    // `verify_totp_at_with_step`, which is the single source of truth for
    // TOTP boundary checking.
    let now = qid_core::util::now_seconds();
    let current_step = match verify_totp_at_with_step(&cred, &req.code, now) {
        Ok(Some(step)) => step,
        Ok(None) => {
            return qid_http::error_response(QidError::BadRequest {
                message: "invalid or already-used TOTP code".to_string(),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };

    // Persist last used step to prevent TOTP replay
    if let Err(e) = state
        .repo
        .update_totp_credential_last_used_step(&user.id, current_step)
        .await
    {
        return qid_http::error_response(e);
    }

    metrics::counter!("qid_mfa_challenges_total", "method" => "totp").increment(1);

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
            &["totp".to_string()],
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
        Err(e) => {
            return qid_http::error_response(QidError::Internal {
                message: format!("failed to build TOTP session cookie header: {e}"),
            });
        }
    };
    headers.insert(header::SET_COOKIE, cookie_value);

    let body = Json(TotpAuthenticateResponse {
        session_id: session.id,
        user: TotpUserResponse {
            id: user.id,
            email: user.email,
        },
    });

    (headers, body).into_response()
}

fn build_totp_qrcode_url(
    issuer: &str,
    email: &str,
    secret: &str,
    verifier: &TotpVerifier,
) -> String {
    let encoded_issuer = urlencoding(issuer);
    let encoded_email = urlencoding(email);
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
        encoded_issuer,
        encoded_email,
        secret,
        encoded_issuer,
        "SHA1",
        verifier.digits,
        verifier.period,
    )
}

fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            ' ' => "+".to_string(),
            other => format!("%{:02X}", other as u8),
        })
        .collect()
}

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
