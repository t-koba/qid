use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use qid_core::web::JsonObject;
use qid_core::{
    config::ServerPaths, error::QidError, models::TotpCredential, plan::RuntimeRealm,
    state::SharedState,
};
use qid_crypto::totp::TotpVerifier;
use qid_mfa::verify_totp_at_with_step;
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::api::{BrowserSessionContext, extract_cookie, load_browser_session};
use crate::browser::SessionManager;
use crate::totp_limit::TotpAttemptLimiter;

/// The TOTP routes with a TOTP admission limiter of their own.
///
/// The limiter is fresh for every router, so a test that builds a router
/// does not share its counts with another test.
pub fn totp_routes<R: Repository>(paths: &ServerPaths) -> Router<Arc<SharedState<R>>> {
    totp_routes_with_attempt_limiter(paths, Arc::new(TotpAttemptLimiter::new()))
}

/// The TOTP routes with the TOTP admission limiter the caller owns.
///
/// A deployment that serves the confirmation and authentication paths from
/// one process passes one limiter to both, so enrolment confirmation and
/// primary authentication enforce the same admission numbers.
pub fn totp_routes_with_attempt_limiter<R: Repository>(
    _paths: &ServerPaths,
    limiter: Arc<TotpAttemptLimiter>,
) -> Router<Arc<SharedState<R>>> {
    Router::new()
        .route("/api/v1/:realm/auth/totp/enroll", post(totp_enroll::<R>))
        .route("/api/v1/:realm/auth/totp/verify", post(totp_verify::<R>))
        .route(
            "/api/v1/:realm/auth/totp/authenticate",
            post(totp_authenticate::<R>),
        )
        .layer(Extension(limiter))
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

/// A realm that does not offer the TOTP factor refuses every TOTP route:
/// it performs no enrolment, confirmation or challenge.
fn totp_unavailable(realm_config: &RuntimeRealm) -> Option<Response> {
    if realm_config.accepts_totp() {
        return None;
    }
    Some(qid_http::error_response(QidError::Unauthorized {
        message: "TOTP is not enabled for this realm".to_string(),
    }))
}

async fn totp_enroll<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Response {
    let BrowserSessionContext {
        realm_config,
        session,
        ..
    } = match load_browser_session(&state, &realm, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    if let Some(response) = totp_unavailable(realm_config) {
        return response;
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
    Extension(limiter): Extension<Arc<TotpAttemptLimiter>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    JsonObject(req): JsonObject<TotpVerifyRequest>,
) -> Response {
    let BrowserSessionContext {
        realm_config,
        session,
        ..
    } = match load_browser_session(&state, &realm, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    if let Some(response) = totp_unavailable(realm_config) {
        return response;
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

    // The user and the credential are known, so the proof spends an
    // admission before any code verification. A refused proof never reaches
    // verification, the step claim or enrolment activation.
    if !limiter.admit(&realm, &session.user_id, &realm_config.mfa.totp) {
        metrics::counter!("qid_authn_rate_limited_total", "method" => "totp").increment(1);
        return qid_http::error_response(QidError::TooManyRequests {
            message: "too many TOTP attempts, please wait and try again".to_string(),
        });
    }

    // Enrollment confirmation validates against a transiently enabled copy:
    // the stored credential stays disabled until a valid proof arrives.
    let now = qid_core::util::now_seconds();
    let probe = TotpCredential {
        enabled: true,
        ..cred.clone()
    };
    let current_step = match verify_totp_at_with_step(&probe, &req.code, now) {
        Ok(Some(step)) => step,
        Ok(None) => {
            return qid_http::error_response(QidError::BadRequest {
                message: "invalid or already-used TOTP code".to_string(),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };

    // Exactly one confirmer wins the step; losers fail without enabling.
    match state.repo.consume_totp_step(&cred.id, current_step).await {
        Ok(true) => {}
        Ok(false) => {
            return qid_http::error_response(QidError::BadRequest {
                message: "invalid or already-used TOTP code".to_string(),
            });
        }
        Err(e) => return qid_http::error_response(e),
    }
    // The proof verified and won the step, so it gives its admission back.
    // Wrong codes, malformed codes and step-claim losers keep theirs.
    limiter.succeeded(&realm, &session.user_id);

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
    Extension(limiter): Extension<Arc<TotpAttemptLimiter>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    JsonObject(req): JsonObject<TotpAuthenticateRequest>,
) -> Response {
    let realm_config = match state.require_realm(&realm) {
        Ok(config) => config,
        Err(error) => return qid_http::error_response(error),
    };
    if let Some(response) = totp_unavailable(realm_config) {
        return response;
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

    // The user and the credential are known, so the proof spends an
    // admission before any code verification. A refused proof never reaches
    // verification, the step claim or session creation.
    if !limiter.admit(&realm, &user.id, &realm_config.mfa.totp) {
        metrics::counter!("qid_authn_rate_limited_total", "method" => "totp").increment(1);
        return qid_http::error_response(QidError::TooManyRequests {
            message: "too many TOTP attempts, please wait and try again".to_string(),
        });
    }

    // Validation runs against the stored snapshot; the repository decides the
    // winner. Only the caller that claims the step reaches session creation.
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

    match state.repo.consume_totp_step(&cred.id, current_step).await {
        Ok(true) => {}
        Ok(false) => {
            return qid_http::error_response(QidError::BadRequest {
                message: "invalid or already-used TOTP code".to_string(),
            });
        }
        Err(e) => return qid_http::error_response(e),
    }
    // The proof verified and won the step, so it gives its admission back.
    // Wrong codes, malformed codes and step-claim losers keep theirs.
    limiter.succeeded(&realm, &user.id);

    metrics::counter!("qid_mfa_challenges_total", "method" => "totp").increment(1);

    let session_config = &realm_config.browser_session;
    let old_session_id = extract_cookie(&headers, &session_config.cookie_name);
    let manager = SessionManager::from_browser_session_config(state.repo.clone(), session_config);

    let session = match manager
        .create_with_regeneration(
            &realm,
            &user.id,
            // TOTP is not phishing-resistant (NIST SP 800-63B-4): TOTP-only
            // sessions get their own ACR, never the WebAuthn `phr` label.
            "urn:qid:acr:totp",
            &["totp".to_string()],
            old_session_id.as_deref(),
        )
        .await
    {
        Ok(s) => s,
        Err(e) => return qid_http::error_response(e),
    };

    let mut headers = HeaderMap::new();
    if let Err(error) = crate::api::set_session_cookie(
        &mut headers,
        session_config,
        &session.id,
        "failed to build TOTP session cookie header",
    ) {
        return qid_http::error_response(error);
    }

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
