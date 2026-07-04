use axum::http::HeaderMap;
use qid_core::error::QidError;
use qid_core::state::SharedState;
use qid_storage::prelude::*;

/// Require an active browser session matching the expected `user_id`.
/// Returns the authenticated `user_id` on success.
pub(crate) async fn require_session<R: Repository>(
    headers: &HeaderMap,
    state: &SharedState<R>,
    realm_id: &str,
    expected_user_id: &str,
) -> Result<String, axum::response::Response> {
    let session = load_active_session(headers, state, realm_id).await?;
    if !expected_user_id.is_empty() && session.user_id != expected_user_id {
        return Err(qid_http::error_response(QidError::Unauthorized {
            message: "session user does not match expected user".to_string(),
        }));
    }
    Ok(session.user_id)
}

/// Require any active session (no user_id check).
/// Returns the authenticated `user_id`.
pub(crate) async fn require_any_session<R: Repository>(
    headers: &HeaderMap,
    state: &SharedState<R>,
    realm_id: &str,
) -> Result<String, axum::response::Response> {
    let session = load_active_session(headers, state, realm_id).await?;
    Ok(session.user_id)
}

async fn load_active_session<R: Repository>(
    headers: &HeaderMap,
    state: &SharedState<R>,
    realm_id: &str,
) -> Result<qid_core::models::Session, axum::response::Response> {
    let realm_cfg = state.plan.realm(realm_id).ok_or_else(|| {
        qid_http::error_response(QidError::Config {
            message: format!("realm {realm_id} not found"),
        })
    })?;
    let cookie_name = &realm_cfg.browser_session.cookie_name;
    let session_id = extract_cookie(headers, cookie_name).ok_or_else(|| {
        qid_http::error_response(QidError::Unauthorized {
            message: "authentication required: missing session cookie".to_string(),
        })
    })?;
    let session = state
        .repo
        .get_session(session_id)
        .await
        .map_err(qid_http::error_response)?
        .ok_or_else(|| {
            qid_http::error_response(QidError::Unauthorized {
                message: "invalid or expired session".to_string(),
            })
        })?;
    if session.revoked
        || session.absolute_expires_at < qid_core::util::now_seconds()
        || session.idle_expires_at < qid_core::util::now_seconds()
    {
        return Err(qid_http::error_response(QidError::Unauthorized {
            message: "session is no longer active".to_string(),
        }));
    }
    if session.realm_id != realm_id {
        return Err(qid_http::error_response(QidError::Unauthorized {
            message: "session realm does not match request realm".to_string(),
        }));
    }
    Ok(session)
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
