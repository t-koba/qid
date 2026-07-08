//! Session management handlers.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use qid_core::{error::QidError, state::SharedState};
use qid_storage::prelude::*;
use std::sync::Arc;

use super::extract_cookie;
use crate::browser::SessionManager;

pub async fn session_refresh<R: Repository>(
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

    let new_idle =
        qid_core::util::now_seconds() + realm_config.browser_session.idle_timeout_minutes * 60;
    if let Err(e) = state
        .repo
        .update_session_idle_expiry(&session_id, new_idle)
        .await
    {
        return qid_http::error_response(e);
    }
    state.session_cache_delete(&session_id);

    StatusCode::OK.into_response()
}

pub async fn session_revoke<R: Repository>(
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

    if let Err(e) = manager.revoke(&session_id).await {
        return qid_http::error_response(e);
    }
    state.session_cache_delete(&session_id);

    let clear_cookie = format!(
        "{}={}; HttpOnly; Secure; Path=/; SameSite={}; Max-Age=0",
        cookie_name, "", realm_config.browser_session.same_site,
    );

    let mut headers = HeaderMap::new();
    let cookie_value = match clear_cookie.parse() {
        Ok(v) => v,
        Err(e) => {
            return qid_http::error_response(QidError::Internal {
                message: format!("invalid Set-Cookie header: {e}"),
            });
        }
    };
    headers.insert(header::SET_COOKIE, cookie_value);

    (headers, StatusCode::OK).into_response()
}
