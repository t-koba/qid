//! Session management handlers.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use qid_core::{error::QidError, state::SharedState};
use qid_storage::prelude::*;
use std::sync::Arc;

use super::{BrowserSessionContext, load_browser_session};

pub async fn session_refresh<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Response {
    let BrowserSessionContext {
        realm_config,
        session_id,
        ..
    } = match load_browser_session(&state, &realm, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };

    let new_idle =
        qid_core::util::now_seconds() + realm_config.browser_session.idle_timeout_minutes * 60;
    match state
        .repo
        .update_session_idle_expiry(&session_id, new_idle, Some(realm.as_str()))
        .await
    {
        Ok(true) => state.session_cache_delete(&session_id),
        Ok(false) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(e) => return qid_http::error_response(e),
    }

    StatusCode::OK.into_response()
}

pub async fn session_revoke<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Response {
    let BrowserSessionContext {
        realm_config,
        session_id,
        manager,
        ..
    } = match load_browser_session(&state, &realm, &headers).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let cookie_name = &realm_config.browser_session.cookie_name;

    match manager.revoke(&session_id, Some(realm.as_str())).await {
        Ok(true) => state.session_cache_delete(&session_id),
        Ok(false) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(e) => return qid_http::error_response(e),
    }

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
