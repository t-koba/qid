//! HTTP runtime for qid.
#![forbid(unsafe_code)]

use axum::{
    Json,
    http::{HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use serde_json::json;

pub mod middleware;
pub mod ratelimit;
pub mod security_headers;
pub mod trusted_types;

pub use middleware::{
    cors_layer, csp_headers_layer, csrf_protection_layer, hsts_layer, security_headers_middleware,
    zero_rtt_rejection_layer,
};

/// Attach a `WWW-Authenticate: Bearer` challenge header to a response.
///
/// Use this on 401 responses to satisfy RFC 6750 §3, which requires that the
/// resource server include a challenge that lets clients distinguish between
/// missing/invalid/expired tokens and other failure modes.
pub fn with_bearer_challenge(mut response: Response, error: &str, description: &str) -> Response {
    let value = format!(
        "Bearer realm=\"qid\", error=\"{}\", error_description=\"{}\"",
        error,
        description.replace('"', "'")
    );
    if let Ok(header) = HeaderValue::from_str(&value) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("www-authenticate"), header);
    }
    response
}

/// Build an OAuth-style JSON error response that includes a
/// `WWW-Authenticate: Bearer` challenge when the status is 401.
pub fn oauth_error_response_with_bearer(
    status: StatusCode,
    error: &str,
    description: &str,
) -> Response {
    let response = oauth_error_response_with_description(status, error, description);
    if status == StatusCode::UNAUTHORIZED {
        with_bearer_challenge(response, error, description)
    } else {
        response
    }
}

/// Build a JSON list handler response from a repository future.
#[macro_export]
macro_rules! list_handler {
    ($future:expr, $map:expr) => {{
        match $future.await {
            Ok(items) => {
                let views: Vec<_> = items.into_iter().map($map).collect();
                ::axum::response::IntoResponse::into_response((
                    ::axum::http::StatusCode::OK,
                    ::axum::Json(views),
                ))
            }
            Err(e) => $crate::error_response(e),
        }
    }};
}

/// Build a JSON get handler response from a repository future returning an optional item.
#[macro_export]
macro_rules! get_handler {
    ($future:expr, $map:expr, $missing:expr) => {{
        match $future.await {
            Ok(Some(item)) => ::axum::response::IntoResponse::into_response((
                ::axum::http::StatusCode::OK,
                ::axum::Json(($map)(item)),
            )),
            Ok(None) => $crate::error_response($missing),
            Err(e) => $crate::error_response(e),
        }
    }};
}

/// Build a JSON create handler response from a repository future returning the created item.
#[macro_export]
macro_rules! create_handler {
    ($future:expr, $map:expr) => {{
        match $future.await {
            Ok(item) => ::axum::response::IntoResponse::into_response((
                ::axum::http::StatusCode::CREATED,
                ::axum::Json(($map)(item)),
            )),
            Err(e) => $crate::error_response(e),
        }
    }};
    ($future:expr) => {{
        match $future.await {
            Ok(item) => ::axum::response::IntoResponse::into_response((
                ::axum::http::StatusCode::CREATED,
                ::axum::Json(item),
            )),
            Err(e) => $crate::error_response(e),
        }
    }};
}

/// Build a JSON update handler response from a repository future.
#[macro_export]
macro_rules! update_handler {
    ($future:expr, $map:expr) => {{
        match $future.await {
            Ok(item) => ::axum::response::IntoResponse::into_response((
                ::axum::http::StatusCode::OK,
                ::axum::Json(($map)(item)),
            )),
            Err(e) => $crate::error_response(e),
        }
    }};
    ($future:expr) => {{
        match $future.await {
            Ok(item) => ::axum::response::IntoResponse::into_response((
                ::axum::http::StatusCode::OK,
                ::axum::Json(item),
            )),
            Err(e) => $crate::error_response(e),
        }
    }};
}

/// Build a delete handler response from a repository future.
#[macro_export]
macro_rules! delete_handler {
    ($future:expr) => {{
        match $future.await {
            Ok(_) => ::axum::http::StatusCode::NO_CONTENT.into_response(),
            Err(e) => $crate::error_response(e),
        }
    }};
}

/// Convert a `QidError` into an HTTP response.
pub fn error_response(err: qid_core::QidError) -> axum::response::Response {
    let status =
        StatusCode::from_u16(err.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = Json(json!({ "error": err.message() }));
    let mut response = (status, body).into_response();
    if response.status() == StatusCode::UNAUTHORIZED {
        response = with_bearer_challenge(response, "invalid_token", &err.message());
    }
    response
}

/// Build an OAuth-style JSON error response.
pub fn oauth_error_response(status: StatusCode, error: &str) -> axum::response::Response {
    (status, Json(json!({ "error": error }))).into_response()
}

/// Build an OAuth-style JSON error response with `error_description` set.
pub fn oauth_error_response_with_description(
    status: StatusCode,
    error: &str,
    description: &str,
) -> axum::response::Response {
    (
        status,
        Json(json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

/// Build an OAuth-style JSON error response from a `QidError`.
pub fn qid_oauth_error_response(err: qid_core::QidError) -> axum::response::Response {
    error_response(err)
}

/// Attach a DPoP-Nonce challenge header to an OAuth error response.
pub fn dpop_nonce_error_response(
    err: qid_core::QidError,
    nonce: Option<&str>,
) -> axum::response::Response {
    let mut response = qid_oauth_error_response(err);
    if let Some(nonce) = nonce.and_then(|nonce| HeaderValue::from_str(nonce).ok()) {
        response.headers_mut().insert("DPoP-Nonce", nonce);
    }
    response
}

/// Validate that a field value is non-empty, returning a BadRequest error otherwise.
pub fn require_non_empty(field: &str, value: &str) -> Result<(), qid_core::QidError> {
    if value.trim().is_empty() {
        return Err(qid_core::QidError::BadRequest {
            message: format!("{field} must not be empty"),
        });
    }
    Ok(())
}

/// Validate that a string is a valid absolute URI, returning a BadRequest error otherwise.
/// Uses basic scheme + authority validation without the `url` crate dependency.
pub fn require_uri(field: &str, value: &str) -> Result<(), qid_core::QidError> {
    require_non_empty(field, value)?;
    let has_scheme = value.contains("://");
    if !has_scheme {
        return Err(qid_core::QidError::BadRequest {
            message: format!("{field} must be a valid absolute URI"),
        });
    }
    Ok(())
}

/// Build a redirect carrying OAuth/OIDC error parameters.
pub fn redirect_error(
    redirect_uri: &str,
    state: Option<&str>,
    error: &str,
    description: &str,
) -> axum::response::Response {
    let mut url = format!(
        "{}?error={}&error_description={}",
        redirect_uri,
        urlencoding::encode(error),
        urlencoding::encode(description)
    );
    if let Some(state) = state {
        url.push_str(&format!("&state={}", urlencoding::encode(state)));
    }
    Redirect::temporary(&url).into_response()
}
