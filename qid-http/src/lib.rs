//! HTTP runtime for qid.
#![forbid(unsafe_code)]

use axum::{
    Json,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header::AsHeaderName},
    response::{IntoResponse, Response},
};
use qid_core::error::{QidError, QidResult};
use serde_json::json;
use std::fmt::Display;

pub mod middleware;
pub mod ratelimit;
pub mod security_headers;

pub use middleware::{
    CsrfConfig, cors_layer, csp_headers_layer, csrf_protection_layer, hsts_layer,
    is_csrf_exempt_path, security_headers_middleware, zero_rtt_rejection_layer,
};

/// Attach a `WWW-Authenticate: Bearer` challenge header to a response.
///
/// Use this on 401 responses to satisfy RFC 6750 §3, which requires that the
/// resource server include a challenge that lets clients distinguish between
/// missing/invalid/expired tokens and other failure modes.
fn with_bearer_challenge(
    mut response: Response,
    error: &str,
    description: &str,
    resource_metadata: Option<&str>,
) -> Response {
    let value = match resource_metadata {
        Some(url) => format!(
            "Bearer resource_metadata=\"{}\", realm=\"qid\", error=\"{}\", error_description=\"{}\"",
            url.replace('"', "'"),
            error,
            description.replace('"', "'")
        ),
        None => format!(
            "Bearer realm=\"qid\", error=\"{}\", error_description=\"{}\"",
            error,
            description.replace('"', "'")
        ),
    };
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
    oauth_error_response_with_bearer_and_metadata(status, error, description, None)
}

/// Build a 401 challenge that also carries the RFC 9728 §5
/// `resource_metadata` pointer so generic clients can discover
/// protected-resource metadata from the `WWW-Authenticate` response.
pub fn oauth_error_response_with_bearer_and_metadata(
    status: StatusCode,
    error: &str,
    description: &str,
    resource_metadata: Option<&str>,
) -> Response {
    let response = oauth_error_response_with_description(status, error, description);
    if status == StatusCode::UNAUTHORIZED {
        with_bearer_challenge(response, error, description, resource_metadata)
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

/// Convert a `QidError` into an HTTP response.
pub fn error_response(err: qid_core::QidError) -> axum::response::Response {
    let message = err.message();
    let mut response = err.into_response();
    if response.status() == StatusCode::UNAUTHORIZED {
        response = with_bearer_challenge(response, "invalid_token", &message, None);
    }
    response
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

/// Attach a DPoP-Nonce challenge header to an OAuth error response.
///
/// Structured DPoP nonce failures (RFC 9449 section 8) keep HTTP 400 with
/// `error` set to `use_dpop_nonce` and the diagnostic text moved to
/// `error_description`; any other failure keeps its own error category.
pub fn dpop_nonce_error_response(
    err: qid_core::QidError,
    nonce: Option<&str>,
) -> axum::response::Response {
    let mut response = match &err {
        qid_core::QidError::DpopNonce { message } => oauth_error_response_with_description(
            StatusCode::BAD_REQUEST,
            "use_dpop_nonce",
            message,
        ),
        _ => error_response(err),
    };
    if let Some(nonce) = nonce.and_then(|nonce| HeaderValue::from_str(nonce).ok()) {
        response.headers_mut().insert("DPoP-Nonce", nonce);
    }
    response
}

/// Read a named cookie from a raw `Cookie` header without decoding its value.
///
/// A repeated name is ambiguous: browsers may order same-named cookies by path,
/// so the first value is not necessarily the one the server issued. Fail closed
/// instead of selecting one. Values are otherwise returned verbatim apart from
/// surrounding whitespace.
pub fn parse_cookie(cookie_header: &str, name: &str) -> Option<String> {
    let mut found: Option<&str> = None;
    for pair in cookie_header.split(';') {
        // Only ASCII separators are trimmed. str::trim would also remove
        // Unicode whitespace prefixes that browsers do not treat as __Host-.
        let pair = pair.trim_ascii();
        if let Some((key, value)) = pair.split_once('=')
            && qid_core::util::is_cookie_name_token(key)
            && key == name
            && found.replace(value.trim_ascii()).is_some()
        {
            return None;
        }
    }
    found.map(str::to_owned)
}

/// Combine every `Cookie` header value into a single header string.
///
/// RFC 6265bis section 4.2.1 permits a user agent to split cookies over
/// multiple `Cookie` fields (for example when HTTP/2 is used), in which case
/// the values are concatenated with "; ". Reading only the first field would
/// hide cookies and let a duplicate name escape `parse_cookie`'s fail-closed
/// check. Any non-UTF-8 value makes the whole header unusable.
pub fn combined_cookie_header(headers: &axum::http::HeaderMap) -> Option<String> {
    let mut values = headers.get_all(axum::http::header::COOKIE).iter();
    let first = values.next()?.to_str().ok()?;
    let mut combined = first.to_owned();
    for value in values {
        combined.push_str("; ");
        combined.push_str(value.to_str().ok()?);
    }
    Some(combined)
}

/// Read a named cookie from the `Cookie` headers of an HTTP request.
pub fn extract_cookie(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    parse_cookie(&combined_cookie_header(headers)?, name)
}

/// Return the sole value of a request header, failing closed when the field
/// set is ambiguous.
///
/// Absence is `Ok(None)` so optional credentials keep their own missing-value
/// handling; more than one field and any non-UTF-8 value are errors. RFC 6749
/// section 2.3 forbids using more than one client authentication method per
/// request, so selecting the first value would hide a second credential.
/// Callers map the error to the `QidError` variant used by their surface.
pub fn sole_header_value(
    headers: &HeaderMap,
    name: impl AsHeaderName + Display + Copy,
) -> QidResult<Option<&str>> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(QidError::BadRequest {
            message: format!("multiple {name} headers are not allowed"),
        });
    }
    value.to_str().map(Some).map_err(|_| QidError::BadRequest {
        message: format!("{name} header is not valid UTF-8"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::{AUTHORIZATION, COOKIE};

    #[test]
    fn sole_header_value_accepts_one_field_and_rejects_duplicates() {
        let mut headers = HeaderMap::new();
        assert_eq!(sole_header_value(&headers, &AUTHORIZATION).unwrap(), None);

        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer first"));
        assert_eq!(
            sole_header_value(&headers, &AUTHORIZATION).unwrap(),
            Some("Bearer first")
        );
        // The helper also covers custom credential headers by static name.
        headers.insert(
            "x-qid-pep-adapter-authorization",
            HeaderValue::from_static("Bearer pep"),
        );
        assert_eq!(
            sole_header_value(&headers, "x-qid-pep-adapter-authorization").unwrap(),
            Some("Bearer pep")
        );

        headers.append(AUTHORIZATION, HeaderValue::from_static("Basic second"));
        assert_eq!(
            sole_header_value(&headers, &AUTHORIZATION).unwrap_err(),
            QidError::BadRequest {
                message: "multiple authorization headers are not allowed".to_string()
            }
        );
        assert_eq!(
            sole_header_value(&headers, &COOKIE).unwrap(),
            None,
            "an ambiguous Authorization field must not affect other headers"
        );
    }

    #[test]
    fn sole_header_value_rejects_non_utf8_values() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_bytes(&[0xff]).unwrap());
        assert_eq!(
            sole_header_value(&headers, &AUTHORIZATION).unwrap_err(),
            QidError::BadRequest {
                message: "authorization header is not valid UTF-8".to_string()
            }
        );
    }
}
