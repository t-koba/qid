//! Web security response headers: Referrer-Policy, Permissions-Policy, X-Frame-Options, Clear-Site-Data.

use axum::http::header::{self, HeaderValue};
use axum::response::Response;

pub fn apply_security_headers(response: &mut Response) {
    let headers = response.headers_mut();

    // Referrer-Policy (RFC 7044)
    if !headers.contains_key("Referrer-Policy") {
        headers.insert(
            header::HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        );
    }

    // Permissions-Policy (W3C)
    if !headers.contains_key("Permissions-Policy") {
        headers.insert(
            header::HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static(
                "camera=(), microphone=(), geolocation=(), interest-cohort=()",
            ),
        );
    }

    // X-Frame-Options (RFC 7034)
    if !headers.contains_key("x-frame-options") && !headers.contains_key("content-security-policy")
    {
        headers.insert(
            header::HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        );
    }
}

pub fn clear_site_data_header() -> HeaderValue {
    HeaderValue::from_static("\"cache\", \"cookies\", \"storage\", \"executionContexts\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn apply_security_headers_adds_referrer_policy() {
        use axum::http::StatusCode;
        let mut resp = StatusCode::OK.into_response();
        apply_security_headers(&mut resp);
        assert!(resp.headers().contains_key("referrer-policy"));
    }

    #[test]
    fn apply_security_headers_adds_permissions_policy() {
        use axum::http::StatusCode;
        let mut resp = StatusCode::OK.into_response();
        apply_security_headers(&mut resp);
        assert!(resp.headers().contains_key("permissions-policy"));
    }

    #[test]
    fn clear_site_data_is_valid() {
        let val = clear_site_data_header();
        assert!(!val.is_empty());
    }
}
