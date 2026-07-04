//! HTTP middleware primitives.
//!
//! Phase 0: request id, trace logging, CORS, CSRF protection, CSP headers, security headers.

use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::http::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri,
    header::{CONTENT_SECURITY_POLICY, HOST, ORIGIN, REFERER, STRICT_TRANSPORT_SECURITY},
};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use qid_core::config::CorsConfig;
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};
use tracing::{info, warn};

use crate::security_headers::apply_security_headers;

pub async fn request_id_layer(req: Request, next: Next) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let response = next.run(req).await;
    let status = response.status().as_u16();
    info!(method, path, status, "request handled");
    response
}

pub fn cors_layer(config: &CorsConfig) -> CorsLayer {
    if config.allowed_origins.is_empty() {
        return CorsLayer::new();
    }
    let mut layer = CorsLayer::new()
        .allow_methods(cors_methods(config))
        .allow_headers(cors_headers(config))
        .allow_credentials(config.allow_credentials);
    if config.allowed_origins.iter().any(|origin| origin == "*") {
        layer = layer.allow_origin(AllowOrigin::any());
    } else {
        layer = layer.allow_origin(AllowOrigin::list(cors_origins(config)));
    }
    layer
}

fn cors_origins(config: &CorsConfig) -> Vec<HeaderValue> {
    config
        .allowed_origins
        .iter()
        .filter_map(|origin| origin.parse::<HeaderValue>().ok())
        .collect()
}

fn cors_methods(config: &CorsConfig) -> Vec<Method> {
    config
        .allowed_methods
        .iter()
        .filter_map(|method| method.parse::<Method>().ok())
        .collect()
}

fn cors_headers(config: &CorsConfig) -> AllowHeaders {
    if config.allowed_headers.iter().any(|header| header == "*") {
        return AllowHeaders::any();
    }
    AllowHeaders::list(
        config
            .allowed_headers
            .iter()
            .filter_map(|header| header.parse::<HeaderName>().ok()),
    )
}

pub async fn csrf_protection_layer(req: Request, next: Next) -> Response {
    if is_state_changing_method(req.method()) && is_cross_site_request(req.headers(), req.uri()) {
        warn!(
            method = %req.method(),
            path = %req.uri().path(),
            "CSRF check rejected cross-site request"
        );
        return (StatusCode::FORBIDDEN, "CSRF check failed").into_response();
    }
    next.run(req).await
}

fn is_state_changing_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    )
}

fn is_cross_site_request(headers: &HeaderMap, uri: &Uri) -> bool {
    if let Some(origin) = headers.get(ORIGIN).and_then(header_to_str) {
        return !same_origin(origin, headers, uri);
    }
    if let Some(referer) = headers.get(REFERER).and_then(header_to_str) {
        return !same_origin(referer, headers, uri);
    }
    matches!(
        headers
            .get("sec-fetch-site")
            .and_then(header_to_str)
            .map(|value| value.to_ascii_lowercase()),
        Some(value) if value == "cross-site"
    )
}

fn same_origin(candidate: &str, headers: &HeaderMap, uri: &Uri) -> bool {
    let Some((candidate_scheme, candidate_host)) = parse_origin(candidate) else {
        return false;
    };
    let Some(expected_host) = headers.get(HOST).and_then(header_to_str) else {
        return false;
    };
    let expected_scheme = headers
        .get("x-forwarded-proto")
        .and_then(header_to_str)
        .or_else(|| uri.scheme_str())
        .unwrap_or("https");
    candidate_scheme.eq_ignore_ascii_case(expected_scheme)
        && candidate_host.eq_ignore_ascii_case(expected_host)
}

fn parse_origin(value: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = value.split_once("://")?;
    let host = rest.split(['/', '?', '#']).next()?.trim_end_matches('.');
    (!scheme.is_empty() && !host.is_empty()).then_some((scheme, host))
}

fn header_to_str(value: &HeaderValue) -> Option<&str> {
    value.to_str().ok().filter(|value| !value.is_empty())
}

/// Set Content-Security-Policy headers on every response.
///
/// Phase 0: strict policy allowing only same-origin resources, no scripts,
/// no objects, and no base URI manipulation.
pub async fn csp_headers_layer(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    response.headers_mut().insert(
        CONTENT_SECURITY_POLICY,
        "default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'"
            .parse()
            .unwrap(),
    );
    response
}

/// Set `Strict-Transport-Security` headers on every response.
///
/// RFC 6797 §7.2 requires HSTS to be sent over plaintext HTTP responses that
/// may be served alongside HTTPS endpoints. We default to a one-year policy
/// with `includeSubDomains` and `preload` directives because the deployment
/// is expected to serve exclusively under its own domain.
pub async fn hsts_layer(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let value = HeaderValue::from_static("max-age=31536000; includeSubDomains; preload");
    response
        .headers_mut()
        .insert(STRICT_TRANSPORT_SECURITY, value);
    response
}

pub async fn zero_rtt_rejection_layer(req: Request, next: Next) -> Response {
    if req.headers().contains_key("early-data") || req.headers().contains_key("Early-Data") {
        let mut response = Response::new(axum::body::Body::empty());
        *response.status_mut() = StatusCode::from_u16(425).unwrap();
        response.headers_mut().insert(
            HeaderName::from_static("early-data"),
            HeaderValue::from_static("1"),
        );
        return response;
    }
    next.run(req).await
}

pub async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    apply_security_headers(&mut response);
    response
}

/// FAPI 2.0 Message Signing Profile (RFC 9421) configuration. When wired
/// in, the middleware validates the `Signature` and `Signature-Input`
/// headers on every incoming request and rejects unsigned or
/// inappropriately-signed traffic with `401 Unauthorized`.
#[derive(Debug, Clone)]
pub struct HttpMessageSignatureConfig {
    /// HMAC-SHA256 secret used to validate the `@authority`, `@method`,
    /// `@path`, `@status`, and `content-digest` signature parameters.
    pub shared_secret: Vec<u8>,
    /// Optional RFC 9421 keyid bound to this shared secret.
    pub key_id: Option<String>,
    /// Per-adapter or per-client HMAC keys selected by RFC 9421 keyid.
    pub keys: Vec<HttpMessageSignatureKey>,
    /// Maximum age, in seconds, between `created` and the local clock.
    /// Requests outside the window are rejected.
    pub max_age_seconds: u64,
    /// When `true`, the middleware enforces FAPI 2.0's mandatory covered
    /// components: `@authority`, `@method`, `@path`, `content-digest`.
    pub require_content_digest: bool,
}

impl Default for HttpMessageSignatureConfig {
    fn default() -> Self {
        Self {
            shared_secret: b"qid-fapi-default-please-override".to_vec(),
            key_id: None,
            keys: Vec::new(),
            max_age_seconds: 300,
            require_content_digest: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpMessageSignatureKey {
    pub key_id: String,
    pub shared_secret: Vec<u8>,
}

/// Verify the RFC 9421 `Signature-Input` and `Signature` headers on every
/// request. The middleware is intentionally conservative: it only
/// recognises HMAC-SHA256 signatures over the canonical FAPI 2.0
/// components. Other algorithms are rejected.
pub async fn http_message_signatures_layer(
    config: axum::extract::State<HttpMessageSignatureConfig>,
    req: Request,
    next: Next,
) -> Response {
    let signature_input = req
        .headers()
        .get("signature-input")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let signature = req
        .headers()
        .get("signature")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let (signature_input, signature) = match (signature_input, signature) {
        (Some(si), Some(s)) => (si, s),
        _ => {
            return unauthorized("missing Signature-Input and/or Signature header");
        }
    };
    let req = match verify_content_digest_and_rebuild(req, config.require_content_digest).await {
        Ok(req) => req,
        Err(message) => return unauthorized(&message),
    };
    if let Err(message) = verify_http_message_signature(&req, &signature_input, &signature, &config)
    {
        return unauthorized(&message);
    }
    next.run(req).await
}

fn unauthorized(message: &str) -> Response {
    let body = serde_json::json!({ "error": "invalid_signature", "error_description": message });
    let mut response = (StatusCode::UNAUTHORIZED, axum::Json(body)).into_response();
    response.headers_mut().insert(
        HeaderName::from_static("www-authenticate"),
        HeaderValue::from_static("Signature realm=\"qid\", error=\"invalid_signature\""),
    );
    response
}

/// Verify a single HTTP message signature per RFC 9421, restricted to
/// the FAPI 2.0 Message Signing Profile. Returns `Ok(())` on success
/// and an `Err(message)` describing the failure otherwise.
pub fn verify_http_message_signature(
    req: &Request,
    signature_input: &str,
    signature: &str,
    config: &HttpMessageSignatureConfig,
) -> Result<(), String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let parsed = parse_signature_input(signature_input)?;
    if !parsed.algorithm.eq_ignore_ascii_case("HMAC-SHA256") {
        return Err(format!(
            "signature algorithm '{}' is not allowed",
            parsed.algorithm
        ));
    }
    let signing_secret = select_http_message_signature_secret(config, parsed.key_id.as_deref())?;
    if config.require_content_digest {
        let requires = parsed
            .covered_components
            .iter()
            .any(|c| matches!(c.name.as_str(), "content-digest"));
        if !requires {
            return Err("FAPI 2.0 requires content-digest to be covered".to_string());
        }
    }
    if let Some(expires) = parsed.expires
        && expires < qid_core::util::now_seconds()
    {
        return Err("HTTP message signature has expired".to_string());
    }
    if let Some(created) = parsed.created {
        let now = qid_core::util::now_seconds();
        if created > now + 5 || now.saturating_sub(created) > config.max_age_seconds {
            return Err("HTTP message signature is outside the allowed window".to_string());
        }
    }
    let signature_bytes = parse_signature_header(signature, &parsed.label)?;
    let canonical = build_signature_base(req, &parsed)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(signing_secret).map_err(|e| format!("hmac: {e}"))?;
    mac.update(canonical.as_bytes());
    mac.verify_slice(&signature_bytes)
        .map_err(|_| "HTTP message signature mismatch".to_string())?;
    Ok(())
}

fn select_http_message_signature_secret<'a>(
    config: &'a HttpMessageSignatureConfig,
    key_id: Option<&str>,
) -> Result<&'a [u8], String> {
    if !config.keys.is_empty() {
        let key_id = key_id.ok_or_else(|| {
            "HTTP message signature keyid is required for configured key set".to_string()
        })?;
        let key = config
            .keys
            .iter()
            .find(|key| key.key_id == key_id)
            .ok_or_else(|| "HTTP message signature keyid is not allowed".to_string())?;
        return Ok(key.shared_secret.as_slice());
    }
    if let Some(expected_key_id) = config.key_id.as_deref()
        && key_id != Some(expected_key_id)
    {
        return Err("HTTP message signature keyid is not allowed".to_string());
    }
    Ok(config.shared_secret.as_slice())
}

struct ParsedSignatureInput {
    label: String,
    algorithm: String,
    covered_components: Vec<ComponentRef>,
    created: Option<u64>,
    expires: Option<u64>,
    key_id: Option<String>,
    signature_params: String,
}

struct ComponentRef {
    name: String,
}

fn parse_signature_input(input: &str) -> Result<ParsedSignatureInput, String> {
    // RFC 9421 §4.2 grammar: `sig1=("@method" "@path" ...);alg="hmac-sha256";created=1700000000;expires=1700003600;keyid="..."`
    let (label_and_components, params) = input
        .split_once(';')
        .ok_or_else(|| "Signature-Input must contain a label and parameters".to_string())?;
    let (label, components_part) = label_and_components.split_once('=').ok_or_else(|| {
        "Signature-Input label must be followed by covered components".to_string()
    })?;
    let signature_params = format!("{};{}", components_part.trim(), params.trim());
    if label.trim().is_empty() {
        return Err("Signature-Input label must not be empty".to_string());
    }
    let components_str = components_part
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim();
    let mut covered_components = Vec::new();
    for raw in components_str.split_whitespace() {
        let trimmed = raw.trim_matches('"');
        if trimmed.is_empty() {
            continue;
        }
        covered_components.push(ComponentRef {
            name: trimmed.to_string(),
        });
    }
    let mut algorithm = String::from("hmac-sha256");
    let mut created = None;
    let mut expires = None;
    let mut key_id = None;
    for param in params.split(';') {
        let param = param.trim();
        if param.is_empty() {
            continue;
        }
        let (key, value) = param
            .split_once('=')
            .ok_or_else(|| format!("malformed Signature-Input parameter '{param}'"))?;
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        match key {
            "alg" => algorithm = value.to_string(),
            "created" => created = value.parse().ok(),
            "expires" => expires = value.parse().ok(),
            "keyid" => key_id = Some(value.to_string()),
            _ => {}
        }
    }
    Ok(ParsedSignatureInput {
        label: label.trim().to_string(),
        algorithm,
        covered_components,
        created,
        expires,
        key_id,
        signature_params,
    })
}

fn parse_signature_header(input: &str, expected_label: &str) -> Result<Vec<u8>, String> {
    for member in input.split(',') {
        let member = member.trim();
        let Some((label, value)) = member.split_once('=') else {
            continue;
        };
        if label.trim() != expected_label {
            continue;
        }
        let value = value.trim();
        if let Some(encoded) = value.strip_prefix(':').and_then(|v| v.strip_suffix(':')) {
            return base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|e| format!("invalid Signature byte sequence encoding: {e}"));
        }
        return base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|e| format!("invalid signature base64url encoding: {e}"));
    }
    if expected_label == "sig1" {
        return base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(input.trim())
            .map_err(|e| format!("invalid signature base64url encoding: {e}"));
    }
    Err(format!(
        "Signature header does not contain signature label '{expected_label}'"
    ))
}

async fn verify_content_digest_and_rebuild(
    req: Request,
    require_content_digest: bool,
) -> Result<Request, String> {
    if !require_content_digest {
        return Ok(req);
    }
    let (parts, body) = req.into_parts();
    let body_bytes = to_bytes(body, 16 * 1024 * 1024)
        .await
        .map_err(|e| format!("failed to read request body for content-digest: {e}"))?;
    verify_content_digest_header(&parts.headers, &body_bytes)?;
    Ok(Request::from_parts(parts, Body::from(body_bytes)))
}

fn verify_content_digest_header(headers: &HeaderMap, body: &[u8]) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let header = headers
        .get("content-digest")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| "content-digest header is required".to_string())?;
    let expected = parse_content_digest_header(header)?;
    let actual = Sha256::digest(body);
    if expected.as_slice() != actual.as_slice() {
        return Err("content-digest does not match request body".to_string());
    }
    Ok(())
}

fn parse_content_digest_header(input: &str) -> Result<Vec<u8>, String> {
    for member in input.split(',') {
        let member = member.trim();
        let Some((algorithm, value)) = member.split_once('=') else {
            continue;
        };
        if !algorithm.trim().eq_ignore_ascii_case("sha-256") {
            continue;
        }
        let value = value.trim();
        let encoded = value
            .strip_prefix(':')
            .and_then(|v| v.strip_suffix(':'))
            .unwrap_or(value);
        return base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| format!("invalid content-digest sha-256 encoding: {e}"));
    }
    Err("content-digest must contain sha-256".to_string())
}

fn build_signature_base(req: &Request, parsed: &ParsedSignatureInput) -> Result<String, String> {
    let mut out = String::new();
    for (idx, component) in parsed.covered_components.iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        match component.name.as_str() {
            "@method" => out.push_str(&format!("\"@method\": {}", req.method())),
            "@path" => out.push_str(&format!("\"@path\": {}", req.uri().path())),
            "@authority" => {
                let authority = req
                    .headers()
                    .get(HOST)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                out.push_str(&format!("\"@authority\": {authority}"));
            }
            "@scheme" => {
                let scheme = req.uri().scheme_str().unwrap_or("https");
                out.push_str(&format!("\"@scheme\": {scheme}"));
            }
            "content-digest" => {
                let digest = req
                    .headers()
                    .get("content-digest")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if digest.is_empty() {
                    return Err("content-digest header is required".to_string());
                }
                out.push_str(&format!("\"content-digest\": {digest}"));
            }
            other => return Err(format!("unsupported covered component '{other}'")),
        }
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(&format!(
        "\"@signature-params\": {}",
        parsed.signature_params
    ));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use qid_core::config::CorsConfig;

    fn headers(values: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in values {
            headers.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    #[test]
    fn csrf_allows_same_origin_signal() {
        let headers = headers(&[
            ("host", "id.example.com"),
            ("origin", "https://id.example.com"),
        ]);
        let uri = Uri::from_static("/oauth2/token");
        assert!(!is_cross_site_request(&headers, &uri));
    }

    #[test]
    fn csrf_rejects_cross_origin_signal() {
        let headers = headers(&[
            ("host", "id.example.com"),
            ("origin", "https://evil.example.com"),
        ]);
        let uri = Uri::from_static("/admin/api/v1/test/clients");
        assert!(is_cross_site_request(&headers, &uri));
    }

    #[test]
    fn csrf_rejects_cross_site_fetch_metadata_without_origin() {
        let headers = headers(&[("host", "id.example.com"), ("sec-fetch-site", "cross-site")]);
        let uri = Uri::from_static("/admin/api/v1/test/clients");
        assert!(is_cross_site_request(&headers, &uri));
    }

    #[test]
    fn csrf_allows_machine_clients_without_browser_signal() {
        let headers = headers(&[("host", "id.example.com")]);
        let uri = Uri::from_static("/oauth2/token");
        assert!(!is_cross_site_request(&headers, &uri));
    }

    #[test]
    fn cors_helpers_keep_default_closed_and_parse_configured_origin() {
        let default_config = CorsConfig::default();
        assert!(cors_origins(&default_config).is_empty());

        let config = CorsConfig {
            allowed_origins: vec!["https://app.example.com".to_string()],
            ..CorsConfig::default()
        };
        assert_eq!(
            cors_origins(&config),
            vec![HeaderValue::from_static("https://app.example.com")]
        );
    }

    #[test]
    fn signature_header_accepts_rfc9421_byte_sequence_dictionary() {
        let signature = base64::engine::general_purpose::STANDARD.encode(b"signature-bytes");
        let parsed = parse_signature_header(&format!("sig1=:{signature}:"), "sig1").unwrap();
        assert_eq!(parsed, b"signature-bytes");
    }

    #[test]
    fn content_digest_must_match_body_bytes() {
        use sha2::{Digest, Sha256};

        let body = br#"{"ok":true}"#;
        let digest = Sha256::digest(body);
        let header = format!(
            "sha-256=:{}:",
            base64::engine::general_purpose::STANDARD.encode(digest)
        );
        let headers = headers(&[("content-digest", &header)]);

        verify_content_digest_header(&headers, body).unwrap();
        assert!(verify_content_digest_header(&headers, br#"{"ok":false}"#).is_err());
    }
}
