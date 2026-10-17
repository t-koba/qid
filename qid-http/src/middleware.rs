//! HTTP middleware primitives.
//!
//! Phase 0: request id, trace logging, CORS, CSRF protection, CSP headers, security headers.

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri,
    header::{CONTENT_SECURITY_POLICY, HOST, ORIGIN, REFERER, STRICT_TRANSPORT_SECURITY},
};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use qid_core::config::{CorsConfig, HstsConfig, ServerPaths};
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};
use tracing::{Instrument, info, warn};

use crate::security_headers::apply_security_headers;

pub async fn request_id_layer(req: Request, next: Next) -> Response {
    let request_id = request_id_from_headers(req.headers()).unwrap_or_else(new_request_id);
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let span = tracing::info_span!(
        "http_request",
        request_id = %request_id,
        method = %method,
        path = %path
    );
    let mut response = next.run(req).instrument(span).await;
    let status = response.status().as_u16();
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-request-id"), value);
    }
    info!(request_id, method, path, status, "request handled");
    response
}

fn request_id_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-request-id")
        .and_then(header_to_str)
        .filter(|value| valid_request_id(value))
        .map(ToOwned::to_owned)
}

fn new_request_id() -> String {
    ulid::Ulid::new().to_string()
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
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

/// Paths that authenticate without the browser session cookie.
///
/// Token, introspection, revocation, PAR, device/CIBA initiation, dynamic
/// client registration, and the RFC 9470 challenge endpoint authenticate with
/// client credentials, bearer tokens, DPoP/mTLS proof, or PKCE rather than an
/// ambient cookie. They are designed for cross-origin and back-channel use
/// (for example the SPA authorization-code/PKCE exchange) and must not be
/// blocked by the cookie-oriented CSRF check. Every other state-changing
/// route stays under strict same-origin CSRF protection.
pub fn is_csrf_exempt_path(path: &str, paths: &ServerPaths) -> bool {
    if path == paths.token
        || path == paths.introspect
        || path == paths.revoke
        || path == paths.par
        || path == paths.device_authorization
        || path == paths.backchannel_authentication
        || path == paths.dynamic_client_registration
        || path == "/oauth2/challenge"
    {
        return true;
    }
    // Dynamic client registration management uses a templated path such as
    // `/oauth2/register/:client_id`; match the concrete instance segment-wise
    // so earlier params (for example `/api/:realm/register/:client_id`) do not
    // exempt unrelated paths sharing a leading prefix.
    matches_path_template(&paths.dynamic_client_registration_management, path)
}

/// Match a configured `server.paths` template against a concrete request path.
///
/// Templates use Axum `:param` segments (for example `:client_id` or
/// `:realm`). Each param matches exactly one non-empty path segment; all
/// other segments must match exactly, including segment count. Templates
/// without params require an exact match.
fn matches_path_template(template: &str, path: &str) -> bool {
    if !template.contains(':') {
        return template == path;
    }
    let mut template_segments = template.split('/');
    let mut path_segments = path.split('/');
    loop {
        match (template_segments.next(), path_segments.next()) {
            (Some(expected), Some(actual)) => {
                if expected.starts_with(':') {
                    // Param name must be non-empty (`/ :` alone is not a param).
                    if expected.len() <= 1 || actual.is_empty() {
                        return false;
                    }
                } else if expected != actual {
                    return false;
                }
            }
            (None, None) => return true,
            _ => return false,
        }
    }
}

/// CSRF protection that exempts non-cookie OAuth routes.
///
/// Wire with `axum::middleware::from_fn_with_state(paths, ..)` so configured
/// `server.paths` are honoured. Approval sub-paths (`.../approve`) remain
/// protected because matching is exact, except for the templated dynamic
/// client registration management route.
pub async fn csrf_protection_layer_with_server_paths(
    State(paths): State<ServerPaths>,
    req: Request,
    next: Next,
) -> Response {
    if is_state_changing_method(req.method())
        && !is_csrf_exempt_path(req.uri().path(), &paths)
        && is_cross_site_request(req.headers(), req.uri())
    {
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
/// no objects, no base URI manipulation, and no framing.
pub async fn csp_headers_layer(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    response.headers_mut().insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
    response
}

/// Set `Strict-Transport-Security` headers on secure deployments.
///
/// Per RFC 6797 s7.2 HSTS must not be sent over insecure transport; transport
/// trust comes from the deployment public scheme resolved at wiring, so behind
/// a TLS proxy `server.public_base_url` declares the external scheme.
/// Wire with `axum::middleware::from_fn_with_state(effective_config, ..)`.
/// Defaults to a one-year policy with `includeSubDomains`. `preload` stays
/// opt-in because it requires operator submission to browser preload lists.
pub async fn hsts_layer(State(config): State<HstsConfig>, req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    if !config.enabled {
        return response;
    }
    let mut value = format!("max-age={}", config.max_age_seconds);
    if config.include_subdomains {
        value.push_str("; includeSubDomains");
    }
    if config.preload {
        value.push_str("; preload");
    }
    if let Ok(header) = HeaderValue::from_str(&value) {
        response
            .headers_mut()
            .insert(STRICT_TRANSPORT_SECURITY, header);
    }
    response
}

pub async fn zero_rtt_rejection_layer(req: Request, next: Next) -> Response {
    // HeaderMap keys are case-insensitive, so one lookup covers all casings.
    if req.headers().contains_key("early-data") {
        let mut response = Response::new(axum::body::Body::empty());
        *response.status_mut() = StatusCode::TOO_EARLY;
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

/// Proprietary HMAC subset inspired by RFC 9421 for edge-pep ingress (not FAPI 2.0 Message Signing). When wired
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
    /// When `true`, the middleware enforces the mandatory covered
    /// components: `@authority`, `@method`, `@path`, `content-digest`.
    pub require_content_digest: bool,
}

impl Default for HttpMessageSignatureConfig {
    fn default() -> Self {
        Self {
            // No placeholder secret: verification must fail closed without
            // operator-configured key material.
            shared_secret: Vec::new(),
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

/// Verify the `Signature-Input` and `Signature` headers on every
/// request. The middleware is intentionally conservative: it only
/// recognises HMAC-SHA256 signatures over a proprietary subset of
/// components for edge-pep ingress. Other algorithms are rejected.
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

/// Verify a single HTTP message signature for the proprietary HMAC-only
/// edge-pep ingress subset inspired by RFC 9421. Returns `Ok(())` on success
/// and an `Err(message)` describing the failure otherwise.
fn verify_http_message_signature(
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
            return Err("content-digest must be covered".to_string());
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
        if key.shared_secret.is_empty() {
            return Err("HTTP message signature secret is not configured".to_string());
        }
        return Ok(key.shared_secret.as_slice());
    }
    if let Some(expected_key_id) = config.key_id.as_deref()
        && key_id != Some(expected_key_id)
    {
        return Err("HTTP message signature keyid is not allowed".to_string());
    }
    if config.shared_secret.is_empty() {
        return Err("HTTP message signature secret is not configured".to_string());
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

    #[tokio::test]
    async fn csp_headers_deny_framing_despite_x_frame_options_skip() {
        use axum::Router;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use axum::routing::get;
        use tower::ServiceExt;

        let app = Router::new()
            .route("/health", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(csp_headers_layer))
            .layer(axum::middleware::from_fn(security_headers_middleware));

        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let csp = res
            .headers()
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            csp.contains("frame-ancestors 'none'"),
            "CSP must deny framing, got: {csp}"
        );
    }

    async fn hsts_get(config: HstsConfig, uri: &str) -> axum::http::Response<axum::body::Body> {
        use tower::ServiceExt;
        let app = axum::Router::new()
            .route("/health", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(config, hsts_layer));
        let req = axum::http::Request::builder()
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap();
        app.oneshot(req).await.unwrap()
    }

    fn hsts_value(res: &axum::http::Response<axum::body::Body>) -> &str {
        res.headers()
            .get("strict-transport-security")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn hsts_layer_defaults_without_preload() {
        use axum::http::StatusCode;
        let res = hsts_get(HstsConfig::default(), "/health").await;
        assert_eq!(res.status(), StatusCode::OK);
        let hsts = hsts_value(&res).to_string();
        assert!(
            hsts.contains("max-age=31536000"),
            "HSTS must carry one-year max-age, got: {hsts}"
        );
        assert!(
            hsts.contains("includeSubDomains"),
            "HSTS must include subdomains, got: {hsts}"
        );
        assert!(
            !hsts.contains("preload"),
            "HSTS preload must stay opt-in, got: {hsts}"
        );
    }

    #[tokio::test]
    async fn hsts_layer_disabled_emits_no_header() {
        use axum::http::StatusCode;
        let config = HstsConfig {
            enabled: false,
            ..HstsConfig::default()
        };
        let res = hsts_get(config, "/health").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(
            res.headers().get("strict-transport-security").is_none(),
            "disabled HSTS must not emit a header"
        );
    }

    #[tokio::test]
    async fn hsts_layer_custom_max_age_without_subdomains() {
        use axum::http::StatusCode;
        let config = HstsConfig {
            max_age_seconds: 86400,
            include_subdomains: false,
            ..HstsConfig::default()
        };
        let res = hsts_get(config, "/health").await;
        assert_eq!(res.status(), StatusCode::OK);
        let hsts = hsts_value(&res).to_string();
        assert!(
            hsts.contains("max-age=86400"),
            "HSTS must carry custom max-age, got: {hsts}"
        );
        assert!(
            !hsts.contains("includeSubDomains"),
            "HSTS must omit subdomains when disabled, got: {hsts}"
        );
    }

    #[tokio::test]
    async fn hsts_layer_preload_opt_in() {
        use axum::http::StatusCode;
        let config = HstsConfig {
            preload: true,
            ..HstsConfig::default()
        };
        let res = hsts_get(config, "/health").await;
        assert_eq!(res.status(), StatusCode::OK);
        let hsts = hsts_value(&res).to_string();
        assert!(
            hsts.contains("preload"),
            "HSTS must include preload when opted in, got: {hsts}"
        );
    }

    #[test]
    fn effective_hsts_config_follows_public_scheme() {
        use qid_core::config::effective_hsts_config;
        assert!(effective_hsts_config(&HstsConfig::default(), "https://id.example.com").enabled);
        assert!(!effective_hsts_config(&HstsConfig::default(), "http://id.example.com").enabled);
    }

    #[tokio::test]
    async fn zero_rtt_rejection_is_case_insensitive() {
        use axum::Router;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use axum::routing::get;
        use tower::ServiceExt;

        let app = Router::new()
            .route("/health", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(zero_rtt_rejection_layer));

        async fn status_for(app: Router, name: Option<&str>) -> StatusCode {
            let mut builder = Request::builder().uri("/health");
            if let Some(name) = name {
                builder = builder.header(name, "1");
            }
            let req = builder.body(Body::empty()).unwrap();
            app.oneshot(req).await.unwrap().status()
        }

        assert_eq!(status_for(app.clone(), None).await, StatusCode::OK);
        assert_eq!(
            status_for(app.clone(), Some("early-data")).await,
            StatusCode::TOO_EARLY
        );
        assert_eq!(
            status_for(app.clone(), Some("Early-Data")).await,
            StatusCode::TOO_EARLY
        );
        assert_eq!(
            status_for(app.clone(), Some("EARLY-DATA")).await,
            StatusCode::TOO_EARLY
        );
    }

    #[test]
    fn request_id_accepts_safe_client_value() {
        let headers = headers(&[("x-request-id", "req-01HZZZZZZZZZZZZZZZZZZZZZZZ")]);

        assert_eq!(
            request_id_from_headers(&headers).as_deref(),
            Some("req-01HZZZZZZZZZZZZZZZZZZZZZZZ")
        );
    }

    #[test]
    fn request_id_rejects_unsafe_client_value() {
        let headers = headers(&[("x-request-id", "bad value with spaces")]);

        assert!(request_id_from_headers(&headers).is_none());
    }

    #[test]
    fn signature_header_accepts_rfc9421_byte_sequence_dictionary() {
        let signature = base64::engine::general_purpose::STANDARD.encode(b"signature-bytes");
        let parsed = parse_signature_header(&format!("sig1=:{signature}:"), "sig1").unwrap();
        assert_eq!(parsed, b"signature-bytes");
    }

    #[test]
    fn http_signature_rejects_non_hmac_algorithm() {
        let req = axum::http::Request::builder()
            .method("GET")
            .uri("https://example.com/path")
            .header("host", "example.com")
            .body(axum::body::Body::empty())
            .unwrap();
        let config = HttpMessageSignatureConfig {
            shared_secret: b"test-secret-32-bytes-long-for-hmac".to_vec(),
            ..HttpMessageSignatureConfig::default()
        };
        let err = verify_http_message_signature(
            &req,
            "sig1=(\"@method\" \"@path\");alg=\"rsa-pss-sha512\";created=1700000000",
            "sig1=:aGk=:",
            &config,
        )
        .expect_err("non-HMAC must fail closed");
        assert!(err.contains("not allowed"), "unexpected error: {err}");
    }

    #[test]
    fn http_signature_rejects_unsupported_component() {
        let req = axum::http::Request::builder()
            .method("GET")
            .uri("https://example.com/path")
            .header("host", "example.com")
            .header("content-digest", "sha-256=:aGk=:")
            .body(axum::body::Body::empty())
            .unwrap();
        let config = HttpMessageSignatureConfig {
            shared_secret: b"test-secret-32-bytes-long-for-hmac".to_vec(),
            ..HttpMessageSignatureConfig::default()
        };
        let err = verify_http_message_signature(
            &req,
            "sig1=(\"@method\" \"@query\" \"content-digest\");alg=\"hmac-sha256\"",
            "sig1=:aGk=:",
            &config,
        )
        .expect_err("unsupported component must fail closed");
        assert!(
            err.contains("unsupported covered component"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn http_signature_fails_closed_without_secret() {
        let config = HttpMessageSignatureConfig::default();
        assert!(
            config.shared_secret.is_empty(),
            "default must not carry a placeholder secret"
        );
        let req = axum::http::Request::builder()
            .method("GET")
            .uri("https://example.com/path")
            .header("host", "example.com")
            .header("content-digest", "sha-256=:aGk=:")
            .body(axum::body::Body::empty())
            .unwrap();
        let err = verify_http_message_signature(
            &req,
            "sig1=(\"@method\" \"@path\" \"content-digest\");alg=\"hmac-sha256\"",
            "sig1=:aGk=:",
            &config,
        )
        .expect_err("unconfigured secret must fail closed");
        assert!(err.contains("not configured"), "unexpected error: {err}");
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

    #[test]
    fn csrf_exempt_paths_cover_oauth_backchannel_but_not_approvals_or_sessions() {
        use qid_core::config::ServerPaths;

        let paths = ServerPaths::default();
        assert!(is_csrf_exempt_path(&paths.token, &paths));
        assert!(is_csrf_exempt_path(&paths.introspect, &paths));
        assert!(is_csrf_exempt_path(&paths.revoke, &paths));
        assert!(is_csrf_exempt_path(&paths.par, &paths));
        assert!(is_csrf_exempt_path(&paths.device_authorization, &paths));
        assert!(is_csrf_exempt_path(
            &paths.backchannel_authentication,
            &paths
        ));
        assert!(is_csrf_exempt_path(
            &paths.dynamic_client_registration,
            &paths
        ));
        assert!(is_csrf_exempt_path("/oauth2/challenge", &paths));
        assert!(is_csrf_exempt_path("/oauth2/register/my-client", &paths));
        // Nested paths under the management prefix stay protected; only a
        // single concrete `:client_id` segment is exempt.
        assert!(!is_csrf_exempt_path("/oauth2/register/foo/bar", &paths));
        assert!(!is_csrf_exempt_path("/oauth2/register/", &paths));

        let device_approve = format!("{}/approve", paths.device_authorization);
        assert!(!is_csrf_exempt_path(&device_approve, &paths));
        let ciba_approve = format!("{}/approve", paths.backchannel_authentication);
        assert!(!is_csrf_exempt_path(&ciba_approve, &paths));

        assert!(!is_csrf_exempt_path(&paths.auth_session_refresh, &paths));
        assert!(!is_csrf_exempt_path(&paths.auth_password, &paths));
        assert!(!is_csrf_exempt_path(&paths.authorize, &paths));
        assert!(!is_csrf_exempt_path(&paths.logout, &paths));

        let mut custom = paths.clone();
        custom.token = "/custom/token".to_string();
        assert!(is_csrf_exempt_path("/custom/token", &custom));
        assert!(!is_csrf_exempt_path("/oauth2/token", &custom));
    }

    #[test]
    fn csrf_exempt_dcr_management_matches_template_segment_wise() {
        use qid_core::config::ServerPaths;

        let paths = ServerPaths {
            dynamic_client_registration: "/api/clients".to_string(),
            dynamic_client_registration_management: "/api/:realm/register/:client_id".to_string(),
            ..ServerPaths::default()
        };

        // Concrete management instance is exempt.
        assert!(is_csrf_exempt_path(
            "/api/customers/register/my-client",
            &paths
        ));
        // Unrelated paths sharing the leading `/api` prefix stay protected,
        // including the session route from the failing scenario.
        assert!(!is_csrf_exempt_path(
            "/api/v1/customers/auth/session/refresh",
            &paths
        ));
        assert!(!is_csrf_exempt_path(
            "/api/customers/auth/session/refresh",
            &paths
        ));
        // Wrong segment count or empty param stays protected.
        assert!(!is_csrf_exempt_path(
            "/api/customers/register/my-client/extra",
            &paths
        ));
        assert!(!is_csrf_exempt_path("/api/customers/register/", &paths));
        assert!(!is_csrf_exempt_path("/api/customers/register", &paths));
        assert!(!is_csrf_exempt_path("/api/other/register", &paths));

        // Non-templated management path requires an exact match.
        let exact = ServerPaths {
            dynamic_client_registration_management: "/custom/register/manage".to_string(),
            ..ServerPaths::default()
        };
        assert!(is_csrf_exempt_path("/custom/register/manage", &exact));
        assert!(!is_csrf_exempt_path(
            "/custom/register/manage/extra",
            &exact
        ));
        assert!(!is_csrf_exempt_path("/custom/register", &exact));
    }

    #[tokio::test]
    async fn composed_router_allows_spa_token_but_protects_session() {
        use axum::Router;
        use axum::body::Body;
        use axum::http::{HeaderMap, Request, StatusCode};
        use axum::routing::post;
        use tower::ServiceExt;

        use qid_core::config::{CorsConfig, HstsConfig, ServerPaths};

        // Mirrors config/usecases/01-getting-started/oidc-spa-pkce.yaml CORS.
        let paths = ServerPaths::default();
        let cors = CorsConfig {
            allowed_origins: vec!["https://spa.example.com".to_string()],
            allowed_methods: vec!["GET".to_string(), "POST".to_string(), "OPTIONS".to_string()],
            allowed_headers: vec![
                "authorization".to_string(),
                "content-type".to_string(),
                "dpop".to_string(),
            ],
            allow_credentials: true,
        };
        let token_path = paths.token.clone();
        let session_template = paths.auth_session_refresh.clone();
        let session_concrete = session_template.replace(":realm", "customers");
        let token_uri = format!("https://id.example.com{token_path}");
        let session_uri = format!("https://id.example.com{session_concrete}");

        // Daemon layer order (inner to outer): CSRF, CSP, 0-RTT, HSTS,
        // security headers, CORS. Request-ID/metrics/mTLS are omitted here;
        // they do not affect the CORS/CSRF composition.
        let app = Router::new()
            .route(&token_path, post(|| async { "token-ok" }))
            .route(&session_template, post(|| async { "session-ok" }))
            .layer(axum::middleware::from_fn_with_state(
                paths.clone(),
                csrf_protection_layer_with_server_paths,
            ))
            .layer(axum::middleware::from_fn(csp_headers_layer))
            .layer(axum::middleware::from_fn(zero_rtt_rejection_layer))
            .layer(axum::middleware::from_fn_with_state(
                HstsConfig::default(),
                hsts_layer,
            ))
            .layer(axum::middleware::from_fn(security_headers_middleware))
            .layer(cors_layer(&cors));

        async fn send(
            app: Router,
            method: &str,
            uri: &str,
            origin: Option<&str>,
            extra: &[(&str, &str)],
        ) -> (StatusCode, HeaderMap) {
            let mut builder = Request::builder().method(method).uri(uri);
            builder = builder.header("host", "id.example.com");
            if let Some(origin) = origin {
                builder = builder.header("origin", origin);
            }
            for (name, value) in extra {
                builder = builder.header(*name, *value);
            }
            let req = builder.body(Body::empty()).unwrap();
            let res = app.oneshot(req).await.unwrap();
            (res.status(), res.headers().clone())
        }

        fn allow_origin(headers: &HeaderMap) -> Option<String> {
            headers
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok())
                .map(ToOwned::to_owned)
        }

        // Preflight from the configured SPA origin succeeds with ACAO.
        let (status, headers) = send(
            app.clone(),
            "OPTIONS",
            &token_uri,
            Some("https://spa.example.com"),
            &[
                ("access-control-request-method", "POST"),
                ("access-control-request-headers", "content-type"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            allow_origin(&headers).as_deref(),
            Some("https://spa.example.com")
        );

        // Configured SPA origin reaches the token handler with ACAO.
        let (status, headers) = send(
            app.clone(),
            "POST",
            &token_uri,
            Some("https://spa.example.com"),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            allow_origin(&headers).as_deref(),
            Some("https://spa.example.com")
        );

        // Denied origin still reaches the token handler (no cookie to protect)
        // but CORS withholds ACAO so the browser blocks the read.
        let (status, headers) = send(
            app.clone(),
            "POST",
            &token_uri,
            Some("https://evil.example.com"),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(allow_origin(&headers).is_none());

        // Same-origin and machine token posts succeed.
        let (status, _) = send(
            app.clone(),
            "POST",
            &token_uri,
            Some("https://id.example.com"),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = send(app.clone(), "POST", &token_uri, None, &[]).await;
        assert_eq!(status, StatusCode::OK);

        // Session operations stay fail-closed even for the allowed CORS origin.
        let (status, headers) = send(
            app.clone(),
            "POST",
            &session_uri,
            Some("https://spa.example.com"),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            allow_origin(&headers).as_deref(),
            Some("https://spa.example.com")
        );

        // Denied session origin is also forbidden.
        let (status, _) = send(
            app.clone(),
            "POST",
            &session_uri,
            Some("https://evil.example.com"),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Same-origin session post reaches the handler.
        let (status, _) = send(
            app.clone(),
            "POST",
            &session_uri,
            Some("https://id.example.com"),
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
}
