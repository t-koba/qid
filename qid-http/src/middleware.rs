//! HTTP middleware primitives.
//!
//! Phase 0: request id, trace logging, CORS, CSRF protection, CSP headers, security headers.

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri,
    header::{CONTENT_SECURITY_POLICY, HOST, ORIGIN, REFERER, STRICT_TRANSPORT_SECURITY},
    uri::Authority,
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
    // Authorization API 1.0 §10.1.3 defines the identifier as an arbitrary
    // string and requires echoing it verbatim. Only empty values and
    // header-unsafe control characters are rejected; shape is not policy.
    !value.is_empty() && !value.chars().any(char::is_control)
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

/// State for same-origin CSRF protection: configured paths and the
/// authoritative scheme from the deployment's `server.public_base_url`.
#[derive(Clone, Debug)]
pub struct CsrfConfig {
    paths: ServerPaths,
    public_scheme: String,
}

impl CsrfConfig {
    pub fn new(paths: ServerPaths, public_scheme: &str) -> Self {
        Self {
            paths,
            public_scheme: public_scheme.to_string(),
        }
    }
}

/// CSRF protection that exempts non-cookie OAuth routes.
///
/// Wire with `axum::middleware::from_fn_with_state(CsrfConfig::new(..), ..)`
/// so configured `server.paths` and the public scheme are honoured. Approval
/// sub-paths (`.../approve`) remain protected because matching is exact,
/// except for the templated dynamic client registration management route.
///
/// The configured public scheme is authoritative for origin comparison,
/// including behind TLS termination. Forwarded and request schemes are never
/// trusted to change the expected scheme.
pub async fn csrf_protection_layer(
    State(config): State<CsrfConfig>,
    req: Request,
    next: Next,
) -> Response {
    if is_state_changing_method(req.method())
        && !is_csrf_exempt_path(req.uri().path(), &config.paths)
        && is_cross_site_request(req.headers(), config.public_scheme.as_str())
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

fn is_cross_site_request(headers: &HeaderMap, public_scheme: &str) -> bool {
    // Presence is checked separately from parsing for every metadata header:
    // an unusable value must fail closed instead of falling through to a
    // weaker signal.
    if let Some(value) = headers.get(ORIGIN) {
        return match header_to_str(value).and_then(parse_origin) {
            Some(origin) => !same_origin(&origin, headers, public_scheme),
            None => true,
        };
    }
    if let Some(value) = headers.get(REFERER) {
        return match header_to_str(value).and_then(parse_referer) {
            Some(referer) => !same_origin(&referer, headers, public_scheme),
            None => true,
        };
    }
    // Sec-Fetch-Site is a fallback only when Origin and Referer are absent.
    // `same-site` means the same registrable site but a different origin, so it
    // does not satisfy a same-origin CSRF check. Unknown, empty and unparseable
    // values fail closed too: presence of the header is checked separately from
    // parsing so an unusable value cannot fall through to the permissive branch.
    match headers.get("sec-fetch-site") {
        Some(value) => !value.to_str().ok().is_some_and(|site| {
            site.eq_ignore_ascii_case("same-origin") || site.eq_ignore_ascii_case("none")
        }),
        None => false,
    }
}

/// The origin of an absolute URL: the only part used for CSRF comparison.
#[derive(Debug)]
struct ParsedOrigin<'a> {
    scheme: &'a str,
    authority: Authority,
}

/// `Origin` is a serialized origin: no path, query, fragment or userinfo.
fn parse_origin(value: &str) -> Option<ParsedOrigin<'_>> {
    let (scheme, authority, remainder) = split_absolute_url(value)?;
    remainder
        .is_none()
        .then_some(ParsedOrigin { scheme, authority })
}

/// `Referer` is an absolute URL whose path, query and fragment are ignored;
/// userinfo and malformed URL syntax are not accepted.
fn parse_referer(value: &str) -> Option<ParsedOrigin<'_>> {
    let (scheme, authority, remainder) = split_absolute_url(value)?;
    if remainder.is_some_and(|suffix| !valid_url_suffix(suffix)) {
        return None;
    }
    Some(ParsedOrigin { scheme, authority })
}

fn split_absolute_url(value: &str) -> Option<(&str, Authority, Option<&str>)> {
    // `Uri` requires an absolute URL and rejects whitespace and invalid
    // authority characters, but it ignores fragments and percent escapes.
    Uri::try_from(value).ok()?.scheme_str()?;
    let (scheme, after_scheme) = value.split_once("://")?;
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = after_scheme[..authority_end].parse::<Authority>().ok()?;
    if !valid_authority(&authority) {
        return None;
    }
    let remainder = after_scheme
        .get(authority_end..)
        .filter(|suffix| !suffix.is_empty());
    Some((scheme, authority, remainder))
}

fn valid_authority(authority: &Authority) -> bool {
    // `Authority` accepts userinfo and silently drops an invalid port, so
    // require the entire serialized form to be host (optionally bracketed)
    // plus a numeric port.
    !authority.as_str().contains('@')
        && (authority.port_u16().is_some() || authority.as_str() == authority.host())
}

/// RFC 3986 `pchar`: unreserved / pct-encoded / sub-delims / ":" / "@".
fn is_pchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

/// Validates a path, query or fragment independently of `Uri`, whose scanner
/// stops at '#' and tolerates bytes outside these RFC 3986 components.
fn valid_component(bytes: &[u8], allow_question: bool) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if !bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
                || !bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit)
            {
                return false;
            }
            index += 3;
        } else if is_pchar(byte) || byte == b'/' || (allow_question && byte == b'?') {
            index += 1;
        } else {
            return false;
        }
    }
    true
}

fn valid_url_suffix(suffix: &str) -> bool {
    let (before_fragment, fragment) = suffix.split_once('#').unwrap_or((suffix, ""));
    let (path, query) = before_fragment
        .split_once('?')
        .unwrap_or((before_fragment, ""));
    valid_component(path.as_bytes(), false)
        && valid_component(query.as_bytes(), true)
        && valid_component(fragment.as_bytes(), true)
}

fn scheme_default_port(scheme: &str) -> Option<u16> {
    if scheme.eq_ignore_ascii_case("http") {
        Some(80)
    } else if scheme.eq_ignore_ascii_case("https") {
        Some(443)
    } else {
        None
    }
}

fn same_origin(candidate: &ParsedOrigin<'_>, headers: &HeaderMap, public_scheme: &str) -> bool {
    let Some(expected_host) = headers.get(HOST).and_then(header_to_str) else {
        return false;
    };
    let Ok(expected_authority) = expected_host.parse::<Authority>() else {
        return false;
    };
    if !valid_authority(&expected_authority) {
        return false;
    }
    if !candidate.scheme.eq_ignore_ascii_case(public_scheme) {
        return false;
    }
    if !candidate
        .authority
        .host()
        .trim_end_matches('.')
        .eq_ignore_ascii_case(expected_authority.host().trim_end_matches('.'))
    {
        return false;
    }
    let Some(default_port) = scheme_default_port(public_scheme) else {
        return false;
    };
    candidate.authority.port_u16().unwrap_or(default_port)
        == expected_authority.port_u16().unwrap_or(default_port)
}

fn header_to_str(value: &HeaderValue) -> Option<&str> {
    value.to_str().ok().filter(|value| !value.is_empty())
}

/// Supply a strict default CSP, preserving a handler's explicit policy.
///
/// Self-contained confirmation pages own their per-response script nonce and
/// framing restrictions; overwriting that policy would disable their scripts.
pub async fn csp_headers_layer(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    response.headers_mut().entry(CONTENT_SECURITY_POLICY).or_insert(
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
        assert!(!is_cross_site_request(&headers, "https"));
    }

    #[test]
    fn csrf_rejects_cross_origin_signal() {
        let headers = headers(&[
            ("host", "id.example.com"),
            ("origin", "https://evil.example.com"),
        ]);
        assert!(is_cross_site_request(&headers, "https"));
    }

    #[test]
    fn csrf_rejects_non_same_origin_fetch_metadata_without_origin() {
        for site in ["cross-site", "same-site", "unknown"] {
            let headers = headers(&[("host", "id.example.com"), ("sec-fetch-site", site)]);
            assert!(is_cross_site_request(&headers, "https"), "site {site}");
        }
    }

    #[test]
    fn csrf_rejects_unparseable_fetch_metadata_without_origin() {
        let name = HeaderName::from_static("sec-fetch-site");
        for value in [
            HeaderValue::from_bytes(&[0xff]).unwrap(),
            HeaderValue::from_static(""),
        ] {
            let mut headers = headers(&[("host", "id.example.com")]);
            headers.insert(name.clone(), value);
            assert!(is_cross_site_request(&headers, "https"));
        }
    }

    fn malformed_header_values() -> [HeaderValue; 2] {
        [
            HeaderValue::from_bytes(&[0xff]).unwrap(),
            HeaderValue::from_static(""),
        ]
    }

    #[test]
    fn csrf_rejects_unparseable_origin() {
        for value in malformed_header_values() {
            let mut headers = headers(&[("host", "id.example.com")]);
            headers.insert(ORIGIN, value);
            assert!(is_cross_site_request(&headers, "https"));
        }
    }

    #[test]
    fn csrf_rejects_unparseable_referer_without_origin() {
        for value in malformed_header_values() {
            let mut headers = headers(&[("host", "id.example.com")]);
            headers.insert(REFERER, value);
            assert!(is_cross_site_request(&headers, "https"));
        }
    }

    #[test]
    fn csrf_rejects_unparseable_origin_not_rescued_by_same_origin_referer() {
        for value in malformed_header_values() {
            let mut headers = headers(&[
                ("host", "id.example.com"),
                ("referer", "https://id.example.com/settings"),
            ]);
            headers.insert(ORIGIN, value);
            assert!(is_cross_site_request(&headers, "https"));
        }
        // A valid Origin still takes precedence over an unusable Referer.
        let mut headers = headers(&[
            ("host", "id.example.com"),
            ("origin", "https://id.example.com"),
        ]);
        headers.insert(REFERER, malformed_header_values()[0].clone());
        assert!(!is_cross_site_request(&headers, "https"));
    }

    #[test]
    fn csrf_rejects_unparseable_referer_not_rescued_by_same_origin_fetch_metadata() {
        for value in malformed_header_values() {
            let mut headers = headers(&[
                ("host", "id.example.com"),
                ("sec-fetch-site", "same-origin"),
            ]);
            headers.insert(REFERER, value);
            assert!(is_cross_site_request(&headers, "https"));
        }
        // A valid Referer still takes precedence over Sec-Fetch-Site.
        let headers = headers(&[
            ("host", "id.example.com"),
            ("referer", "https://id.example.com/settings"),
            ("sec-fetch-site", "cross-site"),
        ]);
        assert!(!is_cross_site_request(&headers, "https"));
    }

    #[test]
    fn csrf_allows_same_origin_fetch_metadata_without_origin() {
        let headers = headers(&[
            ("host", "id.example.com"),
            ("sec-fetch-site", "same-origin"),
        ]);
        assert!(!is_cross_site_request(&headers, "https"));
    }

    #[test]
    fn csrf_allows_machine_clients_without_browser_signal() {
        let headers = headers(&[("host", "id.example.com")]);
        assert!(!is_cross_site_request(&headers, "https"));
    }

    #[test]
    fn csrf_accepts_origin_form_http_request_with_http_public_scheme() {
        let headers = headers(&[
            ("host", "localhost:8080"),
            ("origin", "http://localhost:8080"),
        ]);
        assert!(!is_cross_site_request(&headers, "http"));
    }

    #[test]
    fn csrf_rejects_origin_form_http_request_with_https_public_scheme() {
        let headers = headers(&[
            ("host", "localhost:8080"),
            ("origin", "http://localhost:8080"),
        ]);
        assert!(is_cross_site_request(&headers, "https"));
    }

    #[test]
    fn csrf_ignores_forwarded_proto_when_public_scheme_is_configured() {
        // A forwarded plaintext scheme cannot downgrade a configured https.
        let plaintext_origin = headers(&[
            ("host", "localhost:8080"),
            ("origin", "http://localhost:8080"),
            ("x-forwarded-proto", "http"),
        ]);
        assert!(is_cross_site_request(&plaintext_origin, "https"));

        // A forwarded secure scheme cannot upgrade a configured http.
        let secure_origin = headers(&[
            ("host", "localhost:8080"),
            ("origin", "https://localhost:8080"),
            ("x-forwarded-proto", "https"),
        ]);
        assert!(is_cross_site_request(&secure_origin, "http"));

        // The configured https scheme still accepts a matching origin even
        // when forwarded metadata conflicts with it.
        let secure_origin = headers(&[
            ("host", "localhost:8080"),
            ("origin", "https://localhost:8080"),
            ("x-forwarded-proto", "http"),
        ]);
        assert!(!is_cross_site_request(&secure_origin, "https"));
    }

    #[tokio::test]
    async fn csrf_layer_ignores_absolute_request_uri_scheme() {
        use axum::Router;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use axum::routing::post;
        use tower::ServiceExt;

        // An absolute-form request URI advertising `http` must not downgrade
        // the configured public scheme behind a TLS-terminating proxy.
        let app = Router::new()
            .route("/admin/api/v1/test/clients", post(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                CsrfConfig::new(ServerPaths::default(), "https"),
                csrf_protection_layer,
            ));
        let req = Request::builder()
            .method("POST")
            .uri("http://id.example.com/admin/api/v1/test/clients")
            .header("host", "id.example.com")
            .header("origin", "https://id.example.com")
            .body(Body::empty())
            .unwrap();
        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::OK);

        // The reverse conflict is ignored too: an `https` request URI does not
        // upgrade a configured `http` public scheme.
        let app = Router::new()
            .route("/admin/api/v1/test/clients", post(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                CsrfConfig::new(ServerPaths::default(), "http"),
                csrf_protection_layer,
            ));
        let req = Request::builder()
            .method("POST")
            .uri("https://id.example.com/admin/api/v1/test/clients")
            .header("host", "id.example.com")
            .header("origin", "http://id.example.com")
            .body(Body::empty())
            .unwrap();
        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    #[test]
    fn csrf_rejects_origin_with_path_query_fragment_or_userinfo() {
        for origin in [
            "https://id.example.com/admin",
            "https://id.example.com/?q=1",
            "https://id.example.com#section",
            "https://user@id.example.com",
            "https://user:pass@id.example.com",
        ] {
            let headers = headers(&[("host", "id.example.com"), ("origin", origin)]);
            assert!(is_cross_site_request(&headers, "https"), "origin {origin}");
        }
    }

    #[test]
    fn csrf_rejects_origin_port_mismatch() {
        let mismatch = headers(&[
            ("host", "id.example.com:8443"),
            ("origin", "https://id.example.com:9443"),
        ]);
        assert!(is_cross_site_request(&mismatch, "https"));
        let explicit = headers(&[
            ("host", "id.example.com"),
            ("origin", "https://id.example.com:8443"),
        ]);
        assert!(is_cross_site_request(&explicit, "https"));
    }

    #[test]
    fn csrf_rejects_referer_userinfo_and_port_mismatch() {
        let userinfo = headers(&[
            ("host", "id.example.com"),
            ("referer", "https://user@id.example.com/settings"),
        ]);
        assert!(is_cross_site_request(&userinfo, "https"));
        let mismatch = headers(&[
            ("host", "id.example.com:8443"),
            ("referer", "https://id.example.com:9443/settings"),
        ]);
        assert!(is_cross_site_request(&mismatch, "https"));
    }

    #[test]
    fn csrf_rejects_non_absolute_origin_values() {
        for origin in [
            "null",
            "id.example.com",
            "//id.example.com",
            "https:///admin",
        ] {
            let headers = headers(&[("host", "id.example.com"), ("origin", origin)]);
            assert!(is_cross_site_request(&headers, "https"), "origin {origin}");
        }
    }

    #[test]
    fn csrf_rejects_referer_with_invalid_path_query_or_fragment() {
        for referer in [
            "https://id.example.com/settings?x=%zz",
            "https://id.example.com/my settings",
            "https://id.example.com/settings#<script>",
            "https://id.example.com/settings#a>b",
            "https://id.example.com/settings#a\"b",
            "https://id.example.com/settings#a\\b",
            "https://id.example.com/settings#a^b",
            "https://id.example.com/settings#a{b}",
            "https://id.example.com/settings#a|b",
        ] {
            let headers = headers(&[("host", "id.example.com"), ("referer", referer)]);
            assert!(
                is_cross_site_request(&headers, "https"),
                "referer {referer}"
            );
        }
    }

    #[test]
    fn csrf_accepts_referer_with_path_query_and_fragment() {
        for referer in [
            "https://id.example.com/settings?tab=1#section",
            "https://id.example.com/a/b-c_d.e~f!$&'()*+,;=:@?q=a%20b#part%20one?more=1",
        ] {
            let headers = headers(&[("host", "id.example.com"), ("referer", referer)]);
            assert!(
                !is_cross_site_request(&headers, "https"),
                "referer {referer}"
            );
        }
    }

    #[test]
    fn csrf_accepts_origin_with_explicit_default_port() {
        let omitted = headers(&[
            ("host", "id.example.com"),
            ("origin", "https://id.example.com:443"),
        ]);
        assert!(!is_cross_site_request(&omitted, "https"));
        let explicit = headers(&[
            ("host", "id.example.com:443"),
            ("origin", "https://id.example.com:443"),
        ]);
        assert!(!is_cross_site_request(&explicit, "https"));
    }

    #[test]
    fn csrf_rejects_malformed_origin_not_rescued_by_referer() {
        let headers = headers(&[
            ("host", "id.example.com"),
            ("origin", "https://id.example.com/admin"),
            ("referer", "https://id.example.com/settings"),
        ]);
        assert!(is_cross_site_request(&headers, "https"));
    }

    #[test]
    fn csrf_rejects_malformed_referer_not_rescued_by_fetch_metadata() {
        let headers = headers(&[
            ("host", "id.example.com"),
            ("referer", "https://user@id.example.com/settings"),
            ("sec-fetch-site", "same-origin"),
        ]);
        assert!(is_cross_site_request(&headers, "https"));
    }

    #[test]
    fn csrf_compares_ipv6_authorities_with_effective_port() {
        let same = headers(&[("host", "[::1]:8443"), ("origin", "HTTPS://[::1]:8443")]);
        assert!(!is_cross_site_request(&same, "https"));
        let mismatch = headers(&[("host", "[::1]:8443"), ("origin", "https://[::1]:9443")]);
        assert!(is_cross_site_request(&mismatch, "https"));
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

    #[tokio::test]
    async fn csp_headers_preserve_explicit_handler_policy() {
        use axum::Router;
        use axum::body::Body;
        use axum::http::{HeaderValue, Request, StatusCode};
        use axum::response::IntoResponse;
        use axum::routing::get;
        use tower::ServiceExt;

        let app = Router::new()
            .route(
                "/confirm",
                get(|| async {
                    let mut response = StatusCode::OK.into_response();
                    response.headers_mut().insert(
                        "content-security-policy",
                        HeaderValue::from_static(
                            "default-src 'none'; script-src 'nonce-test'; frame-ancestors 'none'",
                        ),
                    );
                    response
                }),
            )
            .layer(axum::middleware::from_fn(csp_headers_layer));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/confirm")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.headers()["content-security-policy"],
            "default-src 'none'; script-src 'nonce-test'; frame-ancestors 'none'"
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
    async fn hsts_policy_matrix() {
        use axum::http::StatusCode;
        struct Case {
            name: &'static str,
            config: HstsConfig,
            present: bool,
            contains: &'static [&'static str],
            absent: &'static [&'static str],
        }
        let def = HstsConfig::default();
        let cases = [
            Case {
                name: "defaults",
                config: def.clone(),
                present: true,
                contains: &["max-age=31536000", "includeSubDomains"],
                absent: &["preload"],
            },
            Case {
                name: "disabled",
                config: HstsConfig {
                    enabled: false,
                    ..def.clone()
                },
                present: false,
                contains: &[],
                absent: &[],
            },
            Case {
                name: "custom",
                config: HstsConfig {
                    max_age_seconds: 86400,
                    include_subdomains: false,
                    ..def.clone()
                },
                present: true,
                contains: &["max-age=86400"],
                absent: &["includeSubDomains"],
            },
            Case {
                name: "preload",
                config: HstsConfig {
                    preload: true,
                    ..def
                },
                present: true,
                contains: &["preload"],
                absent: &[],
            },
        ];
        for case in cases {
            let res = hsts_get(case.config, "/health").await;
            assert_eq!(res.status(), StatusCode::OK, "{}", case.name);
            let hsts = hsts_value(&res).to_string();
            assert_eq!(!hsts.is_empty(), case.present, "{} emits", case.name);
            for want in case.contains {
                assert!(
                    hsts.contains(want),
                    "{} carries {want}, got: {hsts}",
                    case.name
                );
            }
            for missing in case.absent {
                assert!(
                    !hsts.contains(missing),
                    "{} omits {missing}, got: {hsts}",
                    case.name
                );
            }
        }
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
    fn request_id_accepts_arbitrary_header_safe_value() {
        for value in [
            "req-01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "req+abc/def with spaces",
            "req+abc/def",
        ] {
            let headers = headers(&[("x-request-id", value)]);
            assert_eq!(request_id_from_headers(&headers).as_deref(), Some(value));
        }
    }

    #[tokio::test]
    async fn request_id_layer_echoes_long_header_safe_value() {
        use axum::Router;
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use tower::ServiceExt;

        let value = "x".repeat(1024);
        let app = Router::new()
            .route("/health", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(request_id_layer));
        let req = Request::builder()
            .uri("/health")
            .header("x-request-id", value.clone())
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.headers()["x-request-id"], value);
    }

    #[test]
    fn request_id_rejects_control_characters_and_accepts_long_values() {
        assert!(!valid_request_id(""));
        assert!(!valid_request_id("bad\nvalue"));
        assert!(!valid_request_id("bad\u{7f}value"));
        assert!(valid_request_id(&"x".repeat(1024)));
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
        assert!(!is_csrf_exempt_path(
            &paths.auth_email_magic_link_send,
            &paths
        ));
        assert!(!is_csrf_exempt_path(
            &paths.auth_email_magic_link_verify,
            &paths
        ));
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
                CsrfConfig::new(paths.clone(), "https"),
                csrf_protection_layer,
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
