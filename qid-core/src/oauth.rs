//! OAuth shared validation helpers.

use crate::{
    config::{OAuthResourceServerConfig, RealmConfig},
    error::{QidError, QidResult},
    jwt::JwtClaims,
};
use std::collections::BTreeSet;

/// Grant types qid can redeem at the token endpoint. Registration and static
/// client configuration share this set so that every configured grant is
/// redeemable.
pub fn is_supported_grant_type(grant_type: &str) -> bool {
    matches!(
        grant_type,
        "authorization_code"
            | "client_credentials"
            | "refresh_token"
            | "urn:ietf:params:oauth:grant-type:token-exchange"
            | "urn:ietf:params:oauth:grant-type:jwt-bearer"
            | "urn:ietf:params:oauth:grant-type:saml2-bearer"
            | "urn:ietf:params:oauth:grant-type:device_code"
            | "urn:openid:params:grant-type:ciba"
    )
}

/// Reason a redirect URI was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectUriError {
    /// The URI contains a `*` wildcard.
    Wildcard,
    /// The URI is not a valid URL; the payload is the parser error.
    InvalidUrl(String),
    /// The URI contains a fragment.
    Fragment,
    /// The URI uses a scheme other than HTTPS without true loopback HTTP.
    InsecureScheme,
}

/// Response parameters qid appends to redirect URIs. A registered URI that
/// already carries one would let the client's value collide with qid's.
const RESERVED_REDIRECT_QUERY_KEYS: [&str; 6] = [
    "code",
    "state",
    "iss",
    "error",
    "error_description",
    "response",
];

/// Validate a redirect URI: no `*` wildcards, a valid URL without userinfo or
/// a fragment, no reserved response parameter in its query, and HTTPS except
/// for true loopback HTTP (`localhost`, `127.0.0.0/8`, or `::1`).
pub fn validate_redirect_uri(redirect_uri: &str) -> Result<(), RedirectUriError> {
    if redirect_uri.contains('*') {
        return Err(RedirectUriError::Wildcard);
    }
    let parsed =
        url::Url::parse(redirect_uri).map_err(|e| RedirectUriError::InvalidUrl(e.to_string()))?;
    if parsed.fragment().is_some() {
        return Err(RedirectUriError::Fragment);
    }
    // Use the parser's credentials rather than the raw string: the WHATWG
    // parser accepts userinfo in omitted-slash, backslash and uppercase
    // spellings that a `://` authority scan would miss.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(RedirectUriError::InvalidUrl(
            "redirect_uri must not contain userinfo".to_string(),
        ));
    }
    // An empty userinfo (`https://@rp.example/cb`) is normalized away by the
    // parser, leaving no credential for an accessor to see. Keep rejecting
    // that spelling in the canonical `://` form, where the authority is
    // unambiguous, without reimplementing the parser's authority handling.
    if let Some((_, after_scheme)) = redirect_uri.split_once("://") {
        let authority = after_scheme
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default();
        if authority.contains('@') {
            return Err(RedirectUriError::InvalidUrl(
                "redirect_uri authority must not contain empty userinfo".to_string(),
            ));
        }
    }
    if parsed
        .query_pairs()
        .any(|(key, _)| RESERVED_REDIRECT_QUERY_KEYS.contains(&key.as_ref()))
    {
        return Err(RedirectUriError::InvalidUrl(
            "redirect_uri query must not contain a reserved response parameter".to_string(),
        ));
    }
    if parsed.scheme() == "https" {
        return Ok(());
    }
    if parsed.scheme() == "http" && is_loopback_host(parsed.host()) {
        return Ok(());
    }
    Err(RedirectUriError::InsecureScheme)
}

fn is_loopback_host(host: Option<url::Host<&str>>) -> bool {
    match host {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(addr)) => addr.octets()[0] == 127,
        Some(url::Host::Ipv6(addr)) => addr == std::net::Ipv6Addr::LOCALHOST,
        None => false,
    }
}

/// Validate OAuth Rich Authorization Requests authorization details.
///
/// RFC 9396 defines `authorization_details` as a non-empty JSON array of
/// objects. qid accepts extension members, but every entry must carry a
/// non-empty string `type` so policy and token claims can reason about it.
pub fn validate_authorization_details(details: &serde_json::Value) -> QidResult<()> {
    let entries = details.as_array().ok_or_else(|| QidError::BadRequest {
        message: "authorization_details must be an array".to_string(),
    })?;
    if entries.is_empty() {
        return Err(QidError::BadRequest {
            message: "authorization_details must not be empty".to_string(),
        });
    }
    for (idx, entry) in entries.iter().enumerate() {
        let Some(object) = entry.as_object() else {
            return Err(QidError::BadRequest {
                message: format!("authorization_details[{idx}] must be an object"),
            });
        };
        let Some(detail_type) = object.get("type").and_then(|value| value.as_str()) else {
            return Err(QidError::BadRequest {
                message: format!("authorization_details[{idx}].type is required"),
            });
        };
        if detail_type.trim().is_empty() {
            return Err(QidError::BadRequest {
                message: format!("authorization_details[{idx}].type must not be empty"),
            });
        }
    }
    Ok(())
}

/// Reject sender-constrained tokens presented as plain bearer credentials.
///
/// PEP registration, AuthZEN, risk-evaluation and CAPPORT control adapters
/// accept only unbound bearer tokens. A `cnf` claim (RFC 7800) marks the
/// token as bound to a key the bearer path never verifies, so any presence
/// of `cnf` fails closed here instead of being accepted as a bearer
/// credential.
pub fn reject_sender_constrained_bearer_token(claims: &JwtClaims) -> QidResult<()> {
    if claims.extra.contains_key("cnf") {
        return Err(QidError::Unauthorized {
            message: "sender-constrained tokens cannot be used as bearer credentials".to_string(),
        });
    }
    Ok(())
}

pub fn resolve_token_audience(
    realm: &RealmConfig,
    requested_audiences: &[String],
    resources: &[String],
    scopes: &[String],
    cnf: Option<&serde_json::Value>,
) -> QidResult<Vec<String>> {
    if realm.protocols.oauth.resource_servers.is_empty() {
        return resolve_authorization_audience(realm, requested_audiences, resources, scopes);
    }
    let audiences = resolve_authorization_audience(realm, requested_audiences, resources, scopes)?;
    for audience in &audiences {
        if let Some(server) =
            resource_server_by_audience(&realm.protocols.oauth.resource_servers, audience)
        {
            require_sender_constraint(server, cnf)?;
        }
    }
    Ok(audiences)
}

/// Resolve an authorization target and its scope ceiling, without asserting
/// sender proof. Proof is checked by `resolve_token_audience` at issuance.
pub fn resolve_authorization_audience(
    realm: &RealmConfig,
    requested_audiences: &[String],
    resources: &[String],
    scopes: &[String],
) -> QidResult<Vec<String>> {
    let resource_servers = &realm.protocols.oauth.resource_servers;
    if resource_servers.is_empty() {
        if let Some(resource) = resources.first() {
            return Err(QidError::Unauthorized {
                message: format!("unknown resource indicator: {resource}"),
            });
        }
        if let Some(audience) = requested_audiences.first() {
            return Err(QidError::Unauthorized {
                message: format!("unknown resource server audience: {audience}"),
            });
        }
        return Ok(Vec::new());
    }
    let mut audiences = BTreeSet::new();
    let mut selected_servers = Vec::new();
    for audience in requested_audiences {
        let server = resource_server_by_audience(resource_servers, audience).ok_or_else(|| {
            QidError::Unauthorized {
                message: format!("unknown resource server audience: {audience}"),
            }
        })?;
        selected_servers.push(server);
        audiences.insert(audience.clone());
    }
    for resource in resources {
        let server = resource_server_by_resource(resource_servers, resource).ok_or_else(|| {
            QidError::Unauthorized {
                message: format!("unknown resource indicator: {resource}"),
            }
        })?;
        if !requested_audiences.is_empty() && !requested_audiences.contains(&server.audience) {
            return Err(QidError::Unauthorized {
                message: format!(
                    "resource indicator {resource} is not allowed for requested audience {}",
                    requested_audiences.join(" ")
                ),
            });
        }
        selected_servers.push(server);
        audiences.insert(server.audience.clone());
    }
    if audiences.is_empty() {
        return Err(QidError::BadRequest {
            message: "audience or resource is required when OAuth resource servers are configured"
                .to_string(),
        });
    }
    validate_scopes_per_target(scopes, &selected_servers)?;
    Ok(audiences.into_iter().collect())
}

fn resource_server_by_audience<'a>(
    resource_servers: &'a [OAuthResourceServerConfig],
    audience: &str,
) -> Option<&'a OAuthResourceServerConfig> {
    resource_servers
        .iter()
        .find(|server| server.audience == audience)
}

fn resource_server_by_resource<'a>(
    resource_servers: &'a [OAuthResourceServerConfig],
    resource: &str,
) -> Option<&'a OAuthResourceServerConfig> {
    resource_servers.iter().find(|server| {
        server
            .resources
            .iter()
            .any(|candidate| candidate == resource)
    })
}

/// A cnf claim only binds a token to a sender when it carries a key thumbprint
/// the introspection endpoint can verify (RFC 7800 jkt or mTLS x5t#S256).
fn cnf_has_usable_sender_key(cnf: &serde_json::Value) -> bool {
    let non_empty_string = |key: &str| {
        cnf.get(key)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
    };
    non_empty_string("jkt") || non_empty_string("x5t#S256") || non_empty_string("x5t_s256")
}

fn require_sender_constraint(
    resource_server: &OAuthResourceServerConfig,
    cnf: Option<&serde_json::Value>,
) -> QidResult<()> {
    if (resource_server.require_sender_constraint || resource_server.high_risk)
        && !cnf.is_some_and(cnf_has_usable_sender_key)
    {
        return Err(QidError::Unauthorized {
            message: format!(
                "sender-constrained token is required for audience {}",
                resource_server.audience
            ),
        });
    }
    Ok(())
}

/// Validate requested scopes against every selected target: each configured
/// resource-server scope list is that target's ceiling (RFC 8707 section 2.2
/// recommends downscoping to each resource's needs), so a scope must appear
/// in all selected servers that restrict scopes. Servers with an empty scope
/// list impose no restriction, preserving the current opt-in semantics.
fn validate_scopes_per_target(
    scopes: &[String],
    servers: &[&OAuthResourceServerConfig],
) -> QidResult<()> {
    for server in servers {
        if server.scopes.is_empty() {
            continue;
        }
        for scope in scopes {
            if !server.scopes.contains(scope) {
                return Err(QidError::BadRequest {
                    message: format!(
                        "requested scope {scope} is not allowed for resource server {}",
                        server.audience
                    ),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        RedirectUriError, reject_sender_constrained_bearer_token, validate_authorization_details,
        validate_redirect_uri,
    };
    use crate::config::{
        OAuthProtocolConfig, OAuthResourceServerConfig, ProtocolConfig, RealmConfig,
    };

    #[test]
    fn validates_authorization_details_shape() {
        validate_authorization_details(&serde_json::json!([
            {
                "type": "payment_initiation",
                "actions": ["initiate"]
            }
        ]))
        .unwrap();

        assert!(validate_authorization_details(&serde_json::json!({ "type": "payment" })).is_err());
        assert!(validate_authorization_details(&serde_json::json!([])).is_err());
        assert!(
            validate_authorization_details(&serde_json::json!([{ "actions": ["read"] }])).is_err()
        );
        assert!(validate_authorization_details(&serde_json::json!([{ "type": " " }])).is_err());
    }

    #[test]
    fn redirect_uri_rejects_wildcard_fragment_and_spoofed_loopback() {
        assert_eq!(
            validate_redirect_uri("https://*.example.com/cb"),
            Err(RedirectUriError::Wildcard)
        );
        assert_eq!(
            validate_redirect_uri("https://client.example.com/cb#frag"),
            Err(RedirectUriError::Fragment)
        );
        assert_eq!(
            validate_redirect_uri("http://127.evil.example/cb"),
            Err(RedirectUriError::InsecureScheme)
        );
        assert!(matches!(
            validate_redirect_uri("not a url"),
            Err(RedirectUriError::InvalidUrl(_))
        ));
        assert_eq!(
            validate_redirect_uri("http://app.example.com/cb"),
            Err(RedirectUriError::InsecureScheme)
        );
    }

    #[test]
    fn redirect_uri_rejects_userinfo_and_accepts_query() {
        for uri in [
            "https://user@rp.example/cb",
            "https://@rp.example/cb",
            "https://user:pass@rp.example/cb",
            "https:user@rp.example/cb",
            "HTTPS:user@rp.example/cb",
            "https:/user@rp.example/cb",
            r"https:\user@rp.example/cb",
            r"https:\\user@rp.example/cb",
            "https:///@user@rp.example/cb",
        ] {
            assert!(
                matches!(
                    validate_redirect_uri(uri),
                    Err(RedirectUriError::InvalidUrl(_))
                ),
                "{uri} should be rejected as userinfo"
            );
        }
        validate_redirect_uri("https://client.example.com/cb?next=%2Fhome")
            .expect("a query in a normal redirect URI is allowed");
    }

    #[test]
    fn redirect_uri_rejects_reserved_response_parameters_in_query() {
        for name in [
            "code",
            "state",
            "iss",
            "error",
            "error_description",
            "response",
            "%63ode",
        ] {
            let uri = format!("https://client.example.com/cb?{name}=injected");
            assert!(
                matches!(
                    validate_redirect_uri(&uri),
                    Err(RedirectUriError::InvalidUrl(_))
                ),
                "{uri} should be rejected as a reserved response parameter"
            );
        }
        for uri in [
            "https://client.example.com/cb?tenant=acme",
            "https://client.example.com/cb?tenant=acme&next=%2Fhome&code_challenge=abc",
        ] {
            validate_redirect_uri(uri).expect(uri);
        }
    }

    #[test]
    fn redirect_uri_accepts_https_and_true_loopback_http() {
        for uri in [
            "https://client.example.com/cb",
            "http://localhost:3000/cb",
            "http://127.0.0.1/cb",
            "http://127.1.2.3:8080/cb",
            "http://[::1]/cb",
            "http://[::1]:3000/cb",
        ] {
            validate_redirect_uri(uri).expect(uri);
        }
    }

    #[test]
    fn resolves_registered_resource_audience_and_sender_constraint() {
        let realm = realm_with_resource_servers(vec![
            OAuthResourceServerConfig {
                audience: "api://payments".to_string(),
                resources: vec!["https://api.example.com/payments".to_string()],
                scopes: vec!["payments".to_string()],
                introspection_client_ids: Vec::new(),
                require_sender_constraint: false,
                high_risk: true,
            },
            OAuthResourceServerConfig {
                audience: "api://profile".to_string(),
                resources: vec!["https://api.example.com/profile".to_string()],
                scopes: vec!["profile".to_string()],
                introspection_client_ids: Vec::new(),
                require_sender_constraint: false,
                high_risk: false,
            },
        ]);
        let cnf = serde_json::json!({"jkt": "thumbprint"});
        let audiences = super::resolve_token_audience(
            &realm,
            &[],
            &["https://api.example.com/payments".to_string()],
            &["payments".to_string()],
            Some(&cnf),
        )
        .unwrap();
        assert_eq!(audiences, vec!["api://payments"]);
        assert!(
            super::resolve_token_audience(
                &realm,
                &["api://payments".to_string()],
                &[],
                &["payments".to_string()],
                None,
            )
            .is_err()
        );
        assert!(
            super::resolve_token_audience(
                &realm,
                &["api://payments".to_string()],
                &["https://api.example.com/profile".to_string()],
                &["payments".to_string()],
                Some(&cnf),
            )
            .is_err()
        );
        assert!(
            super::resolve_token_audience(
                &realm,
                &["api://profile".to_string()],
                &[],
                &["payments".to_string()],
                Some(&cnf),
            )
            .is_err()
        );
    }

    #[test]
    fn explicit_targets_require_registered_resource_servers() {
        let realm = realm_with_resource_servers(Vec::new());
        // Untargeted grants keep the client-audience fallback at issuance;
        // the resolver returns no target for issuance to fill in.
        assert_eq!(
            super::resolve_token_audience(&realm, &[], &[], &[], None).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            super::resolve_authorization_audience(&realm, &[], &[], &[]).unwrap(),
            Vec::<String>::new()
        );
        // An explicitly chosen target must be checked against a registration,
        // even when the realm has no resource servers at all.
        assert!(
            super::resolve_token_audience(
                &realm,
                &["api://unregistered".to_string()],
                &[],
                &[],
                None,
            )
            .is_err()
        );
        assert!(
            super::resolve_token_audience(
                &realm,
                &[],
                &["https://api.example.com/unregistered".to_string()],
                &[],
                None,
            )
            .is_err()
        );
        assert!(
            super::resolve_authorization_audience(
                &realm,
                &["api://unregistered".to_string()],
                &[],
                &[],
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_cnf_without_usable_sender_key() {
        let mut target = server("api://workload", Vec::new());
        target.require_sender_constraint = true;
        let realm = realm_with_resource_servers(vec![target]);
        let audience = vec!["api://workload".to_string()];
        let resolve = |cnf: &serde_json::Value| {
            super::resolve_token_audience(&realm, &audience, &[], &[], Some(cnf))
        };

        let empty = serde_json::json!({});
        let unrelated = serde_json::json!({ "other": "value" });
        let jkt = serde_json::json!({ "jkt": "thumbprint" });
        let x5t = serde_json::json!({ "x5t#S256": "abc" });
        assert!(resolve(&empty).is_err());
        assert!(resolve(&unrelated).is_err());
        assert_eq!(resolve(&jkt).unwrap(), audience);
        assert_eq!(resolve(&x5t).unwrap(), audience);
    }

    fn server(audience: &str, scopes: Vec<&str>) -> OAuthResourceServerConfig {
        OAuthResourceServerConfig {
            audience: audience.to_string(),
            resources: Vec::new(),
            scopes: scopes.into_iter().map(str::to_string).collect(),
            introspection_client_ids: Vec::new(),
            require_sender_constraint: false,
            high_risk: false,
        }
    }

    #[test]
    fn scope_ceiling_applies_per_target() {
        let realm = realm_with_resource_servers(vec![
            server("api://reader", vec!["read"]),
            server("api://admin", vec!["admin"]),
        ]);
        // Single restrictive target still enforces its ceiling.
        assert!(
            super::resolve_token_audience(
                &realm,
                &["api://reader".to_string()],
                &[],
                &["admin".to_string()],
                None,
            )
            .is_err()
        );
        // Adding a permissive target must not widen the restrictive ceiling.
        assert!(
            super::resolve_token_audience(
                &realm,
                &["api://reader".to_string(), "api://admin".to_string()],
                &[],
                &["admin".to_string()],
                None,
            )
            .is_err()
        );
        // A scope inside every selected ceiling succeeds with both audiences.
        let audiences = super::resolve_token_audience(
            &realm_with_resource_servers(vec![
                server("api://reader", vec!["read", "admin"]),
                server("api://admin", vec!["admin"]),
            ]),
            &["api://reader".to_string(), "api://admin".to_string()],
            &[],
            &["admin".to_string()],
            None,
        )
        .unwrap();
        assert_eq!(audiences, vec!["api://admin", "api://reader"]);
    }

    #[test]
    fn unrestricted_target_imposes_no_scope_ceiling() {
        let realm = realm_with_resource_servers(vec![
            server("api://open", Vec::new()),
            server("api://reader", vec!["read"]),
        ]);
        assert!(
            super::resolve_token_audience(
                &realm,
                &["api://open".to_string(), "api://reader".to_string()],
                &[],
                &["read".to_string()],
                None,
            )
            .is_ok()
        );
        assert!(
            super::resolve_token_audience(
                &realm,
                &["api://open".to_string()],
                &[],
                &["anything".to_string()],
                None,
            )
            .is_ok()
        );
    }

    #[test]
    fn bearer_adapters_reject_any_cnf_claim() {
        use std::collections::HashMap;

        let unbound = crate::jwt::JwtClaims {
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            extra: HashMap::new(),
        };
        assert!(reject_sender_constrained_bearer_token(&unbound).is_ok());

        for cnf in [
            serde_json::json!({"jkt": "thumbprint"}),
            serde_json::json!({"x5t#S256": "thumbprint"}),
            serde_json::json!({}),
            serde_json::json!(null),
        ] {
            let constrained = crate::jwt::JwtClaims {
                iss: None,
                sub: None,
                aud: None,
                exp: None,
                nbf: None,
                iat: None,
                jti: None,
                extra: HashMap::from([("cnf".to_string(), cnf)]),
            };
            assert!(
                reject_sender_constrained_bearer_token(&constrained).is_err(),
                "cnf-bearing token must fail closed as a bearer credential"
            );
        }
    }

    fn realm_with_resource_servers(
        resource_servers: Vec<OAuthResourceServerConfig>,
    ) -> RealmConfig {
        RealmConfig {
            client_callback_destinations: Default::default(),
            id: "test".to_string(),
            issuer: "https://id.example.com".to_string(),
            display_name: None,
            tenant_id: None,
            clients: Vec::new(),
            protocols: ProtocolConfig {
                oauth: OAuthProtocolConfig {
                    resource_servers,
                    ..OAuthProtocolConfig::default()
                },
                ..ProtocolConfig::default()
            },
            authentication: Default::default(),
            sessions: Default::default(),
            pep_registrations: Default::default(),
            policy: Default::default(),
        }
    }
}
