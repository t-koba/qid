use qid_core::error::QidError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::coded_error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InboundProviderKind {
    Oidc,
    Saml,
    EntraId,
    GoogleWorkspace,
    Okta,
    LdapAdBind,
    Social,
}

impl InboundProviderKind {
    pub fn from_kind_str(s: &str) -> Option<Self> {
        match s {
            "oidc" => Some(Self::Oidc),
            "saml" => Some(Self::Saml),
            "entra_id" | "entra" | "azure_ad" => Some(Self::EntraId),
            "google_workspace" | "google" => Some(Self::GoogleWorkspace),
            "okta" => Some(Self::Okta),
            "ldap_ad_bind" | "ldap" => Some(Self::LdapAdBind),
            "social" => Some(Self::Social),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Saml => "saml",
            Self::EntraId => "entra_id",
            Self::GoogleWorkspace => "google_workspace",
            Self::Okta => "okta",
            Self::LdapAdBind => "ldap_ad_bind",
            Self::Social => "social",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimMapping {
    pub source: String,
    pub target: String,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InboundIdentityProvider {
    pub id: String,
    pub kind: InboundProviderKind,
    pub issuer: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub social_provider: Option<String>,
    /// OAuth 2.0 client credentials for code exchange.
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Token endpoint URL for exchanging authorization code for tokens.
    #[serde(default)]
    pub token_url: Option<String>,
    /// Userinfo endpoint URL for fetching user claims (used when ID token is unavailable).
    #[serde(default)]
    pub userinfo_url: Option<String>,
    #[serde(default)]
    pub jit_provisioning: bool,
    #[serde(default)]
    pub account_linking: bool,
    #[serde(default)]
    pub claim_mappings: Vec<ClaimMapping>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,
    #[serde(default)]
    pub saml_signing_certificates: Vec<String>,
    /// Additional inbound OIDC ID-token audiences trusted for this provider.
    /// The `expected_audience` (configured `client_id` at the OIDC/social
    /// callbacks) is always trusted; an omitted or empty list trusts only it.
    #[serde(default)]
    pub trusted_audiences: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct HomeRealmDiscoveryRequest {
    #[serde(default)]
    pub login_hint: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub idp_hint: Option<String>,
    #[serde(default)]
    pub social_provider: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalIdentityClaims {
    pub issuer: String,
    pub subject: String,
    #[serde(default)]
    pub claims: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrokerAccountLink {
    pub provider_id: String,
    pub external_subject: String,
    pub local_subject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrokerRouteDecision {
    pub provider_id: String,
    pub provider_kind: InboundProviderKind,
    pub reason: String,
    pub jit_provisioning: bool,
    pub account_linking: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrokerLoginPlan {
    pub route: BrokerRouteDecision,
    pub normalized_claims: BTreeMap<String, serde_json::Value>,
    pub linked_subject: Option<String>,
    pub create_subject: bool,
}

pub fn route_inbound_provider(
    providers: &[InboundIdentityProvider],
    request: &HomeRealmDiscoveryRequest,
) -> Result<BrokerRouteDecision, QidError> {
    validate_inbound_providers(providers)?;
    if let Some(idp_hint) = normalized_optional(&request.idp_hint) {
        let provider = providers
            .iter()
            .find(|provider| provider.enabled && provider.id == idp_hint)
            .ok_or_else(|| {
                broker_error(
                    "unknown_idp_hint",
                    "IdP hint does not match an enabled provider",
                )
            })?;
        return Ok(route_decision(provider, "idp_hint"));
    }

    if let Some(social_provider) = normalized_optional(&request.social_provider) {
        let provider = providers
            .iter()
            .find(|provider| {
                provider.enabled
                    && provider.kind == InboundProviderKind::Social
                    && provider
                        .social_provider
                        .as_deref()
                        .is_some_and(|value| value.eq_ignore_ascii_case(&social_provider))
            })
            .ok_or_else(|| {
                broker_error(
                    "unknown_social_provider",
                    "Social provider is not configured",
                )
            })?;
        return Ok(route_decision(provider, "social_provider"));
    }

    let domain = request
        .domain
        .as_deref()
        .and_then(normalized_domain)
        .or_else(|| {
            request
                .login_hint
                .as_deref()
                .and_then(domain_from_login_hint)
        })
        .ok_or_else(|| broker_error("home_realm_not_found", "No routing signal was provided"))?;

    let matches = providers
        .iter()
        .filter(|provider| provider.enabled)
        .filter(|provider| {
            provider
                .domains
                .iter()
                .any(|candidate| domain_matches(candidate, &domain))
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [provider] => Ok(route_decision(provider, "domain_discovery")),
        [] => Err(broker_error(
            "home_realm_not_found",
            "No enabled provider matches the requested domain",
        )),
        _ => Err(broker_error(
            "ambiguous_home_realm",
            "Multiple enabled providers match the requested domain",
        )),
    }
}

pub fn plan_inbound_login(
    providers: &[InboundIdentityProvider],
    request: &HomeRealmDiscoveryRequest,
    external: &ExternalIdentityClaims,
    links: &[BrokerAccountLink],
) -> Result<BrokerLoginPlan, QidError> {
    let route = route_inbound_provider(providers, request)?;
    let provider = providers
        .iter()
        .find(|provider| provider.id == route.provider_id)
        .ok_or_else(|| broker_error("provider_not_found", "Selected provider is missing"))?;
    if provider.issuer != external.issuer {
        return Err(broker_error(
            "issuer_mismatch",
            "External identity issuer does not match selected provider",
        ));
    }

    let normalized_claims = normalize_enterprise_claims(provider, external)?;
    let linked_subject = links
        .iter()
        .find(|link| link.provider_id == provider.id && link.external_subject == external.subject)
        .map(|link| link.local_subject.clone());
    if linked_subject.is_none() && !provider.jit_provisioning {
        return Err(broker_error(
            "jit_disabled",
            "Provider requires an existing account link",
        ));
    }
    if linked_subject.is_some() && !provider.account_linking {
        return Err(broker_error(
            "account_linking_disabled",
            "Provider does not permit account linking",
        ));
    }

    Ok(BrokerLoginPlan {
        route,
        normalized_claims,
        create_subject: linked_subject.is_none(),
        linked_subject,
    })
}

// ---------------------------------------------------------------------------
// F1: Named Inbound IdP Connector Profiles
// ---------------------------------------------------------------------------

/// Azure AD / Entra ID connector profile with well-known endpoints and claim mappings.
///
/// The `tenant_id` can be a UUID or a well-known value such as `"common"`, `"organizations"`,
/// or `"consumers"`.
pub fn azure_ad_provider(
    tenant_id: &str,
    client_id: &str,
    client_secret: &str,
) -> InboundIdentityProvider {
    InboundIdentityProvider {
        id: format!("entra-{tenant_id}"),
        kind: InboundProviderKind::EntraId,
        issuer: format!("https://login.microsoftonline.com/{tenant_id}/v2.0"),
        enabled: true,
        domains: vec![format!("{tenant_id}.onmicrosoft.com")],
        social_provider: None,
        client_id: Some(client_id.to_owned()),
        client_secret: Some(client_secret.to_owned()),
        token_url: Some(format!(
            "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        )),
        userinfo_url: Some("https://graph.microsoft.com/oidc/userinfo".to_owned()),
        jit_provisioning: true,
        account_linking: true,
        jwks_uri: Some(format!(
            "https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
        )),
        jwks: None,
        saml_signing_certificates: Vec::new(),
        trusted_audiences: Vec::new(),
        claim_mappings: vec![
            ClaimMapping {
                source: "oid".to_owned(),
                target: "sub".to_owned(),
                required: true,
            },
            ClaimMapping {
                source: "preferred_username".to_owned(),
                target: "email".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "name".to_owned(),
                target: "name".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "tid".to_owned(),
                target: "tenant_id".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "unique_name".to_owned(),
                target: "username".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "groups".to_owned(),
                target: "groups".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "roles".to_owned(),
                target: "roles".to_owned(),
                required: false,
            },
        ],
    }
}

/// Google Workspace connector profile with well-known endpoints and claim mappings.
pub fn google_workspace_provider(client_id: &str, client_secret: &str) -> InboundIdentityProvider {
    InboundIdentityProvider {
        id: "google-workspace".to_owned(),
        kind: InboundProviderKind::GoogleWorkspace,
        issuer: "https://accounts.google.com".to_owned(),
        enabled: true,
        domains: vec![],
        social_provider: None,
        client_id: Some(client_id.to_owned()),
        client_secret: Some(client_secret.to_owned()),
        token_url: Some("https://oauth2.googleapis.com/token".to_owned()),
        userinfo_url: Some("https://openidconnect.googleapis.com/v1/userinfo".to_owned()),
        jit_provisioning: true,
        account_linking: true,
        jwks_uri: Some("https://www.googleapis.com/oauth2/v3/certs".to_owned()),
        jwks: None,
        saml_signing_certificates: Vec::new(),
        trusted_audiences: Vec::new(),
        claim_mappings: vec![
            ClaimMapping {
                source: "sub".to_owned(),
                target: "sub".to_owned(),
                required: true,
            },
            ClaimMapping {
                source: "email".to_owned(),
                target: "email".to_owned(),
                required: true,
            },
            ClaimMapping {
                source: "email_verified".to_owned(),
                target: "email_verified".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "name".to_owned(),
                target: "name".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "given_name".to_owned(),
                target: "given_name".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "family_name".to_owned(),
                target: "family_name".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "picture".to_owned(),
                target: "picture".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "hd".to_owned(),
                target: "domain".to_owned(),
                required: false,
            },
        ],
    }
}

/// Okta connector profile with well-known endpoints and claim mappings.
///
/// The `domain` is the Okta organisation domain (e.g. `"dev-123456.okta.com"`).
pub fn okta_provider(
    domain: &str,
    client_id: &str,
    client_secret: &str,
) -> InboundIdentityProvider {
    let issuer = format!("https://{domain}/oauth2/default");
    InboundIdentityProvider {
        id: format!("okta-{domain}"),
        kind: InboundProviderKind::Okta,
        issuer: issuer.clone(),
        enabled: true,
        domains: vec![],
        social_provider: None,
        client_id: Some(client_id.to_owned()),
        client_secret: Some(client_secret.to_owned()),
        token_url: Some(format!("{issuer}/v1/token")),
        userinfo_url: Some(format!("{issuer}/v1/userinfo")),
        jit_provisioning: true,
        account_linking: true,
        jwks_uri: Some(format!("{issuer}/v1/keys")),
        jwks: None,
        saml_signing_certificates: Vec::new(),
        trusted_audiences: Vec::new(),
        claim_mappings: vec![
            ClaimMapping {
                source: "sub".to_owned(),
                target: "sub".to_owned(),
                required: true,
            },
            ClaimMapping {
                source: "email".to_owned(),
                target: "email".to_owned(),
                required: true,
            },
            ClaimMapping {
                source: "email_verified".to_owned(),
                target: "email_verified".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "name".to_owned(),
                target: "name".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "preferred_username".to_owned(),
                target: "username".to_owned(),
                required: false,
            },
            ClaimMapping {
                source: "groups".to_owned(),
                target: "groups".to_owned(),
                required: false,
            },
        ],
    }
}

pub fn normalize_enterprise_claims(
    provider: &InboundIdentityProvider,
    external: &ExternalIdentityClaims,
) -> Result<BTreeMap<String, serde_json::Value>, QidError> {
    let mut normalized = BTreeMap::from([
        (
            "issuer".to_string(),
            serde_json::Value::String(external.issuer.clone()),
        ),
        (
            "external_subject".to_string(),
            serde_json::Value::String(external.subject.clone()),
        ),
        (
            "provider_id".to_string(),
            serde_json::Value::String(provider.id.clone()),
        ),
    ]);
    for mapping in &provider.claim_mappings {
        match external.claims.get(&mapping.source) {
            Some(value) => {
                normalized.insert(mapping.target.clone(), value.clone());
            }
            None if mapping.required => {
                return Err(broker_error(
                    "required_claim_missing",
                    "Required external claim is missing",
                ));
            }
            None => {}
        }
    }
    Ok(normalized)
}

/// Verify an inbound ID token from an external OIDC provider.
///
/// Verifies the JWT signature against the provider's cached JWKS only
/// (RS256/RS384/RS512/ES256/ES384/EdDSA with `kid` match). Symmetric
/// `HS256/HS384/HS512` and any other `alg` are rejected fail-closed per
/// RFC 8725 §3.1: the header `alg` never selects an HMAC path and
/// `client_secret` (code-exchange credential) is never used as an HMAC key.
/// Validates `iss`, `aud`, and `exp` claims, then enforces the provider's
/// explicit audience trust policy (`expected_audience` plus `trusted_audiences`).
/// Returns the decoded JWT payload as a `serde_json::Value`.
pub fn verify_inbound_idp_token(
    token: &str,
    provider: &InboundIdentityProvider,
    expected_issuer: &str,
    expected_audience: &str,
) -> Result<serde_json::Value, QidError> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

    let header = decode_header(token)
        .map_err(|e| broker_error("token_header_decode_failed", &format!("{e}")))?;

    let alg = header.alg;
    let kid = header.kid;

    let mut validation = Validation::new(alg);
    validation.set_issuer(&[expected_issuer]);
    validation.set_audience(&[expected_audience]);
    validation.validate_exp = true;
    validation.required_spec_claims = ["iss", "aud", "exp"]
        .iter()
        .map(|&s| s.to_string())
        .collect();

    // RFC 8725 §3.1: pin the operation to asymmetric JWKS verification.
    // The header `alg` selects only within this allowlist; symmetric algs
    // fail closed so a crafted header can never reroute verification to
    // `client_secret` (RS->HS key confusion, CVE-2015-9235 pattern).
    if matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512) {
        return Err(broker_error(
            "symmetric_alg_not_allowed",
            "Inbound ID tokens must use asymmetric JWKS algs; HMAC algs are rejected",
        ));
    }
    let key: DecodingKey = match alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::ES256
        | Algorithm::ES384
        | Algorithm::EdDSA => {
            let kid_str = kid.as_deref().ok_or_else(|| {
                broker_error(
                    "missing_kid",
                    "Asymmetric algorithm requires kid in JWT header",
                )
            })?;
            let jwks_value = provider.jwks.as_ref().ok_or_else(|| {
                broker_error(
                    "missing_jwks",
                    "Asymmetric algorithm requires provider.jwks to be populated",
                )
            })?;
            // Parse inbound JWKS tolerantly per RFC 7517 robustness: unknown
            // `kty`/`alg` entries (e.g. RFC 9964 `AKP`/`ML-DSA-*`) are
            // skipped instead of aborting the whole set, so a PQ key
            // alongside classical keys cannot break classical verification.
            // Unknown `kid` values still fail closed via `key_not_found`.
            let keys_value = jwks_value
                .get("keys")
                .and_then(|v| v.as_array())
                .ok_or_else(|| broker_error("invalid_jwks", "JWKS must contain a `keys` array"))?;
            let mut usable: Vec<jsonwebtoken::jwk::Jwk> = Vec::new();
            for entry in keys_value {
                if let Ok(jwk) = serde_json::from_value::<jsonwebtoken::jwk::Jwk>(entry.clone()) {
                    usable.push(jwk);
                }
            }
            let jwk = usable
                .iter()
                .find(|jwk| {
                    jwk.common
                        .key_id
                        .as_deref()
                        .is_some_and(|kid| kid == kid_str)
                })
                .ok_or_else(|| {
                    broker_error("key_not_found", &format!("No JWK matches kid {kid_str:?}"))
                })?;
            DecodingKey::from_jwk(jwk)
                .map_err(|e| broker_error("jwk_decode_failed", &format!("{e}")))?
        }
        other => {
            return Err(broker_error(
                "unsupported_algorithm",
                &format!("Unsupported JWT algorithm: {other:?}"),
            ));
        }
    };

    let token_data = decode::<serde_json::Value>(token, &key, &validation)
        .map_err(|e| broker_error("token_verification_failed", &format!("{e}")))?;

    let claims = token_data.claims;

    // Double-check exp (jsonwebtoken already validates it, but be explicit)
    if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64()) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if exp <= now {
            return Err(broker_error("token_expired", "ID token has expired"));
        }
    } else {
        return Err(broker_error("missing_exp", "ID token is missing exp claim"));
    }

    // Explicit per-provider audience trust: `expected_audience` (the
    // configured `client_id` at the OIDC/social callbacks) is always trusted.
    // Every `aud` member must equal it or match this provider's
    // `trusted_audiences`. The jsonwebtoken audience membership check above is
    // kept unchanged; this rejects tokens that smuggle an untrusted extra
    // audience alongside the expected one. Malformed `aud` values fail closed.
    // `azp` is not required.
    enforce_inbound_audience_trust(&claims, provider, expected_audience)?;

    Ok(claims)
}

/// Enforce the inbound OIDC audience trust policy on already-decoded claims.
fn enforce_inbound_audience_trust(
    claims: &serde_json::Value,
    provider: &InboundIdentityProvider,
    expected_audience: &str,
) -> Result<(), QidError> {
    let audiences: Vec<&str> = match claims.get("aud") {
        Some(serde_json::Value::String(single)) => vec![single.as_str()],
        Some(serde_json::Value::Array(members)) => {
            let mut collected = Vec::with_capacity(members.len());
            for member in members {
                match member.as_str() {
                    Some(value) => collected.push(value),
                    None => {
                        return Err(broker_error(
                            "invalid_audience",
                            "ID token has a malformed aud member",
                        ));
                    }
                }
            }
            collected
        }
        _ => {
            return Err(broker_error(
                "invalid_audience",
                "ID token has a malformed aud claim",
            ));
        }
    };
    if audiences.iter().any(|value| value.trim().is_empty()) {
        return Err(broker_error(
            "invalid_audience",
            "ID token has an empty aud member",
        ));
    }
    if !audiences.contains(&expected_audience) {
        return Err(broker_error(
            "audience_mismatch",
            "ID token audience does not include the expected audience",
        ));
    }
    if audiences.iter().any(|value| {
        *value != expected_audience && !provider.trusted_audiences.iter().any(|t| t == *value)
    }) {
        return Err(broker_error(
            "untrusted_audience",
            "ID token carries an audience that is not explicitly trusted for this provider",
        ));
    }
    Ok(())
}

fn validate_inbound_providers(providers: &[InboundIdentityProvider]) -> Result<(), QidError> {
    let mut ids = HashSet::new();
    let mut domains: HashMap<String, String> = HashMap::new();
    for provider in providers {
        if provider.id.trim().is_empty() {
            return Err(broker_error(
                "invalid_provider",
                "Provider id must not be empty",
            ));
        }
        if !ids.insert(provider.id.as_str()) {
            return Err(broker_error(
                "duplicate_provider",
                "Provider id must be unique",
            ));
        }
        if provider.enabled && provider.issuer.trim().is_empty() {
            return Err(broker_error(
                "invalid_provider",
                "Enabled provider issuer must not be empty",
            ));
        }
        if provider.enabled
            && provider.kind == InboundProviderKind::Social
            && provider.social_provider.is_none()
        {
            return Err(broker_error(
                "invalid_social_provider",
                "Social provider routing requires social_provider",
            ));
        }
        if !provider.trusted_audiences.is_empty()
            && !matches!(
                &provider.kind,
                InboundProviderKind::Oidc
                    | InboundProviderKind::EntraId
                    | InboundProviderKind::GoogleWorkspace
                    | InboundProviderKind::Okta
                    | InboundProviderKind::Social
            )
        {
            return Err(broker_error(
                "unsupported_trusted_audiences",
                "Provider trusted_audiences is supported only for OIDC ID-token providers",
            ));
        }
        {
            let mut seen = HashSet::new();
            for audience in &provider.trusted_audiences {
                if audience.trim().is_empty() {
                    return Err(broker_error(
                        "invalid_trusted_audience",
                        "Provider trusted_audiences must not contain empty entries",
                    ));
                }
                if !seen.insert(audience) {
                    return Err(broker_error(
                        "duplicate_trusted_audience",
                        "Provider trusted_audiences must not contain duplicates",
                    ));
                }
            }
        }
        for domain in &provider.domains {
            let Some(normalized) = normalized_domain(domain) else {
                return Err(broker_error("invalid_domain", "Provider domain is invalid"));
            };
            if provider.enabled
                && let Some(existing) = domains.insert(normalized.clone(), provider.id.clone())
            {
                return Err(broker_error(
                    "duplicate_domain",
                    &format!(
                        "Domain {normalized} is configured for both {existing} and {}",
                        provider.id
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn route_decision(provider: &InboundIdentityProvider, reason: &str) -> BrokerRouteDecision {
    BrokerRouteDecision {
        provider_id: provider.id.clone(),
        provider_kind: provider.kind.clone(),
        reason: reason.to_string(),
        jit_provisioning: provider.jit_provisioning,
        account_linking: provider.account_linking,
    }
}

fn domain_matches(candidate: &str, domain: &str) -> bool {
    normalized_domain(candidate)
        .as_deref()
        .is_some_and(|candidate| candidate == domain)
}

fn domain_from_login_hint(login_hint: &str) -> Option<String> {
    let (_, domain) = login_hint.rsplit_once('@')?;
    normalized_domain(domain)
}

fn normalized_domain(value: &str) -> Option<String> {
    let normalized = value.trim().trim_start_matches('@').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.contains('/')
        || normalized.contains(':')
        || !normalized.contains('.')
    {
        return None;
    }
    Some(normalized)
}

fn normalized_optional(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn broker_error(code: &str, message: &str) -> QidError {
    coded_error(code, message)
}
