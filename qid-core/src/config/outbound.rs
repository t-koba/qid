use serde::Deserialize;
use url::Url;

use crate::error::{QidError, QidResult};

/// Realm-local authorization for registration-controlled, server-fetched callbacks.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ClientCallbackDestinationsConfig {
    pub backchannel_logout: DestinationPolicyConfig,
    pub ciba_notification: DestinationPolicyConfig,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct DestinationPolicyConfig {
    pub allowed_origins: Vec<String>,
}

/// Bounded reasons, deliberately containing no submitted URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationAuthorizationError {
    InvalidUrl,
    InvalidOrigin,
    NotAllowed,
}

impl std::fmt::Display for DestinationAuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidUrl => "invalid_callback_url",
            Self::InvalidOrigin => "invalid_allowed_origin",
            Self::NotAllowed => "origin_not_allowed",
        })
    }
}

impl std::error::Error for DestinationAuthorizationError {}

fn parse_endpoint(raw: &str) -> Result<Url, DestinationAuthorizationError> {
    let invalid = DestinationAuthorizationError::InvalidUrl;
    // Url's browser-compatible parser repairs whitespace, missing slashes and
    // backslashes. Reject those inputs rather than silently repairing metadata.
    if raw.is_empty()
        || raw.chars().any(|ch| ch.is_whitespace() || ch.is_control())
        || raw.contains('\\')
    {
        return Err(invalid);
    }
    let (_, rest) = raw.split_once("://").ok_or(invalid)?;
    let authority = rest.split(['/', '?', '#']).next().ok_or(invalid)?;
    if authority.is_empty() || authority.contains('@') || authority.ends_with(':') {
        return Err(invalid);
    }
    let url = Url::parse(raw).map_err(|_| invalid)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default().is_none_or(|port| port == 0)
        || url
            .host_str()
            .is_some_and(|host| host.contains('*') || host.starts_with('.'))
    {
        return Err(invalid);
    }
    Ok(url)
}

fn parse_origin(raw: &str) -> Result<Url, DestinationAuthorizationError> {
    let invalid = DestinationAuthorizationError::InvalidOrigin;
    let url = parse_endpoint(raw).map_err(|_| invalid)?;
    // Check the input path too: normalization must not turn /foo/.. into an origin.
    let rest = raw.split_once("://").ok_or(invalid)?.1;
    let path = rest.find('/').map(|index| &rest[index..]).unwrap_or("");
    if !matches!(path, "" | "/") || url.query().is_some() {
        return Err(invalid);
    }
    Ok(url)
}

impl DestinationPolicyConfig {
    pub fn authorize(&self, raw: &str) -> Result<Url, DestinationAuthorizationError> {
        let endpoint = parse_endpoint(raw)?;
        // Invalid configuration fails closed even when constructed without validation.
        let origins = self.allowed_origins.iter().map(|raw| parse_origin(raw));
        let mut allowed = false;
        for origin in origins {
            if origin?.origin() == endpoint.origin() {
                allowed = true;
            }
        }
        if allowed {
            Ok(endpoint)
        } else {
            Err(DestinationAuthorizationError::NotAllowed)
        }
    }

    pub(super) fn validate(&self, realm_id: &str, purpose: &str) -> QidResult<()> {
        for raw in &self.allowed_origins {
            parse_origin(raw).map_err(|reason| QidError::Config {
                message: format!("realm {realm_id} client callback {purpose}: {reason}"),
            })?;
        }
        Ok(())
    }
}

impl ClientCallbackDestinationsConfig {
    pub(super) fn validate(&self, realm_id: &str) -> QidResult<()> {
        self.backchannel_logout
            .validate(realm_id, "backchannel_logout")?;
        self.ciba_notification
            .validate(realm_id, "ciba_notification")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_origin_authorization() {
        let policy = DestinationPolicyConfig {
            allowed_origins: vec![
                "https://x.example:443".into(),
                "http://127.0.0.1:8081".into(),
            ],
        };
        for (raw, allowed) in [
            ("https://x.example/path?query=1", true),
            ("https://x.example:443/", true),
            ("https://x.example:8443/", false),
            ("http://x.example/", false),
            ("https://x.example.evil/", false),
            ("https://evil.x.example/", false),
            ("https://user@x.example/", false),
            ("https://@x.example/", false),
            ("https://x.example/#fragment", false),
            ("/relative", false),
            ("https:x.example", false),
            ("", false),
            (" https://x.example", false),
            ("https://x.example/white space", false),
            ("https://x.example/\n", false),
            ("ftp://x.example/", false),
            ("http://localhost/", false),
            ("http://127.0.0.1/", false),
            ("http://[::1]/", false),
            ("http://127.0.0.1:8081/fixture", true),
            ("http://127.0.0.1:8082/fixture", false),
            ("http://127.0.0.1:0/", false),
        ] {
            assert_eq!(policy.authorize(raw).is_ok(), allowed, "{raw}");
            assert!(DestinationPolicyConfig::default().authorize(raw).is_err());
        }
        assert!(
            DestinationPolicyConfig {
                allowed_origins: vec!["https://x.example".into()]
            }
            .authorize("https://x.example:443/path")
            .is_ok()
        );
    }

    #[test]
    fn configuration_rejects_non_origins_and_defaults_deny() {
        for raw in [
            "",
            "https://",
            "https://*.example",
            "https://.example",
            "example.com",
            "https://user@example.com",
            "https://example.com?query",
            "https://example.com/#fragment",
            "https://example.com/path",
            "https://example.com/foo/..",
            "http://localhost:",
            "http://localhost:0",
            "http://localhost:65536",
        ] {
            let policy = DestinationPolicyConfig {
                allowed_origins: vec![raw.into()],
            };
            assert!(
                matches!(
                    policy.validate("test", "backchannel_logout"),
                    Err(QidError::Config { .. })
                ),
                "{raw}"
            );
        }
        let omitted: ClientCallbackDestinationsConfig = serde_json::from_str("{}").unwrap();
        assert!(
            omitted
                .backchannel_logout
                .authorize("https://x.example")
                .is_err()
        );
        assert!(
            omitted
                .ciba_notification
                .authorize("https://x.example")
                .is_err()
        );
    }
}
