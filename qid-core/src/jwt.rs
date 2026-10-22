//! JWT claims and signer abstraction.

pub use jsonwebtoken::TokenData;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// JWT audience in either compact form: a single string for one audience
/// (RFC 7519 §4.1.3 `StringOrURI`), or an array for several. Array form is
/// required whenever a token names more than one audience — truncating to the
/// first would leave the other resource servers unable to validate it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    /// A single audience value.
    pub fn single(value: impl Into<String>) -> Self {
        Audience::Single(value.into())
    }

    /// Build from resolved audiences: empty omits the claim, one stays a
    /// string, several serialize as an array.
    pub fn from_values(values: Vec<String>) -> Option<Self> {
        match values.len() {
            0 => None,
            1 => Some(Audience::Single(
                values.into_iter().next().unwrap_or_default(),
            )),
            _ => Some(Audience::Multiple(values)),
        }
    }

    /// Whether `audience` is among the named audiences.
    pub fn contains(&self, audience: &str) -> bool {
        match self {
            Audience::Single(value) => value == audience,
            Audience::Multiple(values) => values.iter().any(|value| value == audience),
        }
    }

    /// The first (primary) audience, if any.
    pub fn primary(&self) -> Option<&str> {
        match self {
            Audience::Single(value) => Some(value),
            Audience::Multiple(values) => values.first().map(String::as_str),
        }
    }

    /// Consume an audience claim into its primary value. Struct literals that
    /// move the claim alongside sibling fields use this instead of borrowing
    /// the whole claims value.
    pub fn primary_string(aud: Option<Self>) -> Option<String> {
        aud.and_then(|aud| aud.primary().map(str::to_string))
    }
}

/// Claims used for qid-issued JWTs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Audience>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl JwtClaims {
    /// All audiences named by the token, empty when absent.
    pub fn audiences(&self) -> Vec<&str> {
        match &self.aud {
            None => Vec::new(),
            Some(Audience::Single(value)) => vec![value],
            Some(Audience::Multiple(values)) => values.iter().map(String::as_str).collect(),
        }
    }

    /// Whether `audience` is among the token audiences.
    pub fn aud_contains(&self, audience: &str) -> bool {
        self.aud.as_ref().is_some_and(|aud| aud.contains(audience))
    }

    /// The first (primary) audience, if any. Single-audience tokens round
    /// through here unchanged.
    pub fn aud_primary(&self) -> Option<&str> {
        self.aud.as_ref().and_then(Audience::primary)
    }
}

/// A signer that holds no key.
///
/// A binary that never issues a token needs no signing material, and a key
/// written in the source is a credential every reader of the source holds.
/// This signer refuses every signing and decoding attempt, so a path that
/// expects to sign reports that the process holds no key instead of
/// producing a token anyone could forge.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSigningKey;

impl Signer for NoSigningKey {
    fn sign(&self, _claims: &JwtClaims) -> anyhow::Result<String> {
        anyhow::bail!("this process holds no signing key")
    }

    fn sign_with_typ(&self, _claims: &JwtClaims, _typ: &str) -> anyhow::Result<String> {
        anyhow::bail!("this process holds no signing key")
    }

    fn decode_signature_only(&self, _token: &str) -> anyhow::Result<TokenData<JwtClaims>> {
        anyhow::bail!("this process holds no signing key")
    }

    fn decode_with_aud(
        &self,
        _token: &str,
        _expected_audience: &str,
    ) -> anyhow::Result<TokenData<JwtClaims>> {
        anyhow::bail!("this process holds no signing key")
    }

    fn algorithm(&self) -> &'static str {
        "none"
    }
}

/// Token signer abstraction.
pub trait Signer: Send + Sync {
    fn sign(&self, claims: &JwtClaims) -> anyhow::Result<String>;

    /// Sign with a custom `typ` header value (default `"JWT"`).
    fn sign_with_typ(&self, claims: &JwtClaims, typ: &str) -> anyhow::Result<String>;

    /// Verify the signature and algorithm, require `exp` present, and reject
    /// tokens expired beyond the 60s leeway. `aud`, `iss`, `sub`, and `nbf`
    /// are not validated here. Callers MUST enforce audience/issuer binding
    /// via [`Signer::decode_with_aud`] where needed, and MUST NOT use this
    /// function to inspect expired tokens. Production token validation paths
    /// must use [`Signer::decode_with_aud`] so that audience binding is
    /// enforced by default.
    fn decode_signature_only(&self, token: &str) -> anyhow::Result<TokenData<JwtClaims>>;

    /// Verify the signature and enforce audience binding. The token's `aud` claim
    /// (string or array form) must contain `expected_audience`. This is the
    /// preferred entry point for production token validation.
    fn decode_with_aud(
        &self,
        token: &str,
        expected_audience: &str,
    ) -> anyhow::Result<TokenData<JwtClaims>>;

    fn algorithm(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_keyless_signer_refuses_every_operation() {
        let signer = NoSigningKey;
        let claims = JwtClaims {
            iss: Some("https://id.example.com".to_string()),
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            extra: HashMap::new(),
        };
        assert!(
            signer.sign(&claims).is_err(),
            "a process without a key must not sign"
        );
        assert!(
            signer.sign_with_typ(&claims, "JWT").is_err(),
            "a process without a key must not sign"
        );
        assert!(
            signer.decode_signature_only("token").is_err(),
            "a process without a key must not decode"
        );
        assert!(
            signer.decode_with_aud("token", "audience").is_err(),
            "a process without a key must not decode"
        );
        assert_eq!(signer.algorithm(), "none");
    }
}
