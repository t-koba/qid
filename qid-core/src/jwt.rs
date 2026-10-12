//! JWT claims and signer abstraction.

pub use jsonwebtoken::TokenData;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Claims used for qid-issued JWTs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
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
