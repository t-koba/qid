//! Entity Attestation Token (EAT, RFC 9334) and related RATS
//! primitives (CoSWID, CoRIM).
//!
//! EATs are signed JSON Web Tokens used to convey attestation
//! evidence about an entity (e.g. a workload) to a relying party.
//! CoSWID (W3C CoSWID) describes the software on the entity and
//! CoRIM (IETF RATS working draft) is a manifest of measurement
//! results keyed by CoSWID identifiers.
//!
//! This module does not implement cryptographic verification; it
//! provides the typed data model and JSON (de)serialization that
//! downstream code (the SPIFFE Workload API and RATS verifier) can
//! consume. The tokens themselves are signed by the
//! `qid_crypto::Signer` once the payload has been constructed.

use qid_core::error::{QidError, QidResult};
use qid_crypto::{Jwk, jwt::verify_jwt_signature_with_claims};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// EAT (RFC 9334 §4) top-level claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EatClaims {
    pub iss: String,
    pub sub: String,
    pub iat: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// RFC 9334 §4.4.1 nonce used for freshness.
    pub eat_profile: EatProfile,
    /// Submodules (RFC 9334 §4.3) keyed by name. Common submodules
    /// include `ueid`, `sueids`, `oemid`, `hwmodel`, `swname`, `swversion`,
    /// `manifests`, and `evidence`.
    pub submods: BTreeMap<String, serde_json::Value>,
}

/// Verification policy for an EAT JWT.
#[derive(Debug, Clone)]
pub struct EatVerificationPolicy<'a> {
    pub expected_issuer: &'a str,
    pub expected_audience: &'a str,
    pub expected_nonce: &'a str,
    pub expected_profile: EatProfile,
    pub alg: &'a str,
}

/// Verify a signed EAT JWT and return typed EAT claims.
pub fn verify_eat_jwt(
    token: &str,
    public_jwk: &Jwk,
    policy: &EatVerificationPolicy<'_>,
) -> QidResult<EatClaims> {
    verify_jwt_signature_with_claims(
        token,
        public_jwk,
        policy.alg,
        policy.expected_audience,
        policy.expected_issuer,
    )?;
    let payload = jwt_payload(token)?;
    let claims: EatClaims =
        serde_json::from_value(payload).map_err(|error| QidError::BadRequest {
            message: format!("EAT claims are invalid: {error}"),
        })?;
    if claims.eat_profile != policy.expected_profile {
        return Err(QidError::Unauthorized {
            message: "EAT profile does not match verifier policy".to_string(),
        });
    }
    if claims.nonce.as_deref() != Some(policy.expected_nonce) {
        return Err(QidError::Unauthorized {
            message: "EAT nonce does not match verifier policy".to_string(),
        });
    }
    if claims.submods.is_empty() {
        return Err(QidError::BadRequest {
            message: "EAT must contain at least one submodule".to_string(),
        });
    }
    Ok(claims)
}

fn jwt_payload(token: &str) -> QidResult<serde_json::Value> {
    let mut parts = token.split('.');
    let _header = parts.next().ok_or_else(|| QidError::BadRequest {
        message: "EAT JWT is malformed".to_string(),
    })?;
    let payload = parts.next().ok_or_else(|| QidError::BadRequest {
        message: "EAT JWT is malformed".to_string(),
    })?;
    if parts.next().is_none() || parts.next().is_some() {
        return Err(QidError::BadRequest {
            message: "EAT JWT is malformed".to_string(),
        });
    }
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|error| QidError::BadRequest {
            message: format!("EAT JWT payload is not base64url: {error}"),
        })?;
    serde_json::from_slice(&bytes).map_err(|error| QidError::BadRequest {
        message: format!("EAT JWT payload is not JSON: {error}"),
    })
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EatProfile {
    /// IETF RATS Architecture: <https://www.rfc-editor.org/info/rfc9334>.
    Rats,
    /// OpenID for Verifiable Credential Issuance.
    Openid4Vci,
    /// OpenID for Verifiable Presentations.
    Openid4Vp,
    /// Tag Discovery by JWT.
    TagDiscovery,
}

impl EatProfile {
    pub fn as_uri(self) -> &'static str {
        match self {
            Self::Rats => "tag:ietf.org,2024:rats-eat",
            Self::Openid4Vci => "tag:openid.net,2024:openid4vci",
            Self::Openid4Vp => "tag:openid.net,2024:openid4vp",
            Self::TagDiscovery => "tag:ietf.org,2024:tag-discovery",
        }
    }
}

/// CoSWID (W3C CoSWID) primary entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoswidEntry {
    pub tag_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub entities: Vec<CoswidEntity>,
    pub evidence: Vec<CoswidEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoswidEntity {
    pub entity_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reg_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoswidEvidence {
    pub resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Concise Reference Integrity Manifest (CoRIM) entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorimEntry {
    pub tag_id: String,
    pub profile: String,
    pub coswid_entries: Vec<CoswidEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
}

/// Compute the SHA-256 fingerprint of a CoSWID tag_id for use as a
/// CoRIM reference.
pub fn coswid_fingerprint(coswid: &CoswidEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(coswid.tag_id.as_bytes());
    let digest = hasher.finalize();
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// SPIFFE Workload API `X.509-SVID` document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpiffeX509Svid {
    pub spiffe_id: String,
    pub certificate_chain: Vec<String>,
    pub private_key: Option<String>,
    pub federation_chain: Vec<String>,
    pub ttl_seconds: u64,
    pub issued_at: u64,
}

impl SpiffeX509Svid {
    /// Encode the SVID document per the SPIFFE Workload API §4.2.
    pub fn to_spiffe_document(&self) -> serde_json::Value {
        serde_json::json!({
            "spiffe_id": self.spiffe_id,
            "x5c_svid": self.certificate_chain,
            "x5c_svid_key": self.private_key,
            "x5c_bundle": self.federation_chain,
            "ttl": self.ttl_seconds,
            "iat": self.issued_at,
        })
    }
}

/// SPIFFE JWT SVID document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpiffeJwtSvid {
    pub spiffe_id: String,
    pub token: String,
    pub ttl_seconds: u64,
    pub issued_at: u64,
}

/// Validate that a SPIFFE ID is well-formed per the SPIFFE
/// Specification §2.3: `spiffe://<trust_domain>/<workload_identifier>`.
pub fn validate_spiffe_id(spiffe_id: &str) -> QidResult<()> {
    let rest = spiffe_id
        .strip_prefix("spiffe://")
        .ok_or_else(|| QidError::BadRequest {
            message: format!("SPIFFE ID {spiffe_id} is missing the spiffe:// scheme"),
        })?;
    if rest.is_empty() {
        return Err(QidError::BadRequest {
            message: "SPIFFE ID has an empty trust domain".to_string(),
        });
    }
    if rest.contains(' ') {
        return Err(QidError::BadRequest {
            message: "SPIFFE ID must not contain whitespace".to_string(),
        });
    }
    if rest.contains('?') {
        return Err(QidError::BadRequest {
            message: "SPIFFE ID must not contain query parameters".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use qid_crypto::{jwk::generate_es256, jwt::sign_es256_jwt_with_jwk_header};

    #[test]
    fn coswid_fingerprint_is_deterministic() {
        let entry = CoswidEntry {
            tag_id: "qid-server-1.0.0".to_string(),
            entity_name: Some("qid".to_string()),
            version: Some("1.0.0".to_string()),
            entities: Vec::new(),
            evidence: vec![CoswidEvidence {
                resource: "/usr/local/bin/qidd".to_string(),
                version: Some("1.0.0".to_string()),
            }],
        };
        let first = coswid_fingerprint(&entry);
        let second = coswid_fingerprint(&entry);
        assert_eq!(first, second);
    }

    #[test]
    fn spiffe_id_validation() {
        assert!(validate_spiffe_id("spiffe://trust.domain/ns/default/sa/qid").is_ok());
        assert!(validate_spiffe_id("http://example.com").is_err());
        assert!(validate_spiffe_id("spiffe://").is_err());
    }

    #[test]
    fn verifies_signed_eat_with_nonce_and_profile() {
        let key = generate_es256("eat-verifier").unwrap();
        let now = qid_core::util::now_seconds();
        let token = sign_es256_jwt_with_jwk_header(
            key.private_pem.as_bytes(),
            &key.public_jwk,
            "eat+jwt",
            &serde_json::json!({
                "iss": "https://attester.example.com",
                "sub": "spiffe://example.test/workload",
                "aud": "qid-rats-verifier",
                "iat": now,
                "exp": now + 300,
                "nonce": "nonce-1",
                "eat_profile": "rats",
                "submods": {
                    "evidence": { "measurement": "abc" }
                }
            }),
        )
        .unwrap();
        let claims = verify_eat_jwt(
            &token,
            &key.public_jwk,
            &EatVerificationPolicy {
                expected_issuer: "https://attester.example.com",
                expected_audience: "qid-rats-verifier",
                expected_nonce: "nonce-1",
                expected_profile: EatProfile::Rats,
                alg: "ES256",
            },
        )
        .unwrap();
        assert_eq!(claims.sub, "spiffe://example.test/workload");
        assert!(claims.submods.contains_key("evidence"));
    }
}
