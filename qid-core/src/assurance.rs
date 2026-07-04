use crate::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AssuranceLevel {
    Level1,
    Level2,
    Level3,
    Level4,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustFramework {
    Nist80063,
    Eidas,
    Kantara,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssuranceProfile {
    pub trust_framework: TrustFramework,
    pub identity_assurance_level: Option<AssuranceLevel>,
    pub authenticator_assurance_level: Option<AssuranceLevel>,
    pub federation_assurance_level: Option<AssuranceLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedClaims {
    pub verification: VerificationEvidence,
    pub claims: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationEvidence {
    pub verification_process: Option<String>,
    pub evidence: Vec<IdentityEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct IdentityEvidence {
    pub r#type: String,
    pub issuer: Option<String>,
    pub issued_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub checks: Option<Vec<IdentityCheck>>,
    pub documents: Option<Vec<IdentityDocument>>,
    pub electronic_record: Option<ElectronicRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityCheck {
    pub check_type: String,
    pub outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityDocument {
    pub r#type: String,
    pub issuer: Option<serde_json::Value>,
    pub number: Option<String>,
    pub date_of_issuance: Option<String>,
    pub date_of_expiry: Option<String>,
    pub document_of: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ElectronicRecord {
    pub r#type: String,
    pub issuer: Option<String>,
    pub issued_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub attributes: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct VerifiedClaimRegistration {
    pub verification: Option<VerificationRegistration>,
    pub claims: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationRegistration {
    pub process: Option<String>,
    pub evidence: Vec<EvidenceRegistration>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRegistration {
    pub r#type: String,
    pub checks: Vec<String>,
    pub documents: Vec<String>,
    pub electronic_record: Vec<String>,
}

/// Parse a verified_claims object from the OIDC identity assurance format.
pub fn parse_verified_claims(value: &serde_json::Value) -> Result<VerifiedClaims, String> {
    let verification = value.get("verification").ok_or("missing verification")?;
    let claims = value.get("claims").ok_or("missing claims")?.clone();
    Ok(VerifiedClaims {
        verification: serde_json::from_value(verification.clone())
            .map_err(|e| format!("verification parse error: {e}"))?,
        claims,
    })
}

pub fn build_verified_claims_request(claims: Vec<String>) -> serde_json::Value {
    serde_json::json!({
        "userinfo": {
            "verified_claims": {
                "verification": {
                    "process": null,
                    "evidence": [
                        {"type": "document", "checks": ["authenticity"], "documents": ["passport"]}
                    ]
                },
                "claims": claims
            }
        }
    })
}

pub fn parse_asserted_acr(acr_value: &str) -> QidResult<AssuranceProfile> {
    let parts: Vec<&str> = acr_value.split('/').collect();
    if parts.len() < 4 {
        return Err(QidError::BadRequest {
            message: format!("unrecognized ACR format: {acr_value}"),
        });
    }
    let trust_framework = match parts[parts.len() - 2] {
        "nist" => TrustFramework::Nist80063,
        "eidas" => TrustFramework::Eidas,
        "kantara" => TrustFramework::Kantara,
        other => {
            return Err(QidError::BadRequest {
                message: format!("unknown trust framework: {other}"),
            });
        }
    };
    let level_str = parts[parts.len() - 1];
    let parse_level = |s: &str| -> Option<AssuranceLevel> {
        match s {
            "ial1" | "aal1" | "fal1" => Some(AssuranceLevel::Level1),
            "ial2" | "aal2" | "fal2" => Some(AssuranceLevel::Level2),
            "ial3" | "aal3" | "fal3" => Some(AssuranceLevel::Level3),
            "ial4" | "aal4" | "fal4" => Some(AssuranceLevel::Level4),
            _ => None,
        }
    };
    Ok(AssuranceProfile {
        trust_framework,
        identity_assurance_level: parse_level(level_str).filter(|_| level_str.starts_with("ial")),
        authenticator_assurance_level: parse_level(level_str)
            .filter(|_| level_str.starts_with("aal")),
        federation_assurance_level: parse_level(level_str).filter(|_| level_str.starts_with("fal")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nist_ial2() {
        let profile = parse_asserted_acr("https://refeds.org/profile/nist/ial2").unwrap();
        assert_eq!(profile.trust_framework, TrustFramework::Nist80063);
        assert_eq!(
            profile.identity_assurance_level,
            Some(AssuranceLevel::Level2)
        );
    }

    #[test]
    fn invalid_acr_format() {
        assert!(parse_asserted_acr("invalid").is_err());
    }

    #[test]
    fn verified_claims_round_trip() {
        let vc = VerifiedClaims {
            verification: VerificationEvidence {
                verification_process: Some("https://example.com/proc".to_string()),
                evidence: vec![IdentityEvidence {
                    r#type: "document".to_string(),
                    issuer: Some("https://idp.example.com".to_string()),
                    issued_at: Some(1700000000),
                    expires_at: Some(1800000000),
                    checks: Some(vec![IdentityCheck {
                        check_type: "authenticity".to_string(),
                        outcome: "passed".to_string(),
                    }]),
                    documents: Some(vec![IdentityDocument {
                        r#type: "passport".to_string(),
                        issuer: Some(serde_json::json!({"name": "Country A"})),
                        number: Some("AB123456".to_string()),
                        date_of_issuance: Some("2020-01-01".to_string()),
                        date_of_expiry: Some("2030-01-01".to_string()),
                        document_of: Some("Country A".to_string()),
                    }]),
                    electronic_record: None,
                }],
            },
            claims: serde_json::json!({
                "given_name": "Alice",
                "family_name": "Doe"
            }),
        };
        let json = serde_json::to_value(&vc).unwrap();
        let parsed = parse_verified_claims(&json).unwrap();
        assert_eq!(parsed.verification.evidence[0].r#type, "document");
    }

    #[test]
    fn verified_claims_request() {
        let req = build_verified_claims_request(vec![
            "given_name".to_string(),
            "family_name".to_string(),
        ]);
        assert!(req["userinfo"]["verified_claims"]["claims"].is_array());
    }
}
