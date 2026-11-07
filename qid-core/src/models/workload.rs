use serde::{Deserialize, Serialize};

use crate::error::{QidError, QidResult};

use super::validation::{require_lower_hex_sha256, require_non_empty};

/// A workload identity (SPIFFE-based).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadIdentity {
    pub id: String,
    pub realm_id: String,
    pub spiffe_id: String,
    pub description: Option<String>,
    pub trust_domain: String,
    pub authorities_json: serde_json::Value,
}

/// A short-lived mTLS certificate issued for a workload identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "WorkloadCertificateWire")]
pub struct WorkloadCertificate {
    pub id: String,
    pub realm_id: String,
    pub workload_id: String,
    pub spiffe_id: String,
    pub serial_number: String,
    pub x5t_s256: String,
    pub public_key_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csr_sha256: Option<String>,
    pub certificate_pem: String,
    pub issuer_key_ref: String,
    pub issued_at: u64,
    pub not_before: u64,
    pub not_after: u64,
    #[serde(default)]
    pub revoked_at: Option<u64>,
}

// Before public_key_sha256 was named correctly, csr_sha256 held the SPKI digest.
// Only the presence of the new public-key field distinguishes the two formats.
#[derive(Deserialize)]
struct WorkloadCertificateWire {
    id: String,
    realm_id: String,
    workload_id: String,
    spiffe_id: String,
    serial_number: String,
    x5t_s256: String,
    #[serde(default, deserialize_with = "deserialize_public_key_digest")]
    public_key_sha256: Option<String>,
    csr_sha256: Option<String>,
    certificate_pem: String,
    issuer_key_ref: String,
    issued_at: u64,
    not_before: u64,
    not_after: u64,
    revoked_at: Option<u64>,
}

fn deserialize_public_key_digest<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

impl TryFrom<WorkloadCertificateWire> for WorkloadCertificate {
    type Error = &'static str;

    fn try_from(wire: WorkloadCertificateWire) -> Result<Self, Self::Error> {
        let (public_key_sha256, csr_sha256) = match wire.public_key_sha256 {
            Some(digest) => (digest, wire.csr_sha256),
            None => (wire.csr_sha256.ok_or("missing public_key_sha256")?, None),
        };
        Ok(Self {
            id: wire.id,
            realm_id: wire.realm_id,
            workload_id: wire.workload_id,
            spiffe_id: wire.spiffe_id,
            serial_number: wire.serial_number,
            x5t_s256: wire.x5t_s256,
            public_key_sha256,
            csr_sha256,
            certificate_pem: wire.certificate_pem,
            issuer_key_ref: wire.issuer_key_ref,
            issued_at: wire.issued_at,
            not_before: wire.not_before,
            not_after: wire.not_after,
            revoked_at: wire.revoked_at,
        })
    }
}

impl WorkloadCertificate {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("workload certificate id", &self.id)?;
        require_non_empty("workload certificate realm_id", &self.realm_id)?;
        require_non_empty("workload certificate workload_id", &self.workload_id)?;
        require_non_empty("workload certificate spiffe_id", &self.spiffe_id)?;
        require_non_empty("workload certificate serial_number", &self.serial_number)?;
        require_non_empty("workload certificate issuer_key_ref", &self.issuer_key_ref)?;
        require_lower_hex_sha256("workload certificate x5t_s256", &self.x5t_s256)?;
        require_lower_hex_sha256(
            "workload certificate public_key_sha256",
            &self.public_key_sha256,
        )?;
        if let Some(digest) = &self.csr_sha256 {
            require_lower_hex_sha256("workload certificate csr_sha256", digest)?;
        }
        if !self.certificate_pem.contains("BEGIN CERTIFICATE")
            || !self.certificate_pem.contains("END CERTIFICATE")
        {
            return Err(QidError::BadRequest {
                message: "workload certificate certificate_pem must contain a certificate"
                    .to_string(),
            });
        }
        if self.issued_at == 0 || self.not_before == 0 || self.not_after <= self.not_before {
            return Err(QidError::BadRequest {
                message: "workload certificate validity window is invalid".to_string(),
            });
        }
        if self.not_after.saturating_sub(self.not_before) > 86_400 {
            return Err(QidError::BadRequest {
                message: "workload certificate lifetime must be at most 86400 seconds".to_string(),
            });
        }
        if self
            .revoked_at
            .is_some_and(|revoked_at| revoked_at < self.issued_at)
        {
            return Err(QidError::BadRequest {
                message: "workload certificate revoked_at must not be before issued_at".to_string(),
            });
        }
        Ok(())
    }
}
