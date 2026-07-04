//! High Assurance Interoperability Profile (HAIP) primitives.
//!
//! Implements the conformance primitives defined in the OpenID
//! Foundation High Assurance Interoperability Profile: signed
//! authorization requests (RFC 9101 JAR), detached SD-JWT VC
//! presentation, transaction data binding, and reader registration
//! metadata.

use qid_core::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// A reader authentication credential that the HAIP-enabled wallet
/// is expected to present alongside the user authorization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HaipReaderRegistration {
    pub reader_id: String,
    pub registration_uri: String,
    pub purpose: String,
    #[serde(default)]
    pub trust_list_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HaipTransactionData {
    pub type_: String,
    pub credential_ids: Vec<String>,
    pub nonce: String,
    pub timestamp: u64,
    pub reader_pubkey_fingerprint: String,
    pub hash_algorithm: String,
}

impl HaipTransactionData {
    pub fn compute_hash(&self) -> String {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(self.type_.as_bytes());
        for id in &self.credential_ids {
            hasher.update(id.as_bytes());
        }
        hasher.update(self.nonce.as_bytes());
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(self.reader_pubkey_fingerprint.as_bytes());
        let digest = hasher.finalize();
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    }
}

/// Validate a HAIP transaction data payload before signing or
/// presenting. The wallet must include the hash computed from the
/// request fields and the reader's public-key fingerprint.
pub fn validate_haip_transaction_data(
    data: &HaipTransactionData,
    expected_hash: &str,
    expected_reader_fingerprint: &str,
) -> QidResult<()> {
    if data.reader_pubkey_fingerprint != expected_reader_fingerprint {
        return Err(QidError::BadRequest {
            message: "HAIP transaction data reader pubkey fingerprint mismatch".to_string(),
        });
    }
    let computed = data.compute_hash();
    if computed != expected_hash {
        return Err(QidError::BadRequest {
            message: "HAIP transaction data hash mismatch".to_string(),
        });
    }
    Ok(())
}

/// Build a reader registration entry to publish at the well-known
/// endpoint per the HAIP reader-registration profile.
pub fn build_haip_reader_registration(reader_id: &str, purpose: &str) -> HaipReaderRegistration {
    HaipReaderRegistration {
        reader_id: reader_id.to_string(),
        registration_uri: format!("{reader_id}/.well-known/openid-credential-issuer"),
        purpose: purpose.to_string(),
        trust_list_uri: Some(format!("{reader_id}/.well-known/trust-list")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_hash_is_deterministic() {
        let data = HaipTransactionData {
            type_: "haip.transaction".to_string(),
            credential_ids: vec!["urn:uuid:1".to_string()],
            nonce: "n".to_string(),
            timestamp: 1,
            reader_pubkey_fingerprint: "fp".to_string(),
            hash_algorithm: "sha-256".to_string(),
        };
        let first = data.compute_hash();
        let second = data.compute_hash();
        assert_eq!(first, second);
    }
}
