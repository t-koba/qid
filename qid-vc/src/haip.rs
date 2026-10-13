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
    /// The only transaction hash algorithm this primitive implements.
    pub const HASH_ALGORITHM: &'static str = "sha-256";

    /// Compute the transaction binding hash. Every variable-length field
    /// is length-prefixed (and the credential list carries its count) so
    /// distinct field structures can never collide; unsupported algorithms
    /// fail instead of silently hashing as SHA-256.
    pub fn compute_hash(&self) -> QidResult<String> {
        use sha2::Digest;
        if self.hash_algorithm != Self::HASH_ALGORITHM {
            return Err(QidError::BadRequest {
                message: format!(
                    "unsupported HAIP transaction hash algorithm: {}",
                    self.hash_algorithm
                ),
            });
        }
        fn push_field(hasher: &mut Sha256, field: &[u8]) {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field);
        }
        let mut hasher = Sha256::new();
        push_field(&mut hasher, self.type_.as_bytes());
        hasher.update((self.credential_ids.len() as u64).to_be_bytes());
        for id in &self.credential_ids {
            push_field(&mut hasher, id.as_bytes());
        }
        push_field(&mut hasher, self.nonce.as_bytes());
        hasher.update(self.timestamp.to_be_bytes());
        push_field(&mut hasher, self.reader_pubkey_fingerprint.as_bytes());
        push_field(&mut hasher, Self::HASH_ALGORITHM.as_bytes());
        let digest = hasher.finalize();
        use base64::Engine;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
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
    let computed = data.compute_hash()?;
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

    fn transaction_case(credential_ids: &[&str]) -> HaipTransactionData {
        HaipTransactionData {
            type_: "haip.transaction".to_string(),
            credential_ids: credential_ids.iter().map(|id| id.to_string()).collect(),
            nonce: "n".to_string(),
            timestamp: 1,
            reader_pubkey_fingerprint: "fp".to_string(),
            hash_algorithm: "sha-256".to_string(),
        }
    }

    #[test]
    fn transaction_hash_is_deterministic() {
        let data = transaction_case(&["urn:uuid:1"]);
        assert_eq!(data.compute_hash().unwrap(), data.compute_hash().unwrap());
    }

    #[test]
    fn transaction_hash_distinguishes_credential_id_splits() {
        let first = transaction_case(&["ab", "c"]);
        let second = transaction_case(&["a", "bc"]);
        assert_ne!(
            first.compute_hash().unwrap(),
            second.compute_hash().unwrap()
        );
        // The ambiguous pair must not validate against each other's hash.
        let first_hash = first.compute_hash().unwrap();
        let err = validate_haip_transaction_data(&second, &first_hash, "fp").unwrap_err();
        assert!(err.to_string().contains("hash mismatch"));
    }

    #[test]
    fn transaction_hash_rejects_unsupported_algorithm() {
        let mut data = transaction_case(&["urn:uuid:1"]);
        data.hash_algorithm = "sha-512".to_string();
        let err = data.compute_hash().unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported HAIP transaction hash algorithm")
        );
        let err = validate_haip_transaction_data(&data, "whatever", "fp").unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported HAIP transaction hash algorithm")
        );
    }
}
