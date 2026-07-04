//! TPM 2.0 (Trusted Platform Module) abstraction.
//! Provides a software-backed implementation for development and
//! a trait for HSM/TPM integration in production.

use qid_core::error::QidResult;
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TpmPublicKey {
    pub algorithm: String,
    pub key_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TpmSignature {
    pub algorithm: String,
    pub signature: Vec<u8>,
}

pub trait TpmBackend: Send + Sync {
    fn generate_key(&self, algorithm: &str) -> QidResult<TpmPublicKey>;
    fn sign(&self, key: &TpmPublicKey, data: &[u8]) -> QidResult<TpmSignature>;
    fn verify(&self, key: &TpmPublicKey, data: &[u8], signature: &TpmSignature) -> QidResult<bool>;
    fn get_random(&self, length: usize) -> QidResult<Vec<u8>>;
}

pub struct SoftwareTpm;

impl SoftwareTpm {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SoftwareTpm {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmBackend for SoftwareTpm {
    fn generate_key(&self, algorithm: &str) -> QidResult<TpmPublicKey> {
        match algorithm {
            "RS256" => {
                use rsa::pkcs8::EncodePrivateKey;
                let mut rng = rand::thread_rng();
                let key = rsa::RsaPrivateKey::new(&mut rng, 2048).map_err(|e| {
                    qid_core::error::QidError::Crypto {
                        message: format!("RSA key generation failed: {e}"),
                    }
                })?;
                let der = key
                    .to_pkcs8_der()
                    .map_err(|e| qid_core::error::QidError::Crypto {
                        message: format!("RSA private key DER encoding failed: {e}"),
                    })?;
                Ok(TpmPublicKey {
                    algorithm: algorithm.to_string(),
                    key_bytes: der.as_bytes().to_vec(),
                })
            }
            "ES256" => {
                use p256::pkcs8::EncodePrivateKey;
                let key = p256::SecretKey::random(&mut rand::thread_rng());
                let der = key
                    .to_pkcs8_der()
                    .map_err(|e| qid_core::error::QidError::Crypto {
                        message: format!("EC private key DER encoding failed: {e}"),
                    })?;
                Ok(TpmPublicKey {
                    algorithm: algorithm.to_string(),
                    key_bytes: der.as_bytes().to_vec(),
                })
            }
            _ => Err(qid_core::error::QidError::BadRequest {
                message: format!("unsupported TPM algorithm: {algorithm}"),
            }),
        }
    }

    fn sign(&self, key: &TpmPublicKey, data: &[u8]) -> QidResult<TpmSignature> {
        match key.algorithm.as_str() {
            "ES256" => {
                use p256::ecdsa::SigningKey;
                use p256::ecdsa::signature::Signer;
                use p256::pkcs8::DecodePrivateKey;
                let secret_key = p256::SecretKey::from_pkcs8_der(&key.key_bytes).map_err(|e| {
                    qid_core::error::QidError::Crypto {
                        message: format!("EC key parse failed: {e}"),
                    }
                })?;
                let signing_key = SigningKey::from(secret_key);
                let signature: p256::ecdsa::Signature = signing_key.sign(data);
                Ok(TpmSignature {
                    algorithm: "ES256".to_string(),
                    signature: signature.to_bytes().to_vec(),
                })
            }
            _ => Err(qid_core::error::QidError::BadRequest {
                message: format!("unsupported signing algorithm: {}", key.algorithm),
            }),
        }
    }

    fn verify(&self, key: &TpmPublicKey, data: &[u8], signature: &TpmSignature) -> QidResult<bool> {
        match key.algorithm.as_str() {
            "ES256" => {
                use p256::ecdsa::signature::Verifier;
                use p256::ecdsa::{Signature as P256Signature, SigningKey, VerifyingKey};
                use p256::pkcs8::DecodePrivateKey;
                let secret_key = p256::SecretKey::from_pkcs8_der(&key.key_bytes).map_err(|e| {
                    qid_core::error::QidError::Crypto {
                        message: format!("EC key parse failed: {e}"),
                    }
                })?;
                let signing_key = SigningKey::from(secret_key);
                let verifying_key = VerifyingKey::from(&signing_key);
                let sig = P256Signature::from_slice(&signature.signature).map_err(|e| {
                    qid_core::error::QidError::Crypto {
                        message: format!("signature parse failed: {e}"),
                    }
                })?;
                Ok(verifying_key.verify(data, &sig).is_ok())
            }
            _ => Err(qid_core::error::QidError::BadRequest {
                message: format!("unsupported verification algorithm: {}", key.algorithm),
            }),
        }
    }

    fn get_random(&self, length: usize) -> QidResult<Vec<u8>> {
        let mut buf = vec![0u8; length];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_tpm_generates_rsa_key() {
        let tpm = SoftwareTpm::new();
        let key = tpm.generate_key("RS256").unwrap();
        assert_eq!(key.algorithm, "RS256");
        assert!(!key.key_bytes.is_empty());
    }

    #[test]
    fn software_tpm_generates_ec_key() {
        let tpm = SoftwareTpm::new();
        let key = tpm.generate_key("ES256").unwrap();
        assert_eq!(key.algorithm, "ES256");
    }

    #[test]
    fn software_tpm_signs_and_verifies() {
        let tpm = SoftwareTpm::new();
        let key = tpm.generate_key("ES256").unwrap();
        let data = b"test data";
        let signature = tpm.sign(&key, data).unwrap();
        let valid = tpm.verify(&key, data, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn software_tpm_rejects_invalid_signature() {
        let tpm = SoftwareTpm::new();
        let key_a = tpm.generate_key("ES256").unwrap();
        let key_b = tpm.generate_key("ES256").unwrap();
        let data = b"test data";
        let signature = tpm.sign(&key_a, data).unwrap();
        let valid = tpm.verify(&key_b, data, &signature).unwrap();
        assert!(!valid); // wrong key should fail
    }

    #[test]
    fn software_tpm_generates_random() {
        let tpm = SoftwareTpm::new();
        let rand1 = tpm.get_random(32).unwrap();
        let rand2 = tpm.get_random(32).unwrap();
        assert_eq!(rand1.len(), 32);
        assert_ne!(rand1, rand2); // statistically nearly impossible to match
    }
}
