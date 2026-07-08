//! Encrypted local signing key storage.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use qid_core::error::{QidError, QidResult};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const KEYSTORE_VERSION: u32 = 1;
const ARGON2_MEMORY_KIB: u32 = 19_456;
const ARGON2_TIME_COST: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEK_LEN: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// On-disk encrypted signing key envelope.
///
/// The `ciphertext`, `nonce`, and KDF salt are base64-encoded. The plaintext is
/// expected to be a UTF-8 PEM private key. `kid` and `alg` are authenticated by
/// the surrounding file handling rather than embedded as AES-GCM AAD, so callers
/// must keep the parsed envelope and unsealed key together when loading signing
/// material.
pub struct EncryptedKeyFile {
    pub version: u32,
    pub kdf: KeyKdf,
    pub nonce: String,
    pub ciphertext: String,
    pub kid: String,
    pub alg: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "name", rename_all = "snake_case")]
/// Password-based key derivation parameters stored with an encrypted key.
pub enum KeyKdf {
    /// Argon2id parameters used to derive the AES-256-GCM key-encryption key.
    Argon2id {
        memory_kib: u32,
        time_cost: u32,
        parallelism: u32,
        salt: String,
    },
}

/// Boundary for sealing and unsealing local private keys.
///
/// Implementations must return decrypted private keys in zeroizing buffers and
/// fail closed on malformed metadata, unsupported versions, wrong passphrases,
/// or authentication-tag failures.
pub trait KeyProtector {
    /// Encrypt a UTF-8 PEM private key with metadata used by JWKS publication.
    fn seal(&self, plaintext_pem: &str, kid: &str, alg: &str) -> QidResult<EncryptedKeyFile>;

    /// Decrypt an encrypted key file and return the plaintext PEM.
    fn unseal(&self, encrypted: &EncryptedKeyFile) -> QidResult<Zeroizing<String>>;
}

/// Argon2id + AES-256-GCM protector backed by a local passphrase.
///
/// The passphrase is retained in zeroizing memory for the lifetime of the
/// protector. Construction rejects empty passphrases so callers cannot
/// accidentally create decryptable-at-rest keys with no secret.
pub struct PassphraseProtector {
    passphrase: Zeroizing<Vec<u8>>,
}

impl PassphraseProtector {
    /// Build a passphrase protector from raw passphrase bytes.
    pub fn new(passphrase: impl Into<Vec<u8>>) -> QidResult<Self> {
        let passphrase = Zeroizing::new(passphrase.into());
        if passphrase.is_empty() {
            return Err(QidError::Config {
                message: "key passphrase must not be empty".to_string(),
            });
        }
        Ok(Self { passphrase })
    }
}

impl KeyProtector for PassphraseProtector {
    fn seal(&self, plaintext_pem: &str, kid: &str, alg: &str) -> QidResult<EncryptedKeyFile> {
        if plaintext_pem.trim().is_empty() {
            return Err(QidError::Crypto {
                message: "private key PEM must not be empty".to_string(),
            });
        }
        if kid.trim().is_empty() || alg.trim().is_empty() {
            return Err(QidError::Crypto {
                message: "encrypted key metadata must include kid and alg".to_string(),
            });
        }

        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let key = derive_key(
            &self.passphrase,
            &salt,
            ARGON2_MEMORY_KIB,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
        )?;
        let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|e| QidError::Crypto {
            message: format!("failed to initialize AES-256-GCM: {e}"),
        })?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext_pem.as_bytes())
            .map_err(|_| QidError::Crypto {
                message: "failed to encrypt private key".to_string(),
            })?;

        Ok(EncryptedKeyFile {
            version: KEYSTORE_VERSION,
            kdf: KeyKdf::Argon2id {
                memory_kib: ARGON2_MEMORY_KIB,
                time_cost: ARGON2_TIME_COST,
                parallelism: ARGON2_PARALLELISM,
                salt: base64::engine::general_purpose::STANDARD.encode(salt),
            },
            nonce: base64::engine::general_purpose::STANDARD.encode(nonce),
            ciphertext: base64::engine::general_purpose::STANDARD.encode(ciphertext),
            kid: kid.to_string(),
            alg: alg.to_string(),
            created_at: now_epoch(),
        })
    }

    fn unseal(&self, encrypted: &EncryptedKeyFile) -> QidResult<Zeroizing<String>> {
        if encrypted.version != KEYSTORE_VERSION {
            return Err(QidError::Crypto {
                message: format!("unsupported encrypted key version {}", encrypted.version),
            });
        }
        let (salt, memory_kib, time_cost, parallelism) = match &encrypted.kdf {
            KeyKdf::Argon2id {
                memory_kib,
                time_cost,
                parallelism,
                salt,
            } => (
                decode_b64(salt, "encrypted key salt")?,
                *memory_kib,
                *time_cost,
                *parallelism,
            ),
        };
        let nonce = decode_b64(&encrypted.nonce, "encrypted key nonce")?;
        if nonce.len() != NONCE_LEN {
            return Err(QidError::Crypto {
                message: "encrypted key nonce has invalid length".to_string(),
            });
        }
        let ciphertext = decode_b64(&encrypted.ciphertext, "encrypted key ciphertext")?;
        let key = derive_key(&self.passphrase, &salt, memory_kib, time_cost, parallelism)?;
        let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|e| QidError::Crypto {
            message: format!("failed to initialize AES-256-GCM: {e}"),
        })?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_slice())
            .map_err(|_| QidError::Crypto {
                message: "failed to decrypt private key".to_string(),
            })?;
        String::from_utf8(plaintext)
            .map(Zeroizing::new)
            .map_err(|e| QidError::Crypto {
                message: format!("decrypted private key is not UTF-8 PEM: {e}"),
            })
    }
}

/// Serialize an encrypted key file as pretty-printed JSON for operator review.
pub fn serialize_encrypted_key(file: &EncryptedKeyFile) -> QidResult<String> {
    serde_json::to_string_pretty(file).map_err(|e| QidError::Crypto {
        message: format!("failed to serialize encrypted key file: {e}"),
    })
}

/// Parse an encrypted key file from JSON without decrypting its contents.
pub fn parse_encrypted_key(input: &str) -> QidResult<EncryptedKeyFile> {
    serde_json::from_str(input).map_err(|e| QidError::Crypto {
        message: format!("failed to parse encrypted key file: {e}"),
    })
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
) -> QidResult<Zeroizing<[u8; KEK_LEN]>> {
    let params = Params::new(memory_kib, time_cost, parallelism, Some(KEK_LEN)).map_err(|e| {
        QidError::Crypto {
            message: format!("invalid Argon2id key parameters: {e}"),
        }
    })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEK_LEN]);
    argon2
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|e| QidError::Crypto {
            message: format!("failed to derive key encryption key: {e}"),
        })?;
    Ok(key)
}

fn decode_b64(value: &str, label: &str) -> QidResult<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| QidError::Crypto {
            message: format!("failed to decode {label}: {e}"),
        })
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n";

    #[test]
    fn seal_unseal_round_trip() {
        let protector = PassphraseProtector::new(b"correct horse".to_vec()).unwrap();
        let encrypted = protector.seal(TEST_PEM, "kid-1", "ES256").unwrap();

        let decrypted = protector.unseal(&encrypted).unwrap();

        assert_eq!(decrypted.as_str(), TEST_PEM);
        assert_eq!(encrypted.kid, "kid-1");
        assert_eq!(encrypted.alg, "ES256");
        assert!(!encrypted.ciphertext.contains("PRIVATE KEY"));
    }

    #[test]
    fn wrong_passphrase_fails() {
        let protector = PassphraseProtector::new(b"correct horse".to_vec()).unwrap();
        let encrypted = protector.seal(TEST_PEM, "kid-1", "ES256").unwrap();
        let wrong = PassphraseProtector::new(b"wrong horse".to_vec()).unwrap();

        let err = wrong.unseal(&encrypted).unwrap_err();

        assert!(err.message().contains("decrypt"));
    }

    #[test]
    fn serialized_format_round_trips() {
        let protector = PassphraseProtector::new(b"correct horse".to_vec()).unwrap();
        let encrypted = protector.seal(TEST_PEM, "kid-1", "ES256").unwrap();
        let serialized = serialize_encrypted_key(&encrypted).unwrap();

        let parsed = parse_encrypted_key(&serialized).unwrap();

        assert_eq!(parsed.version, KEYSTORE_VERSION);
        assert_eq!(protector.unseal(&parsed).unwrap().as_str(), TEST_PEM);
    }
}
