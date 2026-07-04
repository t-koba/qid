//! JSON Web Encryption (JWE) — RFC 7516.
//!
//! Supports RSA-OAEP-256 key wrapping + AES-256-GCM content encryption.

use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use qid_core::error::{QidError, QidResult};
use rand::RngCore;
use rsa::{
    Oaep, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::str;

/// JWE protected header (RFC 7516 Section 4.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JweHeader {
    pub alg: Option<String>,
    pub enc: Option<String>,
    pub kid: Option<String>,
    pub typ: Option<String>,
    pub cty: Option<String>,
}

/// Parsed JWE payload in Compact Serialization form.
#[derive(Debug, Clone)]
pub struct JwePayload {
    pub header: JweHeader,
    pub encrypted_key: Vec<u8>,
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub auth_tag: Vec<u8>,
}

/// Parse a JWE Compact Serialization string into its components.
///
/// Format: `BASE64URL(header).BASE64URL(encrypted_key).BASE64URL(iv).BASE64URL(ciphertext).BASE64URL(auth_tag)`
pub fn parse_jwe(jwe: &str) -> QidResult<JwePayload> {
    let parts: Vec<&str> = jwe.split('.').collect();
    if parts.len() != 5 {
        return Err(QidError::BadRequest {
            message: "JWE must have exactly 5 dot-separated parts".to_string(),
        });
    }

    let header_json = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| QidError::BadRequest {
            message: format!("invalid JWE header encoding: {e}"),
        })?;
    let header: JweHeader =
        serde_json::from_slice(&header_json).map_err(|e| QidError::BadRequest {
            message: format!("invalid JWE header JSON: {e}"),
        })?;

    let encrypted_key = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| QidError::BadRequest {
            message: format!("invalid JWE encrypted key encoding: {e}"),
        })?;
    let iv = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| QidError::BadRequest {
            message: format!("invalid JWE IV encoding: {e}"),
        })?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(parts[3])
        .map_err(|e| QidError::BadRequest {
            message: format!("invalid JWE ciphertext encoding: {e}"),
        })?;
    let auth_tag = URL_SAFE_NO_PAD
        .decode(parts[4])
        .map_err(|e| QidError::BadRequest {
            message: format!("invalid JWE auth tag encoding: {e}"),
        })?;

    Ok(JwePayload {
        header,
        encrypted_key,
        iv,
        ciphertext,
        auth_tag,
    })
}

/// Decrypt a JWE Compact string using the given RSA private key PEM.
///
/// Supports `alg: "RSA-OAEP-256"` with `enc: "A256GCM"`.
pub fn decrypt_jwe(jwe: &str, private_key_pem: &[u8]) -> QidResult<Vec<u8>> {
    let payload = parse_jwe(jwe)?;

    let alg = payload.header.alg.as_deref().unwrap_or("");
    let enc = payload.header.enc.as_deref().unwrap_or("");

    if alg != "RSA-OAEP-256" {
        return Err(QidError::Crypto {
            message: format!("unsupported JWE algorithm: {alg}"),
        });
    }
    if enc != "A256GCM" {
        return Err(QidError::Crypto {
            message: format!("unsupported JWE encryption: {enc}"),
        });
    }

    let pem_str = str::from_utf8(private_key_pem).map_err(|_| QidError::BadRequest {
        message: "private key PEM is not valid UTF-8".to_string(),
    })?;
    let private_key = RsaPrivateKey::from_pkcs8_pem(pem_str).map_err(|e| QidError::Crypto {
        message: format!("failed to parse RSA private key: {e}"),
    })?;

    let cek = private_key
        .decrypt(Oaep::new::<Sha256>(), &payload.encrypted_key)
        .map_err(|e| QidError::Unauthorized {
            message: format!("RSA-OAEP decryption failed: {e}"),
        })?;

    let key = Key::<Aes256Gcm>::from_slice(&cek);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&payload.iv);

    let mut ct_with_tag = payload.ciphertext;
    ct_with_tag.extend_from_slice(&payload.auth_tag);

    let plaintext =
        cipher
            .decrypt(nonce, ct_with_tag.as_ref())
            .map_err(|_| QidError::Unauthorized {
                message: "AES-GCM decryption failed (wrong key or tampered data)".to_string(),
            })?;

    Ok(plaintext)
}

/// Encrypt `plaintext` into a JWE Compact string using the given RSA public key PEM.
///
/// `alg` must be `"RSA-OAEP-256"` and `enc` must be `"A256GCM"`.
pub fn encrypt_jwe(
    plaintext: &[u8],
    public_key_pem: &[u8],
    alg: &str,
    enc: &str,
) -> QidResult<String> {
    if alg != "RSA-OAEP-256" {
        return Err(QidError::Crypto {
            message: format!("unsupported JWE algorithm: {alg}"),
        });
    }
    if enc != "A256GCM" {
        return Err(QidError::Crypto {
            message: format!("unsupported JWE encryption: {enc}"),
        });
    }

    let pem_str = str::from_utf8(public_key_pem).map_err(|_| QidError::BadRequest {
        message: "public key PEM is not valid UTF-8".to_string(),
    })?;
    let public_key = RsaPublicKey::from_public_key_pem(pem_str).map_err(|e| QidError::Crypto {
        message: format!("failed to parse RSA public key: {e}"),
    })?;

    let mut cek = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut cek);
    let mut iv = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut iv);

    let key = Key::<Aes256Gcm>::from_slice(&cek);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&iv);

    let ct_with_tag = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| QidError::Crypto {
            message: format!("AES-GCM encryption failed: {e}"),
        })?;

    let tag_start = ct_with_tag.len().saturating_sub(16);
    let ciphertext = ct_with_tag[..tag_start].to_vec();
    let auth_tag = ct_with_tag[tag_start..].to_vec();

    let mut rng = rand::thread_rng();
    let encrypted_key = public_key
        .encrypt(&mut rng, Oaep::new::<Sha256>(), &cek)
        .map_err(|e| QidError::Crypto {
            message: format!("RSA-OAEP encryption failed: {e}"),
        })?;

    let header = JweHeader {
        alg: Some(alg.to_string()),
        enc: Some(enc.to_string()),
        kid: None,
        typ: None,
        cty: None,
    };
    let header_json = serde_json::to_string(&header).map_err(|e| QidError::Internal {
        message: format!("failed to serialize JWE header: {e}"),
    })?;

    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let ek_b64 = URL_SAFE_NO_PAD.encode(&encrypted_key);
    let iv_b64 = URL_SAFE_NO_PAD.encode(iv);
    let ct_b64 = URL_SAFE_NO_PAD.encode(&ciphertext);
    let tag_b64 = URL_SAFE_NO_PAD.encode(&auth_tag);

    Ok(format!("{header_b64}.{ek_b64}.{iv_b64}.{ct_b64}.{tag_b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_rsa_keypair() -> (Vec<u8>, Vec<u8>) {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate RSA key");
        let public_key = private_key.to_public_key();
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
        let private_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("failed to encode private key")
            .to_string()
            .into_bytes();
        let public_pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .expect("failed to encode public key")
            .to_string()
            .into_bytes();
        (private_pem, public_pem)
    }

    #[test]
    fn jwe_roundtrip() {
        let (private_pem, public_pem) = generate_rsa_keypair();
        let plaintext = b"hello jwe world";
        let jwe = encrypt_jwe(plaintext, &public_pem, "RSA-OAEP-256", "A256GCM").unwrap();
        let decrypted = decrypt_jwe(&jwe, &private_pem).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn jwe_wrong_key_rejected() {
        let (_private_pem, public_pem) = generate_rsa_keypair();
        let (wrong_private_pem, _) = generate_rsa_keypair();
        let plaintext = b"secret data";
        let jwe = encrypt_jwe(plaintext, &public_pem, "RSA-OAEP-256", "A256GCM").unwrap();
        let result = decrypt_jwe(&jwe, &wrong_private_pem);
        assert!(result.is_err());
    }
}
