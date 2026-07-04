//! Authenticated encryption with associated data (AEAD).
//!
//! Provides ChaCha20-Poly1305 (RFC 8439) encryption and decryption
//! via the `chacha20poly1305` crate.
//!
//! # Security: Nonce uniqueness
//!
//! This module generates a random 12-byte nonce for each encryption
//! operation using `OsRng`. **Never reuse a (key, nonce) pair.**
//! Reusing a nonce with the same key destroys all confidentiality
//! guarantees for that key.
//!
//! ## Key and message limits
//!
//! With 96-bit random nonces, the birthday bound gives a collision
//! probability of ≈ 2⁻³² after 2³² encryptions under the same key.
//! Practical deployments MUST rotate the key after 2³² messages
//! (≈ 4 billion). For normal qid usage the number of AEAD operations
//! per key is orders of magnitude below this bound.
//!
//! ## External nonce hygiene
//!
//! If you supply a nonce externally (rather than using the random
//! nonce generated here), you MUST ensure that no two encryptions with
//! the same key share a nonce. Consider using a counter-based nonce or
//! a separate key per context to guarantee uniqueness.

use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
use qid_core::error::{QidError, QidResult};
use rand::RngCore;

/// Encrypt `plaintext` with ChaCha20-Poly1305 using a 32-byte key and
/// a 12-byte nonce. Returns a `(nonce, ciphertext)` pair where the
/// nonce is randomly generated.
pub fn chacha20poly1305_encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
    _aad: &[u8],
) -> QidResult<([u8; 12], Vec<u8>)> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| QidError::Internal {
        message: "ChaCha20Poly1305 key init failed".to_string(),
    })?;
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| QidError::Internal {
            message: format!("ChaCha20Poly1305 encryption failed: {e}"),
        })?;
    Ok((nonce_bytes, ciphertext))
}

/// Decrypt `ciphertext` with ChaCha20-Poly1305 using a 32-byte key and
/// the 12-byte nonce that was used during encryption.
pub fn chacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    _aad: &[u8],
) -> QidResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| QidError::Internal {
        message: "ChaCha20Poly1305 key init failed".to_string(),
    })?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| QidError::Unauthorized {
            message: "ChaCha20Poly1305 decryption failed (wrong key or tampered data)".to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha20poly1305_roundtrip() {
        let key = [0x99u8; 32];
        let plaintext = b"hello world";
        let aad = b"associated data";
        let (nonce, ct) = chacha20poly1305_encrypt(&key, plaintext, aad).unwrap();
        let pt = chacha20poly1305_decrypt(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn chacha20poly1305_nonces_unique() {
        let key = [0x99u8; 32];
        let plaintext = b"hello world";
        let mut nonces = std::collections::HashSet::new();
        for _ in 0..1000 {
            let (nonce, _ct) = chacha20poly1305_encrypt(&key, plaintext, b"").unwrap();
            assert!(
                nonces.insert(nonce),
                "nonce collision detected: {:02x?}",
                nonce
            );
        }
    }

    #[test]
    fn chacha20poly1305_wrong_key_rejected() {
        let key = [0x99u8; 32];
        let wrong_key = [0x88u8; 32];
        let (nonce, ct) = chacha20poly1305_encrypt(&key, b"data", b"").unwrap();
        assert!(chacha20poly1305_decrypt(&wrong_key, &nonce, &ct, b"").is_err());
    }
}
