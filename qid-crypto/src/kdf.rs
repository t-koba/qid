//! Key-derivation functions (HKDF, PBKDF2).
//!
//! Provides HKDF (RFC 5869) extract-and-expand using HMAC-SHA256.

use hkdf::Hkdf;
use sha2::Sha256;

/// Derive a key using HKDF-SHA256 (RFC 5869).
#[allow(clippy::expect_used)]
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], okm_len: usize) -> Vec<u8> {
    let (_, hk) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut okm = vec![0u8; okm_len];
    // HKDF-SHA256 only rejects output lengths above RFC 5869 bounds; qid callers request small keys.
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA256 expand cannot fail for reasonable okm_len");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_derives_expected_length() {
        let okm = hkdf_sha256(b"salt", b"ikm", b"info", 32);
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn hkdf_deterministic() {
        let a = hkdf_sha256(b"s", b"i", b"info", 16);
        let b = hkdf_sha256(b"s", b"i", b"info", 16);
        assert_eq!(a, b);
    }
}
