//! Key-derivation functions (HKDF, PBKDF2).
//!
//! Provides HKDF (RFC 5869) extract-and-expand using HMAC-SHA256.

use hkdf::Hkdf;
use sha2::Sha256;

const HKDF_SHA256_MAX_OUTPUT_LEN: usize = 255 * 32;

/// Derive a key using HKDF-SHA256 (RFC 5869).
///
/// Returns [`hkdf::InvalidLength`] when `okm_len` exceeds RFC 5869's 255-block limit.
pub fn hkdf_sha256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    okm_len: usize,
) -> Result<Vec<u8>, hkdf::InvalidLength> {
    if okm_len > HKDF_SHA256_MAX_OUTPUT_LEN {
        return Err(hkdf::InvalidLength);
    }
    let (_, hk) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut okm = vec![0u8; okm_len];
    hk.expand(info, &mut okm)?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_derives_expected_length_and_accepts_rfc_limit() {
        assert!(matches!(
            hkdf_sha256(b"salt", b"ikm", b"info", 32),
            Ok(okm) if okm.len() == 32
        ));
        assert!(matches!(
            hkdf_sha256(b"salt", b"ikm", b"info", HKDF_SHA256_MAX_OUTPUT_LEN),
            Ok(okm) if okm.len() == HKDF_SHA256_MAX_OUTPUT_LEN
        ));
    }

    #[test]
    fn hkdf_rejects_output_above_rfc_limit_before_allocating() {
        assert!(matches!(
            hkdf_sha256(b"salt", b"ikm", b"info", HKDF_SHA256_MAX_OUTPUT_LEN + 1),
            Err(hkdf::InvalidLength)
        ));
    }

    #[test]
    fn hkdf_deterministic() {
        let a = hkdf_sha256(b"s", b"i", b"info", 16);
        let b = hkdf_sha256(b"s", b"i", b"info", 16);
        assert!(matches!((a, b), (Ok(a), Ok(b)) if a == b));
    }
}
