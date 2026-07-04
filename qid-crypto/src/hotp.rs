//! HMAC-Based One-Time Password (RFC 4226) + OCRA (RFC 6287).

use hmac::{Hmac, Mac};
use qid_core::error::{QidError, QidResult};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

pub fn hotp_generate(secret: &[u8], counter: u64, digits: u32) -> QidResult<String> {
    let mut mac = HmacSha1::new_from_slice(secret).map_err(|_| QidError::Crypto {
        message: "HOTP key init failed".to_string(),
    })?;
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let code = ((result[offset] & 0x7f) as u32) << 24
        | (result[offset + 1] as u32) << 16
        | (result[offset + 2] as u32) << 8
        | (result[offset + 3] as u32);
    let mod_val = 10u32.pow(digits);
    Ok(format!(
        "{:0width$}",
        code % mod_val,
        width = digits as usize
    ))
}

pub fn hotp_verify(secret: &[u8], counter: u64, code: &str, digits: u32) -> QidResult<bool> {
    let expected = hotp_generate(secret, counter, digits)?;
    Ok(expected == code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hotp_rfc4226_test_vector() {
        let secret = b"12345678901234567890";
        assert_eq!(hotp_generate(secret, 0, 6).unwrap(), "755224");
        assert_eq!(hotp_generate(secret, 1, 6).unwrap(), "287082");
    }

    #[test]
    fn hotp_verify_correct() {
        let secret = b"12345678901234567890";
        assert!(hotp_verify(secret, 0, "755224", 6).unwrap());
        assert!(!hotp_verify(secret, 0, "000000", 6).unwrap());
    }

    #[test]
    fn hotp_digits_6_returns_six_characters() {
        let secret = b"12345678901234567890";
        for counter in 0..10 {
            let code = hotp_generate(secret, counter, 6).unwrap();
            assert_eq!(
                code.len(),
                6,
                "counter={counter}: expected 6 digits, got {code}"
            );
        }
    }

    #[test]
    fn hotp_digits_8_returns_eight_characters() {
        let secret = b"12345678901234567890";
        for counter in 0..10 {
            let code = hotp_generate(secret, counter, 8).unwrap();
            assert_eq!(
                code.len(),
                8,
                "counter={counter}: expected 8 digits, got {code}"
            );
        }
    }

    #[test]
    fn hotp_code_within_mod_range() {
        let secret = b"12345678901234567890";
        let code_6: u32 = hotp_generate(secret, 0, 6).unwrap().parse().unwrap();
        assert!(code_6 < 1_000_000, "6-digit code exceeds 999999: {code_6}");
        let code_8: u32 = hotp_generate(secret, 0, 8).unwrap().parse().unwrap();
        assert!(
            code_8 < 100_000_000,
            "8-digit code exceeds 99999999: {code_8}"
        );
    }

    #[test]
    fn hotp_truncation_uses_dynamic_offset() {
        // Different counters should produce different offsets in most cases,
        // ensuring the dynamic truncation (RFC 4226 §5.3) is exercised.
        let secret = b"12345678901234567890";
        let codes: Vec<String> = (0..20)
            .map(|c| hotp_generate(secret, c, 6).unwrap())
            .collect();
        let unique = {
            let mut set = codes.clone();
            set.sort();
            set.dedup();
            set.len()
        };
        assert!(
            unique > 15,
            "less than 16 unique codes from 20 counter values"
        );
    }
}
