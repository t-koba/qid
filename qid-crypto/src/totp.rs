use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use qid_core::error::{QidError, QidResult};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha1 = Hmac<Sha1>;

const TOTP_DEFAULT_DIGITS: u32 = 6;

pub struct TotpVerifier {
    pub digits: u32,
    pub period: u64,
}

impl Default for TotpVerifier {
    fn default() -> Self {
        Self {
            digits: TOTP_DEFAULT_DIGITS,
            period: 30,
        }
    }
}

impl TotpVerifier {
    pub fn new(digits: u32, period: u64) -> Self {
        Self { digits, period }
    }

    pub fn generate_secret() -> String {
        let mut buf = [0u8; 20];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut buf);
        BASE32_NOPAD.encode(&buf)
    }

    pub fn generate_code(&self, secret: &str, timestamp: u64) -> QidResult<String> {
        let counter = timestamp / self.period;
        let code = compute_totp(secret, counter, self.digits)?;
        Ok(format!("{:0width$}", code, width = self.digits as usize))
    }

    pub fn current_code(&self, secret: &str) -> QidResult<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| QidError::Internal {
                message: format!("system time before unix epoch: {e}"),
            })?
            .as_secs();
        self.generate_code(secret, now)
    }

    pub fn verify(&self, secret: &str, code: &str) -> QidResult<bool> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| QidError::Internal {
                message: format!("system time before unix epoch: {e}"),
            })?
            .as_secs();
        // Check current and adjacent windows (±1 period)
        let timestamps = [
            now,
            now.saturating_sub(self.period),
            now.saturating_add(self.period),
        ];
        for ts in timestamps {
            let expected = self.generate_code(secret, ts)?;
            if qid_core::util::constant_time_eq(code.as_bytes(), expected.as_bytes()) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn compute_totp(secret: &str, counter: u64, digits: u32) -> QidResult<u64> {
    let key = BASE32_NOPAD
        .decode(secret.as_bytes())
        .map_err(|e| QidError::Crypto {
            message: format!("invalid base32 TOTP secret: {e}"),
        })?;
    let mut mac = HmacSha1::new_from_slice(&key).map_err(|e| QidError::Crypto {
        message: format!("failed to initialize TOTP HMAC: {e}"),
    })?;
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let code = ((result[offset] & 0x7f) as u64) << 24
        | (result[offset + 1] as u64) << 16
        | (result[offset + 2] as u64) << 8
        | result[offset + 3] as u64;
    Ok(code % 10u64.pow(digits))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_secret_generation() {
        let secret = TotpVerifier::generate_secret();
        assert_eq!(secret.len(), 32);
        BASE32_NOPAD.decode(secret.as_bytes()).unwrap();
    }

    #[test]
    fn test_totp_code_format() {
        let verifier = TotpVerifier::default();
        let secret = TotpVerifier::generate_secret();
        let code = verifier.current_code(&secret).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_totp_verify_self() {
        let verifier = TotpVerifier::default();
        let secret = TotpVerifier::generate_secret();
        let code = verifier.current_code(&secret).unwrap();
        assert!(verifier.verify(&secret, &code).unwrap());
    }

    #[test]
    fn test_totp_wrong_code_rejected() {
        let verifier = TotpVerifier::default();
        let secret = TotpVerifier::generate_secret();
        assert!(!verifier.verify(&secret, "000000").unwrap());
    }

    #[test]
    fn test_totp_deterministic() {
        let verifier = TotpVerifier::default();
        let secret = TotpVerifier::generate_secret();
        let first = verifier.generate_code(&secret, 1000000).unwrap();
        let second = verifier.generate_code(&secret, 1000000).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn test_totp_different_timestamps_different_codes() {
        let verifier = TotpVerifier::default();
        let secret = TotpVerifier::generate_secret();
        let code_a = verifier.generate_code(&secret, 1000000).unwrap();
        let code_b = verifier.generate_code(&secret, 1000030).unwrap();
        // Different time windows should produce different codes
        assert_ne!(code_a, code_b);
    }

    #[test]
    fn test_totp_rfc6238_sha1_vectors() {
        // RFC 6238 Appendix B test vectors (SHA-1)
        // Secret: 12345678901234567890 (20 bytes)
        // Base32: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let verifier = TotpVerifier::new(8, 30);
        assert_eq!(verifier.generate_code(secret, 59).unwrap(), "94287082");
        assert_eq!(
            verifier.generate_code(secret, 1111111109).unwrap(),
            "07081804"
        );
        assert_eq!(
            verifier.generate_code(secret, 1111111111).unwrap(),
            "14050471"
        );
        assert_eq!(
            verifier.generate_code(secret, 1234567890).unwrap(),
            "89005924"
        );
        assert_eq!(
            verifier.generate_code(secret, 2000000000).unwrap(),
            "69279037"
        );
    }

    #[test]
    fn test_totp_invalid_base32_rejected() {
        let verifier = TotpVerifier::default();
        assert!(
            verifier
                .generate_code("!!!invalid-base32!!!", 1000000)
                .is_err()
        );
    }
}
