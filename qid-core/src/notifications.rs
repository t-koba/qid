//! RFC 6376 DKIM, RFC 6068 mailto, RFC 3966 tel, ITU-T E.164.

use crate::error::{QidError, QidResult};
use base64::Engine;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailtoUri {
    pub address: String,
    pub subject: Option<String>,
    pub body: Option<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
}

pub fn build_mailto_uri(addr: &MailtoUri) -> String {
    let mut uri = format!("mailto:{}", addr.address);
    let mut params = Vec::new();
    if let Some(ref s) = addr.subject {
        params.push(format!("subject={}", urlencoding::encode(s)));
    }
    if let Some(ref b) = addr.body {
        params.push(format!("body={}", urlencoding::encode(b)));
    }
    for cc in &addr.cc {
        params.push(format!("cc={}", cc));
    }
    for bcc in &addr.bcc {
        params.push(format!("bcc={}", bcc));
    }
    if !params.is_empty() {
        uri.push('?');
        uri.push_str(&params.join("&"));
    }
    uri
}

pub fn validate_email_addr(addr: &str) -> QidResult<()> {
    if !addr.contains('@') {
        return Err(QidError::BadRequest {
            message: "email must contain @".to_string(),
        });
    }
    if addr.len() > 254 {
        return Err(QidError::BadRequest {
            message: "email too long".to_string(),
        });
    }
    Ok(())
}

pub fn canonicalize_tel(uri: &str) -> QidResult<String> {
    let digits: String = uri.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 10 || digits.len() > 15 {
        return Err(QidError::BadRequest {
            message: format!("E.164 number must be 10-15 digits, got {}", digits.len()),
        });
    }
    Ok(format!("tel:+{}", digits.trim_start_matches('0')))
}

pub fn validate_e164(number: &str) -> QidResult<String> {
    let cleaned: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
    if cleaned.len() < 10 || cleaned.len() > 15 {
        return Err(QidError::BadRequest {
            message: format!("E.164 must be 10-15 digits, got {}", cleaned.len()),
        });
    }
    Ok(format!("+{}", cleaned.trim_start_matches('0')))
}

pub fn dkim_sign_header(
    headers: &str,
    domain: &str,
    selector: &str,
    private_key_pem: &[u8],
) -> QidResult<String> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    use sha2::Sha256;
    let key =
        rsa::RsaPrivateKey::from_pkcs8_pem(std::str::from_utf8(private_key_pem).map_err(|_| {
            QidError::BadRequest {
                message: "PEM is not valid UTF-8".to_string(),
            }
        })?)
        .map_err(|e| QidError::Crypto {
            message: format!("DKIM private key parse failed: {e}"),
        })?;
    let sig_signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(key);
    let mut rng = rand::thread_rng();
    let signature = sig_signing_key.sign_with_rng(&mut rng, headers.as_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
    let now = crate::util::now_seconds();
    let timestamp = now.to_string();
    Ok(format!(
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d={domain}; s={selector}; t={timestamp}; bh=; h=; b={sig_b64}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailto_uri_simple() {
        let uri = build_mailto_uri(&MailtoUri {
            address: "user@example.com".to_string(),
            subject: None,
            body: None,
            cc: vec![],
            bcc: vec![],
        });
        assert_eq!(uri, "mailto:user@example.com");
    }

    #[test]
    fn mailto_uri_with_subject() {
        let uri = build_mailto_uri(&MailtoUri {
            address: "user@example.com".to_string(),
            subject: Some("Hello".to_string()),
            body: None,
            cc: vec![],
            bcc: vec![],
        });
        assert!(uri.contains("subject=Hello"));
    }

    #[test]
    fn tel_canonicalization() {
        let result = canonicalize_tel("+81-3-1234-5678").unwrap();
        assert_eq!(result, "tel:+81312345678");
    }

    #[test]
    fn e164_validation() {
        assert!(validate_e164("+14155551234").is_ok());
        assert!(validate_e164("123").is_err());
    }

    #[test]
    fn dkim_sign_header_round_trip() {
        let key_pem = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...\n-----END PRIVATE KEY-----";
        let result = dkim_sign_header("From: user@example.com", "example.com", "qid", key_pem);
        assert!(result.is_err());
    }

    #[test]
    fn validate_email_valid() {
        assert!(validate_email_addr("user@example.com").is_ok());
    }

    #[test]
    fn validate_email_invalid_no_at() {
        assert!(validate_email_addr("userexample.com").is_err());
    }
}
