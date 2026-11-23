use base64::Engine;
use qid_core::error::{QidError, QidResult};
use sha2::{Digest, Sha256};
use std::net::UdpSocket;

#[derive(Debug, Clone)]
pub struct SyslogConfig {
    pub server: String,
    pub port: u16,
    pub protocol: SyslogProtocol,
    pub facility: String,
    pub app_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyslogProtocol {
    Udp,
    Tcp,
}

pub struct SyslogTransport;

pub fn syslog_send(config: &SyslogConfig, message: &str) -> QidResult<()> {
    let addr = format!("{}:{}", config.server, config.port);
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| QidError::Internal {
        message: format!("syslog UDP socket bind failed: {e}"),
    })?;
    let formatted = format_syslog_message(config, message);
    socket
        .send_to(formatted.as_bytes(), &addr)
        .map_err(|e| QidError::Internal {
            message: format!("syslog UDP send failed: {e}"),
        })?;
    Ok(())
}

fn format_syslog_message(config: &SyslogConfig, message: &str) -> String {
    let pri = match config.facility.as_str() {
        "auth" => 4,
        "authpriv" => 10,
        "daemon" => 3,
        "local0" | "local1" | "local2" | "local3" | "local4" | "local5" | "local6" | "local7" => 16,
        _ => 1,
    };
    format!("<{pri}>1 {message}")
}

impl SyslogTransport {
    pub fn send(config: &SyslogConfig, message: &str) -> QidResult<()> {
        syslog_send(config, message)
    }
}

pub fn init_syslog_logging(config: SyslogConfig) -> QidResult<()> {
    tracing::info!(
        "syslog transport configured: {}:{} via {:?} (facility={}, app={})",
        config.server,
        config.port,
        config.protocol,
        config.facility,
        config.app_name,
    );
    Ok(())
}

pub fn signed_syslog_message(message: &str, private_key_pem: &[u8]) -> QidResult<String> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::sha2::Sha256 as RsaSha256;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    let pem = std::str::from_utf8(private_key_pem).map_err(|_| QidError::BadRequest {
        message: "PEM is not valid UTF-8".to_string(),
    })?;
    let key = rsa::PrivateKey::from_pkcs8_pem(pem).map_err(|e| QidError::Crypto {
        message: format!("RSA key parse failed: {e}"),
    })?;
    let sig_signing_key = rsa::pkcs1v15::SigningKey::<RsaSha256>::new(key);
    let mut rng = getrandom::SysRng;
    let signature = sig_signing_key
        .try_sign_with_rng(&mut rng, message.as_bytes())
        .map_err(|e| QidError::Crypto {
            message: format!("RSA signing failed: {e}"),
        })?;
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
    Ok(format!("{message} ::SIGNED::{sig_b64}"))
}

pub fn tsp_request(nonce: &[u8], hash_alg: &str) -> QidResult<String> {
    let hash = Sha256::digest(nonce);
    let b64 = base64::engine::general_purpose::STANDARD.encode(hash);
    Ok(format!(
        "timeStampToken: hash={b64}, alg={hash_alg}, nonce={}",
        hex::encode(nonce)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syslog_config_construct() {
        let config = SyslogConfig {
            server: "127.0.0.1".to_string(),
            port: 514,
            protocol: SyslogProtocol::Udp,
            facility: "auth".to_string(),
            app_name: "qid".to_string(),
        };
        assert!(init_syslog_logging(config).is_ok());
    }

    #[test]
    fn syslog_message_format_is_rfc5424_like() {
        let config = SyslogConfig {
            server: "127.0.0.1".to_string(),
            port: 514,
            protocol: SyslogProtocol::Udp,
            facility: "auth".to_string(),
            app_name: "qid".to_string(),
        };
        assert_eq!(
            format_syslog_message(&config, "test message"),
            "<4>1 test message"
        );
    }

    #[test]
    fn signed_syslog_message_verifies_with_rsa_pkcs1v15_sha256() {
        use rsa::pkcs8::EncodePrivateKey;
        use rsa::sha2::Sha256 as RsaSha256;
        use rsa::signature::Verifier;

        let private = rsa::PrivateKey::new(&mut getrandom::SysRng, 2048).unwrap();
        let pem = private.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
        let signed = signed_syslog_message("test message", pem.as_bytes()).unwrap();
        let (message, signature_b64) = signed.split_once(" ::SIGNED::").unwrap();
        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(signature_b64)
            .unwrap();
        let signature = rsa::pkcs1v15::Signature::try_from(signature_bytes.as_slice()).unwrap();
        let verifying_key = rsa::pkcs1v15::VerifyingKey::<RsaSha256>::new(private.to_public_key());
        verifying_key
            .verify(message.as_bytes(), &signature)
            .unwrap();
    }
}
