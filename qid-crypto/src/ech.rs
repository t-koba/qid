//! Encrypted Client Hello (ECH, RFC 8446 §8).
//! Provides ECH configuration types and helper functions.
//! Actual ECH integration requires rustls with ECH support.

use qid_core::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EchConfig {
    pub version: u16,
    pub public_key: Vec<u8>,
    pub cipher_suite: u16,
    pub maximum_name_length: u8,
    pub public_name: String,
    pub extensions: Vec<u8>,
}

pub fn parse_ech_config_list(data: &[u8]) -> QidResult<Vec<EchConfig>> {
    if data.len() < 2 {
        return Err(QidError::BadRequest {
            message: "ECH config list too short".to_string(),
        });
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + len {
        return Err(QidError::BadRequest {
            message: "ECH config list truncated".to_string(),
        });
    }
    let mut configs = Vec::new();
    let mut offset = 2;
    while offset + 4 <= data.len() {
        let config_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + config_len > data.len() {
            break;
        }
        let config_data = &data[offset..offset + config_len];
        let version = u16::from_be_bytes([config_data[0], config_data[1]]);
        let public_key_start = 6; // version(2) + length(1) + key_type(1) + cipher(2)
        let public_key_len = config_data[2] as usize;
        let public_key = if public_key_start + public_key_len <= config_data.len() {
            config_data[public_key_start..public_key_start + public_key_len].to_vec()
        } else {
            Vec::new()
        };
        let cipher_suite = if 4 + public_key_len + 2 <= config_data.len() {
            u16::from_be_bytes([
                config_data[4 + public_key_len],
                config_data[4 + public_key_len + 1],
            ])
        } else {
            0
        };
        configs.push(EchConfig {
            version,
            public_key,
            cipher_suite,
            maximum_name_length: 0,
            public_name: String::new(),
            extensions: Vec::new(),
        });
        offset += config_len;
    }
    Ok(configs)
}

pub fn ech_inner_hello(_outer_sni: &str, inner_sni: &str) -> QidResult<Vec<u8>> {
    let mut inner = Vec::new();
    // Minimal inner ClientHello structure for ECH
    inner.push(0x01); // client_hello type
    inner.extend_from_slice(&[0x00, 0x00]); // length placeholder
    inner.push(0x03); // legacy_version (TLS 1.2)
    inner.extend_from_slice(&[0x00; 32]); // random
    inner.push(0x00); // legacy_session_id length
    inner.push(0x00); // cipher_suites length placeholder
    inner.push(0x00); // legacy_compression_methods
    inner.push(0x00); // extensions length placeholder
    // SNI extension for inner name
    inner.extend_from_slice(&[0x00, 0x00]); // SNI extension type
    let sni_bytes = inner_sni.as_bytes();
    let sni_list_len = sni_bytes.len() + 5;
    let ext_len = sni_list_len + 4;
    inner.push((ext_len >> 8) as u8);
    inner.push((ext_len & 0xff) as u8);
    inner.push((sni_list_len >> 8) as u8);
    inner.push((sni_list_len & 0xff) as u8);
    inner.push(0x00); // server_name type (host_name)
    inner.push((sni_bytes.len() >> 8) as u8);
    inner.push((sni_bytes.len() & 0xff) as u8);
    inner.extend_from_slice(sni_bytes);
    Ok(inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ech_inner_hello_constructs() {
        let inner = ech_inner_hello("outer.example.com", "inner.example.com").unwrap();
        assert!(!inner.is_empty());
        assert!(inner.len() > 20);
    }

    #[test]
    fn parse_ech_config_empty() {
        let configs = parse_ech_config_list(&[0x00, 0x00]).unwrap();
        assert!(configs.is_empty());
    }
}
