//! Encrypted Client Hello (ECH, RFC 9849).
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
    let end = 2 + len;
    if data.len() != end {
        return Err(QidError::BadRequest {
            message: "ECH config list length mismatch".to_string(),
        });
    }
    let mut configs = Vec::new();
    let mut offset = 2;
    while offset + 2 <= end {
        let config_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + config_len > end {
            return Err(QidError::BadRequest {
                message: "ECH config entry truncated".to_string(),
            });
        }
        let config_data = &data[offset..offset + config_len];
        if config_data.len() < 6 {
            return Err(QidError::BadRequest {
                message: "ECH config entry too short".to_string(),
            });
        }
        let version = u16::from_be_bytes([config_data[0], config_data[1]]);
        let public_key_len = config_data[2] as usize;
        // version(2) + length(1) + key_type(1) + cipher(2): the key and the
        // cipher suite must both fit; inconsistent lengths fail closed.
        if 6 + public_key_len > config_data.len() {
            return Err(QidError::BadRequest {
                message: "ECH config entry has inconsistent inner lengths".to_string(),
            });
        }
        let public_key_start = 6;
        let public_key = config_data[public_key_start..public_key_start + public_key_len].to_vec();
        let cipher_suite = u16::from_be_bytes([
            config_data[4 + public_key_len],
            config_data[4 + public_key_len + 1],
        ]);
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
    if offset != end {
        return Err(QidError::BadRequest {
            message: "ECH config list has trailing bytes".to_string(),
        });
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

    #[test]
    fn parse_ech_config_rejects_short_and_truncated_entries() {
        // Minimal valid entry: version, zero-length key, key type, cipher suite.
        let valid =
            parse_ech_config_list(&[0x00, 0x08, 0x00, 0x06, 0x13, 0x01, 0x00, 0x00, 0x00, 0x00])
                .unwrap();
        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0].version, 0x1301);
        assert!(valid[0].public_key.is_empty());
        // Entries shorter than version plus key length plus cipher fail closed.
        for truncated in [
            vec![0x00, 0x04, 0x00, 0x01, 0xAA, 0xBB],
            vec![0x00, 0x04, 0x00, 0x02, 0xAA, 0xBB],
            vec![0x00, 0x04, 0x00, 0x00, 0xAA, 0xBB],
            vec![0x00, 0x05, 0x00, 0x03, 0x13, 0x01],
        ] {
            assert!(
                parse_ech_config_list(&truncated).is_err(),
                "{truncated:?} must fail"
            );
        }
        // Declared length running past the entry fails closed.
        assert!(parse_ech_config_list(&[0x00, 0x08, 0x00, 0x07, 0x13, 0x01, 0x00]).is_err());
    }

    #[test]
    fn parse_ech_config_rejects_inconsistent_inner_lengths() {
        // 255-byte public key claimed inside a 7-byte entry.
        assert!(
            parse_ech_config_list(&[
                0x00, 0x09, 0x00, 0x07, 0x13, 0x01, 0xFF, 0xAA, 0x00, 0x00, 0x00
            ])
            .is_err()
        );
        // One-byte key present but cipher suite cut off.
        assert!(
            parse_ech_config_list(&[0x00, 0x08, 0x00, 0x06, 0x13, 0x01, 0x01, 0xAA, 0xBB, 0xCC])
                .is_err()
        );
    }

    #[test]
    fn parse_ech_config_rejects_trailing_bytes() {
        // Valid 7-byte entry plus one trailing byte inside the declared list.
        assert!(
            parse_ech_config_list(&[
                0x00, 0x0A, 0x00, 0x07, 0x13, 0x01, 0x01, 0x00, 0x00, 0x01, 0x02, 0xAA
            ])
            .is_err()
        );
        // Extra bytes past the declared list length fail closed.
        assert!(
            parse_ech_config_list(&[
                0x00, 0x09, 0x00, 0x07, 0x13, 0x01, 0x01, 0x00, 0x00, 0x01, 0x02, 0xAA, 0xBB
            ])
            .is_err()
        );
    }

    #[test]
    fn parse_ech_config_accepts_consecutive_entries() {
        let two = [
            vec![0x00, 0x06, 0x13, 0x01, 0x00, 0x00, 0x00, 0x00],
            vec![0x00, 0x06, 0x13, 0x02, 0x00, 0x00, 0x00, 0x01],
        ]
        .concat();
        let mut list = vec![0x00, two.len() as u8];
        list.extend_from_slice(&two);
        let parsed = parse_ech_config_list(&list).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].version, 0x1301);
        assert_eq!(parsed[1].version, 0x1302);
        assert_eq!(parsed[1].cipher_suite, 0x0001);
    }
}
