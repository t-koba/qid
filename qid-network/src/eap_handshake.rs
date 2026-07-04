//! EAP full handshake: EAP-TLS 1.3 (RFC 9190), TEAP (RFC 7170), EAP-TTLS (RFC 5281), EAP-AKA (RFC 4187/5448/9048).

use qid_core::error::{QidError, QidResult};

use crate::EapMethod;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapTlsStart {
    pub flags: u8,
    pub tls_data: Vec<u8>,
}

impl EapTlsStart {
    pub fn parse(data: &[u8]) -> QidResult<Self> {
        if data.is_empty() {
            return Err(QidError::BadRequest {
                message: "EAP-TLS data empty".to_string(),
            });
        }
        Ok(Self {
            flags: data[0],
            tls_data: data[1..].to_vec(),
        })
    }

    pub fn is_length_included(&self) -> bool {
        self.flags & 0x80 != 0
    }
    pub fn is_more_fragments(&self) -> bool {
        self.flags & 0x40 != 0
    }
    pub fn is_start(&self) -> bool {
        self.flags & 0x20 != 0
    }

    pub fn build(version: u8, tls_data: &[u8]) -> Vec<u8> {
        let mut buf = vec![0x20 | (version & 0x07)];
        buf.extend_from_slice(tls_data);
        buf
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapTtlsStart {
    pub flags: u8,
    pub ttls_data: Vec<u8>,
}

impl EapTtlsStart {
    pub fn parse(data: &[u8]) -> QidResult<Self> {
        if data.is_empty() {
            return Err(QidError::BadRequest {
                message: "EAP-TTLS data empty".to_string(),
            });
        }
        Ok(Self {
            flags: data[0],
            ttls_data: data[1..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapAkaAttribute {
    pub attr_type: u16,
    pub value: Vec<u8>,
}

pub fn parse_eap_aka_attributes(data: &[u8]) -> QidResult<Vec<EapAkaAttribute>> {
    let mut attrs = Vec::new();
    let mut offset = 0;
    while offset + 4 <= data.len() {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_len = data[offset + 2] as usize + 2;
        let end = (offset + attr_len).min(data.len());
        attrs.push(EapAkaAttribute {
            attr_type,
            value: data[offset + 4..end].to_vec(),
        });
        offset += attr_len;
    }
    Ok(attrs)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapAkaChallenge {
    pub rand: Vec<u8>,
    pub autn: Vec<u8>,
    pub mac: Option<Vec<u8>>,
}

pub fn parse_eap_aka_challenge(data: &[u8]) -> QidResult<EapAkaChallenge> {
    let attrs = parse_eap_aka_attributes(data)?;
    let mut challenge = EapAkaChallenge {
        rand: vec![],
        autn: vec![],
        mac: None,
    };
    for attr in &attrs {
        match attr.attr_type {
            1 => challenge.rand = attr.value.clone(),
            2 => challenge.autn = attr.value.clone(),
            11 => challenge.mac = Some(attr.value.clone()),
            _ => {}
        }
    }
    if challenge.rand.is_empty() || challenge.autn.is_empty() {
        return Err(QidError::BadRequest {
            message: "EAP-AKA missing RAND or AUTN".to_string(),
        });
    }
    Ok(challenge)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapTeapStart {
    pub flags: u8,
    pub teap_data: Vec<u8>,
}

impl EapTeapStart {
    pub fn parse(data: &[u8]) -> QidResult<Self> {
        if data.is_empty() {
            return Err(QidError::BadRequest {
                message: "EAP-TEAP data empty".to_string(),
            });
        }
        Ok(Self {
            flags: data[0],
            teap_data: data[1..].to_vec(),
        })
    }
}

pub enum EapFullHandshake {
    Tls13(EapTlsStart),
    Ttls(EapTtlsStart),
    Aka(EapAkaChallenge),
    AkaPrime(EapAkaChallenge),
    Teap(EapTeapStart),
}

pub fn parse_eap_handshake(method: EapMethod, data: &[u8]) -> QidResult<EapFullHandshake> {
    match method {
        EapMethod::Tls => Ok(EapFullHandshake::Tls13(EapTlsStart::parse(data)?)),
        EapMethod::Ttls => Ok(EapFullHandshake::Ttls(EapTtlsStart::parse(data)?)),
        EapMethod::Aka => Ok(EapFullHandshake::Aka(parse_eap_aka_challenge(data)?)),
        EapMethod::AkaPrime => Ok(EapFullHandshake::AkaPrime(parse_eap_aka_challenge(data)?)),
        EapMethod::Teap => Ok(EapFullHandshake::Teap(EapTeapStart::parse(data)?)),
        _ => Err(QidError::BadRequest {
            message: format!("unsupported EAP method for handshake: {method:?}"),
        }),
    }
}

/// RADIUS/1.1 ALPN configuration (RFC 9765).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Radius11Config {
    pub alpn_protocols: Vec<String>,
}

/// TACACS+/TLS 1.3 configuration (RFC 9887).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TacacsPlusTlsConfig {
    pub server_address: String,
    pub server_port: u16,
    pub certificate_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eap_tls_start_parse() {
        let data = &[0xe0, 0x01, 0x02, 0x03]; // flags=0xe0 (L+M+S), data=0x01,0x02,0x03
        let start = EapTlsStart::parse(data).unwrap();
        assert!(start.is_start());
        assert!(start.is_more_fragments());
        assert!(start.is_length_included());
        assert_eq!(start.tls_data, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn eap_tls_build_round_trip() {
        let original = vec![0x01, 0x02, 0x03];
        let built = EapTlsStart::build(0, &original);
        let parsed = EapTlsStart::parse(&built).unwrap();
        assert_eq!(parsed.tls_data, original);
    }

    #[test]
    fn eap_aka_parse_challenge() {
        let data = &[
            0x00, 0x01, 0x12, 0x12, // AT_RAND, length=18, value=16 bytes
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x00, 0x02, 0x12, 0x12, // AT_AUTN, length=18
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f, 0x20,
        ];
        let challenge = parse_eap_aka_challenge(data).unwrap();
        assert_eq!(challenge.rand.len(), 16);
        assert_eq!(challenge.autn.len(), 16);
    }

    #[test]
    fn eap_aka_missing_rand() {
        let data = &[
            0x00, 0x02, 0x12, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]; // AT_AUTN only
        assert!(parse_eap_aka_challenge(data).is_err());
    }

    #[test]
    fn eap_teap_start_parse() {
        let data = &[0x20, 0x01, 0x02];
        let start = EapTeapStart::parse(data).unwrap();
        assert_eq!(start.flags, 0x20);
        assert_eq!(start.teap_data, vec![0x01, 0x02]);
    }

    #[test]
    fn eap_handshake_dispatch() {
        let data = &[0x20, 0x01];
        let hs = parse_eap_handshake(EapMethod::Tls, data).unwrap();
        assert!(matches!(hs, EapFullHandshake::Tls13(_)));

        let hs = parse_eap_handshake(EapMethod::Teap, data).unwrap();
        assert!(matches!(hs, EapFullHandshake::Teap(_)));

        assert!(parse_eap_handshake(EapMethod::Identity, data).is_err());
    }

    #[test]
    fn radius_11_config() {
        let config = Radius11Config {
            alpn_protocols: vec!["radius/1.1".to_string()],
        };
        assert_eq!(config.alpn_protocols[0], "radius/1.1");
    }

    #[test]
    fn tacacs_plus_tls_config() {
        let config = TacacsPlusTlsConfig {
            server_address: "192.0.2.1".to_string(),
            server_port: 4949,
            certificate_der: vec![0x00],
            private_key_der: vec![0x00],
        };
        assert_eq!(config.server_port, 4949);
    }
}
