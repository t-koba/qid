//! qid-network: Network-AAA profile (RADIUS / EAP / TACACS+).
#![forbid(unsafe_code)]
//!
//! Implements the request/response packet format and message
//! authentication for the three protocols called out in INTEROP §3's
//! network-aaa profile:
//!
//!   * RADIUS (RFC 2865) — UDP transport, shared-secret MAC.
//!   * EAP (RFC 3748) — generic frame used inside RADIUS (RFC 3579).
//!   * TACACS+ (RFC 8907) — TCP transport, per-session MD5 hashing.
//!
//! This crate is intentionally implementation-light: it provides the
//! wire format, MAC computation, and request encoding helpers needed by
//! the network-aaa adapter. The UDP/TCP transport itself is owned by
//! the calling adapter so the connector can be plumbed into the
//! existing `qid-worker` and `qid-proxy` infrastructure.

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use qid_core::error::{QidError, QidResult};
use sha2::Sha256;

#[cfg(feature = "quic")]
pub mod quic;

pub mod capport;
pub mod diameter;
pub mod eap_handshake;
pub mod radius_tls;
pub mod server;

type HmacSha256 = Hmac<Sha256>;

/// RADIUS (RFC 2865) packet codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadiusCode {
    AccessRequest,
    AccessAccept,
    AccessReject,
    AccessChallenge,
    AccountingRequest,
    AccountingResponse,
    CoARequest,
    CoAACK,
    CoANAK,
    DisconnectRequest,
    DisconnectACK,
    DisconnectNAK,
    Other(u8),
}

impl RadiusCode {
    pub fn as_byte(self) -> u8 {
        match self {
            Self::AccessRequest => 1,
            Self::AccessAccept => 2,
            Self::AccessReject => 3,
            Self::AccessChallenge => 11,
            Self::AccountingRequest => 4,
            Self::AccountingResponse => 5,
            Self::CoARequest => 43,
            Self::CoAACK => 44,
            Self::CoANAK => 45,
            Self::DisconnectRequest => 46,
            Self::DisconnectACK => 47,
            Self::DisconnectNAK => 48,
            Self::Other(code) => code,
        }
    }

    pub fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::AccessRequest,
            2 => Self::AccessAccept,
            3 => Self::AccessReject,
            4 => Self::AccountingRequest,
            5 => Self::AccountingResponse,
            11 => Self::AccessChallenge,
            43 => Self::CoARequest,
            44 => Self::CoAACK,
            45 => Self::CoANAK,
            46 => Self::DisconnectRequest,
            47 => Self::DisconnectACK,
            48 => Self::DisconnectNAK,
            other => Self::Other(other),
        }
    }
}

/// Decoded RADIUS packet.
#[derive(Debug, Clone)]
pub struct RadiusPacket<'a> {
    pub code: RadiusCode,
    pub identifier: u8,
    pub authenticator: [u8; 16],
    pub attributes: Vec<RadiusAttribute<'a>>,
}

/// RADIUS attribute (TLV).
#[derive(Debug, Clone)]
pub struct RadiusAttribute<'a> {
    pub kind: u8,
    pub value: &'a [u8],
}

/// Parse a RADIUS packet (without the response authenticator, which
/// callers compute separately).
pub fn parse_radius_packet(bytes: &[u8]) -> QidResult<RadiusPacket<'_>> {
    if bytes.len() < 20 {
        return Err(QidError::BadRequest {
            message: "RADIUS packet is shorter than 20 bytes".to_string(),
        });
    }
    let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if bytes.len() < length {
        return Err(QidError::BadRequest {
            message: format!("RADIUS packet is shorter than declared length {length}"),
        });
    }
    let mut authenticator = [0u8; 16];
    authenticator.copy_from_slice(&bytes[4..20]);
    let mut attributes = Vec::new();
    let mut cursor = 20;
    while cursor < length {
        if cursor + 2 > length {
            return Err(QidError::BadRequest {
                message: "RADIUS attribute header extends past packet length".to_string(),
            });
        }
        let kind = bytes[cursor];
        let attr_len = bytes[cursor + 1] as usize;
        if attr_len < 2 || cursor + attr_len > length {
            return Err(QidError::BadRequest {
                message: "RADIUS attribute length exceeds packet length".to_string(),
            });
        }
        let value = &bytes[cursor + 2..cursor + attr_len];
        attributes.push(RadiusAttribute { kind, value });
        cursor += attr_len;
    }
    Ok(RadiusPacket {
        code: RadiusCode::from_byte(bytes[0]),
        identifier: bytes[1],
        authenticator,
        attributes,
    })
}

/// Encode a RADIUS packet (header + authenticator + attributes).
pub fn encode_radius_packet(packet: &RadiusPacket<'_>) -> Vec<u8> {
    let body_len: usize = packet
        .attributes
        .iter()
        .map(|attr| attr.value.len() + 2)
        .sum();
    let total_len = 20 + body_len;
    let mut buf = Vec::with_capacity(total_len);
    buf.push(packet.code.as_byte());
    buf.push(packet.identifier);
    buf.extend_from_slice(&(total_len as u16).to_be_bytes());
    buf.extend_from_slice(&packet.authenticator);
    for attr in &packet.attributes {
        buf.push(attr.kind);
        buf.push((attr.value.len() + 2) as u8);
        buf.extend_from_slice(attr.value);
    }
    buf
}

/// Compute the RADIUS response authenticator using the first 16 bytes of
/// HMAC-SHA256(secret, request_authenticator || body). SHA-256 replaces
/// the original RFC 2865 MD5 construction for improved security while
/// staying within the 16-byte authenticator field.
pub fn radius_response_authenticator(
    secret: &[u8],
    request_authenticator: &[u8; 16],
    body: &[u8],
) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 accepts arbitrary keys");
    mac.update(request_authenticator);
    mac.update(body);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result[..16]);
    out
}

/// Verify the RADIUS request authenticator using HMAC-SHA256 truncated to
/// 16 bytes (HMAC-SHA256(secret, body)[..16]).
pub fn verify_radius_request_authenticator(
    secret: &[u8],
    packet: &RadiusPacket<'_>,
    body: &[u8],
) -> bool {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 accepts arbitrary keys");
    mac.update(body);
    let result = mac.finalize().into_bytes();
    let mut expected = [0u8; 16];
    expected.copy_from_slice(&result[..16]);
    qid_core::util::constant_time_eq(expected, packet.authenticator)
}

/// RADIUS attribute numbers used by qid-network.
pub mod attrs {
    pub const USER_NAME: u8 = 1;
    pub const USER_PASSWORD: u8 = 2;
    pub const CHAP_PASSWORD: u8 = 3;
    pub const NAS_IP_ADDRESS: u8 = 4;
    pub const NAS_PORT: u8 = 5;
    pub const SERVICE_TYPE: u8 = 6;
    pub const REPLY_MESSAGE: u8 = 18;
    pub const STATE: u8 = 24;
    pub const VENDOR_SPECIFIC: u8 = 26;
    pub const SESSION_TIMEOUT: u8 = 27;
    pub const CALLED_STATION_ID: u8 = 30;
    pub const CALLING_STATION_ID: u8 = 31;
    pub const EAP_MESSAGE: u8 = 79;
    pub const MESSAGE_AUTHENTICATOR: u8 = 80;
}

/// EAP (RFC 3748) frame decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapFrame {
    pub code: EapCode,
    pub identifier: u8,
    pub length: u16,
    pub method: Option<EapMethod>,
    pub method_data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapCode {
    Request,
    Response,
    Success,
    Failure,
    Other(u8),
}

impl EapCode {
    pub fn as_byte(self) -> u8 {
        match self {
            Self::Request => 1,
            Self::Response => 2,
            Self::Success => 3,
            Self::Failure => 4,
            Self::Other(c) => c,
        }
    }
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::Request,
            2 => Self::Response,
            3 => Self::Success,
            4 => Self::Failure,
            other => Self::Other(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapMethod {
    Identity,
    Notification,
    Nak,
    Md5Challenge,
    Tls,
    Ttls,
    Aka,
    AkaPrime,
    Teap,
    Other(u8),
}

impl EapMethod {
    pub fn as_byte(self) -> u8 {
        match self {
            Self::Identity => 1,
            Self::Notification => 2,
            Self::Nak => 3,
            Self::Md5Challenge => 4,
            Self::Tls => 13,
            Self::Ttls => 21,
            Self::Aka => 23,
            Self::AkaPrime => 50,
            Self::Teap => 55,
            Self::Other(c) => c,
        }
    }
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::Identity,
            2 => Self::Notification,
            3 => Self::Nak,
            4 => Self::Md5Challenge,
            13 => Self::Tls,
            21 => Self::Ttls,
            23 => Self::Aka,
            50 => Self::AkaPrime,
            55 => Self::Teap,
            other => Self::Other(other),
        }
    }
}

pub fn parse_eap_frame(bytes: &[u8]) -> QidResult<EapFrame> {
    if bytes.len() < 4 {
        return Err(QidError::BadRequest {
            message: "EAP frame is shorter than 4 bytes".to_string(),
        });
    }
    let length = u16::from_be_bytes([bytes[2], bytes[3]]);
    if length < 4 || bytes.len() < length as usize {
        return Err(QidError::BadRequest {
            message: "EAP frame length mismatch".to_string(),
        });
    }
    let (method, method_data) = match EapCode::from_byte(bytes[0]) {
        EapCode::Request | EapCode::Response => {
            if length < 5 {
                return Err(QidError::BadRequest {
                    message: "EAP Request/Response frame is missing Type field".to_string(),
                });
            }
            let method = EapMethod::from_byte(bytes[4]);
            let data = bytes[5..length as usize].to_vec();
            (Some(method), data)
        }
        _ => (None, Vec::new()),
    };
    Ok(EapFrame {
        code: EapCode::from_byte(bytes[0]),
        identifier: bytes[1],
        length,
        method,
        method_data,
    })
}

/// TACACS+ (RFC 8907) packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TacacsHeader {
    pub version: u8,
    pub tacacs_type: TacacsType,
    pub sequence_number: u8,
    pub flags: u8,
    pub session_id: u32,
    pub length: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TacacsType {
    Authentication,
    Authorization,
    Accounting,
    Other(u8),
}

impl TacacsType {
    pub fn as_byte(self) -> u8 {
        match self {
            Self::Authentication => 1,
            Self::Authorization => 2,
            Self::Accounting => 3,
            Self::Other(c) => c,
        }
    }
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::Authentication,
            2 => Self::Authorization,
            3 => Self::Accounting,
            other => Self::Other(other),
        }
    }
}

const TACACS_HEADER_LEN: usize = 12;
const TACACS_VERSION: u8 = 0xc1;

pub fn parse_tacacs_header(bytes: &[u8]) -> QidResult<TacacsHeader> {
    if bytes.len() < TACACS_HEADER_LEN {
        return Err(QidError::BadRequest {
            message: "TACACS+ header is shorter than 12 bytes".to_string(),
        });
    }
    if bytes[0] != TACACS_VERSION {
        return Err(QidError::BadRequest {
            message: format!("unsupported TACACS+ version byte 0x{:02x}", bytes[0]),
        });
    }
    let tacacs_type = TacacsType::from_byte(bytes[1]);
    let sequence_number = bytes[2];
    let flags = bytes[3];
    let session_id = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let length = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if bytes.len() < TACACS_HEADER_LEN + length as usize {
        return Err(QidError::BadRequest {
            message: "TACACS+ body is shorter than declared length".to_string(),
        });
    }
    Ok(TacacsHeader {
        version: bytes[0],
        tacacs_type,
        sequence_number,
        flags,
        session_id,
        length,
    })
}

pub fn encode_tacacs_header(header: &TacacsHeader) -> Vec<u8> {
    let mut buf = Vec::with_capacity(TACACS_HEADER_LEN);
    buf.push(TACACS_VERSION);
    buf.push(header.tacacs_type.as_byte());
    buf.push(header.sequence_number);
    buf.push(header.flags);
    buf.extend_from_slice(&header.session_id.to_be_bytes());
    buf.extend_from_slice(&header.length.to_be_bytes());
    buf
}

/// TACACS+ Authentication start packet (RFC 8907 §4.5.1).
#[derive(Debug, Clone)]
pub struct TacacsAuthenticationStart {
    pub action: u8,
    pub privilege_level: u8,
    pub authentication_type: u8,
    pub service: String,
    pub port: String,
    pub remote_address: String,
    pub user: String,
}

pub fn encode_tacacs_authentication_start(
    header: &TacacsHeader,
    start: &TacacsAuthenticationStart,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(start.action);
    body.push(start.privilege_level);
    body.push(start.authentication_type);
    push_tacacs_string(&mut body, &start.service);
    push_tacacs_string(&mut body, &start.port);
    push_tacacs_string(&mut body, &start.remote_address);
    push_tacacs_string(&mut body, &start.user);
    let mut out = encode_tacacs_header(header);
    out.extend_from_slice(&body);
    out
}

fn push_tacacs_string(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    buf.push(bytes.len() as u8);
    buf.extend_from_slice(bytes);
}

/// TACACS+ Accounting request packet (RFC 8907 §4.6.1).
#[derive(Debug, Clone)]
pub struct TacacsAccountingRequest {
    pub flags: u8,
    pub privilege_level: u8,
    pub authentication_type: u8,
    pub service: String,
    pub port: String,
    pub remote_address: String,
    pub user: String,
    pub attributes: Vec<(u8, String)>,
}

pub fn encode_tacacs_accounting_request(
    header: &TacacsHeader,
    request: &TacacsAccountingRequest,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(request.flags);
    body.push(request.privilege_level);
    body.push(request.authentication_type);
    push_tacacs_string(&mut body, &request.service);
    push_tacacs_string(&mut body, &request.port);
    push_tacacs_string(&mut body, &request.remote_address);
    push_tacacs_string(&mut body, &request.user);
    for (key, value) in &request.attributes {
        body.push(*key);
        push_tacacs_string(&mut body, value);
    }
    let mut out = encode_tacacs_header(header);
    out.extend_from_slice(&body);
    out
}

/// TACACS+ Authorization request packet (RFC 8907 §4.5.3).
#[derive(Debug, Clone)]
pub struct TacacsAuthorizationRequest {
    pub authentication_action: u8,
    pub privilege_level: u8,
    pub authentication_type: u8,
    pub service: String,
    pub port: String,
    pub remote_address: String,
    pub user: String,
    pub arguments: Vec<(u8, String)>,
}

pub fn encode_tacacs_authorization_request(
    header: &TacacsHeader,
    request: &TacacsAuthorizationRequest,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(request.authentication_action);
    body.push(request.privilege_level);
    body.push(request.authentication_type);
    push_tacacs_string(&mut body, &request.service);
    push_tacacs_string(&mut body, &request.port);
    push_tacacs_string(&mut body, &request.remote_address);
    push_tacacs_string(&mut body, &request.user);
    for (key, value) in &request.arguments {
        body.push(*key);
        push_tacacs_string(&mut body, value);
    }
    let mut out = encode_tacacs_header(header);
    out.extend_from_slice(&body);
    out
}

/// TACACS+ session_id obfuscation per RFC 8907 §4.4: the body is XORed
/// against a pseudo-random pad derived from the shared secret, the
/// session id, the version, and the sequence number.
pub fn tacacs_obfuscate_body(
    body: &[u8],
    key: &[u8],
    session_id: u32,
    version: u8,
    sequence_number: u8,
) -> QidResult<Vec<u8>> {
    if body.len() > 65535 {
        return Err(QidError::Crypto {
            message: format!("TACACS+ body length {} exceeds maximum 65535", body.len()),
        });
    }
    let mut pad_source = Vec::with_capacity(19 + key.len());
    pad_source.extend_from_slice(&session_id.to_be_bytes());
    pad_source.push(version);
    pad_source.push(sequence_number);
    pad_source.extend_from_slice(key);
    let mut hasher = Md5::new();
    hasher.update(&pad_source);
    let mut pad = hasher.finalize().to_vec();
    while pad.len() < body.len() {
        let mut next = Md5::new();
        next.update(&pad);
        let digest = next.finalize();
        pad.extend_from_slice(&digest);
    }
    pad.truncate(body.len());
    let mut out = Vec::with_capacity(body.len());
    for (a, b) in body.iter().zip(pad.iter()) {
        out.push(a ^ b);
    }
    Ok(out)
}

/// Reverse of [`tacacs_obfuscate_body`].
pub fn tacacs_deobfuscate_body(
    body: &[u8],
    key: &[u8],
    session_id: u32,
    version: u8,
    sequence_number: u8,
) -> QidResult<Vec<u8>> {
    tacacs_obfuscate_body(body, key, session_id, version, sequence_number)
}

/// Compute the RADIUS Message-Authenticator (RFC 3579 §3.2, RADIUS/1.1)
/// using HMAC-SHA256 keyed by the shared secret.
pub fn radius_message_authenticator(secret: &[u8], packet: &[u8]) -> QidResult<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|e| QidError::Internal {
        message: format!("HMAC-SHA256 init failed: {e}"),
    })?;
    mac.update(packet);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Ok(out)
}

/// Verify the RADIUS Message-Authenticator by replacing the
/// authenticator in `packet` with zeros, recomputing the HMAC-SHA256, and
/// comparing it with the supplied value.
pub fn verify_radius_message_authenticator(
    secret: &[u8],
    packet_with_authenticator: &[u8],
    authenticator_offset: usize,
    expected: &[u8; 32],
) -> QidResult<bool> {
    if packet_with_authenticator.len() < authenticator_offset + 32 {
        return Err(QidError::BadRequest {
            message: "RADIUS Message-Authenticator is outside the packet".to_string(),
        });
    }
    let mut packet = packet_with_authenticator.to_vec();
    for byte in &mut packet[authenticator_offset..authenticator_offset + 32] {
        *byte = 0;
    }
    let computed = radius_message_authenticator(secret, &packet)?;
    Ok(qid_core::util::constant_time_eq(computed, expected))
}

/// Compute the TACACS+ per-packet checksum per RFC 8907 §4.3.
///
/// The checksum is the MD5 hash of:
///   session_id (4 octets) || version (1 octet) || seq_no (1 octet)
///   || shared_secret || padded_body
/// where padded_body is the body padded with NUL bytes to a multiple of 16.
pub fn tacacs_packet_checksum(
    body: &[u8],
    key: &[u8],
    session_id: u32,
    version: u8,
    sequence_number: u8,
) -> [u8; 16] {
    let pad_len = (16 - (body.len() % 16)) % 16;
    let mut input = Vec::with_capacity(6 + key.len() + body.len() + pad_len);
    input.extend_from_slice(&session_id.to_be_bytes());
    input.push(version);
    input.push(sequence_number);
    input.extend_from_slice(key);
    input.extend_from_slice(body);
    input.resize(input.len() + pad_len, 0);
    let digest = Md5::digest(&input);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

/// Network Access Identifier (NAI) per RFC 7542.
///
/// An NAI has the form `user@realm` or simply `user` when no realm
/// is present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nai<'a> {
    pub user: &'a str,
    pub realm: Option<&'a str>,
}

/// Parse a Network Access Identifier (RFC 7542 §2).
pub fn parse_nai(input: &str) -> Nai<'_> {
    let input = input.trim();
    if let Some(at) = input.rfind('@') {
        let user = &input[..at];
        let realm = if at + 1 < input.len() {
            Some(&input[at + 1..])
        } else {
            None
        };
        Nai { user, realm }
    } else {
        Nai {
            user: input,
            realm: None,
        }
    }
}

/// RADIUS typed attribute constants from RFC 2865 and RFC 8044.
///
/// These complement the basic constants in `server::attrs`.
pub mod radius_attrs {
    // RFC 2865 (base attributes)
    pub const USER_NAME: u8 = 1;
    pub const USER_PASSWORD: u8 = 2;
    pub const CHAP_PASSWORD: u8 = 3;
    pub const NAS_IP_ADDRESS: u8 = 4;
    pub const NAS_PORT: u8 = 5;
    pub const SERVICE_TYPE: u8 = 6;
    pub const FRAMED_PROTOCOL: u8 = 7;
    pub const NAS_PORT_TYPE: u8 = 61;
    pub const TUNNEL_TYPE: u8 = 64;
    pub const TUNNEL_MEDIUM_TYPE: u8 = 65;
    pub const EAP_MESSAGE: u8 = 79;
    pub const MESSAGE_AUTHENTICATOR: u8 = 80;

    // RFC 8044 (extended attributes for network-AAA)
    pub const OPERATOR_NAME: u8 = 126;
    pub const LOCATION_DATA: u8 = 128;
    pub const LOCATION_CAPABLE: u8 = 131;
    pub const NAS_ACCESS_GROUP: u8 = 135;
    pub const OPERATOR_ID: u8 = 137;
    pub const OPERATOR_REALM: u8 = 138;

    // RFC 2866 (accounting)
    pub const ACCT_STATUS_TYPE: u8 = 40;
    pub const ACCT_INPUT_OCTETS: u8 = 42;
    pub const ACCT_OUTPUT_OCTETS: u8 = 43;
    pub const ACCT_SESSION_ID: u8 = 44;
    pub const ACCT_INPUT_PACKETS: u8 = 47;
    pub const ACCT_OUTPUT_PACKETS: u8 = 48;
    pub const NAS_PORT_ID: u8 = 87;

    /// Look up a human-readable name for a RADIUS attribute type.
    pub fn attr_name(kind: u8) -> &'static str {
        match kind {
            1 => "User-Name",
            2 => "User-Password",
            3 => "CHAP-Password",
            4 => "NAS-IP-Address",
            5 => "NAS-Port",
            6 => "Service-Type",
            7 => "Framed-Protocol",
            40 => "Acct-Status-Type",
            42 => "Acct-Input-Octets",
            43 => "Acct-Output-Octets",
            44 => "Acct-Session-Id",
            47 => "Acct-Input-Packets",
            48 => "Acct-Output-Packets",
            61 => "NAS-Port-Type",
            64 => "Tunnel-Type",
            65 => "Tunnel-Medium-Type",
            79 => "EAP-Message",
            80 => "Message-Authenticator",
            87 => "NAS-Port-Id",
            126 => "Operator-Name",
            128 => "Location-Data",
            131 => "Location-Capable",
            135 => "NAS-Access-Group",
            137 => "Operator-Id",
            138 => "Operator-Realm",
            _ => "Unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radius_round_trip() {
        let attributes = vec![RadiusAttribute {
            kind: attrs::USER_NAME,
            value: b"alice",
        }];
        let packet = RadiusPacket {
            code: RadiusCode::AccessRequest,
            identifier: 1,
            authenticator: [0u8; 16],
            attributes,
        };
        let encoded = encode_radius_packet(&packet);
        let parsed = parse_radius_packet(&encoded).unwrap();
        assert_eq!(parsed.code, RadiusCode::AccessRequest);
        assert_eq!(parsed.attributes[0].value, b"alice");
    }

    #[test]
    fn eap_parses_identity() {
        // Code=1 (Request), Identifier=5, Length=6, Type=1 (Identity), Data="a"
        let frame = parse_eap_frame(&[1, 5, 0, 6, 1, b'a']).unwrap();
        assert_eq!(frame.code, EapCode::Request);
        assert_eq!(frame.method, Some(EapMethod::Identity));
    }

    #[test]
    fn tacacs_obfuscation_round_trip() {
        let body = b"hello world";
        let key = b"secret";
        let obfuscated = tacacs_obfuscate_body(body, key, 1, 0xc1, 1).unwrap();
        let deobfuscated = tacacs_deobfuscate_body(&obfuscated, key, 1, 0xc1, 1).unwrap();
        assert_eq!(deobfuscated, body);
    }

    #[test]
    fn nai_parses_user_realm() {
        let nai = parse_nai("alice@example.com");
        assert_eq!(nai.user, "alice");
        assert_eq!(nai.realm, Some("example.com"));
    }

    #[test]
    fn nai_parses_user_only() {
        let nai = parse_nai("bob");
        assert_eq!(nai.user, "bob");
        assert_eq!(nai.realm, None);
    }

    #[test]
    fn nai_parses_user_empty_realm() {
        let nai = parse_nai("alice@");
        assert_eq!(nai.user, "alice");
        assert_eq!(nai.realm, None);
    }

    #[test]
    fn radius_attrs_name_lookup() {
        assert_eq!(radius_attrs::attr_name(1), "User-Name");
        assert_eq!(radius_attrs::attr_name(126), "Operator-Name");
        assert_eq!(radius_attrs::attr_name(255), "Unknown");
    }
}
