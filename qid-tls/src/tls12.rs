//! Strict TLS 1.2 wire groundwork and offline handshake derivation: handshake
//! record reassembly, ClientHello parsing, RFC 6961 `status_request_v2`
//! parsing and encoding, the TLS 1.2 key schedule, Finished messages and
//! AES-GCM record protection, plus a pure byte-in/byte-out server handshake
//! driver.
//!
//! All of this operates on caller-supplied bytes. It enables no listener,
//! sockets or transport and does not change rustls defaults.

mod driver;
mod finish;
mod flight;
mod prf;
mod record;
mod status;
mod wire;

pub use driver::{ServerHandshake, ServerHandshakeConfig, ServerHandshakeState, plaintext_record};
pub use finish::{
    FinishedResult, complete_server_handshake, ecdh_pre_master, parse_client_key_exchange,
};
pub use flight::{ServerFirstFlight, ServerFirstFlightInput, build_server_first_flight};
pub use prf::{KeyBlock, ems_session_hash, key_block, master_secret, tls12_prf, verify_data};
pub use record::{
    ALERT, APPLICATION_DATA, CCS_RECORD, CHANGE_CIPHER_SPEC, HANDSHAKE, RECORD_VERSION,
    RecordProtector, parse_ccs,
};
pub use status::{
    OcspResponse, StatusRequestItem, StatusRequestV2, StatusSelection,
    build_certificate_status_multi, parse_status_request_v2, select_status_request,
    wrap_handshake_message,
};
pub use wire::{
    ClientHello, Extension, HandshakeMessage, HandshakeReassembler, parse_client_hello,
};

/// RFC 6066 `status_request` extension type.
pub const STATUS_REQUEST: u16 = 5;
/// RFC 6961 `status_request_v2` extension type.
pub const STATUS_REQUEST_V2: u16 = 17;
/// RFC 6961 `ocsp` status type.
pub const OCSP: u8 = 1;
/// RFC 6961 `ocsp_multi` status type.
pub const OCSP_MULTI: u8 = 2;
/// RFC 6961 `CertificateStatus` handshake message type.
pub const CERTIFICATE_STATUS: u8 = 22;
/// ServerHello extension 17 with empty `extension_data` (RFC 6961 §3).
pub const STATUS_REQUEST_V2_ACK: [u8; 4] = [0x00, 0x11, 0x00, 0x00];

// Protocol maxima, derived from the wire formats, not deployment policy:
// RFC 5246 §6.2.1 (2^14 fragment), §7.4.1.2 (u16 vectors, 32-byte SessionID),
// and the u24 vectors of RFC 6961 §§2.2 and 3.
pub(crate) const MAX_RECORD_FRAGMENT: usize = 1 << 14;
pub(crate) const MAX_U16: usize = (1 << 16) - 1;
pub(crate) const MAX_U24: usize = (1 << 24) - 1;
pub(crate) const MAX_SESSION_ID: usize = 32;
pub(crate) const MAX_CIPHER_SUITE_BYTES: usize = (1 << 16) - 2;
pub(crate) const MAX_COMPRESSION_METHODS: usize = (1 << 8) - 1;

// Resource budget, NOT a protocol maximum: a caller picks its own limit with
// `HandshakeReassembler::with_budget`. This default only bounds buffered bytes.
pub(crate) const DEFAULT_REASSEMBLY_BUDGET: usize = 1 << 20;

pub(crate) fn u24_bytes(len: usize) -> [u8; 3] {
    [(len >> 16) as u8, (len >> 8) as u8, len as u8]
}

/// A typed rejection of malformed TLS 1.2 wire input or invalid status output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tls12Error {
    TruncatedRecord,
    UnexpectedContentType,
    InvalidRecordVersion,
    RecordTooLarge,
    BufferBudgetExceeded,
    MessageTooLarge,
    TruncatedHandshake,
    TruncatedClientHello,
    UnsupportedVersion,
    InvalidSessionId,
    InvalidCipherSuites,
    InvalidCompressionMethods,
    InvalidExtensions,
    DuplicateExtension,
    InvalidStatusRequest,
    UnsupportedStatusType,
    DuplicateStatusType,
    InvalidCertificateStatus,
    TooManyResponses,
    EmptyResponse,
    InvalidClientHelloMessage,
    UnsupportedCipherSuite,
    UnsupportedCompressionMethod,
    InvalidSupportedGroups,
    UnsupportedNamedCurve,
    InvalidEcPointFormats,
    UnsupportedPointFormat,
    InvalidSignatureAlgorithms,
    UnsupportedSignatureScheme,
    InvalidCertificateList,
    InvalidEcdhePoint,
    InvalidSignature,
    InvalidClientKeyExchange,
    InvalidFinishedMessage,
    FinishedVerifyFailed,
    InvalidServerFirstFlight,
    InvalidChangeCipherSpec,
    EmptyFragment,
    SequenceExhausted,
    InvalidCiphertext,
    AuthenticationFailed,
    RecordProtectionFailed,
}

impl std::fmt::Display for Tls12Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TruncatedRecord => "truncated TLS 1.2 handshake record",
            Self::UnexpectedContentType => "unexpected TLS record content type",
            Self::InvalidRecordVersion => "invalid TLS 1.2 record version",
            Self::RecordTooLarge => "TLS 1.2 record fragment exceeds the protocol maximum",
            Self::BufferBudgetExceeded => "TLS 1.2 handshake buffer budget exceeded",
            Self::MessageTooLarge => "TLS 1.2 handshake message is too large",
            Self::TruncatedHandshake => "TLS 1.2 handshake message is truncated",
            Self::TruncatedClientHello => "truncated TLS 1.2 ClientHello",
            Self::UnsupportedVersion => "unsupported TLS 1.2 ClientHello version",
            Self::InvalidSessionId => "invalid ClientHello session_id",
            Self::InvalidCipherSuites => "invalid ClientHello cipher_suites",
            Self::InvalidCompressionMethods => "invalid ClientHello compression_methods",
            Self::InvalidExtensions => "invalid ClientHello extensions",
            Self::DuplicateExtension => "duplicate TLS 1.2 extension",
            Self::InvalidStatusRequest => "invalid status_request_v2 encoding",
            Self::UnsupportedStatusType => "unsupported certificate status type",
            Self::DuplicateStatusType => "duplicate certificate status type",
            Self::InvalidCertificateStatus => "invalid CertificateStatus encoding",
            Self::TooManyResponses => "more OCSP responses than certificates",
            Self::EmptyResponse => "empty DER OCSP response",
            Self::InvalidClientHelloMessage => "invalid ClientHello handshake message",
            Self::UnsupportedCipherSuite => "unsupported TLS 1.2 cipher suite",
            Self::UnsupportedCompressionMethod => "unsupported TLS 1.2 compression method",
            Self::InvalidSupportedGroups => "invalid supported_groups extension",
            Self::UnsupportedNamedCurve => "unsupported named curve",
            Self::InvalidEcPointFormats => "invalid ec_point_formats extension",
            Self::UnsupportedPointFormat => "unsupported EC point format",
            Self::InvalidSignatureAlgorithms => "invalid signature_algorithms extension",
            Self::UnsupportedSignatureScheme => "unsupported signature scheme",
            Self::InvalidCertificateList => "invalid TLS 1.2 certificate list",
            Self::InvalidEcdhePoint => "invalid P-256 ECDHE public point",
            Self::InvalidSignature => "invalid P-256 ECDSA signature encoding",
            Self::InvalidClientKeyExchange => "invalid TLS 1.2 ClientKeyExchange",
            Self::InvalidFinishedMessage => "invalid TLS 1.2 Finished message",
            Self::FinishedVerifyFailed => "TLS 1.2 Finished verification failed",
            Self::InvalidServerFirstFlight => "invalid TLS 1.2 server first flight",
            Self::InvalidChangeCipherSpec => "invalid TLS 1.2 ChangeCipherSpec record",
            Self::EmptyFragment => "empty TLS 1.2 handshake fragment",
            Self::SequenceExhausted => "TLS 1.2 record sequence number exhausted",
            Self::InvalidCiphertext => "invalid TLS 1.2 AEAD ciphertext framing",
            Self::AuthenticationFailed => "TLS 1.2 record authentication failed",
            Self::RecordProtectionFailed => "TLS 1.2 record AEAD protection failed",
        })
    }
}

impl std::error::Error for Tls12Error {}

#[cfg(test)]
mod tests;
