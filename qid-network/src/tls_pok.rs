//! RFC 9966 TLS Proof of Knowledge key and identity primitives.
//!
//! This module implements bootstrap-key validation, the RFC 9258 key importer,
//! and an RFC 8773 TLS 1.3 server configuration that binds the selected external
//! PSK to the client's RFC 7250 Raw Public Key in the same handshake.

use hkdf::Hkdf;
use qid_core::error::{QidError, QidResult};
use sha2::{Digest, Sha256};
use spki::{ObjectIdentifier, SubjectPublicKeyInfoRef};
use zeroize::Zeroizing;

#[cfg(feature = "tls-pok")]
use std::sync::Arc;

pub const TLS_POK_NAI: &str = "tls-pok-dpp@teap.eap.arpa";
pub const TLS_POK_CONTEXT: &[u8] = b"tls13-bsk";
pub const TLS_1_3_PROTOCOL_VERSION: u16 = 0x0304;

const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const SECP521R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
const BRAINPOOL_P256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.7");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsPokCurve {
    Prime256v1,
    Secp384r1,
    Secp521r1,
    BrainpoolP256r1,
}

impl TlsPokCurve {
    fn from_oid(oid: ObjectIdentifier) -> QidResult<Self> {
        match oid {
            PRIME256V1 => Ok(Self::Prime256v1),
            SECP384R1 => Ok(Self::Secp384r1),
            SECP521R1 => Ok(Self::Secp521r1),
            BRAINPOOL_P256R1 => Ok(Self::BrainpoolP256r1),
            _ => Err(QidError::BadRequest {
                message: format!("TLS-POK BSK uses unsupported EC named curve {oid}"),
            }),
        }
    }

    fn compressed_point_len(self) -> usize {
        match self {
            Self::Prime256v1 | Self::BrainpoolP256r1 => 33,
            Self::Secp384r1 => 49,
            Self::Secp521r1 => 67,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TlsPokTargetKdf {
    HkdfSha256 = 0x0001,
    HkdfSha384 = 0x0002,
}

impl TlsPokTargetKdf {
    fn from_u16(value: u16) -> QidResult<Self> {
        match value {
            0x0001 => Ok(Self::HkdfSha256),
            0x0002 => Ok(Self::HkdfSha384),
            _ => Err(QidError::BadRequest {
                message: format!("unsupported TLS-POK target KDF 0x{value:04x}"),
            }),
        }
    }

    fn output_len(self) -> usize {
        match self {
            Self::HkdfSha256 => 32,
            Self::HkdfSha384 => 48,
        }
    }
}

#[derive(Clone)]
pub struct TlsPokBootstrapKey {
    spki_der: Zeroizing<Vec<u8>>,
    curve: TlsPokCurve,
    external_identity: [u8; 32],
}

impl std::fmt::Debug for TlsPokBootstrapKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsPokBootstrapKey")
            .field("curve", &self.curve)
            .field("spki_der_len", &self.spki_der.len())
            .finish_non_exhaustive()
    }
}

impl TlsPokBootstrapKey {
    pub fn from_spki_der(spki_der: Vec<u8>) -> QidResult<Self> {
        let curve = validate_bsk_spki(&spki_der)?;
        let external_identity = derive_epsk_external_identity(&spki_der)?;
        Ok(Self {
            spki_der: Zeroizing::new(spki_der),
            curve,
            external_identity,
        })
    }

    pub fn curve(&self) -> TlsPokCurve {
        self.curve
    }

    pub fn spki_der(&self) -> &[u8] {
        &self.spki_der
    }

    pub fn external_identity(&self) -> &[u8; 32] {
        &self.external_identity
    }

    pub fn imported_key(&self, target_kdf: TlsPokTargetKdf) -> QidResult<TlsPokImportedKey> {
        let identity = TlsPokImportedIdentity {
            external_identity: self.external_identity,
            target_kdf,
        };
        let identity_bytes = identity.encode();
        let imported_psk = derive_imported_psk(&self.spki_der, &identity_bytes, target_kdf)?;
        Ok(TlsPokImportedKey {
            identity,
            imported_psk,
        })
    }

    pub fn imported_key_for_identity(
        &self,
        encoded_identity: &[u8],
    ) -> QidResult<Option<TlsPokImportedKey>> {
        let identity = TlsPokImportedIdentity::decode(encoded_identity)?;
        if !qid_core::util::constant_time_eq(self.external_identity, identity.external_identity) {
            return Ok(None);
        }
        let imported_psk =
            derive_imported_psk(&self.spki_der, encoded_identity, identity.target_kdf)?;
        Ok(Some(TlsPokImportedKey {
            identity,
            imported_psk,
        }))
    }

    pub fn matches_presented_raw_public_key(&self, presented_spki_der: &[u8]) -> bool {
        qid_core::util::constant_time_eq(&self.spki_der, presented_spki_der)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPokImportedIdentity {
    external_identity: [u8; 32],
    target_kdf: TlsPokTargetKdf,
}

impl TlsPokImportedIdentity {
    pub fn external_identity(&self) -> &[u8; 32] {
        &self.external_identity
    }

    pub fn target_kdf(&self) -> TlsPokTargetKdf {
        self.target_kdf
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(49);
        encoded.extend_from_slice(&(self.external_identity.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&self.external_identity);
        encoded.extend_from_slice(&(TLS_POK_CONTEXT.len() as u16).to_be_bytes());
        encoded.extend_from_slice(TLS_POK_CONTEXT);
        encoded.extend_from_slice(&TLS_1_3_PROTOCOL_VERSION.to_be_bytes());
        encoded.extend_from_slice(&(self.target_kdf as u16).to_be_bytes());
        encoded
    }

    pub fn decode(encoded: &[u8]) -> QidResult<Self> {
        let mut cursor = 0;
        let external_identity = read_tls_vector(encoded, &mut cursor, "external_identity")?;
        if external_identity.len() != 32 {
            return Err(QidError::BadRequest {
                message: "TLS-POK external identity must be 32 bytes".to_string(),
            });
        }
        let context = read_tls_vector(encoded, &mut cursor, "context")?;
        if context != TLS_POK_CONTEXT {
            return Err(QidError::BadRequest {
                message: "TLS-POK ImportedIdentity context must be tls13-bsk".to_string(),
            });
        }
        let target_protocol = read_u16(encoded, &mut cursor, "target_protocol")?;
        if target_protocol != TLS_1_3_PROTOCOL_VERSION {
            return Err(QidError::BadRequest {
                message: format!(
                    "TLS-POK target protocol must be TLS 1.3 (0x0304), got 0x{target_protocol:04x}"
                ),
            });
        }
        let target_kdf = TlsPokTargetKdf::from_u16(read_u16(encoded, &mut cursor, "target_kdf")?)?;
        if cursor != encoded.len() {
            return Err(QidError::BadRequest {
                message: "TLS-POK ImportedIdentity has trailing data".to_string(),
            });
        }
        let mut external_identity_array = [0u8; 32];
        external_identity_array.copy_from_slice(external_identity);
        Ok(Self {
            external_identity: external_identity_array,
            target_kdf,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TlsPokImportedKey {
    identity: TlsPokImportedIdentity,
    imported_psk: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for TlsPokImportedKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsPokImportedKey")
            .field("identity", &self.identity)
            .field("imported_psk_len", &self.imported_psk.len())
            .finish_non_exhaustive()
    }
}

impl TlsPokImportedKey {
    pub fn identity(&self) -> &TlsPokImportedIdentity {
        &self.identity
    }

    pub fn identity_bytes(&self) -> Vec<u8> {
        self.identity.encode()
    }

    pub fn imported_psk(&self) -> &[u8] {
        &self.imported_psk
    }
}

pub fn validate_tls_pok_nai(identity: &str) -> QidResult<()> {
    if identity == TLS_POK_NAI {
        return Ok(());
    }
    Err(QidError::BadRequest {
        message: format!("TLS-POK EAP identity must be {TLS_POK_NAI}"),
    })
}

pub fn derive_epsk_external_identity(base_key: &[u8]) -> QidResult<[u8; 32]> {
    if base_key.is_empty() {
        return Err(QidError::BadRequest {
            message: "TLS-POK EPSK base key must not be empty".to_string(),
        });
    }
    let hkdf = Hkdf::<Sha256>::new(None, base_key);
    let mut output = [0u8; 32];
    hkdf.expand(b"tls13-bspsk-identity", &mut output)
        .map_err(|_| QidError::Internal {
            message: "TLS-POK EPSK identity derivation failed".to_string(),
        })?;
    Ok(output)
}

fn validate_bsk_spki(spki_der: &[u8]) -> QidResult<TlsPokCurve> {
    let spki =
        SubjectPublicKeyInfoRef::try_from(spki_der).map_err(|error| QidError::BadRequest {
            message: format!("TLS-POK BSK is not a single DER SubjectPublicKeyInfo: {error}"),
        })?;
    if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
        return Err(QidError::BadRequest {
            message: "TLS-POK BSK algorithm must be id-ecPublicKey".to_string(),
        });
    }
    let curve_oid = spki
        .algorithm
        .parameters_oid()
        .map_err(|error| QidError::BadRequest {
            message: format!("TLS-POK BSK must identify an EC named curve: {error}"),
        })?;
    let curve = TlsPokCurve::from_oid(curve_oid)?;
    let public_key = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| QidError::BadRequest {
            message: "TLS-POK BSK subjectPublicKey must be octet-aligned".to_string(),
        })?;
    if public_key.len() != curve.compressed_point_len()
        || !matches!(public_key.first(), Some(0x02 | 0x03))
    {
        return Err(QidError::BadRequest {
            message: format!(
                "TLS-POK BSK subjectPublicKey must be a compressed {:?} point",
                curve
            ),
        });
    }
    Ok(curve)
}

fn derive_imported_psk(
    base_key: &[u8],
    imported_identity: &[u8],
    target_kdf: TlsPokTargetKdf,
) -> QidResult<Zeroizing<Vec<u8>>> {
    // RFC 9258 Section 5.1 uses the hash associated with the EPSK, not
    // target_kdf. RFC 9966 Section 3.1 binds TLS-POK EPSKs to SHA-256;
    // target_kdf changes the ImportedIdentity and output length only.
    let identity_hash = Sha256::digest(imported_identity);
    let label = b"tls13 derived psk";
    let mut hkdf_label = Vec::with_capacity(2 + 1 + label.len() + 1 + identity_hash.len());
    hkdf_label.extend_from_slice(&(target_kdf.output_len() as u16).to_be_bytes());
    hkdf_label.push(label.len() as u8);
    hkdf_label.extend_from_slice(label);
    hkdf_label.push(identity_hash.len() as u8);
    hkdf_label.extend_from_slice(&identity_hash);

    let hkdf = Hkdf::<Sha256>::new(None, base_key);
    let mut imported_psk = Zeroizing::new(vec![0u8; target_kdf.output_len()]);
    hkdf.expand(&hkdf_label, &mut imported_psk)
        .map_err(|_| QidError::Internal {
            message: "TLS-POK imported PSK derivation failed".to_string(),
        })?;
    Ok(imported_psk)
}

fn read_tls_vector<'a>(encoded: &'a [u8], cursor: &mut usize, field: &str) -> QidResult<&'a [u8]> {
    let length = read_u16(encoded, cursor, field)? as usize;
    let end = cursor
        .checked_add(length)
        .filter(|end| *end <= encoded.len())
        .ok_or_else(|| QidError::BadRequest {
            message: format!("TLS-POK ImportedIdentity {field} is truncated"),
        })?;
    let value = &encoded[*cursor..end];
    *cursor = end;
    Ok(value)
}

fn read_u16(encoded: &[u8], cursor: &mut usize, field: &str) -> QidResult<u16> {
    let end = cursor
        .checked_add(2)
        .filter(|end| *end <= encoded.len())
        .ok_or_else(|| QidError::BadRequest {
            message: format!("TLS-POK ImportedIdentity {field} is truncated"),
        })?;
    let value = u16::from_be_bytes([encoded[*cursor], encoded[*cursor + 1]]);
    *cursor = end;
    Ok(value)
}

#[cfg(feature = "tls-pok")]
#[derive(Clone)]
pub struct TlsPokServerResolver {
    bootstrap_keys: Vec<TlsPokBootstrapKey>,
}

#[cfg(feature = "tls-pok")]
impl std::fmt::Debug for TlsPokServerResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsPokServerResolver")
            .field("bootstrap_key_count", &self.bootstrap_keys.len())
            .finish()
    }
}

#[cfg(feature = "tls-pok")]
impl TlsPokServerResolver {
    pub fn new(bootstrap_keys: Vec<TlsPokBootstrapKey>) -> QidResult<Self> {
        if bootstrap_keys.is_empty() {
            return Err(QidError::Config {
                message: "TLS-POK requires at least one bootstrap key".to_string(),
            });
        }

        for (index, key) in bootstrap_keys.iter().enumerate() {
            if bootstrap_keys[..index].iter().any(|existing| {
                qid_core::util::constant_time_eq(
                    existing.external_identity(),
                    key.external_identity(),
                )
            }) {
                return Err(QidError::Config {
                    message: "TLS-POK bootstrap key external identities must be unique".to_string(),
                });
            }
        }

        Ok(Self { bootstrap_keys })
    }
}

#[cfg(feature = "tls-pok")]
impl rustls::server::ResolvesServerImportedPsk for TlsPokServerResolver {
    fn resolve(
        &self,
        identity: &[u8],
        hash_algorithm: rustls::crypto::hash::HashAlgorithm,
    ) -> Option<rustls::server::ServerImportedPsk> {
        let parsed = TlsPokImportedIdentity::decode(identity).ok()?;
        let required_kdf = match hash_algorithm {
            rustls::crypto::hash::HashAlgorithm::SHA256 => TlsPokTargetKdf::HkdfSha256,
            rustls::crypto::hash::HashAlgorithm::SHA384 => TlsPokTargetKdf::HkdfSha384,
            _ => return None,
        };
        if parsed.target_kdf() != required_kdf {
            return None;
        }

        let bootstrap_key = self.bootstrap_keys.iter().find(|key| {
            qid_core::util::constant_time_eq(key.external_identity(), parsed.external_identity())
        })?;
        let imported_key = bootstrap_key.imported_key_for_identity(identity).ok()??;

        rustls::server::ServerImportedPsk::new(
            imported_key.imported_psk().to_vec(),
            rustls_pki_types::SubjectPublicKeyInfoDer::from(bootstrap_key.spki_der().to_vec()),
        )
        .ok()
    }
}

#[cfg(feature = "tls-pok")]
#[derive(Debug)]
struct TlsPokClientRawPublicKeyVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
    root_hints: Vec<rustls::DistinguishedName>,
}

#[cfg(feature = "tls-pok")]
impl rustls::server::danger::ClientCertVerifier for TlsPokClientRawPublicKeyVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &self.root_hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        if !intermediates.is_empty()
            || TlsPokBootstrapKey::from_spki_der(end_entity.as_ref().to_vec()).is_err()
        {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "TLS-POK requires TLS 1.3".to_string(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &rustls_pki_types::SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

#[cfg(feature = "tls-pok")]
pub fn build_tls_pok_server_config(
    certificate_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    private_key: rustls_pki_types::PrivateKeyDer<'static>,
    bootstrap_keys: Vec<TlsPokBootstrapKey>,
) -> QidResult<rustls::ServerConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(TlsPokClientRawPublicKeyVerifier {
        provider: provider.clone(),
        root_hints: Vec::new(),
    });
    let resolver = Arc::new(TlsPokServerResolver::new(bootstrap_keys)?);

    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| QidError::Config {
            message: format!("TLS-POK TLS 1.3 configuration is invalid: {error}"),
        })?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificate_chain, private_key)
        .map_err(|error| QidError::BadRequest {
            message: format!("TLS-POK server certificate is invalid: {error}"),
        })?
        .with_imported_psk_resolver(resolver)
        .map_err(|error| QidError::Config {
            message: format!("TLS-POK imported PSK configuration is invalid: {error}"),
        })?;

    Ok(config)
}

#[cfg(feature = "tls-pok")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPokTeapResult {
    pub response: Option<Vec<u8>>,
    pub authenticated_identity: Option<Vec<u8>>,
    pub tunnel_data: Vec<u8>,
}

#[cfg(feature = "tls-pok")]
pub struct TlsPokTeapServerSession {
    connection: rustls::ServerConnection,
    maximum_frame_size: usize,
    maximum_message_size: usize,
    inbound_message: Vec<u8>,
    inbound_message_length: Option<usize>,
    outbound_message: Vec<u8>,
    outbound_offset: usize,
}

#[cfg(feature = "tls-pok")]
impl std::fmt::Debug for TlsPokTeapServerSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsPokTeapServerSession")
            .field("is_handshaking", &self.connection.is_handshaking())
            .field("maximum_frame_size", &self.maximum_frame_size)
            .field("maximum_message_size", &self.maximum_message_size)
            .field("inbound_message_length", &self.inbound_message_length)
            .field(
                "outbound_bytes_remaining",
                &self
                    .outbound_message
                    .len()
                    .saturating_sub(self.outbound_offset),
            )
            .finish()
    }
}

#[cfg(feature = "tls-pok")]
impl TlsPokTeapServerSession {
    pub fn new(
        config: Arc<rustls::ServerConfig>,
        maximum_frame_size: usize,
        maximum_message_size: usize,
    ) -> QidResult<Self> {
        if maximum_frame_size < 64 {
            return Err(QidError::Config {
                message: "TLS-POK TEAP maximum frame size must be at least 64 bytes".to_string(),
            });
        }
        if maximum_message_size < maximum_frame_size {
            return Err(QidError::Config {
                message: "TLS-POK TEAP maximum message size must cover one frame".to_string(),
            });
        }
        let connection =
            rustls::ServerConnection::new(config).map_err(|error| QidError::Config {
                message: format!("TLS-POK server connection is invalid: {error}"),
            })?;

        Ok(Self {
            connection,
            maximum_frame_size,
            maximum_message_size,
            inbound_message: Vec::new(),
            inbound_message_length: None,
            outbound_message: Vec::new(),
            outbound_offset: 0,
        })
    }

    pub fn start_request() -> Vec<u8> {
        crate::eap_handshake::EapTeapFrame {
            version: crate::eap_handshake::TEAP_VERSION,
            message_length: None,
            tls_data: Vec::new(),
            outer_tlvs: Vec::new(),
            more_fragments: false,
            start: true,
        }
        .encode()
        .expect("fixed TEAP start frame is valid")
    }

    pub fn receive(&mut self, encoded_frame: &[u8]) -> QidResult<TlsPokTeapResult> {
        use std::io::{Cursor, Read};

        let frame = crate::eap_handshake::EapTeapFrame::parse(encoded_frame)?;
        self.validate_peer_frame(&frame)?;

        if self.has_outbound_fragments() {
            if !frame.tls_data.is_empty() || frame.more_fragments || frame.message_length.is_some()
            {
                return Err(QidError::BadRequest {
                    message: "TLS-POK TEAP expected a fragment acknowledgement".to_string(),
                });
            }
            return self.result_with_next_outbound(Vec::new());
        }

        let tls_message = match self.reassemble_peer_message(frame)? {
            Some(message) => message,
            None => {
                let acknowledgement = crate::eap_handshake::EapTeapFrame {
                    version: crate::eap_handshake::TEAP_VERSION,
                    message_length: None,
                    tls_data: Vec::new(),
                    outer_tlvs: Vec::new(),
                    more_fragments: false,
                    start: false,
                }
                .encode()?;
                return Ok(TlsPokTeapResult {
                    response: Some(acknowledgement),
                    authenticated_identity: self.authenticated_identity(),
                    tunnel_data: Vec::new(),
                });
            }
        };

        if tls_message.is_empty() {
            return Ok(TlsPokTeapResult {
                response: None,
                authenticated_identity: self.authenticated_identity(),
                tunnel_data: Vec::new(),
            });
        }

        let mut cursor = Cursor::new(tls_message.as_slice());
        let consumed =
            self.connection
                .read_tls(&mut cursor)
                .map_err(|error| QidError::BadRequest {
                    message: format!("TLS-POK TEAP TLS record is invalid: {error}"),
                })?;
        if consumed != tls_message.len() {
            return Err(QidError::BadRequest {
                message: "TLS-POK TEAP TLS message was not consumed completely".to_string(),
            });
        }
        self.connection
            .process_new_packets()
            .map_err(|error| QidError::Unauthorized {
                message: format!("TLS-POK handshake failed: {error}"),
            })?;

        let mut tunnel_data = Vec::new();
        match self.connection.reader().read_to_end(&mut tunnel_data) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => {
                return Err(QidError::Internal {
                    message: format!("TLS-POK tunnel read failed: {error}"),
                });
            }
        }
        self.collect_outbound_tls()?;
        self.result_with_next_outbound(tunnel_data)
    }

    pub fn send_tunnel_data(&mut self, data: &[u8]) -> QidResult<TlsPokTeapResult> {
        use std::io::Write;

        if self.authenticated_identity().is_none() {
            return Err(QidError::Unauthorized {
                message: "TLS-POK tunnel is not authenticated".to_string(),
            });
        }
        if self.has_outbound_fragments() {
            return Err(QidError::BadRequest {
                message: "TLS-POK TEAP has an unacknowledged outbound fragment".to_string(),
            });
        }
        self.connection
            .writer()
            .write_all(data)
            .map_err(|error| QidError::Internal {
                message: format!("TLS-POK tunnel write failed: {error}"),
            })?;
        self.collect_outbound_tls()?;
        self.result_with_next_outbound(Vec::new())
    }

    pub fn authenticated_identity(&self) -> Option<Vec<u8>> {
        if self.connection.is_handshaking() {
            return None;
        }
        self.connection
            .imported_psk_identity()
            .map(ToOwned::to_owned)
    }

    fn validate_peer_frame(&self, frame: &crate::eap_handshake::EapTeapFrame) -> QidResult<()> {
        if frame.version != crate::eap_handshake::TEAP_VERSION {
            return Err(QidError::BadRequest {
                message: format!(
                    "TLS-POK requires TEAP version {}, got {}",
                    crate::eap_handshake::TEAP_VERSION,
                    frame.version
                ),
            });
        }
        if frame.start {
            return Err(QidError::BadRequest {
                message: "TLS-POK peer must not set the TEAP Start flag".to_string(),
            });
        }
        if !frame.outer_tlvs.is_empty() {
            return Err(QidError::BadRequest {
                message: "TLS-POK does not accept unauthenticated TEAP Outer TLVs".to_string(),
            });
        }
        Ok(())
    }

    fn reassemble_peer_message(
        &mut self,
        frame: crate::eap_handshake::EapTeapFrame,
    ) -> QidResult<Option<Vec<u8>>> {
        if let Some(expected_length) = self.inbound_message_length {
            if frame.message_length.is_some() {
                return Err(QidError::BadRequest {
                    message: "TLS-POK TEAP continuation fragment must not include length"
                        .to_string(),
                });
            }
            self.inbound_message.extend_from_slice(&frame.tls_data);
            if self.inbound_message.len() > expected_length {
                return Err(QidError::BadRequest {
                    message: "TLS-POK TEAP fragments exceed declared message length".to_string(),
                });
            }
            if frame.more_fragments {
                return Ok(None);
            }
            if self.inbound_message.len() != expected_length {
                return Err(QidError::BadRequest {
                    message: "TLS-POK TEAP final fragment does not match declared length"
                        .to_string(),
                });
            }
            self.inbound_message_length = None;
            return Ok(Some(std::mem::take(&mut self.inbound_message)));
        }

        if frame.more_fragments {
            let expected_length = frame.message_length.ok_or_else(|| QidError::BadRequest {
                message: "TLS-POK TEAP first fragment must include message length".to_string(),
            })? as usize;
            if expected_length <= frame.tls_data.len()
                || expected_length > self.maximum_message_size
            {
                return Err(QidError::BadRequest {
                    message: "TLS-POK TEAP declared message length is invalid".to_string(),
                });
            }
            self.inbound_message = frame.tls_data;
            self.inbound_message_length = Some(expected_length);
            return Ok(None);
        }

        if frame.message_length.is_some() {
            return Err(QidError::BadRequest {
                message: "TLS-POK TEAP unfragmented message must not include length".to_string(),
            });
        }
        if frame.tls_data.len() > self.maximum_message_size {
            return Err(QidError::BadRequest {
                message: "TLS-POK TEAP message exceeds configured limit".to_string(),
            });
        }
        Ok(Some(frame.tls_data))
    }

    fn collect_outbound_tls(&mut self) -> QidResult<()> {
        if self.has_outbound_fragments() {
            return Err(QidError::Internal {
                message: "TLS-POK attempted to overwrite pending TEAP fragments".to_string(),
            });
        }
        self.outbound_message.clear();
        self.outbound_offset = 0;
        while self.connection.wants_write() {
            self.connection
                .write_tls(&mut self.outbound_message)
                .map_err(|error| QidError::Internal {
                    message: format!("TLS-POK TLS record write failed: {error}"),
                })?;
        }
        Ok(())
    }

    fn result_with_next_outbound(&mut self, tunnel_data: Vec<u8>) -> QidResult<TlsPokTeapResult> {
        Ok(TlsPokTeapResult {
            response: self.next_outbound_frame()?,
            authenticated_identity: self.authenticated_identity(),
            tunnel_data,
        })
    }

    fn next_outbound_frame(&mut self) -> QidResult<Option<Vec<u8>>> {
        if !self.has_outbound_fragments() {
            return Ok(None);
        }

        let total_length = self.outbound_message.len();
        let first_fragment = self.outbound_offset == 0;
        let unfragmented_capacity = self.maximum_frame_size - 1;
        if first_fragment && total_length <= unfragmented_capacity {
            self.outbound_offset = total_length;
            let encoded = crate::eap_handshake::EapTeapFrame {
                version: crate::eap_handshake::TEAP_VERSION,
                message_length: None,
                tls_data: self.outbound_message.clone(),
                outer_tlvs: Vec::new(),
                more_fragments: false,
                start: false,
            }
            .encode()?;
            self.clear_completed_outbound();
            return Ok(Some(encoded));
        }

        let header_length = if first_fragment { 5 } else { 1 };
        let capacity = self.maximum_frame_size - header_length;
        let end = (self.outbound_offset + capacity).min(total_length);
        let tls_data = self.outbound_message[self.outbound_offset..end].to_vec();
        self.outbound_offset = end;
        let more_fragments = end < total_length;
        let encoded = crate::eap_handshake::EapTeapFrame {
            version: crate::eap_handshake::TEAP_VERSION,
            message_length: first_fragment.then_some(total_length as u32),
            tls_data,
            outer_tlvs: Vec::new(),
            more_fragments,
            start: false,
        }
        .encode()?;
        self.clear_completed_outbound();
        Ok(Some(encoded))
    }

    fn has_outbound_fragments(&self) -> bool {
        self.outbound_offset < self.outbound_message.len()
    }

    fn clear_completed_outbound(&mut self) {
        if self.outbound_offset == self.outbound_message.len() {
            self.outbound_message.clear();
            self.outbound_offset = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    use super::*;

    const P256_BSK: &str = concat!(
        "MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgACMvLyoOykj8sFJxSoZfzafuVEvM+kNYCxp",
        "EC6KITLb9g="
    );
    const P384_BSK: &str = concat!(
        "MEYwEAYHKoZIzj0CAQYFK4EEACIDMgACwDXKQ1pytcR1WbfqPaNGaXQ0RJnijJG1em8ZK",
        "ilryZRDfNioq7+EPquT6l9laRvw"
    );
    const P521_BSK_AS_PUBLISHED: &str = concat!(
        "MFgwEAYHKoZIzj0CAQYFK4EEACMDRAADAIiHIAOXdPVuI8khCnJQHT1j53rQRnFCcY3CZ",
        "UvxdXKJR9KW5RVB3HDQfmkoQWHEz4XngXUeFyDXliEo3eF6vhqDMFgwEAYHKoZIzj0CAQ",
        "YFK4EEACMDRAADAIiHIAOXdPVuI8khCnJQHT1j53rQRnFCcY3CZUvxdXKJR9KW5RVB3HD",
        "QfmkoQWHEz4XngXUeFyDXliEo3eF6vhqD"
    );
    const BRAINPOOL_P256_BSK: &str = concat!(
        "MDowFAYHKoZIzj0CAQYJKyQDAwIIAQEHAyIAA3fyUWqiV8NC9DAC88JzmVqnoT/",
        "reuCvq8lHowtwWNOZ"
    );

    #[test]
    fn appendix_a_valid_vectors_derive_expected_external_identities() {
        let vectors = [
            (
                P256_BSK,
                "Bd+lLlg/ERdtYacfzDfh1LjdL0+QWJQHdYXoS7JDSkA=",
                TlsPokCurve::Prime256v1,
            ),
            (
                P384_BSK,
                "yMWK26ec3klVFewg2znKntQgVoRcRRjW81n677GL+8w=",
                TlsPokCurve::Secp384r1,
            ),
            (
                BRAINPOOL_P256_BSK,
                "j2TLWcXtrTej+f3q7EZrhp5SmP31uk1ZB23dfcR93EY=",
                TlsPokCurve::BrainpoolP256r1,
            ),
        ];
        for (bsk_base64, epskid_base64, curve) in vectors {
            let bsk = STANDARD.decode(bsk_base64).unwrap();
            let key = TlsPokBootstrapKey::from_spki_der(bsk).unwrap();
            assert_eq!(key.curve(), curve);
            assert_eq!(
                key.external_identity().as_slice(),
                STANDARD.decode(epskid_base64).unwrap()
            );
        }
    }

    #[test]
    fn appendix_a_p521_published_bytes_reproduce_epskid_but_fail_der_validation() {
        let published_bsk = STANDARD.decode(P521_BSK_AS_PUBLISHED).unwrap();
        assert_eq!(published_bsk.len(), 180);
        assert_eq!(published_bsk[..90], published_bsk[90..]);
        let epskid = derive_epsk_external_identity(&published_bsk).unwrap();
        assert_eq!(
            epskid.as_slice(),
            STANDARD
                .decode("D+s3Ex81A8N36ECI3AdXwBzrOXuonZUMdhhHXVINhg8=")
                .unwrap()
        );
        assert!(TlsPokBootstrapKey::from_spki_der(published_bsk).is_err());
    }

    #[test]
    fn bsk_rejects_uncompressed_point_and_trailing_data() {
        let mut uncompressed = STANDARD.decode(P256_BSK).unwrap();
        let point_offset = uncompressed.len() - 33;
        uncompressed[point_offset] = 0x04;
        assert!(TlsPokBootstrapKey::from_spki_der(uncompressed).is_err());

        let mut trailing = STANDARD.decode(P256_BSK).unwrap();
        trailing.push(0);
        assert!(TlsPokBootstrapKey::from_spki_der(trailing).is_err());
    }

    #[test]
    fn imported_identity_round_trip_is_strict() {
        let key = TlsPokBootstrapKey::from_spki_der(STANDARD.decode(P256_BSK).unwrap()).unwrap();
        let imported = key.imported_key(TlsPokTargetKdf::HkdfSha256).unwrap();
        let encoded = imported.identity_bytes();
        assert_eq!(encoded.len(), 49);
        assert_eq!(
            TlsPokImportedIdentity::decode(&encoded).unwrap(),
            *imported.identity()
        );

        let mut wrong_context = encoded.clone();
        wrong_context[36] = b'x';
        assert!(TlsPokImportedIdentity::decode(&wrong_context).is_err());

        let mut trailing = encoded;
        trailing.push(0);
        assert!(TlsPokImportedIdentity::decode(&trailing).is_err());
    }

    #[test]
    fn imported_psks_are_bound_to_target_kdf_and_identity() {
        let key = TlsPokBootstrapKey::from_spki_der(STANDARD.decode(P256_BSK).unwrap()).unwrap();
        let sha256 = key.imported_key(TlsPokTargetKdf::HkdfSha256).unwrap();
        let sha384 = key.imported_key(TlsPokTargetKdf::HkdfSha384).unwrap();

        assert_eq!(
            sha256.identity_bytes(),
            STANDARD
                .decode("ACAF36UuWD8RF21hpx/MN+HUuN0vT5BYlAd1hehLskNKQAAJdGxzMTMtYnNrAwQAAQ==")
                .unwrap()
        );
        assert_eq!(
            sha256.imported_psk(),
            STANDARD
                .decode("CFOp4snqnR41SOsFnefVy12rW7gAUdilzkcCIYkIoCI=")
                .unwrap()
        );
        assert_eq!(
            sha384.identity_bytes(),
            STANDARD
                .decode("ACAF36UuWD8RF21hpx/MN+HUuN0vT5BYlAd1hehLskNKQAAJdGxzMTMtYnNrAwQAAg==")
                .unwrap()
        );
        assert_eq!(
            sha384.imported_psk(),
            STANDARD
                .decode("BxCBwnaEf07volI8ZrOMiQBs5CtGwWp79UYYLz+nPSv53pJdff0xBkpg4k+LppGb")
                .unwrap()
        );

        assert_eq!(sha256.imported_psk().len(), 32);
        assert_eq!(sha384.imported_psk().len(), 48);
        assert_ne!(sha256.imported_psk(), &sha384.imported_psk()[..32]);
        assert_ne!(sha256.identity_bytes(), sha384.identity_bytes());
        assert!(key.matches_presented_raw_public_key(key.spki_der()));

        let encoded_identity = sha256.identity_bytes();
        let looked_up = key
            .imported_key_for_identity(&encoded_identity)
            .unwrap()
            .unwrap();
        assert_eq!(looked_up.imported_psk(), sha256.imported_psk());

        let mut unknown_identity = encoded_identity;
        unknown_identity[2] ^= 1;
        assert!(
            key.imported_key_for_identity(&unknown_identity)
                .unwrap()
                .is_none()
        );

        let mut other_key = key.spki_der().to_vec();
        let last = other_key.len() - 1;
        other_key[last] ^= 1;
        assert!(!key.matches_presented_raw_public_key(&other_key));
    }

    #[test]
    fn tls_pok_nai_is_exact() {
        assert!(validate_tls_pok_nai(TLS_POK_NAI).is_ok());
        assert!(validate_tls_pok_nai("TLS-POK-DPP@teap.eap.arpa").is_err());
        assert!(validate_tls_pok_nai("tls-pok-dpp@example.com").is_err());
    }

    #[cfg(feature = "tls-pok")]
    mod handshake {
        use std::io::Cursor;
        use std::sync::Arc;

        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::pkcs8::EncodePublicKey;
        use rcgen::{
            BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
            ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
        };
        use rustls::crypto::hash::HashAlgorithm;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
        use rustls::sign::CertifiedKey;
        use spki::der::Encode;
        use spki::der::asn1::BitString;
        use spki::der::referenced::RefToOwned;
        use spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};

        use super::*;

        #[test]
        fn full_tls_pok_handshake_authenticates_imported_psk_and_raw_public_key() {
            let server_identity = server_identity();
            let client_identity = client_raw_public_key();
            let bootstrap_key =
                TlsPokBootstrapKey::from_spki_der(client_identity.raw_public_key.clone()).unwrap();
            let imported = bootstrap_key
                .imported_key(TlsPokTargetKdf::HkdfSha256)
                .unwrap();
            let expected_identity = imported.identity_bytes();

            let server_config = build_tls_pok_server_config(
                server_identity.certificate_chain,
                server_identity.private_key,
                vec![bootstrap_key],
            )
            .unwrap();
            let client_config =
                client_config(&server_identity.ca, client_identity, imported, false);

            let selected_identity = drive_handshake(server_config, client_config).unwrap();
            assert_eq!(selected_identity, expected_identity);
        }

        #[test]
        fn full_tls_pok_handshake_is_carried_over_fragmented_teap() {
            let server_identity = server_identity();
            let client_identity = client_raw_public_key();
            let bootstrap_key =
                TlsPokBootstrapKey::from_spki_der(client_identity.raw_public_key.clone()).unwrap();
            let imported = bootstrap_key
                .imported_key(TlsPokTargetKdf::HkdfSha256)
                .unwrap();
            let expected_identity = imported.identity_bytes();

            let server_config = build_tls_pok_server_config(
                server_identity.certificate_chain,
                server_identity.private_key,
                vec![bootstrap_key],
            )
            .unwrap();
            let client_config =
                client_config(&server_identity.ca, client_identity, imported, false);

            let selected_identity = drive_teap_handshake(server_config, client_config).unwrap();
            assert_eq!(selected_identity, expected_identity);
        }

        #[test]
        fn tls_pok_rejects_incorrect_imported_psk_binder() {
            let server_identity = server_identity();
            let client_identity = client_raw_public_key();
            let bootstrap_key =
                TlsPokBootstrapKey::from_spki_der(client_identity.raw_public_key.clone()).unwrap();
            let imported = bootstrap_key
                .imported_key(TlsPokTargetKdf::HkdfSha256)
                .unwrap();

            let server_config = build_tls_pok_server_config(
                server_identity.certificate_chain,
                server_identity.private_key,
                vec![bootstrap_key],
            )
            .unwrap();
            let client_config = client_config(&server_identity.ca, client_identity, imported, true);

            assert!(drive_handshake(server_config, client_config).is_err());
        }

        #[test]
        fn tls_pok_rejects_raw_public_key_different_from_selected_bsk() {
            let server_identity = server_identity();
            let registered_identity = client_raw_public_key();
            let presented_identity = client_raw_public_key();
            let bootstrap_key =
                TlsPokBootstrapKey::from_spki_der(registered_identity.raw_public_key).unwrap();
            let imported = bootstrap_key
                .imported_key(TlsPokTargetKdf::HkdfSha256)
                .unwrap();

            let server_config = build_tls_pok_server_config(
                server_identity.certificate_chain,
                server_identity.private_key,
                vec![bootstrap_key],
            )
            .unwrap();
            let client_config =
                client_config(&server_identity.ca, presented_identity, imported, false);

            assert!(drive_handshake(server_config, client_config).is_err());
        }

        struct ServerIdentity {
            ca: Certificate,
            certificate_chain: Vec<CertificateDer<'static>>,
            private_key: PrivateKeyDer<'static>,
        }

        fn server_identity() -> ServerIdentity {
            let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let mut ca_params = CertificateParams::default();
            let mut distinguished_name = DistinguishedName::new();
            distinguished_name.push(DnType::CommonName, "TLS-POK test CA");
            ca_params.distinguished_name = distinguished_name;
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let ca = ca_params.self_signed(&ca_key).unwrap();

            let server_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
            server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let server_certificate = server_params.signed_by(&server_key, &ca, &ca_key).unwrap();

            ServerIdentity {
                ca,
                certificate_chain: vec![server_certificate.der().clone()],
                private_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    server_key.serialize_der(),
                )),
            }
        }

        struct ClientRawPublicKey {
            private_key: PrivateKeyDer<'static>,
            raw_public_key: Vec<u8>,
        }

        fn client_raw_public_key() -> ClientRawPublicKey {
            let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let public_key = p256::PublicKey::from_sec1_bytes(key_pair.public_key_raw()).unwrap();
            let compressed_point = public_key.to_encoded_point(true);
            let uncompressed_spki = public_key.to_public_key_der().unwrap();
            let parsed = SubjectPublicKeyInfoRef::try_from(uncompressed_spki.as_ref()).unwrap();
            let compressed_spki = SubjectPublicKeyInfoOwned {
                algorithm: parsed.algorithm.ref_to_owned(),
                subject_public_key: BitString::from_bytes(compressed_point.as_bytes()).unwrap(),
            }
            .to_der()
            .unwrap();

            ClientRawPublicKey {
                private_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    key_pair.serialize_der(),
                )),
                raw_public_key: compressed_spki,
            }
        }

        fn client_config(
            server_ca: &Certificate,
            client_identity: ClientRawPublicKey,
            imported: TlsPokImportedKey,
            corrupt_secret: bool,
        ) -> rustls::ClientConfig {
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let signing_key = provider
                .key_provider
                .load_private_key(client_identity.private_key)
                .unwrap();
            let certified_key = Arc::new(CertifiedKey::new(
                vec![CertificateDer::from(client_identity.raw_public_key)],
                signing_key,
            ));
            let mut roots = rustls::RootCertStore::empty();
            roots.add(server_ca.der().clone()).unwrap();

            let mut secret = imported.imported_psk().to_vec();
            if corrupt_secret {
                secret[0] ^= 0x80;
            }
            let imported_psk = rustls::client::ClientImportedPsk::new(
                imported.identity_bytes(),
                secret,
                HashAlgorithm::SHA256,
            )
            .unwrap();

            rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_client_cert_resolver(Arc::new(
                    rustls::client::AlwaysResolvesClientRawPublicKeys::new(certified_key),
                ))
                .with_imported_psk(imported_psk)
                .unwrap()
        }

        fn drive_handshake(
            server_config: rustls::ServerConfig,
            client_config: rustls::ClientConfig,
        ) -> Result<Vec<u8>, rustls::Error> {
            let mut server = rustls::ServerConnection::new(Arc::new(server_config))?;
            let server_name = ServerName::try_from("localhost").unwrap().to_owned();
            let mut client = rustls::ClientConnection::new(Arc::new(client_config), server_name)?;

            for _ in 0..20 {
                let mut client_wire = Vec::new();
                client.write_tls(&mut client_wire).unwrap();
                if !client_wire.is_empty() {
                    server.read_tls(&mut Cursor::new(client_wire)).unwrap();
                    server.process_new_packets()?;
                }

                let mut server_wire = Vec::new();
                server.write_tls(&mut server_wire).unwrap();
                if !server_wire.is_empty() {
                    client.read_tls(&mut Cursor::new(server_wire)).unwrap();
                    client.process_new_packets()?;
                }

                if !client.is_handshaking() && !server.is_handshaking() {
                    return server
                        .imported_psk_identity()
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| {
                            rustls::Error::General(
                                "TLS-POK handshake did not select an imported identity".to_string(),
                            )
                        });
                }
            }

            Err(rustls::Error::General(
                "TLS-POK handshake did not complete".to_string(),
            ))
        }

        fn drive_teap_handshake(
            server_config: rustls::ServerConfig,
            client_config: rustls::ClientConfig,
        ) -> QidResult<Vec<u8>> {
            const FRAME_SIZE: usize = 128;

            let mut session =
                TlsPokTeapServerSession::new(Arc::new(server_config), FRAME_SIZE, 1024 * 1024)?;
            let start = crate::eap_handshake::EapTeapFrame::parse(
                &TlsPokTeapServerSession::start_request(),
            )?;
            assert!(start.start);
            assert_eq!(start.version, crate::eap_handshake::TEAP_VERSION);

            let server_name = ServerName::try_from("localhost").unwrap().to_owned();
            let mut client = rustls::ClientConnection::new(Arc::new(client_config), server_name)
                .map_err(|error| QidError::Config {
                    message: format!("TLS-POK test client is invalid: {error}"),
                })?;

            for _ in 0..20 {
                let mut client_tls = Vec::new();
                client
                    .write_tls(&mut client_tls)
                    .map_err(|error| QidError::Internal {
                        message: format!("TLS-POK test client write failed: {error}"),
                    })?;
                if !client_tls.is_empty() {
                    let server_tls = send_teap_tls_message(&mut session, &client_tls, FRAME_SIZE)?;
                    if !server_tls.is_empty() {
                        client
                            .read_tls(&mut Cursor::new(server_tls))
                            .map_err(|error| QidError::BadRequest {
                                message: format!("TLS-POK test server TLS is invalid: {error}"),
                            })?;
                        client
                            .process_new_packets()
                            .map_err(|error| QidError::Unauthorized {
                                message: format!("TLS-POK test client rejected handshake: {error}"),
                            })?;
                    }
                }

                if let Some(identity) = session.authenticated_identity() {
                    return Ok(identity);
                }
            }

            Err(QidError::Internal {
                message: "TLS-POK TEAP handshake did not complete".to_string(),
            })
        }

        fn send_teap_tls_message(
            session: &mut TlsPokTeapServerSession,
            tls_message: &[u8],
            frame_size: usize,
        ) -> QidResult<Vec<u8>> {
            let first_capacity = frame_size - 5;
            let continuation_capacity = frame_size - 1;
            let fragmented = tls_message.len() > frame_size - 1;
            let mut offset = 0usize;
            let mut result = None;

            while offset < tls_message.len() {
                let first = offset == 0;
                let capacity = if first && fragmented {
                    first_capacity
                } else {
                    continuation_capacity
                };
                let end = (offset + capacity).min(tls_message.len());
                let more_fragments = end < tls_message.len();
                let frame = crate::eap_handshake::EapTeapFrame {
                    version: crate::eap_handshake::TEAP_VERSION,
                    message_length: (first && fragmented).then_some(tls_message.len() as u32),
                    tls_data: tls_message[offset..end].to_vec(),
                    outer_tlvs: Vec::new(),
                    more_fragments,
                    start: false,
                }
                .encode()?;
                let current = session.receive(&frame)?;
                if more_fragments {
                    let acknowledgement = current.response.ok_or_else(|| QidError::Internal {
                        message: "TLS-POK TEAP server omitted fragment acknowledgement".to_string(),
                    })?;
                    let acknowledgement =
                        crate::eap_handshake::EapTeapFrame::parse(&acknowledgement)?;
                    if !acknowledgement.tls_data.is_empty() {
                        return Err(QidError::Internal {
                            message: "TLS-POK TEAP fragment acknowledgement was not empty"
                                .to_string(),
                        });
                    }
                } else {
                    result = Some(current);
                }
                offset = end;
            }

            collect_teap_tls_response(session, result.expect("at least one peer fragment"))
        }

        fn collect_teap_tls_response(
            session: &mut TlsPokTeapServerSession,
            mut result: TlsPokTeapResult,
        ) -> QidResult<Vec<u8>> {
            let mut tls_message = Vec::new();
            let mut expected_length = None;

            while let Some(encoded) = result.response {
                let frame = crate::eap_handshake::EapTeapFrame::parse(&encoded)?;
                if expected_length.is_none() {
                    expected_length = frame.message_length.map(|length| length as usize);
                }
                tls_message.extend_from_slice(&frame.tls_data);
                if !frame.more_fragments {
                    break;
                }
                let acknowledgement = crate::eap_handshake::EapTeapFrame {
                    version: crate::eap_handshake::TEAP_VERSION,
                    message_length: None,
                    tls_data: Vec::new(),
                    outer_tlvs: Vec::new(),
                    more_fragments: false,
                    start: false,
                }
                .encode()?;
                result = session.receive(&acknowledgement)?;
            }

            if let Some(expected_length) = expected_length
                && tls_message.len() != expected_length
            {
                return Err(QidError::Internal {
                    message: "TLS-POK TEAP response length mismatch".to_string(),
                });
            }
            Ok(tls_message)
        }
    }
}
