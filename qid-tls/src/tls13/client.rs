//! Offline client-side TLS-POK handshake state machine (RFC 9966 / RFC 9973).
//!
//! The caller supplies one framed handshake message at a time (including its
//! four-byte handshake header), after recovering plaintext from the record
//! layer. This module tracks the transcript, validates the server's messages,
//! derives the key schedule and produces the client's authentication messages.
//! It never opens a socket: record protection remains the caller's job through
//! [`super::ReadEpoch`] and [`super::WriteEpoch`].
//!
//! Only TLS 1.3 with `TLS_AES_128_GCM_SHA256` and P-256 is supported, matching
//! the SHA-256 key schedule and record epochs in this crate. The caller keeps
//! the client BSK signing key; this module only receives its DER signatures.

use super::certificate;
use super::certificate_request;
use super::certificate_verify::{self, CertificateVerifySender, SignatureScheme};
use super::client_hello::{self, ClientHelloParams};
use super::encrypted_extensions;
use super::external_psk::ImportedIdentity;
use super::key_schedule::{self, HandshakeSecrets};
use super::server_hello;
use super::tls_pok::{self, CLIENT_CERTIFICATE_TYPE_TYPE, SERVER_CERTIFICATE_TYPE_TYPE};
use super::transcript::{self, Transcript};
use p256::ecdsa::signature::Verifier;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::DecodePublicKey;
use p256::{PublicKey, SecretKey};
use std::fmt;
use zeroize::Zeroizing;

const SERVER_HELLO: u8 = 0x02;
const ENCRYPTED_EXTENSIONS: u8 = 0x08;
const CERTIFICATE: u8 = 0x0b;
const CERTIFICATE_REQUEST: u8 = 0x0d;
const CERTIFICATE_VERIFY: u8 = 0x0f;
const FINISHED: u8 = 0x14;
const P256_GROUP: u16 = 0x0017;
const AES_128_GCM_SHA256: u16 = 0x1301;
const KEY_LEN: usize = 32;
const UNCOMPRESSED_POINT_LEN: usize = 65;
const MAX_U24: usize = 0x00ff_ffff;

/// An invalid message, negotiation, key or signature during the handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    UnexpectedMessage,
    Framing(transcript::Error),
    ClientHello(client_hello::Error),
    ServerHello(server_hello::Error),
    EncryptedExtensions(encrypted_extensions::Error),
    Certificate(certificate::Error),
    CertificateRequest(certificate_request::Error),
    CertificateVerify(certificate_verify::Error),
    KeySchedule(key_schedule::Error),
    Negotiation,
    KeyShare,
    ClientKey,
    PeerKey,
    Signature,
    CipherSuite,
    MessageTooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnexpectedMessage => "unexpected TLS 1.3 handshake message for this state",
            Self::Framing(_) => "invalid TLS 1.3 handshake framing",
            Self::ClientHello(_) => "invalid TLS-POK ClientHello inputs",
            Self::ServerHello(_) => "invalid TLS 1.3 ServerHello",
            Self::EncryptedExtensions(_) => "invalid TLS 1.3 EncryptedExtensions",
            Self::Certificate(_) => "invalid TLS-POK raw public key Certificate",
            Self::CertificateRequest(_) => "invalid TLS 1.3 CertificateRequest",
            Self::CertificateVerify(_) => "invalid TLS 1.3 CertificateVerify",
            Self::KeySchedule(_) => "TLS 1.3 key schedule or Finished check failed",
            Self::Negotiation => "TLS-POK negotiation was not accepted",
            Self::KeyShare => "key share is not a valid, matching P-256 share",
            Self::ClientKey => "client SPKI is not a P-256 public key",
            Self::PeerKey => "peer SPKI is not a P-256 public key",
            Self::Signature => "ECDSA signature is malformed or does not verify",
            Self::CipherSuite => "only TLS_AES_128_GCM_SHA256 is supported",
            Self::MessageTooLarge => "handshake message exceeds the 24-bit length",
        })
    }
}

impl std::error::Error for Error {}

impl From<transcript::Error> for Error {
    fn from(error: transcript::Error) -> Self {
        Self::Framing(error)
    }
}

impl From<client_hello::Error> for Error {
    fn from(error: client_hello::Error) -> Self {
        Self::ClientHello(error)
    }
}

impl From<server_hello::Error> for Error {
    fn from(error: server_hello::Error) -> Self {
        Self::ServerHello(error)
    }
}

impl From<encrypted_extensions::Error> for Error {
    fn from(error: encrypted_extensions::Error) -> Self {
        Self::EncryptedExtensions(error)
    }
}

impl From<certificate::Error> for Error {
    fn from(error: certificate::Error) -> Self {
        Self::Certificate(error)
    }
}

impl From<certificate_request::Error> for Error {
    fn from(error: certificate_request::Error) -> Self {
        Self::CertificateRequest(error)
    }
}

impl From<certificate_verify::Error> for Error {
    fn from(error: certificate_verify::Error) -> Self {
        Self::CertificateVerify(error)
    }
}

impl From<key_schedule::Error> for Error {
    fn from(error: key_schedule::Error) -> Self {
        Self::KeySchedule(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    AwaitServerHello,
    AwaitEncryptedExtensions,
    AwaitCertificateRequest,
    AwaitCertificate,
    AwaitCertificateVerify,
    AwaitFinished,
    AwaitClientCertificate,
    AwaitClientCertificateVerify,
    AwaitClientFinished,
    Complete,
}

/// Inputs to a client-side TLS-POK handshake.
///
/// `ecdhe_secret` is the 32-byte P-256 ephemeral scalar and `key_share` its
/// uncompressed SEC1 point. `client_spki` is the DER `SubjectPublicKeyInfo` of
/// the client BSK whose signing key signs CertificateVerify; `imported_identity`
/// and `imported_psk` are that BSK's RFC 9258 identity and imported PSK.
#[derive(Clone, Copy)]
pub struct ClientHandshakeParams<'a> {
    pub random: [u8; 32],
    pub legacy_session_id: &'a [u8],
    pub cipher_suite: u16,
    pub ecdhe_secret: &'a [u8],
    pub key_share: &'a [u8],
    pub client_spki: &'a [u8],
    pub imported_identity: &'a ImportedIdentity,
    pub imported_psk: &'a [u8],
}

impl fmt::Debug for ClientHandshakeParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientHandshakeParams")
            .field("random", &self.random)
            .field("legacy_session_id", &self.legacy_session_id)
            .field("cipher_suite", &self.cipher_suite)
            .field("ecdhe_secret", &"[redacted]")
            .field("key_share", &self.key_share)
            .field("client_spki", &self.client_spki)
            .field("imported_identity", &self.imported_identity)
            .field("imported_psk", &"[redacted]")
            .finish()
    }
}

/// Application traffic secrets derived from the completed handshake transcript.
#[derive(Clone)]
pub struct ApplicationSecrets {
    pub client: Zeroizing<[u8; KEY_LEN]>,
    pub server: Zeroizing<[u8; KEY_LEN]>,
}

impl fmt::Debug for ApplicationSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApplicationSecrets { client: [redacted], server: [redacted] }")
    }
}

/// One in-memory client handshake. It is neither reusable nor cloneable: each
/// handshake owns its transcript, secrets and strict message order.
pub struct ClientHandshake {
    stage: Stage,
    transcript: Transcript,
    client_hello: Vec<u8>,
    legacy_session_id: Vec<u8>,
    cipher_suite: u16,
    ecdhe_secret: SecretKey,
    client_spki: Vec<u8>,
    certificate_request_context: Vec<u8>,
    client_verifying_key: p256::ecdsa::VerifyingKey,
    peer_spki: Vec<u8>,
    peer_verifying_key: p256::ecdsa::VerifyingKey,
    imported_psk: Zeroizing<Vec<u8>>,
    handshake_secrets: Option<HandshakeSecrets>,
    application_transcript_hash: Option<[u8; 32]>,
    application_secrets: Option<ApplicationSecrets>,
}

impl fmt::Debug for ClientHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientHandshake")
            .field("stage", &self.stage)
            .finish_non_exhaustive()
    }
}

fn u24(len: usize) -> Result<[u8; 3], Error> {
    if len > MAX_U24 {
        return Err(Error::MessageTooLarge);
    }
    let [_, high, middle, low] = (len as u32).to_be_bytes();
    Ok([high, middle, low])
}

impl ClientHandshake {
    /// Build the ClientHello and start its transcript. Rejects inconsistent
    /// keys, a non-P-256 share, an unsupported cipher suite or a bad identity.
    pub fn new(params: ClientHandshakeParams<'_>, peer_bsk_spki: &[u8]) -> Result<Self, Error> {
        if params.cipher_suite != AES_128_GCM_SHA256 {
            return Err(Error::CipherSuite);
        }
        if params.imported_psk.len() != KEY_LEN {
            return Err(Error::ClientHello(client_hello::Error::InvalidImportedPsk));
        }
        let ecdhe_secret =
            SecretKey::from_slice(params.ecdhe_secret).map_err(|_| Error::KeyShare)?;
        if params.key_share != ecdhe_secret.public_key().to_sec1_point(false).as_bytes() {
            return Err(Error::KeyShare);
        }
        let client_public =
            PublicKey::from_public_key_der(params.client_spki).map_err(|_| Error::ClientKey)?;
        let expected_identity =
            tls_pok::imported_identity(params.client_spki).map_err(|_| Error::ClientKey)?;
        if params.imported_identity != &expected_identity {
            return Err(Error::ClientHello(
                client_hello::Error::InvalidImportedIdentity,
            ));
        }
        let peer_public =
            PublicKey::from_public_key_der(peer_bsk_spki).map_err(|_| Error::PeerKey)?;
        let client_hello = client_hello::build_cert_with_extern_psk(&ClientHelloParams {
            random: params.random,
            legacy_session_id: params.legacy_session_id,
            cipher_suite: params.cipher_suite,
            key_share_group: P256_GROUP,
            key_exchange: params.key_share,
            imported_identity: params.imported_identity,
            imported_psk: params.imported_psk,
        })?;
        let mut transcript = Transcript::new();
        transcript.update(&client_hello)?;
        Ok(Self {
            stage: Stage::AwaitServerHello,
            transcript,
            client_hello,
            legacy_session_id: params.legacy_session_id.to_vec(),
            cipher_suite: params.cipher_suite,
            ecdhe_secret,
            client_spki: params.client_spki.to_vec(),
            certificate_request_context: Vec::new(),
            client_verifying_key: (&client_public).into(),
            peer_spki: peer_bsk_spki.to_vec(),
            peer_verifying_key: (&peer_public).into(),
            imported_psk: Zeroizing::new(params.imported_psk.to_vec()),
            handshake_secrets: None,
            application_transcript_hash: None,
            application_secrets: None,
        })
    }

    /// The framed ClientHello to send through the record layer.
    pub fn client_hello(&self) -> &[u8] {
        &self.client_hello
    }

    /// Handshake traffic secrets, available once the ServerHello was accepted.
    pub fn handshake_secrets(&self) -> Option<&HandshakeSecrets> {
        self.handshake_secrets.as_ref()
    }

    /// Application traffic secrets, available once the handshake completed.
    pub fn application_secrets(&self) -> Option<&ApplicationSecrets> {
        self.application_secrets.as_ref()
    }

    fn expect(&self, expected: Stage) -> Result<(), Error> {
        if self.stage == expected {
            Ok(())
        } else {
            Err(Error::UnexpectedMessage)
        }
    }

    fn incoming<'a>(
        &self,
        expected: Stage,
        kind: u8,
        encoded: &'a [u8],
    ) -> Result<transcript::HandshakeMessage<'a>, Error> {
        self.expect(expected)?;
        let (message, remaining) = transcript::split_message(encoded)?;
        if message.msg_type != kind || !remaining.is_empty() {
            return Err(Error::UnexpectedMessage);
        }
        Ok(message)
    }

    fn append(&mut self, encoded: &[u8], next: Stage) -> Result<(), Error> {
        let mut transcript = self.transcript.clone();
        transcript.update(encoded)?;
        self.transcript = transcript;
        self.stage = next;
        Ok(())
    }

    /// Accept the ServerHello, negotiate TLS-POK and derive handshake secrets.
    pub fn receive_server_hello(&mut self, encoded: &[u8]) -> Result<(), Error> {
        let message = self.incoming(Stage::AwaitServerHello, SERVER_HELLO, encoded)?;
        let (server_hello, negotiated) = server_hello::parse(message.body)?;
        if negotiated.selected_psk != Some(0)
            || !negotiated.cert_with_extern_psk
            || negotiated.early_data
            || server_hello.cipher_suite != self.cipher_suite
            || server_hello.legacy_session_id_echo != self.legacy_session_id
        {
            return Err(Error::Negotiation);
        }
        let Some(share) = negotiated.key_share else {
            return Err(Error::KeyShare);
        };
        if share.group != P256_GROUP
            || share.key_exchange.len() != UNCOMPRESSED_POINT_LEN
            || share.key_exchange[0] != 0x04
        {
            return Err(Error::KeyShare);
        }
        let peer_dhe =
            PublicKey::from_sec1_bytes(share.key_exchange).map_err(|_| Error::KeyShare)?;
        let shared =
            p256::ecdh::diffie_hellman(self.ecdhe_secret.to_nonzero_scalar(), peer_dhe.as_affine());
        let mut dhe_secret = Zeroizing::new([0u8; KEY_LEN]);
        dhe_secret.copy_from_slice(shared.raw_secret_bytes());

        let early = key_schedule::early_secret(&self.imported_psk);
        let mut transcript = self.transcript.clone();
        transcript.update(encoded)?;
        let secrets =
            key_schedule::handshake_secrets(&early[..], &dhe_secret[..], &transcript.hash())?;
        self.transcript = transcript;
        self.handshake_secrets = Some(secrets);
        self.stage = Stage::AwaitEncryptedExtensions;
        Ok(())
    }

    /// Accept EncryptedExtensions, including the raw public key acknowledgement.
    pub fn receive_encrypted_extensions(&mut self, encoded: &[u8]) -> Result<(), Error> {
        let message = self.incoming(
            Stage::AwaitEncryptedExtensions,
            ENCRYPTED_EXTENSIONS,
            encoded,
        )?;
        let extensions = encrypted_extensions::parse(
            message.body,
            encrypted_extensions::ParseParams {
                offered_extensions: &[CLIENT_CERTIFICATE_TYPE_TYPE, SERVER_CERTIFICATE_TYPE_TYPE],
                cert_with_extern_psk: true,
            },
        )?;
        if !extensions
            .iter()
            .any(|extension| extension.kind == CLIENT_CERTIFICATE_TYPE_TYPE)
        {
            return Err(Error::Negotiation);
        }
        self.append(encoded, Stage::AwaitCertificateRequest)
    }

    /// Accept the mandatory TLS-POK CertificateRequest and remember the
    /// request context that the client Certificate must echo.
    pub fn receive_certificate_request(&mut self, encoded: &[u8]) -> Result<(), Error> {
        let message =
            self.incoming(Stage::AwaitCertificateRequest, CERTIFICATE_REQUEST, encoded)?;
        let request = certificate_request::parse(message.body)?;
        self.certificate_request_context = request.certificate_request_context.to_vec();
        self.append(encoded, Stage::AwaitCertificate)
    }

    /// Accept the server's Certificate and pin its raw public key to the BSK
    /// SPKI supplied to [`Self::new`].
    pub fn receive_certificate(&mut self, encoded: &[u8]) -> Result<(), Error> {
        let message = self.incoming(Stage::AwaitCertificate, CERTIFICATE, encoded)?;
        certificate::parse_raw_public_key(message.body, &self.peer_spki)?;
        self.append(encoded, Stage::AwaitCertificateVerify)
    }

    /// Verify the server's CertificateVerify with the pinned P-256 raw key.
    pub fn receive_certificate_verify(&mut self, encoded: &[u8]) -> Result<(), Error> {
        let message = self.incoming(Stage::AwaitCertificateVerify, CERTIFICATE_VERIFY, encoded)?;
        let verified = certificate_verify::parse(message.body)?;
        if verified.algorithm != SignatureScheme::ECDSA_SECP256R1_SHA256 {
            return Err(Error::Signature);
        }
        let signature =
            p256::ecdsa::Signature::from_der(verified.signature).map_err(|_| Error::Signature)?;
        let content = certificate_verify::signed_content(
            CertificateVerifySender::Server,
            &self.transcript.hash(),
        );
        self.peer_verifying_key
            .verify(&content, &signature)
            .map_err(|_| Error::Signature)?;
        self.append(encoded, Stage::AwaitFinished)
    }

    /// Check the server Finished, then make the client Certificate available.
    pub fn receive_finished(&mut self, encoded: &[u8]) -> Result<(), Error> {
        let message = self.incoming(Stage::AwaitFinished, FINISHED, encoded)?;
        let secrets = self
            .handshake_secrets
            .as_ref()
            .ok_or(Error::UnexpectedMessage)?;
        let key = key_schedule::finished_key(&secrets.server_traffic[..])?;
        key_schedule::verify_finished(&key[..], &self.transcript.hash(), message.body)?;
        self.append(encoded, Stage::AwaitClientCertificate)?;
        // RFC 8446 §7.1: application traffic secrets bind the transcript
        // through the server Finished, not the client's later flight.
        self.application_transcript_hash = Some(self.transcript.hash());
        Ok(())
    }

    /// Frame the client's raw-public-key Certificate and append it to the transcript.
    pub fn client_certificate(&mut self) -> Result<Vec<u8>, Error> {
        self.expect(Stage::AwaitClientCertificate)?;
        let mut entry = u24(self.client_spki.len())?.to_vec();
        entry.extend_from_slice(&self.client_spki);
        entry.extend_from_slice(&[0x00, 0x00]);
        let mut body = vec![
            u8::try_from(self.certificate_request_context.len())
                .map_err(|_| Error::MessageTooLarge)?,
        ];
        body.extend_from_slice(&self.certificate_request_context);
        body.extend_from_slice(&u24(entry.len())?);
        body.extend_from_slice(&entry);
        let encoded = transcript::encode_message(CERTIFICATE, &body)?;
        self.append(&encoded, Stage::AwaitClientCertificateVerify)?;
        Ok(encoded)
    }

    /// Bytes for the client BSK signing key to sign with ECDSA-SHA256.
    pub fn client_certificate_verify_content(&self) -> Result<Vec<u8>, Error> {
        self.expect(Stage::AwaitClientCertificateVerify)?;
        Ok(certificate_verify::signed_content(
            CertificateVerifySender::Client,
            &self.transcript.hash(),
        ))
    }

    /// Frame a client CertificateVerify from a DER ECDSA signature by the
    /// client BSK, after checking it against the client's own raw public key.
    pub fn client_certificate_verify(&mut self, der_signature: &[u8]) -> Result<Vec<u8>, Error> {
        self.expect(Stage::AwaitClientCertificateVerify)?;
        let signature =
            p256::ecdsa::Signature::from_der(der_signature).map_err(|_| Error::Signature)?;
        let content = self.client_certificate_verify_content()?;
        self.client_verifying_key
            .verify(&content, &signature)
            .map_err(|_| Error::Signature)?;
        let mut body = SignatureScheme::ECDSA_SECP256R1_SHA256
            .0
            .to_be_bytes()
            .to_vec();
        body.extend_from_slice(
            &u16::try_from(der_signature.len())
                .map_err(|_| Error::MessageTooLarge)?
                .to_be_bytes(),
        );
        body.extend_from_slice(der_signature);
        let encoded = transcript::encode_message(CERTIFICATE_VERIFY, &body)?;
        self.append(&encoded, Stage::AwaitClientFinished)?;
        Ok(encoded)
    }

    /// Frame the client Finished and derive application traffic secrets from
    /// the resulting transcript hash.
    pub fn client_finished(&mut self) -> Result<Vec<u8>, Error> {
        self.expect(Stage::AwaitClientFinished)?;
        let handshake = self
            .handshake_secrets
            .as_ref()
            .ok_or(Error::UnexpectedMessage)?;
        let key = key_schedule::finished_key(&handshake.client_traffic[..])?;
        let verify_data = key_schedule::finished_verify_data(&key[..], &self.transcript.hash())?;
        let encoded = transcript::encode_message(FINISHED, &verify_data[..])?;

        self.transcript.update(&encoded)?;
        let master = key_schedule::master_secret(&handshake.handshake_secret[..])?;
        let hash = self
            .application_transcript_hash
            .ok_or(Error::UnexpectedMessage)?;
        let client = key_schedule::traffic_secret(&master[..], b"c ap traffic", &hash)?;
        let server = key_schedule::traffic_secret(&master[..], b"s ap traffic", &hash)?;
        self.application_secrets = Some(ApplicationSecrets { client, server });
        self.stage = Stage::Complete;
        Ok(encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls13::external_psk::import_external_psk;
    use crate::tls13::psk_extension::{
        CERT_WITH_EXTERN_PSK_TYPE, EARLY_DATA_TYPE, KEY_SHARE_TYPE, PRE_SHARED_KEY_TYPE,
    };
    use crate::tls13::tls_pok;
    use p256::ecdsa::signature::{Signer, Verifier};
    use p256::pkcs8::EncodePublicKey;

    const SESSION_ID: &[u8] = b"qid-session";

    struct Fixture {
        client_bsk: [u8; 32],
        server_bsk: [u8; 32],
        client_ecdhe: [u8; 32],
        server_ecdhe: [u8; 32],
        client_spki: Vec<u8>,
        server_spki: Vec<u8>,
        client_share: Vec<u8>,
        server_share: Vec<u8>,
        identity: ImportedIdentity,
        imported_psk: Zeroizing<Vec<u8>>,
    }

    #[derive(Clone, Copy)]
    struct ServerHelloOptions<'a> {
        selected: u16,
        cert_with_extern_psk: bool,
        early_data: bool,
        group: u16,
        cipher_suite: u16,
        session_id: &'a [u8],
    }

    impl Default for ServerHelloOptions<'static> {
        fn default() -> Self {
            Self {
                selected: 0,
                cert_with_extern_psk: true,
                early_data: false,
                group: P256_GROUP,
                cipher_suite: AES_128_GCM_SHA256,
                session_id: SESSION_ID,
            }
        }
    }

    fn secret(bytes: &[u8; 32]) -> SecretKey {
        SecretKey::from_slice(bytes).expect("valid P-256 scalar")
    }

    fn spki(key: &SecretKey) -> Vec<u8> {
        key.public_key()
            .to_public_key_der()
            .expect("encode P-256 SPKI")
            .as_bytes()
            .to_vec()
    }

    fn share(key: &SecretKey) -> Vec<u8> {
        key.public_key().to_sec1_point(false).as_bytes().to_vec()
    }

    fn fixture() -> Fixture {
        let client_bsk = [0x11; 32];
        let server_bsk = [0x22; 32];
        let client_ecdhe = [0x33; 32];
        let server_ecdhe = [0x44; 32];
        let client_spki = spki(&secret(&client_bsk));
        let identity = tls_pok::imported_identity(&client_spki).expect("TLS-POK identity");
        let imported_psk = import_external_psk(&client_spki, &identity).expect("imported PSK");
        Fixture {
            client_bsk,
            server_bsk,
            client_ecdhe,
            server_ecdhe,
            server_spki: spki(&secret(&server_bsk)),
            client_share: share(&secret(&client_ecdhe)),
            server_share: share(&secret(&server_ecdhe)),
            client_spki,
            identity,
            imported_psk,
        }
    }

    fn client(fx: &Fixture) -> ClientHandshake {
        ClientHandshake::new(
            ClientHandshakeParams {
                random: [0x5a; 32],
                legacy_session_id: SESSION_ID,
                cipher_suite: AES_128_GCM_SHA256,
                ecdhe_secret: &fx.client_ecdhe,
                key_share: &fx.client_share,
                client_spki: &fx.client_spki,
                imported_identity: &fx.identity,
                imported_psk: &fx.imported_psk,
            },
            &fx.server_spki,
        )
        .expect("build TLS-POK client")
    }

    fn push_extension(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(body);
    }

    fn server_hello(fx: &Fixture, options: ServerHelloOptions<'_>) -> Vec<u8> {
        let mut extensions = Vec::new();
        push_extension(
            &mut extensions,
            PRE_SHARED_KEY_TYPE,
            &options.selected.to_be_bytes(),
        );
        let point = if options.group == P256_GROUP {
            fx.server_share.clone()
        } else {
            vec![0x55; 32]
        };
        let mut key_share = options.group.to_be_bytes().to_vec();
        key_share.extend_from_slice(&u16::try_from(point.len()).unwrap().to_be_bytes());
        key_share.extend_from_slice(&point);
        push_extension(&mut extensions, KEY_SHARE_TYPE, &key_share);
        push_extension(&mut extensions, 0x002b, &[0x03, 0x04]);
        if options.cert_with_extern_psk {
            push_extension(&mut extensions, CERT_WITH_EXTERN_PSK_TYPE, &[]);
        }
        if options.early_data {
            push_extension(&mut extensions, EARLY_DATA_TYPE, &[]);
        }

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x77; 32]);
        body.push(u8::try_from(options.session_id.len()).unwrap());
        body.extend_from_slice(options.session_id);
        body.extend_from_slice(&options.cipher_suite.to_be_bytes());
        body.push(0x00);
        body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&extensions);
        transcript::encode_message(SERVER_HELLO, &body).unwrap()
    }

    fn encrypted_extensions(raw_public_key: bool) -> Vec<u8> {
        let mut extensions = Vec::new();
        if raw_public_key {
            push_extension(
                &mut extensions,
                CLIENT_CERTIFICATE_TYPE_TYPE,
                &[tls_pok::RAW_PUBLIC_KEY],
            );
        }
        let mut body = u16::try_from(extensions.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        body.extend_from_slice(&extensions);
        transcript::encode_message(ENCRYPTED_EXTENSIONS, &body).unwrap()
    }

    fn certificate_request_message() -> Vec<u8> {
        let extensions = [0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04];
        let mut body = vec![0x00];
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        transcript::encode_message(CERTIFICATE_REQUEST, &body).unwrap()
    }

    fn raw_public_key_body(spki: &[u8]) -> Vec<u8> {
        let mut entry = u24(spki.len()).unwrap().to_vec();
        entry.extend_from_slice(spki);
        entry.extend_from_slice(&[0x00, 0x00]);
        let mut body = vec![0x00];
        body.extend_from_slice(&u24(entry.len()).unwrap());
        body.extend_from_slice(&entry);
        body
    }

    fn certificate_message(spki: &[u8]) -> Vec<u8> {
        transcript::encode_message(CERTIFICATE, &raw_public_key_body(spki)).unwrap()
    }

    fn signature(key: &[u8; 32], content: &[u8]) -> Vec<u8> {
        let signing_key: p256::ecdsa::SigningKey = secret(key).into();
        let signed: p256::ecdsa::Signature = signing_key.sign(content);
        signed.to_der().as_bytes().to_vec()
    }

    fn certificate_verify_message(client: &ClientHandshake, signer: &[u8; 32]) -> Vec<u8> {
        let content = certificate_verify::signed_content(
            CertificateVerifySender::Server,
            &client.transcript.hash(),
        );
        let der = signature(signer, &content);
        let mut body = SignatureScheme::ECDSA_SECP256R1_SHA256
            .0
            .to_be_bytes()
            .to_vec();
        body.extend_from_slice(&u16::try_from(der.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&der);
        transcript::encode_message(CERTIFICATE_VERIFY, &body).unwrap()
    }

    fn finished_message(client: &ClientHandshake, corrupt: bool) -> Vec<u8> {
        let handshake = client.handshake_secrets().unwrap();
        let key = key_schedule::finished_key(&handshake.server_traffic[..]).unwrap();
        let mut verify_data =
            key_schedule::finished_verify_data(&key[..], &client.transcript.hash())
                .unwrap()
                .to_vec();
        if corrupt {
            verify_data[0] ^= 0x01;
        }
        transcript::encode_message(FINISHED, &verify_data).unwrap()
    }

    fn advance_to_client_certificate(fx: &Fixture, client: &mut ClientHandshake) {
        client
            .receive_server_hello(&server_hello(fx, ServerHelloOptions::default()))
            .unwrap();
        client
            .receive_encrypted_extensions(&encrypted_extensions(true))
            .unwrap();
        client
            .receive_certificate_request(&certificate_request_message())
            .unwrap();
        client
            .receive_certificate(&certificate_message(&fx.server_spki))
            .unwrap();
        let verify = certificate_verify_message(client, &fx.server_bsk);
        client.receive_certificate_verify(&verify).unwrap();
        let finished = finished_message(client, false);
        client.receive_finished(&finished).unwrap();
    }

    #[test]
    fn completes_both_authentication_legs_and_derives_application_secrets() {
        let fx = fixture();
        let mut client = client(&fx);
        assert_eq!(client.client_hello()[0], 0x01);
        // RFC 8446 4.2.8 and Appendix B.3.1: the extension body carries a
        // KeyShareEntry vector, then secp256r1 group 0x0017 and its point.
        assert!(
            client.client_hello().windows(10).any(
                |window| window == [0x00, 0x33, 0x00, 0x47, 0x00, 0x45, 0x00, 0x17, 0x00, 0x41]
            )
        );
        assert!(client.handshake_secrets().is_none());
        assert!(client.application_secrets().is_none());

        let hello = server_hello(&fx, ServerHelloOptions::default());
        client.receive_server_hello(&hello).unwrap();
        let hello_hash = client.transcript.hash();
        assert_ne!(
            &client.handshake_secrets().unwrap().client_traffic[..],
            &client.handshake_secrets().unwrap().server_traffic[..]
        );
        let (client_traffic, server_traffic) = {
            let secrets = client.handshake_secrets().unwrap();
            (*secrets.client_traffic, *secrets.server_traffic)
        };

        let extensions = encrypted_extensions(true);
        client.receive_encrypted_extensions(&extensions).unwrap();
        let certificate_request = certificate_request_message();
        client
            .receive_certificate_request(&certificate_request)
            .unwrap();
        let server_certificate = certificate_message(&fx.server_spki);
        client.receive_certificate(&server_certificate).unwrap();
        let server_verify = certificate_verify_message(&client, &fx.server_bsk);
        client.receive_certificate_verify(&server_verify).unwrap();
        let server_finished = finished_message(&client, false);
        client.receive_finished(&server_finished).unwrap();

        let client_certificate = client.client_certificate().unwrap();
        assert_eq!(
            certificate::parse(&client_certificate[4..])
                .unwrap()
                .entries[0]
                .cert_data,
            fx.client_spki
        );
        let content = client.client_certificate_verify_content().unwrap();
        assert_eq!(content.len(), 64 + 33 + 1 + 32);
        let client_der = signature(&fx.client_bsk, &content);
        let client_verifier =
            p256::ecdsa::VerifyingKey::from_public_key_der(&fx.client_spki).unwrap();
        client_verifier
            .verify(
                &content,
                &p256::ecdsa::Signature::from_der(&client_der).unwrap(),
            )
            .expect("client signature verifies against its raw public key");
        let client_verify = client.client_certificate_verify(&client_der).unwrap();
        let client_finished = client.client_finished().unwrap();
        assert_eq!(client_finished.len(), 4 + KEY_LEN);
        let application = client.application_secrets().unwrap();

        // Recompute the whole schedule independently from the wire messages.
        let early = key_schedule::early_secret(&fx.imported_psk);
        let shared = p256::ecdh::diffie_hellman(
            secret(&fx.client_ecdhe).to_nonzero_scalar(),
            secret(&fx.server_ecdhe).public_key().as_affine(),
        );
        let mut dhe_secret = [0u8; KEY_LEN];
        dhe_secret.copy_from_slice(shared.raw_secret_bytes());
        let mut transcript = Transcript::new();
        transcript.update(client.client_hello()).unwrap();
        transcript.update(&hello).unwrap();
        assert_eq!(transcript.hash(), hello_hash);
        let expected_handshake =
            key_schedule::handshake_secrets(&early[..], &dhe_secret, &transcript.hash()).unwrap();
        assert_eq!(&expected_handshake.client_traffic[..], &client_traffic[..]);
        assert_eq!(&expected_handshake.server_traffic[..], &server_traffic[..]);

        let mut server_transcript = transcript.clone();
        for message in [
            &extensions,
            &certificate_request,
            &server_certificate,
            &server_verify,
        ] {
            server_transcript.update(message).unwrap();
        }
        let server_finished_key =
            key_schedule::finished_key(&expected_handshake.server_traffic[..]).unwrap();
        key_schedule::verify_finished(
            &server_finished_key[..],
            &server_transcript.hash(),
            &server_finished[4..],
        )
        .expect("server Finished matches the independent transcript");

        for message in [
            &extensions,
            &certificate_request,
            &server_certificate,
            &server_verify,
        ] {
            transcript.update(message).unwrap();
        }
        transcript.update(&server_finished).unwrap();
        let server_finished_hash = transcript.hash();
        for message in [&client_certificate, &client_verify] {
            transcript.update(message).unwrap();
        }
        let before_client_finished = transcript.hash();
        let client_finished_key = key_schedule::finished_key(&client_traffic[..]).unwrap();
        let expected_verify_data =
            key_schedule::finished_verify_data(&client_finished_key[..], &before_client_finished)
                .unwrap();
        assert_eq!(&client_finished[4..], &expected_verify_data[..]);

        transcript.update(&client_finished).unwrap();
        let master = key_schedule::master_secret(&expected_handshake.handshake_secret[..]).unwrap();
        let hash = server_finished_hash;
        assert_eq!(
            &key_schedule::traffic_secret(&master[..], b"c ap traffic", &hash).unwrap()[..],
            &application.client[..]
        );
        assert_eq!(
            &key_schedule::traffic_secret(&master[..], b"s ap traffic", &hash).unwrap()[..],
            &application.server[..]
        );
    }

    #[test]
    fn rejects_bad_server_hello_negotiation_without_changing_state() {
        let fx = fixture();
        let mut client = client(&fx);
        for options in [
            ServerHelloOptions {
                selected: 1,
                ..ServerHelloOptions::default()
            },
            ServerHelloOptions {
                cert_with_extern_psk: false,
                ..ServerHelloOptions::default()
            },
            ServerHelloOptions {
                group: 0x001d + 1,
                ..ServerHelloOptions::default()
            },
            ServerHelloOptions {
                session_id: b"other-session",
                ..ServerHelloOptions::default()
            },
        ] {
            assert!(
                client
                    .receive_server_hello(&server_hello(&fx, options))
                    .is_err()
            );
            assert!(client.handshake_secrets().is_none());
        }
        let early = ServerHelloOptions {
            early_data: true,
            ..ServerHelloOptions::default()
        };
        assert!(matches!(
            client.receive_server_hello(&server_hello(&fx, early)),
            Err(Error::ServerHello(server_hello::Error::InvalidNegotiation))
        ));
        client
            .receive_server_hello(&server_hello(&fx, ServerHelloOptions::default()))
            .expect("valid ServerHello still accepted after rejected ones");
        assert_eq!(
            client.receive_encrypted_extensions(&encrypted_extensions(false)),
            Err(Error::Negotiation)
        );
    }

    #[test]
    fn echoes_the_certificate_request_context() {
        let fx = fixture();
        let mut client = client(&fx);
        client
            .receive_server_hello(&server_hello(&fx, ServerHelloOptions::default()))
            .unwrap();
        client
            .receive_encrypted_extensions(&encrypted_extensions(true))
            .unwrap();
        let extensions = [0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04];
        let mut body = vec![3];
        body.extend_from_slice(b"ctx");
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let request = transcript::encode_message(CERTIFICATE_REQUEST, &body).unwrap();
        client.receive_certificate_request(&request).unwrap();
        assert_eq!(client.certificate_request_context, b"ctx");
    }

    #[test]
    fn rejects_wrong_peer_key_bad_signature_and_bad_finished() {
        let fx = fixture();
        let mut client = client(&fx);
        client
            .receive_server_hello(&server_hello(&fx, ServerHelloOptions::default()))
            .unwrap();
        client
            .receive_encrypted_extensions(&encrypted_extensions(true))
            .unwrap();
        client
            .receive_certificate_request(&certificate_request_message())
            .unwrap();

        let wrong_key = spki(&secret(&[0x99; 32]));
        assert_eq!(
            client.receive_certificate(&certificate_message(&wrong_key)),
            Err(Error::Certificate(certificate::Error::RawPublicKeyMismatch))
        );
        let correct = certificate_message(&fx.server_spki);
        client.receive_certificate(&correct).unwrap();

        let wrong_signer = certificate_verify_message(&client, &[0x88; 32]);
        assert_eq!(
            client.receive_certificate_verify(&wrong_signer),
            Err(Error::Signature)
        );
        let good_signer = certificate_verify_message(&client, &fx.server_bsk);
        client.receive_certificate_verify(&good_signer).unwrap();

        let bad_finished = finished_message(&client, true);
        assert_eq!(
            client.receive_finished(&bad_finished),
            Err(Error::KeySchedule(key_schedule::Error::FinishedMismatch))
        );
        let good_finished = finished_message(&client, false);
        client.receive_finished(&good_finished).unwrap();
        assert!(client.application_secrets().is_none());
    }

    #[test]
    fn rejects_out_of_order_and_unexpected_messages() {
        let fx = fixture();
        let mut client = client(&fx);
        let certificate = certificate_message(&fx.server_spki);
        assert_eq!(
            client.receive_certificate(&certificate),
            Err(Error::UnexpectedMessage)
        );
        assert_eq!(
            client.receive_encrypted_extensions(&encrypted_extensions(true)),
            Err(Error::UnexpectedMessage)
        );
        assert_eq!(client.client_certificate(), Err(Error::UnexpectedMessage));
        assert_eq!(
            client.client_certificate_verify_content(),
            Err(Error::UnexpectedMessage)
        );

        let hello = server_hello(&fx, ServerHelloOptions::default());
        client.receive_server_hello(&hello).unwrap();
        assert_eq!(
            client.receive_server_hello(&hello),
            Err(Error::UnexpectedMessage)
        );
        let mut trailing = hello.clone();
        trailing.push(0);
        assert_eq!(
            client.receive_server_hello(&trailing),
            Err(Error::UnexpectedMessage)
        );
        let ch = client.client_hello().to_vec();
        assert_eq!(
            client.receive_server_hello(&ch),
            Err(Error::UnexpectedMessage)
        );
        client
            .receive_encrypted_extensions(&encrypted_extensions(true))
            .unwrap();
        client
            .receive_certificate_request(&certificate_request_message())
            .unwrap();
        assert_eq!(
            client.receive_finished(&finished_message(&client, false)),
            Err(Error::UnexpectedMessage)
        );
        client.receive_certificate(&certificate).unwrap();
        assert_eq!(
            client.receive_certificate(&certificate),
            Err(Error::UnexpectedMessage)
        );
        let verify = certificate_verify_message(&client, &fx.server_bsk);
        client.receive_certificate_verify(&verify).unwrap();
        assert_eq!(
            client.receive_certificate_verify(&verify),
            Err(Error::UnexpectedMessage)
        );
        assert_eq!(client.client_certificate(), Err(Error::UnexpectedMessage));
        let finished = finished_message(&client, false);
        client.receive_finished(&finished).unwrap();
        assert_eq!(
            client.receive_finished(&finished),
            Err(Error::UnexpectedMessage)
        );
    }

    #[test]
    fn rejects_wrong_client_signature_and_runs_to_completion() {
        let fx = fixture();
        let mut client = client(&fx);
        advance_to_client_certificate(&fx, &mut client);
        client.client_certificate().unwrap();
        let content = client.client_certificate_verify_content().unwrap();
        assert_eq!(
            client.client_certificate_verify(&signature(&[0x77; 32], &content)),
            Err(Error::Signature)
        );
        assert_eq!(
            client.client_certificate_verify(&[0x30, 0x00]),
            Err(Error::Signature)
        );
        let der = signature(&fx.client_bsk, &content);
        client.client_certificate_verify(&der).unwrap();
        assert_eq!(
            client.client_certificate_verify(&der),
            Err(Error::UnexpectedMessage)
        );
        client.client_finished().unwrap();
        assert_eq!(client.client_finished(), Err(Error::UnexpectedMessage));
        assert_eq!(
            client.client_certificate_verify_content(),
            Err(Error::UnexpectedMessage)
        );
    }

    #[test]
    fn rejects_invalid_construction_inputs() {
        let fx = fixture();
        let identity = tls_pok::imported_identity(&fx.client_spki).unwrap();
        for (suite, share, spki, psk) in [
            (
                0x1302,
                fx.client_share.as_slice(),
                fx.client_spki.as_slice(),
                fx.imported_psk.as_slice(),
            ),
            (
                AES_128_GCM_SHA256,
                &fx.server_share,
                fx.client_spki.as_slice(),
                fx.imported_psk.as_slice(),
            ),
            (
                AES_128_GCM_SHA256,
                fx.client_share.as_slice(),
                &fx.server_spki,
                fx.imported_psk.as_slice(),
            ),
            (
                AES_128_GCM_SHA256,
                fx.client_share.as_slice(),
                fx.client_spki.as_slice(),
                &[0x00; 16],
            ),
        ] {
            assert!(
                ClientHandshake::new(
                    ClientHandshakeParams {
                        random: [0x01; 32],
                        legacy_session_id: SESSION_ID,
                        cipher_suite: suite,
                        ecdhe_secret: &fx.client_ecdhe,
                        key_share: share,
                        client_spki: spki,
                        imported_identity: &identity,
                        imported_psk: psk,
                    },
                    &fx.server_spki,
                )
                .is_err()
            );
        }
        assert!(
            ClientHandshake::new(
                ClientHandshakeParams {
                    random: [0x01; 32],
                    legacy_session_id: SESSION_ID,
                    cipher_suite: AES_128_GCM_SHA256,
                    ecdhe_secret: &fx.client_ecdhe,
                    key_share: &fx.client_share,
                    client_spki: &fx.client_spki,
                    imported_identity: &identity,
                    imported_psk: &fx.imported_psk,
                },
                b"not a P-256 SPKI",
            )
            .is_err()
        );
    }

    #[test]
    fn debug_output_redacts_secret_material() {
        let fx = fixture();
        let mut client = client(&fx);
        advance_to_client_certificate(&fx, &mut client);
        client.client_certificate().unwrap();
        let content = client.client_certificate_verify_content().unwrap();
        let der = signature(&fx.client_bsk, &content);
        client.client_certificate_verify(&der).unwrap();
        client.client_finished().unwrap();

        let params = ClientHandshakeParams {
            random: [0x5a; 32],
            legacy_session_id: SESSION_ID,
            cipher_suite: AES_128_GCM_SHA256,
            ecdhe_secret: &fx.client_ecdhe,
            key_share: &fx.client_share,
            client_spki: &fx.client_spki,
            imported_identity: &fx.identity,
            imported_psk: &fx.imported_psk,
        };
        let params_debug = format!("{params:?}");
        assert!(!params_debug.contains(&hex::encode(fx.client_ecdhe)));
        assert!(!params_debug.contains(&hex::encode(&fx.imported_psk[..])));
        let debug = format!("{client:?}");
        let secrets = client.application_secrets().unwrap();
        assert!(!debug.contains(&hex::encode(&fx.imported_psk[..])));
        assert!(!debug.contains(&hex::encode(&secrets.client[..])));
        assert!(!debug.contains(&hex::encode(&secrets.server[..])));
        assert_eq!(
            format!("{secrets:?}"),
            "ApplicationSecrets { client: [redacted], server: [redacted] }"
        );
    }
}
