//! Minimal in-memory TLS 1.3 record-layer driver for the TLS-POK client.
//!
//! [`super::client::ClientHandshake`] consumes one framed handshake message at
//! a time; this module supplies the record framing and traffic protection
//! around it. The ServerHello arrives in a plaintext handshake record; the
//! rest of the server flight arrives in application-data records protected
//! under the server handshake traffic secret. The client's final flight is
//! emitted as one protected record per handshake message.
//!
//! There is no socket, I/O trait, buffering across records or async here: the
//! caller passes exactly one complete record at a time. The caller also keeps
//! the client BSK signing key and supplies only its DER signature.

use super::client::{self, ApplicationSecrets, ClientHandshake, ClientHandshakeParams};
use super::transcript;
use super::{ReadEpoch, RecordError, WriteEpoch};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

const HEADER_LEN: usize = 5;
// RFC 8446 §5.1: a plaintext fragment must fit in one record; fragmentation
// across records is outside this minimal driver.
const MAX_PLAINTEXT_FRAGMENT: usize = 1 << 14;
const LEGACY_VERSION: [u8; 2] = [0x03, 0x03];
const HANDSHAKE: u8 = 0x16;
const APPLICATION_DATA: u8 = 0x17;
// RFC 8446 Appendix D.4: a TLS 1.3 peer may send a dummy ChangeCipherSpec
// for middlebox compatibility. It carries only 0x01 and is not part of the
// handshake transcript, so the receiver must ignore it.
const CHANGE_CIPHER_SPEC: u8 = 0x14;
const SERVER_HELLO: u8 = 0x02;
const ENCRYPTED_EXTENSIONS: u8 = 0x08;
const CERTIFICATE: u8 = 0x0b;
const CERTIFICATE_REQUEST: u8 = 0x0d;
const CERTIFICATE_VERIFY: u8 = 0x0f;
const FINISHED: u8 = 0x14;
const TRAFFIC_SECRET_LEN: usize = 32;

/// Progress of the record-layer handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordStage {
    AwaitServerHello,
    AwaitServerFlight,
    AwaitClientSignature,
    AwaitClientFlight,
    Complete,
    /// A framing or authentication failure is terminal for this driver.
    Failed,
}

/// An invalid record, handshake message or call order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The record or method is not valid for the current stage.
    State,
    /// The outer record type or the inner content type is not the required one.
    WrongRecordType,
    /// A handshake message was not the next expected server message.
    UnexpectedHandshakeMessage,
    /// A ClientHello cannot fit in a TLS record length field.
    RecordTooLarge,
    Handshake(client::Error),
    Record(RecordError),
    Framing(transcript::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::State => "TLS 1.3 record operation is invalid in this state",
            Self::WrongRecordType => "unexpected TLS 1.3 record or inner content type",
            Self::UnexpectedHandshakeMessage => "unexpected TLS 1.3 handshake message",
            Self::RecordTooLarge => "TLS 1.3 record exceeds the length field",
            Self::Handshake(_) => "TLS-POK handshake message was rejected",
            Self::Record(_) => "TLS 1.3 record protection failed",
            Self::Framing(_) => "invalid TLS 1.3 handshake framing",
        })
    }
}

impl std::error::Error for Error {}

impl From<client::Error> for Error {
    fn from(error: client::Error) -> Self {
        Self::Handshake(error)
    }
}

impl From<RecordError> for Error {
    fn from(error: RecordError) -> Self {
        Self::Record(error)
    }
}

impl From<transcript::Error> for Error {
    fn from(error: transcript::Error) -> Self {
        Self::Framing(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServerMessage {
    EncryptedExtensions,
    CertificateRequest,
    Certificate,
    CertificateVerify,
    Finished,
}

/// Application-direction epochs derived only after the handshake completes.
/// Both start at record sequence zero and are independent of the handshake
/// epochs, which are discarded on completion.
pub struct ApplicationEpochs {
    pub client_write: WriteEpoch,
    pub server_read: ReadEpoch,
}

impl fmt::Debug for ApplicationEpochs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApplicationEpochs { client_write: [redacted], server_read: [redacted] }")
    }
}

/// One TLS-POK client handshake driven by complete TLS 1.3 records.
///
/// A failure is terminal: the driver enters [`RecordStage::Failed`], drops its
/// epochs and rejects every later call. Secrets are never included in `Debug`.
pub struct TlsPokClient {
    handshake: ClientHandshake,
    stage: RecordStage,
    next_server_message: ServerMessage,
    server_handshake_read: Option<ReadEpoch>,
    client_handshake_write: Option<WriteEpoch>,
    client_certificate: Option<Vec<u8>>,
    application_epochs_issued: bool,
}

impl fmt::Debug for TlsPokClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsPokClient")
            .field("stage", &self.stage)
            .finish_non_exhaustive()
    }
}

impl TlsPokClient {
    /// Wrap a fresh offline TLS-POK handshake for a peer pinned to `peer_bsk_spki`.
    pub fn new(params: ClientHandshakeParams<'_>, peer_bsk_spki: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            handshake: ClientHandshake::new(params, peer_bsk_spki)?,
            stage: RecordStage::AwaitServerHello,
            next_server_message: ServerMessage::EncryptedExtensions,
            server_handshake_read: None,
            client_handshake_write: None,
            client_certificate: None,
            application_epochs_issued: false,
        })
    }

    /// Current record-layer stage.
    pub fn stage(&self) -> RecordStage {
        self.stage
    }

    /// The complete plaintext ClientHello record to send first.
    pub fn client_hello_record(&self) -> Result<Vec<u8>, Error> {
        let hello = self.handshake.client_hello();
        if hello.len() > MAX_PLAINTEXT_FRAGMENT {
            return Err(Error::RecordTooLarge);
        }
        let length = u16::try_from(hello.len()).map_err(|_| Error::RecordTooLarge)?;
        let [high, low] = length.to_be_bytes();
        let mut record = Vec::with_capacity(HEADER_LEN + hello.len());
        record.extend_from_slice(&[HANDSHAKE, LEGACY_VERSION[0], LEGACY_VERSION[1], high, low]);
        record.extend_from_slice(hello);
        Ok(record)
    }

    /// A middlebox-compatibility ChangeCipherSpec has a TLS record header and a
    /// single-byte 0x01 payload. Anything else is not ignored.
    fn is_change_cipher_spec(record: &[u8]) -> bool {
        record
            == [
                CHANGE_CIPHER_SPEC,
                LEGACY_VERSION[0],
                LEGACY_VERSION[1],
                0x00,
                0x01,
                0x01,
            ]
    }

    /// Consume exactly one complete record from the server.
    ///
    /// The whole buffer is zeroized on every error, including framing errors
    /// that the epoch itself does not classify as an authentication failure.
    pub fn receive_record(&mut self, record: &mut [u8]) -> Result<(), Error> {
        if matches!(
            self.stage,
            RecordStage::AwaitServerHello | RecordStage::AwaitServerFlight
        ) && Self::is_change_cipher_spec(record)
        {
            return Ok(());
        }
        match self.stage {
            RecordStage::AwaitServerHello => self.receive_server_hello_record(record),
            RecordStage::AwaitServerFlight => self.receive_server_flight_record(record),
            _ => {
                record.zeroize();
                Err(Error::State)
            }
        }
    }

    fn receive_server_hello_record(&mut self, record: &mut [u8]) -> Result<(), Error> {
        let epochs = (|| -> Result<(ReadEpoch, WriteEpoch), Error> {
            if record.len() < HEADER_LEN
                || record[..3] != [HANDSHAKE, LEGACY_VERSION[0], LEGACY_VERSION[1]]
            {
                return Err(Error::WrongRecordType);
            }
            let length = usize::from(u16::from_be_bytes([record[3], record[4]]));
            let available = record.len() - HEADER_LEN;
            if length > available {
                return Err(Error::Framing(transcript::Error::TruncatedBody));
            }
            if length < available {
                return Err(Error::Framing(transcript::Error::TrailingBytes));
            }
            let (message, remaining) = transcript::split_message(&record[HEADER_LEN..])?;
            if !remaining.is_empty() {
                return Err(Error::Framing(transcript::Error::TrailingBytes));
            }
            if message.msg_type != SERVER_HELLO {
                return Err(Error::UnexpectedHandshakeMessage);
            }
            self.handshake.receive_server_hello(message.encoded)?;
            let secrets = self.handshake.handshake_secrets().ok_or(Error::State)?;
            let client_traffic: Zeroizing<[u8; TRAFFIC_SECRET_LEN]> =
                Zeroizing::new(*secrets.client_traffic);
            let server_traffic: Zeroizing<[u8; TRAFFIC_SECRET_LEN]> =
                Zeroizing::new(*secrets.server_traffic);
            Ok((
                ReadEpoch::aes_128_gcm_sha256(&server_traffic)?,
                WriteEpoch::aes_128_gcm_sha256(&client_traffic)?,
            ))
        })();
        match epochs {
            Ok((server_read, client_write)) => {
                self.server_handshake_read = Some(server_read);
                self.client_handshake_write = Some(client_write);
                self.stage = RecordStage::AwaitServerFlight;
                Ok(())
            }
            Err(error) => Err(self.fail(record, error)),
        }
    }

    fn receive_server_flight_record(&mut self, record: &mut [u8]) -> Result<(), Error> {
        if record.len() < HEADER_LEN || record[0] != APPLICATION_DATA {
            return Err(self.fail(record, Error::WrongRecordType));
        }
        let Some(reader) = self.server_handshake_read.as_mut() else {
            return Err(self.fail(record, Error::State));
        };
        let opened = reader.open(record);
        let (content_type, content) = match opened {
            Ok(inner) => (inner.content_type, inner.content.to_vec()),
            Err(error) => return Err(self.fail(record, error.into())),
        };
        if content_type != HANDSHAKE {
            return Err(self.fail(record, Error::WrongRecordType));
        }
        let mut messages = Vec::new();
        let mut remaining = content.as_slice();
        while !remaining.is_empty() {
            match transcript::split_message(remaining) {
                Ok((message, rest)) => {
                    messages.push((message.msg_type, message.encoded.to_vec()));
                    remaining = rest;
                }
                Err(error) => return Err(self.fail(record, error.into())),
            }
        }
        for (kind, encoded) in messages {
            if let Err(error) = self.dispatch(kind, &encoded) {
                return Err(self.fail(record, error));
            }
        }
        Ok(())
    }

    fn dispatch(&mut self, kind: u8, encoded: &[u8]) -> Result<(), Error> {
        let expected = match self.next_server_message {
            ServerMessage::EncryptedExtensions => ENCRYPTED_EXTENSIONS,
            ServerMessage::CertificateRequest => CERTIFICATE_REQUEST,
            ServerMessage::Certificate => CERTIFICATE,
            ServerMessage::CertificateVerify => CERTIFICATE_VERIFY,
            ServerMessage::Finished => FINISHED,
        };
        if kind != expected {
            return Err(Error::UnexpectedHandshakeMessage);
        }
        match self.next_server_message {
            ServerMessage::EncryptedExtensions => {
                self.handshake.receive_encrypted_extensions(encoded)?;
                self.next_server_message = ServerMessage::CertificateRequest;
            }
            ServerMessage::CertificateRequest => {
                self.handshake.receive_certificate_request(encoded)?;
                self.next_server_message = ServerMessage::Certificate;
            }
            ServerMessage::Certificate => {
                self.handshake.receive_certificate(encoded)?;
                self.next_server_message = ServerMessage::CertificateVerify;
            }
            ServerMessage::CertificateVerify => {
                self.handshake.receive_certificate_verify(encoded)?;
                self.next_server_message = ServerMessage::Finished;
            }
            ServerMessage::Finished => {
                self.handshake.receive_finished(encoded)?;
                self.stage = RecordStage::AwaitClientSignature;
            }
        }
        Ok(())
    }

    /// Frame the client Certificate and return what the client BSK key signs.
    ///
    /// Called once, after the server Finished. The framed certificate is held
    /// until [`Self::complete_client_flight`] protects it.
    pub fn pending_client_signature_content(&mut self) -> Result<Vec<u8>, Error> {
        if self.stage != RecordStage::AwaitClientSignature {
            return Err(Error::State);
        }
        let certificate = match self.handshake.client_certificate() {
            Ok(certificate) => certificate,
            Err(error) => {
                self.discard();
                return Err(error.into());
            }
        };
        self.client_certificate = Some(certificate);
        match self.handshake.client_certificate_verify_content() {
            Ok(content) => {
                self.stage = RecordStage::AwaitClientFlight;
                Ok(content)
            }
            Err(error) => {
                self.discard();
                Err(error.into())
            }
        }
    }

    /// Protect the client Certificate, CertificateVerify and Finished, each in
    /// its own record, and return them in wire order.
    pub fn complete_client_flight(&mut self, der_signature: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        if self.stage != RecordStage::AwaitClientFlight {
            return Err(Error::State);
        }
        let Some(certificate) = self.client_certificate.take() else {
            self.discard();
            return Err(Error::State);
        };
        let verify = match self.handshake.client_certificate_verify(der_signature) {
            Ok(verify) => verify,
            Err(error) => {
                self.discard();
                return Err(error.into());
            }
        };
        let finished = match self.handshake.client_finished() {
            Ok(finished) => finished,
            Err(error) => {
                self.discard();
                return Err(error.into());
            }
        };
        let Some(mut writer) = self.client_handshake_write.take() else {
            self.discard();
            return Err(Error::State);
        };
        let mut records = Vec::with_capacity(3);
        for message in [&certificate, &verify, &finished] {
            let mut record = Vec::new();
            if let Err(error) = writer.protect(HANDSHAKE, message, &mut record) {
                Self::zeroize_outputs(&mut records);
                record.zeroize();
                self.discard();
                return Err(error.into());
            }
            records.push(record);
        }
        if self.handshake.application_secrets().is_none() {
            Self::zeroize_outputs(&mut records);
            self.discard();
            return Err(Error::State);
        }
        self.server_handshake_read.take();
        self.stage = RecordStage::Complete;
        Ok(records)
    }

    /// Application secrets, available only once the handshake completed.
    pub fn application_secrets(&self) -> Option<&ApplicationSecrets> {
        if self.stage == RecordStage::Complete {
            self.handshake.application_secrets()
        } else {
            None
        }
    }

    /// Application epochs at sequence zero, issued only once after completion.
    /// A second call fails so the same nonces are never handed out twice.
    pub fn application_epochs(&mut self) -> Result<ApplicationEpochs, Error> {
        if self.stage != RecordStage::Complete || self.application_epochs_issued {
            return Err(Error::State);
        }
        let secrets = self.handshake.application_secrets().ok_or(Error::State)?;
        let epochs = ApplicationEpochs {
            client_write: WriteEpoch::aes_128_gcm_sha256(&secrets.client)?,
            server_read: ReadEpoch::aes_128_gcm_sha256(&secrets.server)?,
        };
        self.application_epochs_issued = true;
        Ok(epochs)
    }

    fn fail(&mut self, record: &mut [u8], error: Error) -> Error {
        record.zeroize();
        self.discard();
        error
    }

    fn discard(&mut self) {
        self.stage = RecordStage::Failed;
        self.server_handshake_read.take();
        self.client_handshake_write.take();
        self.client_certificate.take();
    }

    fn zeroize_outputs(outputs: &mut [Vec<u8>]) {
        for output in outputs {
            output.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls13::certificate_verify::{self, CertificateVerifySender, SignatureScheme};
    use crate::tls13::external_psk::import_external_psk;
    use crate::tls13::key_schedule::{self, HandshakeSecrets};
    use crate::tls13::psk_extension::{
        CERT_WITH_EXTERN_PSK_TYPE, KEY_SHARE_TYPE, PRE_SHARED_KEY_TYPE,
    };
    use crate::tls13::tls_pok;
    use crate::tls13::transcript;
    use p256::ecdsa::signature::Signer;
    use p256::elliptic_curve::sec1::ToSec1Point;
    use p256::pkcs8::EncodePublicKey;
    use p256::{SecretKey, ecdsa};

    const SESSION_ID: &[u8] = b"qid-session";
    const AES_128_GCM_SHA256: u16 = 0x1301;
    const P256_GROUP: u16 = 0x0017;

    struct Fixture {
        client_bsk: [u8; 32],
        server_bsk: [u8; 32],
        client_ecdhe: [u8; 32],
        server_ecdhe: [u8; 32],
        client_spki: Vec<u8>,
        server_spki: Vec<u8>,
        client_share: Vec<u8>,
        server_share: Vec<u8>,
        identity: crate::tls13::external_psk::ImportedIdentity,
        imported_psk: Zeroizing<Vec<u8>>,
    }

    struct Flight {
        server_hello: Vec<u8>,
        messages: Vec<Vec<u8>>,
        writer: WriteEpoch,
        secrets: HandshakeSecrets,
        application_hash: [u8; 32],
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
            server_spki: spki(&secret(&server_bsk)),
            client_share: share(&secret(&client_ecdhe)),
            server_share: share(&secret(&server_ecdhe)),
            client_bsk,
            server_bsk,
            client_ecdhe,
            server_ecdhe,
            client_spki,
            identity,
            imported_psk,
        }
    }

    fn client(fx: &Fixture) -> TlsPokClient {
        TlsPokClient::new(
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
        .expect("build TLS-POK record client")
    }

    fn push_extension(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(body);
    }

    fn server_hello(fx: &Fixture) -> Vec<u8> {
        let mut extensions = Vec::new();
        push_extension(&mut extensions, PRE_SHARED_KEY_TYPE, &0u16.to_be_bytes());
        let mut key_share = P256_GROUP.to_be_bytes().to_vec();
        key_share.extend_from_slice(&u16::try_from(fx.server_share.len()).unwrap().to_be_bytes());
        key_share.extend_from_slice(&fx.server_share);
        push_extension(&mut extensions, KEY_SHARE_TYPE, &key_share);
        push_extension(&mut extensions, 0x002b, &[0x03, 0x04]);
        push_extension(&mut extensions, CERT_WITH_EXTERN_PSK_TYPE, &[]);

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x77; 32]);
        body.push(u8::try_from(SESSION_ID.len()).unwrap());
        body.extend_from_slice(SESSION_ID);
        body.extend_from_slice(&AES_128_GCM_SHA256.to_be_bytes());
        body.push(0x00);
        body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&extensions);
        transcript::encode_message(SERVER_HELLO, &body).unwrap()
    }

    fn encrypted_extensions() -> Vec<u8> {
        let extensions = [0x00, 0x13, 0x00, 0x01, tls_pok::RAW_PUBLIC_KEY];
        let mut body = u16::try_from(extensions.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        body.extend_from_slice(&extensions);
        transcript::encode_message(ENCRYPTED_EXTENSIONS, &body).unwrap()
    }

    fn certificate_request() -> Vec<u8> {
        let extensions = [0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04];
        let mut body = vec![0x00];
        body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&extensions);
        transcript::encode_message(CERTIFICATE_REQUEST, &body).unwrap()
    }

    fn certificate_message(spki: &[u8]) -> Vec<u8> {
        let mut entry = [0u8; 3];
        let len = u32::try_from(spki.len()).unwrap().to_be_bytes();
        entry.copy_from_slice(&len[1..]);
        let mut entry = entry.to_vec();
        entry.extend_from_slice(spki);
        entry.extend_from_slice(&[0x00, 0x00]);
        let mut body = vec![0x00];
        let entry_len = u32::try_from(entry.len()).unwrap().to_be_bytes();
        body.extend_from_slice(&entry_len[1..]);
        body.extend_from_slice(&entry);
        transcript::encode_message(CERTIFICATE, &body).unwrap()
    }

    fn signature(key: &[u8; 32], content: &[u8]) -> Vec<u8> {
        let signing_key: ecdsa::SigningKey = secret(key).into();
        let signed: ecdsa::Signature = signing_key.sign(content);
        signed.to_der().as_bytes().to_vec()
    }

    fn certificate_verify_message(fx: &Fixture, hash: &[u8; 32]) -> Vec<u8> {
        let content = certificate_verify::signed_content(CertificateVerifySender::Server, hash);
        let der = signature(&fx.server_bsk, &content);
        let mut body = SignatureScheme::ECDSA_SECP256R1_SHA256
            .0
            .to_be_bytes()
            .to_vec();
        body.extend_from_slice(&u16::try_from(der.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&der);
        transcript::encode_message(CERTIFICATE_VERIFY, &body).unwrap()
    }

    fn finished_message(traffic: &[u8; 32], hash: &[u8; 32]) -> Vec<u8> {
        let key = key_schedule::finished_key(&traffic[..]).unwrap();
        let data = key_schedule::finished_verify_data(&key[..], hash).unwrap();
        transcript::encode_message(FINISHED, &data[..]).unwrap()
    }

    fn plaintext_record(content: &[u8]) -> Vec<u8> {
        let length = u16::try_from(content.len()).unwrap();
        let [high, low] = length.to_be_bytes();
        let mut record = vec![HANDSHAKE, LEGACY_VERSION[0], LEGACY_VERSION[1], high, low];
        record.extend_from_slice(content);
        record
    }

    fn independent_handshake_secrets(
        fx: &Fixture,
        transcript: &transcript::Transcript,
    ) -> HandshakeSecrets {
        let early = key_schedule::early_secret(&fx.imported_psk);
        let shared = p256::ecdh::diffie_hellman(
            secret(&fx.client_ecdhe).to_nonzero_scalar(),
            secret(&fx.server_ecdhe).public_key().as_affine(),
        );
        let mut dhe = [0u8; 32];
        dhe.copy_from_slice(shared.raw_secret_bytes());
        key_schedule::handshake_secrets(&early[..], &dhe, &transcript.hash()).unwrap()
    }

    fn flight(fx: &Fixture, client: &TlsPokClient) -> Flight {
        let hello = client.client_hello_record().unwrap();
        let mut seen = transcript::Transcript::new();
        seen.update(&hello[HEADER_LEN..]).unwrap();
        let server_hello = server_hello(fx);
        seen.update(&server_hello).unwrap();
        let secrets = independent_handshake_secrets(fx, &seen);
        let writer = WriteEpoch::aes_128_gcm_sha256(&secrets.server_traffic).unwrap();

        let ee = encrypted_extensions();
        seen.update(&ee).unwrap();
        let request = certificate_request();
        seen.update(&request).unwrap();
        let certificate = certificate_message(&fx.server_spki);
        seen.update(&certificate).unwrap();
        let verify = certificate_verify_message(fx, &seen.hash());
        seen.update(&verify).unwrap();
        let finished = finished_message(&secrets.server_traffic, &seen.hash());
        seen.update(&finished).unwrap();

        Flight {
            server_hello,
            messages: vec![ee, request, certificate, verify, finished],
            writer,
            secrets,
            application_hash: seen.hash(),
        }
    }

    fn fresh_writer(flight: &Flight) -> WriteEpoch {
        WriteEpoch::aes_128_gcm_sha256(&flight.secrets.server_traffic).unwrap()
    }

    fn protect(writer: &mut WriteEpoch, message: &[u8]) -> Vec<u8> {
        let mut record = Vec::new();
        writer.protect(HANDSHAKE, message, &mut record).unwrap();
        record
    }

    fn past_hello(fx: &Fixture, flight: &Flight) -> TlsPokClient {
        let mut client = client(fx);
        let mut record = plaintext_record(&flight.server_hello);
        client.receive_record(&mut record).unwrap();
        assert_eq!(client.stage(), RecordStage::AwaitServerFlight);
        client
    }

    fn assert_zeroized(record: &[u8]) {
        assert!(record.iter().all(|&octet| octet == 0));
    }

    #[test]
    fn ignores_middlebox_change_cipher_spec() {
        let fx = fixture();
        let mut client = client(&fx);
        let mut ccs = vec![CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
        client.receive_record(&mut ccs).unwrap();
        assert_eq!(client.stage(), RecordStage::AwaitServerHello);

        let mut malformed = vec![CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x00];
        assert_eq!(
            client.receive_record(&mut malformed).unwrap_err(),
            Error::WrongRecordType
        );
        assert_zeroized(&malformed);
    }

    #[test]
    fn rejects_change_cipher_spec_after_terminal_failure() {
        let fx = fixture();
        let mut client = client(&fx);
        let flight = flight(&fx, &client);
        let mut wrong = plaintext_record(&flight.server_hello);
        wrong[0] = APPLICATION_DATA;
        assert_eq!(
            client.receive_record(&mut wrong).unwrap_err(),
            Error::WrongRecordType
        );
        assert_eq!(client.stage(), RecordStage::Failed);

        let mut ccs = vec![CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
        assert_eq!(client.receive_record(&mut ccs).unwrap_err(), Error::State);
        assert_zeroized(&ccs);
        assert_eq!(client.stage(), RecordStage::Failed);
    }

    #[test]
    fn completes_a_full_record_flow_with_independent_server_traffic() {
        let fx = fixture();
        let mut client = client(&fx);
        let mut flight = flight(&fx, &client);

        let mut hello = plaintext_record(&flight.server_hello);
        client.receive_record(&mut hello).unwrap();
        assert_eq!(client.stage(), RecordStage::AwaitServerFlight);
        assert!(client.application_secrets().is_none());
        assert_eq!(client.application_epochs().unwrap_err(), Error::State);

        let server_records: Vec<Vec<u8>> = flight
            .messages
            .iter()
            .map(|message| protect(&mut flight.writer, message))
            .collect();
        for mut record in server_records {
            client.receive_record(&mut record).unwrap();
        }
        assert_eq!(client.stage(), RecordStage::AwaitClientSignature);
        assert!(client.application_secrets().is_none());

        let mut extra = protect(&mut flight.writer, &flight.messages[0]);
        assert_eq!(client.receive_record(&mut extra).unwrap_err(), Error::State);
        assert_zeroized(&extra);

        let content = client.pending_client_signature_content().unwrap();
        assert_eq!(client.stage(), RecordStage::AwaitClientFlight);
        assert_eq!(
            client.pending_client_signature_content().unwrap_err(),
            Error::State
        );
        let der = signature(&fx.client_bsk, &content);
        let mut outgoing = client.complete_client_flight(&der).unwrap();
        assert_eq!(outgoing.len(), 3);
        assert_eq!(client.stage(), RecordStage::Complete);

        let mut reader = ReadEpoch::aes_128_gcm_sha256(&flight.secrets.client_traffic).unwrap();
        let cert = reader.open(&mut outgoing[0]).unwrap();
        assert_eq!(cert.content_type, HANDSHAKE);
        assert_eq!(cert.content[0], CERTIFICATE);
        let certificate = cert.content.to_vec();
        let verify = reader.open(&mut outgoing[1]).unwrap();
        assert_eq!(verify.content_type, HANDSHAKE);
        assert_eq!(verify.content[0], CERTIFICATE_VERIFY);
        let verification = verify.content.to_vec();
        let finished = reader.open(&mut outgoing[2]).unwrap();
        assert_eq!(finished.content_type, HANDSHAKE);
        assert_eq!(finished.content[0], FINISHED);
        let client_finished = finished.content.to_vec();

        let mut seen = transcript::Transcript::new();
        seen.update(&client.client_hello_record().unwrap()[HEADER_LEN..])
            .unwrap();
        seen.update(&flight.server_hello).unwrap();
        for message in &flight.messages {
            seen.update(message).unwrap();
        }
        assert_eq!(seen.hash(), flight.application_hash);
        seen.update(&certificate).unwrap();
        let signed =
            certificate_verify::signed_content(CertificateVerifySender::Client, &seen.hash());
        assert_eq!(signed, content);
        let parsed = certificate_verify::parse(&verification[4..]).unwrap();
        assert_eq!(parsed.algorithm, SignatureScheme::ECDSA_SECP256R1_SHA256);
        assert_eq!(parsed.signature, der);
        seen.update(&verification).unwrap();
        let key = key_schedule::finished_key(&flight.secrets.client_traffic[..]).unwrap();
        let expected = key_schedule::finished_verify_data(&key[..], &seen.hash()).unwrap();
        assert_eq!(&client_finished[4..], &expected[..]);

        let master = key_schedule::master_secret(&flight.secrets.handshake_secret[..]).unwrap();
        let client_app =
            key_schedule::traffic_secret(&master[..], b"c ap traffic", &flight.application_hash)
                .unwrap();
        let server_app =
            key_schedule::traffic_secret(&master[..], b"s ap traffic", &flight.application_hash)
                .unwrap();
        let application = client.application_secrets().unwrap();
        assert_eq!(&application.client[..], &client_app[..]);
        assert_eq!(&application.server[..], &server_app[..]);

        let mut epochs = client.application_epochs().unwrap();
        assert_eq!(client.application_epochs().unwrap_err(), Error::State);
        let mut server_record = Vec::new();
        let mut server_writer = WriteEpoch::aes_128_gcm_sha256(&server_app).unwrap();
        server_writer
            .protect(APPLICATION_DATA, b"ping", &mut server_record)
            .unwrap();
        let opened = epochs.server_read.open(&mut server_record).unwrap();
        assert_eq!(opened.content_type, APPLICATION_DATA);
        assert_eq!(opened.content, b"ping");
        let mut client_record = Vec::new();
        epochs
            .client_write
            .protect(APPLICATION_DATA, b"pong", &mut client_record)
            .unwrap();
        let mut app_reader = ReadEpoch::aes_128_gcm_sha256(&client_app).unwrap();
        let opened = app_reader.open(&mut client_record).unwrap();
        assert_eq!(opened.content_type, APPLICATION_DATA);
        assert_eq!(opened.content, b"pong");
        assert!(!format!("{client:?}").contains("redacted"));
        assert!(!format!("{epochs:?}").contains("ping"));
    }

    #[test]
    fn rejects_wrong_outer_type_terminally() {
        let fx = fixture();
        let mut client = client(&fx);
        let flight = flight(&fx, &client);
        let mut wrong = plaintext_record(&flight.server_hello);
        wrong[0] = APPLICATION_DATA;
        assert_eq!(
            client.receive_record(&mut wrong).unwrap_err(),
            Error::WrongRecordType
        );
        assert_zeroized(&wrong);
        assert_eq!(client.stage(), RecordStage::Failed);
        let mut valid = plaintext_record(&flight.server_hello);
        assert_eq!(client.receive_record(&mut valid).unwrap_err(), Error::State);
        assert_zeroized(&valid);

        let flight = flight;
        let mut client = past_hello(&fx, &flight);
        let mut protected = protect(&mut fresh_writer(&flight), &flight.messages[0]);
        protected[0] = HANDSHAKE;
        assert_eq!(
            client.receive_record(&mut protected).unwrap_err(),
            Error::WrongRecordType
        );
        assert_zeroized(&protected);
        assert_eq!(client.stage(), RecordStage::Failed);

        let mut client = past_hello(&fx, &flight);
        let mut alert = Vec::new();
        fresh_writer(&flight)
            .protect(0x15, &[0x01, 0x00], &mut alert)
            .unwrap();
        assert_eq!(
            client.receive_record(&mut alert).unwrap_err(),
            Error::WrongRecordType
        );
        assert_zeroized(&alert);
        assert_eq!(client.stage(), RecordStage::Failed);
    }

    #[test]
    fn rejects_partial_and_extra_handshake_bytes_terminally() {
        let fx = fixture();
        let mut client = client(&fx);
        let flight = flight(&fx, &client);
        let mut hello = plaintext_record(&flight.server_hello);
        hello.push(0);
        assert_eq!(
            client.receive_record(&mut hello).unwrap_err(),
            Error::Framing(transcript::Error::TrailingBytes)
        );
        assert_zeroized(&hello);
        assert_eq!(client.stage(), RecordStage::Failed);

        let truncated = &flight.messages[0][..flight.messages[0].len() - 1];
        let mut partial = protect(&mut fresh_writer(&flight), truncated);
        let mut client = past_hello(&fx, &flight);
        assert_eq!(
            client.receive_record(&mut partial).unwrap_err(),
            Error::Framing(transcript::Error::TruncatedBody)
        );
        assert_zeroized(&partial);
        assert_eq!(client.stage(), RecordStage::Failed);

        let mut padded = flight.messages[0].clone();
        padded.push(0x00);
        let mut extra = protect(&mut fresh_writer(&flight), &padded);
        let mut client = past_hello(&fx, &flight);
        assert_eq!(
            client.receive_record(&mut extra).unwrap_err(),
            Error::Framing(transcript::Error::TruncatedHeader)
        );
        assert_zeroized(&extra);
        assert_eq!(client.stage(), RecordStage::Failed);
    }

    #[test]
    fn rejects_bad_aead_tag_terminally() {
        let fx = fixture();
        let flight = flight(&fx, &client(&fx));
        let mut client = past_hello(&fx, &flight);
        let mut record = protect(&mut fresh_writer(&flight), &flight.messages[0]);
        *record.last_mut().unwrap() ^= 0x01;
        assert_eq!(
            client.receive_record(&mut record).unwrap_err(),
            Error::Record(RecordError::AuthenticationFailed)
        );
        assert_zeroized(&record);
        assert_eq!(client.stage(), RecordStage::Failed);
    }

    #[test]
    fn rejects_out_of_order_messages_and_early_calls() {
        let fx = fixture();
        let mut client = client(&fx);
        let flight = flight(&fx, &client);

        let mut early = plaintext_record(&flight.messages[0]);
        assert_eq!(
            client.receive_record(&mut early).unwrap_err(),
            Error::UnexpectedHandshakeMessage
        );
        assert_zeroized(&early);

        let mut client = past_hello(&fx, &flight);
        let mut certificate = protect(&mut fresh_writer(&flight), &flight.messages[2]);
        assert_eq!(
            client.receive_record(&mut certificate).unwrap_err(),
            Error::UnexpectedHandshakeMessage
        );
        assert_zeroized(&certificate);

        let mut client = past_hello(&fx, &flight);
        let mut writer = fresh_writer(&flight);
        let mut ee = protect(&mut writer, &flight.messages[0]);
        client.receive_record(&mut ee).unwrap();
        let mut finished = protect(&mut writer, &flight.messages[4]);
        assert_eq!(
            client.receive_record(&mut finished).unwrap_err(),
            Error::UnexpectedHandshakeMessage
        );
        assert_zeroized(&finished);

        let mut client = past_hello(&fx, &flight);
        assert_eq!(
            client.pending_client_signature_content().unwrap_err(),
            Error::State
        );
        assert_eq!(
            client.complete_client_flight(&[0u8; 8]).unwrap_err(),
            Error::State
        );
        assert!(client.application_secrets().is_none());
        assert_eq!(client.stage(), RecordStage::AwaitServerFlight);
    }
}
