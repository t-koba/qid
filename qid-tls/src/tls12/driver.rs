//! Pure byte-in/byte-out TLS 1.2 server handshake driver.
//!
//! The driver owns handshake state and record sequencing, not I/O: `push`
//! consumes wire bytes and returns only the bytes the server must send. All
//! transport (sockets, listeners, byte pipes) belongs to callers. The fixed
//! profile is the one implemented by `flight` and `finish`: TLS 1.2,
//! ECDHE-ECDSA with AES-128-GCM-SHA256 (0xC02B), P-256.
//!
//! RFC 5246 §7.4 places the client's plaintext ClientKeyExchange before its
//! ChangeCipherSpec. Consequently the `ExpectingClientCcs` state accepts one
//! plaintext handshake record carrying that message before requiring the CCS;
//! every other record is rejected. The client Finished is expected inside a
//! protected record after the CCS.

use super::HandshakeReassembler;
use super::finish::derive_handshake_keys;
use super::{
    ALERT, APPLICATION_DATA, CCS_RECORD, CHANGE_CIPHER_SPEC, HANDSHAKE, KeyBlock,
    MAX_RECORD_FRAGMENT, OcspResponse, RECORD_VERSION, RecordProtector, ServerFirstFlight,
    ServerFirstFlightInput, Tls12Error, build_server_first_flight, complete_server_handshake,
    parse_ccs, parse_client_hello, wrap_handshake_message,
};
use p256::{SecretKey, ecdsa::SigningKey};

const CLIENT_HELLO: u8 = 1;
const CLIENT_KEY_EXCHANGE: u8 = 16;
const FINISHED: u8 = 20;
const EXTENDED_MASTER_SECRET: u16 = 0x0017;
const HEADER_LEN: usize = 5;
// RFC 5246 §6.2.3.3: a protected fragment is at most 2^14 + 2048 octets.
const MAX_WIRE_RECORD: usize = MAX_RECORD_FRAGMENT + 2048;

/// Caller-owned key material and configuration for one server handshake.
pub struct ServerHandshakeConfig<'a> {
    pub certificates: &'a [&'a [u8]],
    pub ocsp_responses: &'a [OcspResponse<'a>],
    pub signing_key: &'a SigningKey,
    pub ecdhe_secret: &'a SecretKey,
    pub server_random: [u8; 32],
}

/// Progress of one server-side handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerHandshakeState {
    ExpectingClientHello,
    /// The client's plaintext ClientKeyExchange may precede its CCS (RFC 5246).
    ExpectingClientCcs,
    ExpectingClientFinished,
    Complete,
}

/// One TLS 1.2 server handshake over opaque wire bytes.
///
/// After `Complete`, further `push` calls return no bytes: application data and
/// closes are outside this handshake-only driver.
pub struct ServerHandshake<'a> {
    config: ServerHandshakeConfig<'a>,
    state: ServerHandshakeState,
    wire: Vec<u8>,
    plaintext_reassembly: HandshakeReassembler,
    protected_reassembly: HandshakeReassembler,
    client_hello_message: Vec<u8>,
    client_random: [u8; 32],
    ems_negotiated: bool,
    flight: Option<ServerFirstFlight>,
    client_key_exchange: Option<Vec<u8>>,
    client_finished: Option<Vec<u8>>,
    protector: Option<RecordProtector>,
    key_block: Option<KeyBlock>,
    selected_ocsp_multi: bool,
}

impl<'a> ServerHandshake<'a> {
    pub fn new(config: ServerHandshakeConfig<'a>) -> Self {
        Self {
            config,
            state: ServerHandshakeState::ExpectingClientHello,
            wire: Vec::new(),
            plaintext_reassembly: HandshakeReassembler::new(),
            protected_reassembly: HandshakeReassembler::new(),
            client_hello_message: Vec::new(),
            client_random: [0; 32],
            ems_negotiated: false,
            flight: None,
            client_key_exchange: None,
            client_finished: None,
            protector: None,
            key_block: None,
            selected_ocsp_multi: false,
        }
    }

    pub fn state(&self) -> &ServerHandshakeState {
        &self.state
    }

    /// Whether the emitted first flight acknowledged RFC 6961 `ocsp_multi`.
    /// This is a report of the flight's own selection, not an interop claim.
    pub fn selected_ocsp_multi(&self) -> bool {
        self.selected_ocsp_multi
    }

    /// The negotiated key block, available once the handshake is complete.
    pub fn key_block(&self) -> Option<&KeyBlock> {
        self.key_block.as_ref()
    }

    /// Consume wire bytes and return every record the server must send now.
    /// A partial record is buffered until a later call completes it.
    pub fn push(&mut self, wire: &[u8]) -> Result<Vec<u8>, Tls12Error> {
        let mut output = Vec::new();
        self.wire.extend_from_slice(wire);
        while self.state != ServerHandshakeState::Complete {
            let Some(len) = next_record_len(&self.wire)? else {
                break;
            };
            let record: Vec<u8> = self.wire[..len].to_vec();
            self.wire.drain(..len);
            match self.state {
                ServerHandshakeState::ExpectingClientHello => {
                    self.on_client_hello_record(&record, &mut output)?;
                }
                ServerHandshakeState::ExpectingClientCcs => {
                    self.on_cke_or_ccs_record(&record)?;
                }
                ServerHandshakeState::ExpectingClientFinished => {
                    self.on_finished_record(&record, &mut output)?;
                }
                ServerHandshakeState::Complete => unreachable!("loop exits on Complete"),
            }
        }
        // Post-handshake records are not this driver's responsibility; do not
        // drop an incomplete record while the handshake is still in progress.
        if self.state == ServerHandshakeState::Complete {
            self.wire.clear();
        }
        Ok(output)
    }

    fn on_client_hello_record(
        &mut self,
        record: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), Tls12Error> {
        let messages = self.plaintext_reassembly.push_records(record)?;
        for message in messages {
            if message.msg_type != CLIENT_HELLO || !self.client_hello_message.is_empty() {
                return Err(Tls12Error::InvalidClientHelloMessage);
            }
            let client = parse_client_hello(&message.body)?;
            self.client_random = client.random.try_into().map_err(|_| {
                // parse_client_hello always returns exactly 32 random bytes.
                Tls12Error::TruncatedClientHello
            })?;
            self.ems_negotiated = client
                .extensions
                .iter()
                .any(|extension| extension.ext_type == EXTENDED_MASTER_SECRET);
            self.client_hello_message = wrap_handshake_message(CLIENT_HELLO, &message.body)?;

            let flight = build_server_first_flight(&ServerFirstFlightInput {
                client_hello_message: &self.client_hello_message,
                server_random: self.config.server_random,
                certificates: self.config.certificates,
                ocsp_responses: self.config.ocsp_responses,
                ecdhe_secret: self.config.ecdhe_secret,
                signing_key: self.config.signing_key,
            })?;
            self.selected_ocsp_multi = flight.selected_ocsp_multi;
            for emitted in &flight.messages {
                let framed = wrap_handshake_message(emitted.msg_type, &emitted.body)?;
                for fragment in framed.chunks(MAX_RECORD_FRAGMENT) {
                    output.extend_from_slice(&plaintext_record(HANDSHAKE, fragment)?);
                }
            }
            self.flight = Some(flight);
            self.state = ServerHandshakeState::ExpectingClientCcs;
        }
        Ok(())
    }

    fn on_cke_or_ccs_record(&mut self, record: &[u8]) -> Result<(), Tls12Error> {
        match record[0] {
            CHANGE_CIPHER_SPEC => {
                parse_ccs(record)?;
                // The keys are installed when the plaintext CKE arrives. A CCS
                // without it is incomplete, so it cannot activate read keys.
                if self.protector.is_none() || self.client_key_exchange.is_none() {
                    return Err(Tls12Error::InvalidClientKeyExchange);
                }
                self.protected_reassembly = HandshakeReassembler::new();
                self.protector
                    .as_mut()
                    .ok_or(Tls12Error::InvalidClientKeyExchange)?
                    .reset_read_sequence();
                self.state = ServerHandshakeState::ExpectingClientFinished;
            }
            HANDSHAKE => {
                if self.client_key_exchange.is_some() {
                    return Err(Tls12Error::UnexpectedContentType);
                }
                let messages = self.plaintext_reassembly.push_records(record)?;
                for message in messages {
                    if self.client_key_exchange.is_some() || message.msg_type != CLIENT_KEY_EXCHANGE
                    {
                        return Err(Tls12Error::InvalidClientKeyExchange);
                    }
                    let framed = wrap_handshake_message(CLIENT_KEY_EXCHANGE, &message.body)?;
                    self.install_read_keys(&framed, &message.body)?;
                    self.client_key_exchange = Some(framed);
                }
            }
            _ => return Err(Tls12Error::UnexpectedContentType),
        }
        Ok(())
    }

    /// Derive the keys needed to open the client's protected Finished before
    /// `complete_server_handshake` re-derives them while verifying it.
    fn install_read_keys(&mut self, cke_message: &[u8], cke_body: &[u8]) -> Result<(), Tls12Error> {
        let flight = self
            .flight
            .as_ref()
            .ok_or(Tls12Error::InvalidServerFirstFlight)?;
        let (_, keys) = derive_handshake_keys(
            flight,
            &self.client_hello_message,
            cke_message,
            cke_body,
            self.config.ecdhe_secret,
            &self.client_random,
            &self.config.server_random,
            self.ems_negotiated,
        )?;
        self.protector = Some(RecordProtector::new(&keys));
        Ok(())
    }

    fn on_finished_record(
        &mut self,
        record: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), Tls12Error> {
        let (content_type, plaintext) = self
            .protector
            .as_mut()
            .ok_or(Tls12Error::InvalidClientKeyExchange)?
            .open(record)?;
        if content_type != HANDSHAKE {
            return Err(Tls12Error::UnexpectedContentType);
        }
        let plain_record = plaintext_record(HANDSHAKE, &plaintext)?;
        let messages = self.protected_reassembly.push_records(&plain_record)?;
        for message in messages {
            if self.client_finished.is_some() || message.msg_type != FINISHED {
                return Err(Tls12Error::InvalidFinishedMessage);
            }
            self.client_finished = Some(wrap_handshake_message(FINISHED, &message.body)?);
        }
        let Some(client_finished) = self.client_finished.as_ref() else {
            return Ok(());
        };
        let result = complete_server_handshake(
            self.flight
                .as_ref()
                .ok_or(Tls12Error::InvalidServerFirstFlight)?,
            &self.client_hello_message,
            self.client_key_exchange
                .as_ref()
                .ok_or(Tls12Error::InvalidClientKeyExchange)?,
            client_finished,
            self.config.ecdhe_secret,
            &self.client_random,
            &self.config.server_random,
            self.ems_negotiated,
        )?;
        self.key_block = Some(result.key_block);
        self.state = ServerHandshakeState::Complete;

        // CCS is plaintext; the new write keys start at sequence zero only for
        // the Finished message that follows it.
        output.extend_from_slice(&CCS_RECORD);
        let protector = self
            .protector
            .as_mut()
            .ok_or(Tls12Error::InvalidClientKeyExchange)?;
        protector.reset_write_sequence();
        output.extend_from_slice(&protector.protect(HANDSHAKE, &result.server_finished_message)?);
        Ok(())
    }
}

/// One TLS 1.2 plaintext record with an exact-length fragment. Callers
/// fragment larger handshake messages themselves; the driver does that for
/// its first flight.
pub fn plaintext_record(content_type: u8, fragment: &[u8]) -> Result<Vec<u8>, Tls12Error> {
    if !matches!(
        content_type,
        CHANGE_CIPHER_SPEC | ALERT | HANDSHAKE | APPLICATION_DATA
    ) {
        return Err(Tls12Error::UnexpectedContentType);
    }
    if fragment.len() > MAX_RECORD_FRAGMENT {
        return Err(Tls12Error::RecordTooLarge);
    }
    if matches!(content_type, HANDSHAKE | CHANGE_CIPHER_SPEC) && fragment.is_empty() {
        return Err(Tls12Error::EmptyFragment);
    }
    let len = u16::try_from(fragment.len()).map_err(|_| Tls12Error::RecordTooLarge)?;
    let mut record = Vec::with_capacity(HEADER_LEN + fragment.len());
    record.push(content_type);
    record.extend_from_slice(&RECORD_VERSION);
    record.extend_from_slice(&len.to_be_bytes());
    record.extend_from_slice(fragment);
    Ok(record)
}

/// Locate the next complete record; a partial header or fragment is buffered.
fn next_record_len(wire: &[u8]) -> Result<Option<usize>, Tls12Error> {
    if wire.len() < HEADER_LEN {
        return Ok(None);
    }
    if wire[1] != 0x03 || !(0x01..=0x03).contains(&wire[2]) {
        return Err(Tls12Error::InvalidRecordVersion);
    }
    let fragment_len = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
    if fragment_len > MAX_WIRE_RECORD {
        return Err(Tls12Error::RecordTooLarge);
    }
    let total = HEADER_LEN + fragment_len;
    Ok((wire.len() >= total).then_some(total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls12::{
        HandshakeMessage, ecdh_pre_master, ems_session_hash, key_block, master_secret, verify_data,
    };
    use p256::elliptic_curve::sec1::ToSec1Point;
    use sha2::{Digest, Sha256};

    const CLIENT_SCALAR: [u8; 32] = [0x33; 32];
    const SERVER_SCALAR: [u8; 32] = [0x11; 32];
    const SIGNING_SCALAR: [u8; 32] = [0x22; 32];
    const CLIENT_RANDOM: [u8; 32] = [0xA1; 32];
    const SERVER_RANDOM: [u8; 32] = [0xB2; 32];
    const CERT: &[u8] = &[0x30, 0x00];

    struct Fixture {
        client_secret: SecretKey,
        server_secret: SecretKey,
        signing_key: SigningKey,
        client_random: [u8; 32],
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                client_secret: SecretKey::from_slice(&CLIENT_SCALAR).expect("client scalar"),
                server_secret: SecretKey::from_slice(&SERVER_SCALAR).expect("server scalar"),
                signing_key: SigningKey::from_slice(&SIGNING_SCALAR).expect("signing scalar"),
                client_random: CLIENT_RANDOM,
            }
        }

        fn hello(&self, ems: bool) -> Vec<u8> {
            let mut extensions = Vec::new();
            if ems {
                extensions.extend_from_slice(&0x0017u16.to_be_bytes());
                extensions.extend_from_slice(&0u16.to_be_bytes());
            }
            let mut body = vec![0x03, 0x03];
            body.extend_from_slice(&self.client_random);
            body.push(0);
            body.extend_from_slice(&2u16.to_be_bytes());
            body.extend_from_slice(&0xC02Bu16.to_be_bytes());
            body.extend_from_slice(&[1, 0]);
            body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            body.extend_from_slice(&extensions);
            let mut message = vec![CLIENT_HELLO, 0, 0, 0];
            message[1..4].copy_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
            message.extend_from_slice(&body);
            message
        }

        fn cke(&self) -> Vec<u8> {
            let point = self.client_secret.public_key().to_sec1_point(false);
            let mut body = vec![65];
            body.extend_from_slice(point.as_bytes());
            wrap_handshake_message(CLIENT_KEY_EXCHANGE, &body).expect("frame CKE")
        }

        fn config(&self) -> ServerHandshakeConfig<'_> {
            ServerHandshakeConfig {
                certificates: &[CERT],
                ocsp_responses: &[],
                signing_key: &self.signing_key,
                ecdhe_secret: &self.server_secret,
                server_random: SERVER_RANDOM,
            }
        }
    }

    /// Reconstruct the client script from the server's actual first flight,
    /// including the freshly signed ServerKeyExchange and transcript.
    struct Script {
        cke: Vec<u8>,
        finished: Vec<u8>,
        protector: RecordProtector,
        expected_server_finished: Vec<u8>,
        keys: KeyBlock,
    }

    impl Script {
        fn new(fixture: &Fixture, hello: &[u8], first_flight: &[u8], ems: bool) -> Self {
            let messages = reassemble(first_flight);
            assert_eq!(
                messages.iter().map(|msg| msg.msg_type).collect::<Vec<_>>(),
                vec![2, 11, 12, 14],
                "no CertificateStatus without status_request_v2"
            );
            let params = &messages[2].body;
            assert_eq!(&params[..4], &[0x03, 0x00, 0x17, 65]);
            let pre_master =
                ecdh_pre_master(&fixture.client_secret, &params[4..69]).expect("client ECDHE");
            let mut transcript = hello.to_vec();
            for msg in &messages {
                transcript.extend_from_slice(
                    &wrap_handshake_message(msg.msg_type, &msg.body).expect("frame flight message"),
                );
            }
            let cke = fixture.cke();
            let ems_seed = if ems {
                Some(ems_session_hash(
                    &[transcript.as_slice(), cke.as_slice()].concat(),
                ))
            } else {
                None
            };
            let master = master_secret(
                &pre_master,
                &fixture.client_random,
                &SERVER_RANDOM,
                ems_seed.as_ref(),
            );
            let client_digest: [u8; 32] = Sha256::new_with_prefix(&transcript)
                .chain_update(&cke)
                .finalize()
                .into();
            let verify = verify_data(&master, &client_digest, b"client finished");
            let finished = wrap_handshake_message(FINISHED, &verify).expect("frame Finished");

            let mut server_digest = Sha256::new();
            server_digest.update(&transcript);
            server_digest.update(&cke);
            server_digest.update(&finished);
            let digest: [u8; 32] = server_digest.finalize().into();
            let expected_server_finished = wrap_handshake_message(
                FINISHED,
                &verify_data(&master, &digest, b"server finished"),
            )
            .expect("frame server Finished");

            let keys = key_block(&master, &SERVER_RANDOM, &fixture.client_random);
            let client_keys = KeyBlock {
                client_write_key: keys.server_write_key,
                client_write_iv: keys.server_write_iv,
                server_write_key: keys.client_write_key,
                server_write_iv: keys.client_write_iv,
            };
            Self {
                cke,
                finished,
                protector: RecordProtector::new(&client_keys),
                expected_server_finished,
                keys,
            }
        }

        fn protected_finished(&mut self) -> Vec<u8> {
            self.protector
                .protect(HANDSHAKE, &self.finished)
                .expect("protect client Finished")
        }
    }

    fn reassemble(records: &[u8]) -> Vec<HandshakeMessage> {
        let mut reassembler = HandshakeReassembler::new();
        let messages = reassembler
            .push_records(records)
            .expect("reassemble flight");
        reassembler.finish().expect("complete messages");
        messages
    }

    fn open_server_finished(script: &mut Script, wire: &[u8]) -> Vec<u8> {
        assert!(
            wire.starts_with(&CCS_RECORD),
            "server CCS must be plaintext"
        );
        let (content_type, plaintext) = script
            .protector
            .open(&wire[CCS_RECORD.len()..])
            .expect("open server Finished");
        assert_eq!(content_type, HANDSHAKE);
        plaintext
    }

    #[test]
    fn complete_roundtrip_transitions_and_emits_expected_records() {
        for ems in [true, false] {
            let fixture = Fixture::new();
            let hello = fixture.hello(ems);
            let mut server = ServerHandshake::new(fixture.config());
            assert_eq!(server.state(), &ServerHandshakeState::ExpectingClientHello);

            let first = server
                .push(&plaintext_record(HANDSHAKE, &hello).expect("hello record"))
                .expect("server accepts ClientHello");
            assert_eq!(server.state(), &ServerHandshakeState::ExpectingClientCcs);
            assert!(!server.selected_ocsp_multi());
            assert!(server.key_block().is_none());

            let mut script = Script::new(&fixture, &hello, &first, ems);
            let mut wire = plaintext_record(HANDSHAKE, &script.cke).expect("CKE record");
            wire.extend_from_slice(&CCS_RECORD);
            wire.extend_from_slice(&script.protected_finished());
            let second = server.push(&wire).expect("server completes handshake");

            assert_eq!(server.state(), &ServerHandshakeState::Complete);
            assert_eq!(
                open_server_finished(&mut script, &second),
                script.expected_server_finished
            );
            let keys = server.key_block().expect("key block after completion");
            assert_eq!(keys.client_write_key, script.keys.client_write_key);
            assert_eq!(keys.server_write_iv, script.keys.server_write_iv);
            assert!(
                server
                    .push(b"unexpected post-handshake bytes")
                    .expect("post-handshake noop")
                    .is_empty()
            );
        }
    }

    #[test]
    fn fragmented_client_hello_is_buffered_across_records() {
        let fixture = Fixture::new();
        let hello = fixture.hello(true);
        let mut server = ServerHandshake::new(fixture.config());
        let half = hello.len() / 2;
        let mut record = plaintext_record(HANDSHAKE, &hello[..half]).expect("first fragment");
        record.extend_from_slice(
            &plaintext_record(HANDSHAKE, &hello[half..]).expect("second fragment"),
        );
        assert!(
            server
                .push(&record[..3])
                .expect("partial header")
                .is_empty()
        );
        assert_eq!(server.state(), &ServerHandshakeState::ExpectingClientHello);
        assert!(
            server
                .push(&record[3..10])
                .expect("partial fragment")
                .is_empty()
        );
        assert_eq!(server.state(), &ServerHandshakeState::ExpectingClientHello);
        let first = server.push(&record[10..]).expect("complete hello");
        assert_eq!(server.state(), &ServerHandshakeState::ExpectingClientCcs);
        assert_eq!(reassemble(&first).len(), 4);
    }

    #[test]
    fn ccs_is_required_before_the_protected_finished() {
        let fixture = Fixture::new();
        let hello = fixture.hello(true);
        let mut server = ServerHandshake::new(fixture.config());
        let first = server
            .push(&plaintext_record(HANDSHAKE, &hello).expect("hello record"))
            .expect("first flight");
        let mut script = Script::new(&fixture, &hello, &first, true);

        let mut wire = plaintext_record(HANDSHAKE, &script.cke).expect("CKE record");
        wire.extend_from_slice(&script.protected_finished());
        assert_eq!(
            server.push(&wire).err(),
            Some(Tls12Error::UnexpectedContentType),
            "a protected record is not a CCS"
        );
        assert_eq!(server.state(), &ServerHandshakeState::ExpectingClientCcs);

        let second = server.push(&CCS_RECORD).expect("CCS accepted");
        assert!(second.is_empty());
        assert_eq!(
            server.state(),
            &ServerHandshakeState::ExpectingClientFinished
        );
        // A second CCS is never accepted.
        assert_eq!(
            server.push(&CCS_RECORD).err(),
            Some(Tls12Error::UnexpectedContentType)
        );
    }

    #[test]
    fn tampered_finished_is_rejected_without_advancing_the_sequence() {
        let fixture = Fixture::new();
        let hello = fixture.hello(true);
        let mut server = ServerHandshake::new(fixture.config());
        let first = server
            .push(&plaintext_record(HANDSHAKE, &hello).expect("hello record"))
            .expect("first flight");
        let mut script = Script::new(&fixture, &hello, &first, true);

        let mut cke_and_ccs = plaintext_record(HANDSHAKE, &script.cke).expect("CKE record");
        cke_and_ccs.extend_from_slice(&CCS_RECORD);
        server.push(&cke_and_ccs).expect("CKE and CCS");

        let mut bad = script.protected_finished();
        *bad.last_mut().expect("tag byte") ^= 1;
        assert_eq!(
            server.push(&bad).err(),
            Some(Tls12Error::AuthenticationFailed)
        );
        assert_eq!(
            server.state(),
            &ServerHandshakeState::ExpectingClientFinished
        );

        // A rejected record leaves the server's read sequence at zero. The
        // client-side test protector is rewound so its retry also uses seq 0.
        script.protector.reset_write_sequence();
        let done = server
            .push(&script.protected_finished())
            .expect("genuine Finished after failed record");
        assert_eq!(server.state(), &ServerHandshakeState::Complete);
        assert_eq!(
            open_server_finished(&mut script, &done),
            script.expected_server_finished
        );
    }

    #[test]
    fn plaintext_record_enforces_protocol_bounds() {
        assert_eq!(
            plaintext_record(HANDSHAKE, &[]).err(),
            Some(Tls12Error::EmptyFragment)
        );
        assert_eq!(
            plaintext_record(CHANGE_CIPHER_SPEC, &[]).err(),
            Some(Tls12Error::EmptyFragment)
        );
        assert_eq!(
            plaintext_record(HANDSHAKE, &[0; MAX_RECORD_FRAGMENT + 1]).err(),
            Some(Tls12Error::RecordTooLarge)
        );
        assert_eq!(
            plaintext_record(0x99, &[1]).err(),
            Some(Tls12Error::UnexpectedContentType)
        );
        let record = plaintext_record(HANDSHAKE, &[1, 2, 3]).expect("valid record");
        assert_eq!(&record[..5], &[0x16, 0x03, 0x03, 0x00, 0x03]);
    }
}
