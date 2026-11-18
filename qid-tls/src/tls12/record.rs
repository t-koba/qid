//! RFC 5246 §6.2.3.3 AES-128-GCM record protection for the TLS 1.2 profile.
//!
//! This is pure record encoding/decoding on caller-supplied bytes: no sockets,
//! listener, handshake state machine or rustls configuration lives here. The
//! outer record type is unchanged by protection; in particular an encrypted
//! Finished record still has outer type `HANDSHAKE`, not `APPLICATION_DATA`.
//! The `TLSCiphertext.length` field counts the explicit nonce, ciphertext and
//! tag together (40 bytes for the 16-byte plaintext vector below).
//!
//! Sequence numbers belong to a connection state, so the caller must reset the
//! matching direction exactly when new keys become active after a
//! ChangeCipherSpec (see [`RecordProtector::reset_read_sequence`] and
//! [`RecordProtector::reset_write_sequence`]).

use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use zeroize::Zeroizing;

use super::{KeyBlock, Tls12Error};

/// RFC 5246 §6.2.1 `ContentType.change_cipher_spec`.
pub const CHANGE_CIPHER_SPEC: u8 = 0x14;
/// RFC 5246 §6.2.1 `ContentType.alert`.
pub const ALERT: u8 = 0x15;
/// RFC 5246 §6.2.1 `ContentType.handshake`.
pub const HANDSHAKE: u8 = 0x16;
/// RFC 5246 §6.2.1 `ContentType.application_data`.
pub const APPLICATION_DATA: u8 = 0x17;
/// Record protocol version used by this TLS 1.2 profile (RFC 5246 §6.2.1).
pub const RECORD_VERSION: [u8; 2] = [0x03, 0x03];

/// The single valid ChangeCipherSpec record: `change_cipher_spec(1)` with
/// payload `enum { change_cipher_spec(1), (255) }`.
pub const CCS_RECORD: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

const HEADER_LEN: usize = 5;
const FIXED_IV_LEN: usize = 4;
const EXPLICIT_NONCE_LEN: usize = 8;
const TAG_LEN: usize = 16;
// seq_num(8) || type(1) || version(2) || length(2), RFC 5246 §6.2.3.3.
const AAD_LEN: usize = 8 + 1 + 2 + 2;
// RFC 5246 §6.2.1 and §6.2.3.3: 2^14 fragment and 2^14+2048 ciphertext;
// the AEAD expansion of any permitted cipher is at most 1024 octets.
const MAX_PLAINTEXT: usize = 1 << 14;
const MAX_CIPHERTEXT: usize = (1 << 14) + 2048;
const MIN_CIPHERTEXT: usize = EXPLICIT_NONCE_LEN + TAG_LEN;

/// Parse one plaintext ChangeCipherSpec record. It is never protected.
pub fn parse_ccs(record: &[u8]) -> Result<(), Tls12Error> {
    if record == CCS_RECORD.as_slice() {
        Ok(())
    } else {
        Err(Tls12Error::InvalidChangeCipherSpec)
    }
}

/// Read/write keys, implicit nonces and sequence numbers for one connection
/// direction pair.
///
/// [`RecordProtector::new`] builds the server side: reads use the client keys
/// and writes use the server keys. A client-side instance swaps the two fields
/// of the `KeyBlock` before construction. The caller owns key installation and
/// must reset the affected sequence number when a ChangeCipherSpec activates
/// new keys; resetting while reusing old keys would repeat AEAD nonces.
pub struct RecordProtector {
    read_key: Zeroizing<[u8; 16]>,
    write_key: Zeroizing<[u8; 16]>,
    read_iv: [u8; FIXED_IV_LEN],
    write_iv: [u8; FIXED_IV_LEN],
    // `None` means exhausted, so no sequence can ever be repeated.
    read_sequence: Option<u64>,
    write_sequence: Option<u64>,
}

impl RecordProtector {
    /// Construct the server-side record state from the negotiated key block.
    pub fn new(client_to_server: &KeyBlock) -> Self {
        Self {
            read_key: Zeroizing::new(client_to_server.client_write_key),
            write_key: Zeroizing::new(client_to_server.server_write_key),
            read_iv: client_to_server.client_write_iv,
            write_iv: client_to_server.server_write_iv,
            read_sequence: Some(0),
            write_sequence: Some(0),
        }
    }

    /// Start the read sequence at zero. Call only when fresh read keys become
    /// active after a ChangeCipherSpec, never to continue with old keys.
    pub fn reset_read_sequence(&mut self) {
        self.read_sequence = Some(0);
    }

    /// Start the write sequence at zero. Call only when fresh write keys become
    /// active after a ChangeCipherSpec, never to continue with old keys.
    pub fn reset_write_sequence(&mut self) {
        self.write_sequence = Some(0);
    }

    /// Protect one fragment with the 8-byte big-endian write sequence number
    /// as explicit nonce (RFC 5246 §6.2.3.3). RFC 9325 §7.2.1 recommends
    /// sequence-number nonces; random explicit nonces give only about a
    /// 2^24.5-record confidentiality ceiling per key (RFC 9325 §4.4). That is
    /// a documented bound, not a runtime cap. The returned `TLSCiphertext`
    /// includes its five-byte header.
    pub fn protect(&mut self, content_type: u8, plaintext: &[u8]) -> Result<Vec<u8>, Tls12Error> {
        let sequence = self.peek_write_sequence()?;
        let mut explicit_nonce = Zeroizing::new([0u8; EXPLICIT_NONCE_LEN]);
        explicit_nonce.copy_from_slice(&sequence.to_be_bytes());
        self.protect_with_nonce(content_type, plaintext, &explicit_nonce)
    }

    /// Protect one fragment with a caller-supplied explicit nonce. Intended
    /// for deterministic tests; callers must never reuse a nonce under one key.
    pub fn protect_with_nonce(
        &mut self,
        content_type: u8,
        plaintext: &[u8],
        explicit_nonce: &[u8; EXPLICIT_NONCE_LEN],
    ) -> Result<Vec<u8>, Tls12Error> {
        check_content_type(content_type)?;
        if content_type == HANDSHAKE && plaintext.is_empty() {
            return Err(Tls12Error::EmptyFragment);
        }
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(Tls12Error::RecordTooLarge);
        }
        let sequence = self.next_write_sequence()?;
        let aad = build_aad(sequence, content_type, plaintext.len())?;
        let nonce = build_nonce(&self.write_iv, explicit_nonce);
        let cipher = Aes128Gcm::new((&*self.write_key).into());
        let encrypted = Zeroizing::new(
            cipher
                .encrypt(
                    (&*nonce).into(),
                    Payload {
                        msg: plaintext,
                        aad: &aad[..],
                    },
                )
                .map_err(|_| Tls12Error::RecordProtectionFailed)?,
        );
        let body_len = EXPLICIT_NONCE_LEN + encrypted.len();
        let length = u16::try_from(body_len).map_err(|_| Tls12Error::RecordTooLarge)?;
        if body_len > MAX_CIPHERTEXT {
            return Err(Tls12Error::RecordTooLarge);
        }

        let mut record = Vec::with_capacity(HEADER_LEN + body_len);
        record.extend_from_slice(&[content_type, RECORD_VERSION[0], RECORD_VERSION[1]]);
        record.extend_from_slice(&length.to_be_bytes());
        record.extend_from_slice(explicit_nonce);
        record.extend_from_slice(&encrypted);
        self.write_sequence = Some(sequence + 1);
        Ok(record)
    }

    /// Authenticate and decrypt exactly one `TLSCiphertext`. The read sequence
    /// advances only after the AEAD tag has been verified; rejected records
    /// leave it unchanged.
    pub fn open(&mut self, record: &[u8]) -> Result<(u8, Vec<u8>), Tls12Error> {
        let (header, body) = record
            .split_at_checked(HEADER_LEN)
            .ok_or(Tls12Error::TruncatedRecord)?;
        if header[1..3] != RECORD_VERSION {
            return Err(Tls12Error::InvalidRecordVersion);
        }
        let content_type = header[0];
        check_content_type(content_type)?;
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if length != body.len() || !(MIN_CIPHERTEXT..=MAX_CIPHERTEXT).contains(&length) {
            return Err(Tls12Error::InvalidCiphertext);
        }
        let plaintext_len = length - MIN_CIPHERTEXT;
        if plaintext_len > MAX_PLAINTEXT {
            return Err(Tls12Error::RecordTooLarge);
        }

        let sequence = self.next_read_sequence()?;
        let aad = build_aad(sequence, content_type, plaintext_len)?;
        let (explicit_nonce, tagged) = body
            .split_at_checked(EXPLICIT_NONCE_LEN)
            .ok_or(Tls12Error::InvalidCiphertext)?;
        let explicit_nonce: &[u8; EXPLICIT_NONCE_LEN] = explicit_nonce
            .try_into()
            .map_err(|_| Tls12Error::InvalidCiphertext)?;
        let nonce = build_nonce(&self.read_iv, explicit_nonce);
        let cipher = Aes128Gcm::new((&*self.read_key).into());
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    (&*nonce).into(),
                    Payload {
                        msg: tagged,
                        aad: &aad[..],
                    },
                )
                .map_err(|_| Tls12Error::AuthenticationFailed)?,
        );
        if content_type == HANDSHAKE && plaintext.is_empty() {
            return Err(Tls12Error::EmptyFragment);
        }
        self.read_sequence = Some(sequence + 1);
        Ok((content_type, plaintext.to_vec()))
    }

    fn next_read_sequence(&mut self) -> Result<u64, Tls12Error> {
        match self.read_sequence {
            Some(sequence) if sequence < u64::MAX => Ok(sequence),
            _ => {
                self.read_sequence = None;
                Err(Tls12Error::SequenceExhausted)
            }
        }
    }

    // Peek without consuming: `protect_with_nonce` performs the increment.
    fn peek_write_sequence(&mut self) -> Result<u64, Tls12Error> {
        match self.write_sequence {
            Some(sequence) if sequence < u64::MAX => Ok(sequence),
            _ => {
                self.write_sequence = None;
                Err(Tls12Error::SequenceExhausted)
            }
        }
    }

    fn next_write_sequence(&mut self) -> Result<u64, Tls12Error> {
        match self.write_sequence {
            Some(sequence) if sequence < u64::MAX => Ok(sequence),
            _ => {
                self.write_sequence = None;
                Err(Tls12Error::SequenceExhausted)
            }
        }
    }
}

fn check_content_type(content_type: u8) -> Result<(), Tls12Error> {
    match content_type {
        HANDSHAKE | ALERT | APPLICATION_DATA => Ok(()),
        // CCS and unknown types are never protected in this profile.
        _ => Err(Tls12Error::UnexpectedContentType),
    }
}

fn build_aad(
    sequence: u64,
    content_type: u8,
    plaintext_len: usize,
) -> Result<Zeroizing<[u8; AAD_LEN]>, Tls12Error> {
    let length = u16::try_from(plaintext_len).map_err(|_| Tls12Error::RecordTooLarge)?;
    let mut aad = Zeroizing::new([0u8; AAD_LEN]);
    aad[..8].copy_from_slice(&sequence.to_be_bytes());
    aad[8] = content_type;
    aad[9..11].copy_from_slice(&RECORD_VERSION);
    aad[11..].copy_from_slice(&length.to_be_bytes());
    Ok(aad)
}

fn build_nonce(
    fixed_iv: &[u8; FIXED_IV_LEN],
    explicit_nonce: &[u8; EXPLICIT_NONCE_LEN],
) -> Zeroizing<[u8; FIXED_IV_LEN + EXPLICIT_NONCE_LEN]> {
    let mut nonce = Zeroizing::new([0u8; FIXED_IV_LEN + EXPLICIT_NONCE_LEN]);
    nonce[..FIXED_IV_LEN].copy_from_slice(fixed_iv);
    nonce[FIXED_IV_LEN..].copy_from_slice(explicit_nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independently computed with OpenSSL EVP_aes_128_gcm in a disposable
    // experiment: key 000102..0f, fixed IV 00010203, explicit nonce
    // 0405060708090a0b, AAD 00000000000000001603030010. The AEAD bytes below
    // are the EVP ciphertext and tag. The supplied vector's header printed a
    // length of 0x0018 (`16030300180405060708090a0b876ca7c26719f4504ed466823fa97b04
    // eb28201d21b37a0b8a70ecd5e9d9dc07`); RFC 5246 §6.2.3.3 counts
    // nonce(8)+ciphertext(16)+tag(16) in TLSCiphertext.length, so the wire
    // value is 0x0028. All AEAD bytes match the EVP result exactly.
    const KAT_KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const KAT_IV: [u8; 4] = [0x00, 0x01, 0x02, 0x03];
    const KAT_NONCE: [u8; 8] = [0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b];
    const KAT_PLAINTEXT: &[u8] = &[
        0x14, 0x00, 0x00, 0x0c, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c,
    ];
    const KAT_RECORD: &[u8] = &[
        0x16, 0x03, 0x03, 0x00, 0x28, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x87, 0x6c,
        0xa7, 0xc2, 0x67, 0x19, 0xf4, 0x50, 0x4e, 0xd4, 0x66, 0x82, 0x3f, 0xa9, 0x7b, 0x04, 0xeb,
        0x28, 0x20, 0x1d, 0x21, 0xb3, 0x7a, 0x0b, 0x8a, 0x70, 0xec, 0xd5, 0xe9, 0xd9, 0xdc, 0x07,
    ];

    fn kat_protector() -> RecordProtector {
        let block = KeyBlock {
            client_write_key: KAT_KEY,
            server_write_key: KAT_KEY,
            client_write_iv: KAT_IV,
            server_write_iv: KAT_IV,
        };
        RecordProtector::new(&block)
    }

    // Two protectors with distinct keys, one per endpoint. `new` is server-side,
    // so the client swaps read/write fields in its key block.
    fn paired_protectors() -> (RecordProtector, RecordProtector) {
        let client_key = [0xA1; 16];
        let server_key = [0xB2; 16];
        let client_iv = [0xC1, 0xC2, 0xC3, 0xC4];
        let server_iv = [0xD1, 0xD2, 0xD3, 0xD4];
        let server = KeyBlock {
            client_write_key: client_key,
            client_write_iv: client_iv,
            server_write_key: server_key,
            server_write_iv: server_iv,
        };
        let client = KeyBlock {
            client_write_key: server_key,
            client_write_iv: server_iv,
            server_write_key: client_key,
            server_write_iv: client_iv,
        };
        (RecordProtector::new(&client), RecordProtector::new(&server))
    }

    #[test]
    fn openssl_evp_known_answer_protects_and_opens_exact_bytes() {
        let mut protector = kat_protector();
        assert_eq!(
            protector
                .protect_with_nonce(HANDSHAKE, KAT_PLAINTEXT, &KAT_NONCE)
                .expect("KAT protection"),
            KAT_RECORD
        );
        let mut opener = kat_protector();
        assert_eq!(
            opener.open(KAT_RECORD).expect("KAT open"),
            (HANDSHAKE, KAT_PLAINTEXT.to_vec())
        );
    }

    #[test]
    fn roundtrip_keeps_outer_type_for_all_protected_types_and_sequences() {
        let (mut sender, mut receiver) = paired_protectors();
        let mut expected_sequence = 0u64;
        for _ in 0..6 {
            for (content_type, plaintext) in [
                (HANDSHAKE, b"finished".as_slice()),
                (ALERT, b"\x02\x28".as_slice()),
                (APPLICATION_DATA, b"payload".as_slice()),
            ] {
                let record = sender.protect(content_type, plaintext).expect("protect");
                assert_eq!(record[0], content_type, "outer type must be unchanged");
                assert_eq!(&record[1..3], &RECORD_VERSION);
                assert_eq!(
                    receiver.open(&record).expect("open"),
                    (content_type, plaintext.to_vec())
                );
            }
            expected_sequence += 3;
            assert_eq!(receiver.read_sequence, Some(expected_sequence));
            assert_eq!(sender.write_sequence, Some(expected_sequence));
        }
    }

    #[test]
    fn protect_uses_write_sequence_as_explicit_nonce() {
        let (mut sender, _) = paired_protectors();
        for expected in 0..2u64 {
            let record = sender
                .protect(APPLICATION_DATA, b"payload")
                .expect("protect");
            assert_eq!(
                &record[HEADER_LEN..HEADER_LEN + EXPLICIT_NONCE_LEN],
                &expected.to_be_bytes(),
                "explicit nonce must be the big-endian write sequence"
            );
        }
    }

    #[test]
    fn tampered_ciphertext_tag_type_version_and_length_fail_closed() {
        let mut cases = Vec::new();
        let mut ciphertext = kat_protector()
            .protect_with_nonce(HANDSHAKE, KAT_PLAINTEXT, &KAT_NONCE)
            .expect("valid record");
        ciphertext[13] ^= 1;
        cases.push((ciphertext, Tls12Error::AuthenticationFailed));

        let mut tag = kat_protector()
            .protect_with_nonce(HANDSHAKE, KAT_PLAINTEXT, &KAT_NONCE)
            .expect("valid record");
        let last = tag.len() - 1;
        tag[last] ^= 1;
        cases.push((tag, Tls12Error::AuthenticationFailed));

        let mut inner_type = kat_protector()
            .protect_with_nonce(HANDSHAKE, KAT_PLAINTEXT, &KAT_NONCE)
            .expect("valid record");
        inner_type[0] = ALERT;
        cases.push((inner_type, Tls12Error::AuthenticationFailed));

        let mut version = kat_protector()
            .protect_with_nonce(HANDSHAKE, KAT_PLAINTEXT, &KAT_NONCE)
            .expect("valid record");
        version[1] = 0x02;
        cases.push((version, Tls12Error::InvalidRecordVersion));

        let mut length = kat_protector()
            .protect_with_nonce(HANDSHAKE, KAT_PLAINTEXT, &KAT_NONCE)
            .expect("valid record");
        length[3] += 1;
        cases.push((length, Tls12Error::InvalidCiphertext));

        let mut truncated = kat_protector()
            .protect_with_nonce(HANDSHAKE, KAT_PLAINTEXT, &KAT_NONCE)
            .expect("valid record");
        truncated.truncate(truncated.len() - 1);
        cases.push((truncated, Tls12Error::InvalidCiphertext));

        for (record, expected) in cases {
            assert_eq!(
                kat_protector().open(&record).err(),
                Some(expected),
                "{record:?}"
            );
        }
    }

    #[test]
    fn sequence_is_bound_to_aad_and_replay_or_swap_fails() {
        let (mut sender, mut receiver) = paired_protectors();
        let first = sender.protect(HANDSHAKE, b"first").expect("first");
        let second = sender.protect(HANDSHAKE, b"second").expect("second");
        assert_eq!(
            receiver.open(&second).err(),
            Some(Tls12Error::AuthenticationFailed)
        );
        assert_eq!(
            receiver.open(&first).expect("first after rejected second"),
            (HANDSHAKE, b"first".to_vec())
        );
        assert_eq!(
            receiver.open(&first).err(),
            Some(Tls12Error::AuthenticationFailed),
            "replay at the next sequence must fail"
        );
        assert_eq!(
            receiver.open(&second).expect("second"),
            (HANDSHAKE, b"second".to_vec())
        );
    }

    #[test]
    fn repeated_explicit_nonce_changes_ciphertext_only_with_sequence() {
        let mut sender = kat_protector();
        let first = sender
            .protect_with_nonce(HANDSHAKE, KAT_PLAINTEXT, &KAT_NONCE)
            .expect("first");
        let second = sender
            .protect_with_nonce(HANDSHAKE, KAT_PLAINTEXT, &KAT_NONCE)
            .expect("second");
        assert_eq!(&first[..HEADER_LEN + EXPLICIT_NONCE_LEN], &second[..13]);
        assert_ne!(&first[13..], &second[13..]);

        let mut receiver = kat_protector();
        assert_eq!(
            receiver.open(&first).expect("first"),
            (HANDSHAKE, KAT_PLAINTEXT.to_vec())
        );
        assert_eq!(
            receiver.open(&second).expect("second"),
            (HANDSHAKE, KAT_PLAINTEXT.to_vec())
        );
    }

    #[test]
    fn resetting_sequences_installs_a_new_epoch() {
        let (mut sender, mut receiver) = paired_protectors();
        let old = sender.protect(APPLICATION_DATA, b"old").expect("old");
        assert!(receiver.open(&old).is_ok());

        sender.reset_write_sequence();
        receiver.reset_read_sequence();
        let fresh = sender.protect(APPLICATION_DATA, b"fresh").expect("fresh");
        assert_eq!(
            receiver.open(&fresh).expect("fresh after reset"),
            (APPLICATION_DATA, b"fresh".to_vec())
        );
        assert_eq!(
            receiver.open(&fresh).err(),
            Some(Tls12Error::AuthenticationFailed)
        );
    }

    #[test]
    fn sequence_exhaustion_is_terminal() {
        let (mut sender, mut receiver) = paired_protectors();
        sender.write_sequence = Some(u64::MAX - 1);
        receiver.read_sequence = Some(u64::MAX - 1);
        let last = sender.protect(ALERT, b"\x01\x00").expect("last sequence");
        assert_eq!(
            sender.protect(ALERT, b"\x01\x00").err(),
            Some(Tls12Error::SequenceExhausted)
        );
        assert_eq!(
            receiver.open(&last).expect("last open"),
            (ALERT, b"\x01\x00".to_vec())
        );
        assert_eq!(
            receiver.open(&last).err(),
            Some(Tls12Error::SequenceExhausted)
        );

        sender.reset_write_sequence();
        receiver.reset_read_sequence();
        sender.write_sequence = Some(u64::MAX);
        receiver.read_sequence = Some(u64::MAX);
        assert_eq!(
            sender.protect(ALERT, b"\x01\x00").err(),
            Some(Tls12Error::SequenceExhausted)
        );
        let fresh = kat_protector()
            .protect_with_nonce(ALERT, b"\x01\x00", &KAT_NONCE)
            .expect("record for exhausted reader");
        assert_eq!(
            receiver.open(&fresh).err(),
            Some(Tls12Error::SequenceExhausted)
        );
    }

    #[test]
    fn change_cipher_spec_is_plaintext_only() {
        assert_eq!(parse_ccs(&CCS_RECORD), Ok(()));
        for invalid in [
            &[][..],
            &CCS_RECORD[..5],
            &[0x15, 0x03, 0x03, 0x00, 0x01, 0x01][..],
            &[0x14, 0x02, 0x03, 0x00, 0x01, 0x01][..],
            &[0x14, 0x03, 0x03, 0x00, 0x02, 0x01, 0x01][..],
            &[0x14, 0x03, 0x03, 0x00, 0x01, 0x02][..],
        ] {
            assert_eq!(parse_ccs(invalid), Err(Tls12Error::InvalidChangeCipherSpec));
        }
        assert_eq!(
            kat_protector().protect(CHANGE_CIPHER_SPEC, &[0x01]).err(),
            Some(Tls12Error::UnexpectedContentType)
        );
        assert_eq!(
            kat_protector().open(&CCS_RECORD).err(),
            Some(Tls12Error::UnexpectedContentType)
        );
    }

    #[test]
    fn bounds_and_unsupported_types_are_rejected() {
        let mut sender = kat_protector();
        assert_eq!(
            sender.protect(HANDSHAKE, &[]).err(),
            Some(Tls12Error::EmptyFragment)
        );
        assert!(
            sender
                .protect(APPLICATION_DATA, &[0x00; MAX_PLAINTEXT])
                .is_ok()
        );
        assert_eq!(
            kat_protector()
                .protect(HANDSHAKE, &[0x00; MAX_PLAINTEXT + 1])
                .err(),
            Some(Tls12Error::RecordTooLarge)
        );
        for unsupported in [0x00, CHANGE_CIPHER_SPEC, 0xFE] {
            assert_eq!(
                kat_protector().protect(unsupported, b"x").err(),
                Some(Tls12Error::UnexpectedContentType)
            );
            assert_eq!(
                kat_protector()
                    .open(&[unsupported, 0x03, 0x03, 0x00, 0x18])
                    .err(),
                Some(Tls12Error::UnexpectedContentType)
            );
        }

        // Declared length below nonce+tag, and a full-size record whose
        // plaintext would exceed 2^14 while ciphertext is still within bounds.
        let short = [HANDSHAKE, 0x03, 0x03, 0x00, 0x17];
        assert_eq!(
            kat_protector().open(&short).err(),
            Some(Tls12Error::InvalidCiphertext)
        );
        let too_long_plaintext = MAX_PLAINTEXT + 1;
        let mut over = vec![HANDSHAKE, 0x03, 0x03];
        over.extend_from_slice(
            &u16::try_from(MIN_CIPHERTEXT + too_long_plaintext)
                .unwrap()
                .to_be_bytes(),
        );
        over.resize(HEADER_LEN + MIN_CIPHERTEXT + too_long_plaintext, 0);
        assert_eq!(
            kat_protector().open(&over).err(),
            Some(Tls12Error::RecordTooLarge)
        );

        // Declared ciphertext beyond 2^14+2048 is rejected before decryption.
        let oversize = MAX_CIPHERTEXT + 1;
        let mut record = vec![HANDSHAKE, 0x03, 0x03];
        record.extend_from_slice(&u16::try_from(oversize).unwrap().to_be_bytes());
        record.resize(HEADER_LEN + oversize, 0);
        assert_eq!(
            kat_protector().open(&record).err(),
            Some(Tls12Error::InvalidCiphertext)
        );
        assert_eq!(
            kat_protector().open(&record[..4]).err(),
            Some(Tls12Error::TruncatedRecord)
        );
    }
}
