use super::*;

// RFC 8448 §3, client handshake traffic secret and protected Finished record.
const SECRET: [u8; 32] = *b"\xb3\xed\xdb\x12\x6e\x06\x7f\x35\xa7\x80\xb3\xab\xf4\x5e\x2d\x8f\
    \x3b\x1a\x95\x07\x38\xf5\x2e\x96\x00\x74\x6a\x0e\x27\xa5\x5a\x21";
const KEY: [u8; 16] = *b"\xdb\xfa\xa6\x93\xd1\x76\x2c\x5b\x66\x6a\xf5\xd9\x50\x25\x8d\x01";
const IV: RecordIv = *b"\x5b\xd3\xc7\x1b\x83\x6e\x0b\x76\xbb\x73\x26\x5f";
const RECORD: [u8; 58] = *b"\x17\x03\x03\x00\x35\
    \x75\xec\x4d\xc2\x38\xcc\xe6\x0b\x29\x80\x44\xa7\x1e\x21\x9c\x56\
    \xcc\x77\xb0\x51\x7f\xe9\xb9\x3c\x7a\x4b\xfc\x44\xd8\x7f\x38\xf8\
    \x03\x38\xac\x98\xfc\x46\xde\xb3\x84\xbd\x1c\xae\xac\xab\x68\x67\xd7\x26\xc4\x05\x46";
const FINISHED: [u8; 36] = *b"\x14\x00\x00\x20\
    \xa8\xec\x43\x6d\x67\x76\x34\xae\x52\x5a\xc1\xfc\xeb\xe1\x1a\x03\
    \x9e\xc1\x76\x94\xfa\xc6\xe9\x85\x27\xb6\x42\xf2\xed\xd5\xce\x61";

// RFC 8448 §3, server application traffic secret and protected payload.
const SERVER_APPLICATION_SECRET_HEX: &str =
    "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643";
const SERVER_APPLICATION_KEY_HEX: &str = "9f02283b6c9c07efc26bb9f2ac92e356";
const SERVER_APPLICATION_IV_HEX: &str = "cf782b88dd83549aadf1e984";
const APPLICATION_PAYLOAD_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031";
const APPLICATION_RECORD_HEX: &str = "17030300432e937e11ef4ac740e538ad36005fc4a46932fc3225d05f82aa1b36e30efaf97d90e6dffc602dcb501a59a8fcc49c4bf2e5f0a21c0047c2abf332540dd032e167c2955d";

fn from_hex<const N: usize>(digits: &str) -> [u8; N] {
    hex::decode(digits).unwrap().try_into().unwrap()
}

fn server_application_epoch() -> WriteEpoch {
    WriteEpoch::aes_128_gcm_sha256(&from_hex::<32>(SERVER_APPLICATION_SECRET_HEX))
        .expect("initialize test write epoch")
}

fn epoch() -> ReadEpoch {
    ReadEpoch::aes_128_gcm_sha256(&SECRET).expect("initialize test read epoch")
}

fn seal(inner: &[u8], nonce: RecordIv) -> Vec<u8> {
    let length = u16::try_from(inner.len() + TAG_LEN).expect("test record length fits in u16");
    let [msb, lsb] = length.to_be_bytes();
    let mut record = vec![0x17, 0x03, 0x03, msb, lsb];
    record.extend_from_slice(inner);
    let (aad, data) = record.split_at_mut(HEADER_LEN);
    let tag = Aes128Gcm::new((&KEY).into())
        .encrypt_in_place_detached((&nonce).into(), aad, data)
        .expect("seal test record");
    record.extend_from_slice(&tag);
    record
}

fn assert_closed(epoch: &mut ReadEpoch) {
    let mut valid = RECORD;
    assert_eq!(epoch.open(&mut valid).err(), Some(RecordError::EpochClosed));
    assert_eq!(valid, [0; RECORD.len()]);
}

fn assert_terminal_error(epoch: &mut ReadEpoch, record: &mut [u8], error: RecordError) {
    assert_eq!(epoch.open(record).err(), Some(error));
    assert!(record.iter().all(|&octet| octet == 0));
    assert_closed(epoch);
}

#[test]
fn derives_rfc8448_client_handshake_key_and_iv() {
    let (key, iv) = derive_key_iv(&SECRET).expect("derive RFC 8448 key and IV");
    assert_eq!(*key, KEY);
    assert_eq!(iv, IV);
}

#[test]
fn opens_rfc8448_client_finished() {
    let mut record = RECORD;
    let inner = epoch()
        .open(&mut record)
        .expect("authenticate RFC 8448 record");
    // 0x14 is the Finished handshake message type, not the enclosing record type.
    assert_eq!(inner.content_type, 0x16);
    assert_eq!(inner.content, FINISHED);
}

#[test]
fn rejects_bad_framing() {
    let mut short = RECORD;
    let mut truncated = RECORD;
    let mut wrong_type = RECORD;
    wrong_type[0] = 0x16;
    let mut wrong_version = RECORD;
    wrong_version[2] = 0x01;
    let mut trailing = RECORD.to_vec();
    trailing.push(0);
    let mut tag_only = seal(&[], IV);
    let mut oversized = seal(&[0; MAX_CIPHERTEXT - TAG_LEN + 1], IV);
    for record in [
        &mut short[..4],
        &mut truncated[..RECORD.len() - 1],
        &mut wrong_type[..],
        &mut wrong_version[..],
        &mut trailing[..],
        &mut tag_only[..],
        &mut oversized[..],
    ] {
        assert_terminal_error(&mut epoch(), record, RecordError::InvalidCiphertext);
    }
}

#[test]
fn rejects_corrupted_tag() {
    let mut record = RECORD;
    record[RECORD.len() - 1] ^= 1;
    assert_terminal_error(&mut epoch(), &mut record, RecordError::AuthenticationFailed);
}

#[test]
fn rejects_invalid_authenticated_inner_plaintext() {
    let mut oversized = vec![0; MAX_INNER_PLAINTEXT + 1];
    oversized[0] = APPLICATION_DATA;
    for inner in [&[0, 0][..], &[1, 0x14], &[1, 0xff], &[ALERT, 0], &oversized] {
        let mut record = seal(inner, IV);
        assert_terminal_error(
            &mut epoch(),
            &mut record,
            RecordError::InvalidInnerPlaintext,
        );
    }
}

#[test]
fn opens_padded_record_at_next_sequence() {
    let mut reader = epoch();
    let mut first = RECORD;
    reader.open(&mut first).expect("open sequence zero");
    let mut nonce = IV;
    nonce[11] ^= 1;
    let mut padded = vec![0; MAX_INNER_PLAINTEXT];
    padded[..3].copy_from_slice(&[42, 0, APPLICATION_DATA]);
    let mut record = seal(&padded, nonce);
    let inner = reader.open(&mut record).expect("open sequence one");
    assert_eq!(inner.content_type, APPLICATION_DATA);
    assert_eq!(inner.content, [42, 0]);
}

#[test]
fn rejects_replay_in_one_epoch() {
    let mut reader = epoch();
    let mut first = RECORD;
    let mut replay = first;
    reader.open(&mut first).expect("open sequence zero");
    assert_terminal_error(&mut reader, &mut replay, RecordError::AuthenticationFailed);
}

#[test]
fn closes_at_sequence_exhaustion_without_wrap() {
    let mut reader = epoch();
    reader.next_sequence = Some(u64::MAX);
    let mut nonce = IV;
    nonce[4..].iter_mut().for_each(|octet| *octet = !*octet);
    let mut last = seal(&[APPLICATION_DATA], nonce);
    assert!(
        reader
            .open(&mut last)
            .expect("open final record")
            .content
            .is_empty()
    );
    assert_closed(&mut reader);
}

#[test]
fn derives_rfc8448_server_application_key_and_iv() {
    let secret = from_hex::<32>(SERVER_APPLICATION_SECRET_HEX);
    let (key, iv) = derive_key_iv(&secret).expect("derive server application key and IV");
    assert_eq!(hex::encode(&key[..]), SERVER_APPLICATION_KEY_HEX);
    assert_eq!(hex::encode(iv), SERVER_APPLICATION_IV_HEX);
}

#[test]
fn protects_rfc8448_server_application_record() {
    let payload = hex::decode(APPLICATION_PAYLOAD_HEX).unwrap();
    assert_eq!(payload.len(), 50);
    let mut writer = server_application_epoch();
    // RFC 8448 protects this payload as the second server application record,
    // so its sequence number is one rather than zero.
    writer.next_sequence = Some(1);
    let mut out = Vec::new();
    writer
        .protect(APPLICATION_DATA, &payload, &mut out)
        .expect("protect RFC 8448 application data");
    assert_eq!(out.len(), 72);
    assert_eq!(hex::encode(&out), APPLICATION_RECORD_HEX);
}

#[test]
fn advances_write_sequence_without_reusing_a_nonce() {
    let secret = from_hex::<32>(SERVER_APPLICATION_SECRET_HEX);
    let payload = hex::decode(APPLICATION_PAYLOAD_HEX).unwrap();
    let mut writer = server_application_epoch();
    let mut first = Vec::new();
    let mut second = Vec::new();
    writer
        .protect(APPLICATION_DATA, &payload, &mut first)
        .expect("protect at sequence zero");
    writer
        .protect(APPLICATION_DATA, &payload, &mut second)
        .expect("protect at sequence one");
    assert_ne!(first[HEADER_LEN..], second[HEADER_LEN..]);

    let mut reader =
        ReadEpoch::aes_128_gcm_sha256(&secret).expect("initialize matching read epoch");
    let first_inner = reader.open(&mut first).expect("open sequence zero");
    let second_inner = reader.open(&mut second).expect("open sequence one");
    assert_eq!(first_inner.content_type, APPLICATION_DATA);
    assert_eq!(second_inner.content_type, APPLICATION_DATA);
    assert_eq!(second_inner.content, payload);
}

#[test]
fn rejects_invalid_write_inner_plaintext_without_changing_output() {
    let payload = hex::decode(APPLICATION_PAYLOAD_HEX).unwrap();
    let mut writer = server_application_epoch();
    let mut out = vec![0xaa, 0xbb];
    for content_type in [0x14, 0xff] {
        assert_eq!(
            writer.protect(content_type, &payload, &mut out),
            Err(RecordError::InvalidInnerPlaintext)
        );
    }
    for (content_type, content) in [
        (ALERT, &[][..]),
        (HANDSHAKE, &[][..]),
        (APPLICATION_DATA, &[0; MAX_INNER_PLAINTEXT][..]),
    ] {
        assert_eq!(
            writer.protect(content_type, content, &mut out),
            Err(RecordError::InvalidInnerPlaintext)
        );
    }
    assert_eq!(out, [0xaa, 0xbb]);

    // Rejected input consumed no sequence, so the epoch still protects records.
    writer
        .protect(ALERT, b"\x02\x28", &mut out)
        .expect("protect valid alert after rejections");
    assert!(out.len() > 2);
}

#[test]
fn closes_write_epoch_at_sequence_exhaustion() {
    let payload = hex::decode(APPLICATION_PAYLOAD_HEX).unwrap();
    let mut writer = server_application_epoch();
    writer.next_sequence = Some(u64::MAX);
    let mut out = Vec::new();
    writer
        .protect(APPLICATION_DATA, &payload, &mut out)
        .expect("protect with final sequence");
    assert_eq!(
        writer.protect(APPLICATION_DATA, &payload, &mut out),
        Err(RecordError::EpochClosed)
    );
    assert_eq!(out.len(), 72);
}
