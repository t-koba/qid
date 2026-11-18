#![no_main]

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes128Gcm;
use libfuzzer_sys::fuzz_target;
use qid_tls::tls13::ReadEpoch;

const HEADER_LEN: usize = 5;
const TAG_LEN: usize = 16;
const MAX_INNER: usize = 512;

// Public RFC 8448 section 3 test vectors: the client handshake traffic secret
// and its derived AES-128-GCM key and IV. These are published vectors, not secrets.
const SECRET: [u8; 32] = *b"\xb3\xed\xdb\x12\x6e\x06\x7f\x35\xa7\x80\xb3\xab\xf4\x5e\x2d\x8f\
    \x3b\x1a\x95\x07\x38\xf5\x2e\x96\x00\x74\x6a\x0e\x27\xa5\x5a\x21";
const KEY: [u8; 16] = *b"\xdb\xfa\xa6\x93\xd1\x76\x2c\x5b\x66\x6a\xf5\xd9\x50\x25\x8d\x01";
const IV: [u8; 12] = *b"\x5b\xd3\xc7\x1b\x83\x6e\x0b\x76\xbb\x73\x26\x5f";

fuzz_target!(|data: &[u8]| {
    // Unauthenticated path: framing, authentication, and error zeroization.
    if let Ok(mut epoch) = ReadEpoch::aes_128_gcm_sha256(&SECRET) {
        let mut candidate = data.to_vec();
        let _ = epoch.open(&mut candidate);
    }

    // Authenticated path: attacker-controlled inner plaintext in a valid record.
    if let Ok(mut epoch) = ReadEpoch::aes_128_gcm_sha256(&SECRET) {
        let inner = &data[..data.len().min(MAX_INNER)];
        let length = (inner.len() + TAG_LEN) as u16;
        let [msb, lsb] = length.to_be_bytes();
        let mut record = Vec::with_capacity(HEADER_LEN + inner.len() + TAG_LEN);
        record.extend_from_slice(&[0x17, 0x03, 0x03, msb, lsb]);
        record.extend_from_slice(inner);

        let mut nonce = IV;
        for (octet, seq_octet) in nonce[4..].iter_mut().zip(0u64.to_be_bytes()) {
            *octet ^= seq_octet;
        }

        let (aad, ciphertext) = record.split_at_mut(HEADER_LEN);
        if let Ok(tag) = Aes128Gcm::new((&KEY).into()).encrypt_in_place_detached(
            (&nonce).into(),
            aad,
            ciphertext,
        ) {
            record.extend_from_slice(&tag);
            let _ = epoch.open(&mut record);
        }
    }
});
