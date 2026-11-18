//! TLS 1.2 key derivation for the narrow ECDHE-ECDSA-AES128-GCM-SHA256 profile.
//!
//! Pure computation: no records, sockets, cipher state or handshake control
//! flow lives here. Every secret buffer is zeroized on scope exit.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

fn hmac_sha256(secret: &[u8], data: &[u8]) -> [u8; 32] {
    // HMAC accepts keys of any length; a length error is not representable.
    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        unreachable!("HMAC-SHA256 accepts keys of any length");
    };
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// RFC 5246 §5 HMAC-SHA256 `P_hash(secret, label + seed)`.
///
/// `A(1) = HMAC(secret, label || seed)`, `P(i) = HMAC(secret, A(i) || label ||
/// seed)` and `A(i+1) = HMAC(secret, A(i))`; output is truncated to `out`.
pub fn tls12_prf(out: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
    let mut label_seed = Zeroizing::new(Vec::with_capacity(label.len() + seed.len()));
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);

    let mut a = Zeroizing::new(hmac_sha256(secret, &label_seed));
    let mut offset = 0;
    while offset < out.len() {
        let mut input = Zeroizing::new(Vec::with_capacity(a.len() + label_seed.len()));
        input.extend_from_slice(&a[..]);
        input.extend_from_slice(&label_seed);
        let block = Zeroizing::new(hmac_sha256(secret, &input));
        let len = (out.len() - offset).min(block.len());
        out[offset..offset + len].copy_from_slice(&block[..len]);
        offset += len;
        let next = Zeroizing::new(hmac_sha256(secret, &a[..]));
        a.copy_from_slice(&next[..]);
    }
}

/// RFC 5246 §7.4.9 master secret. With RFC 7627 EMS the seed is the session
/// hash of ClientHello and ServerHello instead of the two random values.
pub fn master_secret(
    pms: &[u8; 32],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    ems_seed: Option<&[u8; 32]>,
) -> [u8; 48] {
    let mut master = Zeroizing::new([0u8; 48]);
    match ems_seed {
        Some(session_hash) => tls12_prf(
            &mut master[..],
            pms,
            b"extended master secret",
            session_hash,
        ),
        None => {
            let mut seed = Zeroizing::new(Vec::with_capacity(64));
            seed.extend_from_slice(client_random);
            seed.extend_from_slice(server_random);
            tls12_prf(&mut master[..], pms, b"master secret", &seed);
        }
    }
    *master
}

/// RFC 5246 §6.3 key block for AEAD with zero-length MAC keys: two 16-byte
/// AES-128 keys followed by two 4-byte implicit nonces.
#[derive(Clone, Default, Eq, PartialEq, Zeroize)]
pub struct KeyBlock {
    pub client_write_key: [u8; 16],
    pub server_write_key: [u8; 16],
    pub client_write_iv: [u8; 4],
    pub server_write_iv: [u8; 4],
}

impl Drop for KeyBlock {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// RFC 5246 §6.3: `PRF(master_secret, "key expansion", server_random ||
/// client_random)`. The seed order is the reverse of `master_secret`.
pub fn key_block(
    master: &[u8; 48],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
) -> KeyBlock {
    let mut seed = Zeroizing::new(Vec::with_capacity(64));
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);
    let mut material = Zeroizing::new([0u8; 40]);
    tls12_prf(&mut material[..], master, b"key expansion", &seed);

    let mut block = KeyBlock::default();
    block.client_write_key.copy_from_slice(&material[..16]);
    block.server_write_key.copy_from_slice(&material[16..32]);
    block.client_write_iv.copy_from_slice(&material[32..36]);
    block.server_write_iv.copy_from_slice(&material[36..40]);
    block
}

/// RFC 5246 §7.4.9 `verify_data` for one role's Finished message.
pub fn verify_data(master: &[u8; 48], transcript_sha256: &[u8; 32], label: &[u8]) -> [u8; 12] {
    let mut out = Zeroizing::new([0u8; 12]);
    tls12_prf(&mut out[..], master, label, transcript_sha256);
    *out
}

/// RFC 7627 §5.1 session hash: SHA-256 over the raw ClientHello message
/// (including its handshake header) followed by the framed ServerHello.
/// No other handshake messages enter this hash.
pub fn ems_session_hash(client_hello_message: &[u8], server_hello_message: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(client_hello_message);
    hash.update(server_hello_message);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::super::HandshakeMessage;
    use super::super::status::wrap_handshake_message;
    use super::*;

    // Botan tls_prf.vec, citing the IETF TLS test vector: TLS-12-PRF with
    // HMAC(SHA-256), a 100-byte output and "test label".
    #[test]
    fn botan_tls12_prf_known_answer() {
        let secret = hex::decode("9bbe436ba940f017b17652849a71db35").unwrap();
        let salt = hex::decode("a0ba9f936cda311827a6f796ffd5198c").unwrap();
        let expected = hex::decode(
            "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66",
        )
        .unwrap();
        assert_eq!(expected.len(), 100);
        let mut out = [0u8; 100];
        tls12_prf(&mut out, &secret, b"test label", &salt);
        assert_eq!(out.as_slice(), expected.as_slice());
    }

    // RFC 4231 test case 2: HMAC-SHA-256 with a 20-byte 0x0b key.
    #[test]
    fn hmac_sha256_matches_rfc_4231() {
        let mut mac = HmacSha256::new_from_slice(&[0x0b; 20]).unwrap();
        mac.update(b"Hi There");
        assert_eq!(
            hex::encode(mac.finalize().into_bytes()),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn master_secret_uses_the_right_seed_and_ems_changes_it() {
        let pms = [0x11; 32];
        let client = [0xA1; 32];
        let server = [0xB2; 32];
        let session_hash = [0xC3; 32];

        let mut seed = Vec::new();
        seed.extend_from_slice(&client);
        seed.extend_from_slice(&server);
        let mut expected = [0u8; 48];
        tls12_prf(&mut expected, &pms, b"master secret", &seed);
        assert_eq!(master_secret(&pms, &client, &server, None), expected);

        let mut ems = [0u8; 48];
        tls12_prf(&mut ems, &pms, b"extended master secret", &session_hash);
        assert_eq!(
            master_secret(&pms, &client, &server, Some(&session_hash)),
            ems
        );
        assert_ne!(ems, expected);
    }

    #[test]
    fn key_block_matches_direct_prf_in_aead_field_order() {
        let master = [0x44; 48];
        let client = [0xA1; 32];
        let server = [0xB2; 32];
        let mut seed = Vec::new();
        seed.extend_from_slice(&server);
        seed.extend_from_slice(&client);
        let mut material = [0u8; 40];
        tls12_prf(&mut material, &master, b"key expansion", &seed);

        let block = key_block(&master, &server, &client);
        assert_eq!(block.client_write_key.as_slice(), &material[..16]);
        assert_eq!(block.server_write_key.as_slice(), &material[16..32]);
        assert_eq!(block.client_write_iv.as_slice(), &material[32..36]);
        assert_eq!(block.server_write_iv.as_slice(), &material[36..40]);
    }

    #[test]
    fn ems_session_hash_covers_only_client_hello_and_framed_server_hello() {
        let client_hello = [1u8, 0, 0, 2, 0x03, 0x03];
        let server_hello = HandshakeMessage {
            msg_type: 2,
            body: vec![0x03, 0x03],
        };
        let framed = wrap_handshake_message(server_hello.msg_type, &server_hello.body).unwrap();
        let expected: [u8; 32] =
            Sha256::digest([client_hello.as_slice(), framed.as_slice()].concat()).into();
        assert_eq!(
            ems_session_hash(&client_hello, &framed).as_slice(),
            expected.as_slice()
        );

        let other = HandshakeMessage {
            msg_type: 12,
            body: vec![0x03, 0x00, 0x17],
        };
        let mut later = framed.clone();
        later.extend_from_slice(&wrap_handshake_message(other.msg_type, &other.body).unwrap());
        assert_ne!(ems_session_hash(&client_hello, &later), expected);
    }
}
