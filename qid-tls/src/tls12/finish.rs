//! Offline completion of the narrow TLS 1.2 server handshake: ECDHE secret,
//! Finished verification and the server's Finished message.
//!
//! This module derives key material and checks handshake bytes only. It does
//! not encrypt records, touch sockets, install a listener or change another
//! TLS stack. ChangeCipherSpec records are the caller's responsibility.

use super::Tls12Error;
use super::flight::ServerFirstFlight;
use super::prf::{KeyBlock, ems_session_hash, key_block, master_secret, verify_data};
use super::status::wrap_handshake_message;
use p256::{PublicKey, SecretKey, ecdh::diffie_hellman};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const SERVER_HELLO: u8 = 2;
const CLIENT_KEY_EXCHANGE: u8 = 16;
const FINISHED: u8 = 20;
const UNCOMPRESSED_POINT_LEN: usize = 65;

/// RFC 4492 §5.10: the X coordinate of ECDHE shared point as the 32-byte
/// pre-master secret. Only the fixed P-256 uncompressed point is accepted.
pub fn ecdh_pre_master(secret: &SecretKey, peer_point: &[u8]) -> Result<[u8; 32], Tls12Error> {
    if peer_point.len() != UNCOMPRESSED_POINT_LEN || peer_point[0] != 0x04 {
        return Err(Tls12Error::InvalidEcdhePoint);
    }
    let public =
        PublicKey::from_sec1_bytes(peer_point).map_err(|_| Tls12Error::InvalidEcdhePoint)?;
    let shared = diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    let mut pms = [0u8; 32];
    pms.copy_from_slice(shared.raw_secret_bytes());
    Ok(pms)
}

/// RFC 5246 §7.4.6 `ClientKeyExchange`: an `opaque point<1..2^8-1>` whose
/// single point must be exactly 65 uncompressed P-256 bytes.
pub fn parse_client_key_exchange(body: &[u8]) -> Result<&[u8], Tls12Error> {
    match body.first().copied() {
        Some(len)
            if len as usize == UNCOMPRESSED_POINT_LEN
                && body.len() == UNCOMPRESSED_POINT_LEN + 1 =>
        {
            Ok(&body[1..])
        }
        _ => Err(Tls12Error::InvalidClientKeyExchange),
    }
}

/// Check a framed handshake message's type and exact body length, returning
/// its body. Reassembly of record fragments belongs to the caller.
fn framed_body(message: &[u8], msg_type: u8, error: Tls12Error) -> Result<&[u8], Tls12Error> {
    if message.len() < 4 || message[0] != msg_type {
        return Err(error);
    }
    let body_len = u32::from_be_bytes([0, message[1], message[2], message[3]]) as usize;
    if body_len != message.len() - 4 {
        return Err(error);
    }
    Ok(&message[4..])
}

/// Derive the master secret and key block shared by handshake completion
/// and early read-key installation. The flight and the ClientKeyExchange are
/// validated before any key material is returned.
#[allow(clippy::too_many_arguments)]
pub(crate) fn derive_handshake_keys(
    flight: &ServerFirstFlight,
    client_hello_message: &[u8],
    client_key_exchange_message: &[u8],
    client_key_exchange_body: &[u8],
    ecdhe_secret: &SecretKey,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    ems_negotiated: bool,
) -> Result<(Zeroizing<[u8; 48]>, KeyBlock), Tls12Error> {
    if flight.messages.first().map(|message| message.msg_type) != Some(SERVER_HELLO)
        || !flight.transcript.starts_with(client_hello_message)
    {
        return Err(Tls12Error::InvalidServerFirstFlight);
    }
    let peer_point = parse_client_key_exchange(client_key_exchange_body)?;
    let pms = Zeroizing::new(ecdh_pre_master(ecdhe_secret, peer_point)?);
    let ems_seed = if ems_negotiated {
        let mut transcript = flight.transcript.clone();
        transcript.extend_from_slice(client_key_exchange_message);
        Some(ems_session_hash(&transcript))
    } else {
        None
    };
    let master = Zeroizing::new(master_secret(
        &pms,
        client_random,
        server_random,
        ems_seed.as_ref(),
    ));
    let keys = key_block(&master, server_random, client_random);
    Ok((master, keys))
}

/// The derived results of a completed offline server handshake.
pub struct FinishedResult {
    /// Framed `Finished` handshake message (type 20, u24 length 12, verify_data).
    pub server_finished_message: Vec<u8>,
    /// RFC 5246 §7.4.9 master secret, with EMS when negotiated. Callers own
    /// this value and should wipe it when no longer needed.
    pub master_secret: [u8; 48],
    /// AEAD keys and implicit nonces; no record state is created here.
    pub key_block: KeyBlock,
}

/// Verify the client's Finished and produce the server's Finished.
///
/// `flight.transcript` holds the raw ClientHello plus the framed messages
/// emitted in `flight.messages`; the two Finished hashes extend those exact
/// bytes with the framed ClientKeyExchange and client Finished messages. When
/// `ems_negotiated` is true, the RFC 7627 session hash covers the framed
/// transcript through the client's ClientKeyExchange.
///
/// The flight is never mutated. Callers send ChangeCipherSpec records and do
/// any record encryption outside this function.
// Each handshake input stays a separate argument so callers must supply the
// exact bytes used by each transcript hash; the signature is part of the API.
#[allow(clippy::too_many_arguments)]
pub fn complete_server_handshake(
    flight: &ServerFirstFlight,
    client_hello_message: &[u8],
    client_key_exchange_message: &[u8],
    client_finished_message: &[u8],
    ecdhe_secret: &SecretKey,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    ems_negotiated: bool,
) -> Result<FinishedResult, Tls12Error> {
    let cke_body = framed_body(
        client_key_exchange_message,
        CLIENT_KEY_EXCHANGE,
        Tls12Error::InvalidClientKeyExchange,
    )?;
    let (master, keys) = derive_handshake_keys(
        flight,
        client_hello_message,
        client_key_exchange_message,
        cke_body,
        ecdhe_secret,
        client_random,
        server_random,
        ems_negotiated,
    )?;

    let finished_body = framed_body(
        client_finished_message,
        FINISHED,
        Tls12Error::InvalidFinishedMessage,
    )?;
    if finished_body.len() != 12 {
        return Err(Tls12Error::InvalidFinishedMessage);
    }
    let mut client_hash = Sha256::new();
    client_hash.update(&flight.transcript);
    client_hash.update(client_key_exchange_message);
    let client_digest: [u8; 32] = client_hash.finalize().into();
    let expected = verify_data(&master, &client_digest, b"client finished");
    if expected.as_slice().ct_eq(finished_body).unwrap_u8() != 1 {
        return Err(Tls12Error::FinishedVerifyFailed);
    }

    let mut server_hash = Sha256::new();
    server_hash.update(&flight.transcript);
    server_hash.update(client_key_exchange_message);
    server_hash.update(client_finished_message);
    let server_digest: [u8; 32] = server_hash.finalize().into();
    let server_verify = verify_data(&master, &server_digest, b"server finished");
    let server_finished_message = wrap_handshake_message(FINISHED, &server_verify)?;

    Ok(FinishedResult {
        server_finished_message,
        master_secret: *master,
        key_block: keys,
    })
}

#[cfg(test)]
mod tests {
    use super::super::status::{OcspResponse, wrap_handshake_message};
    use super::super::{ServerFirstFlight, ServerFirstFlightInput, build_server_first_flight};
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::sec1::ToSec1Point;

    const CLIENT_SCALAR: [u8; 32] = [0x33; 32];
    const SERVER_SCALAR: [u8; 32] = [0x11; 32];
    const SIGNING_SCALAR: [u8; 32] = [0x22; 32];
    const CLIENT_RANDOM: [u8; 32] = [0xA1; 32];
    const SERVER_RANDOM: [u8; 32] = [0xB2; 32];

    fn extension(ext_type: u16, data: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(4 + data.len());
        encoded.extend_from_slice(&ext_type.to_be_bytes());
        encoded.extend_from_slice(&(data.len() as u16).to_be_bytes());
        encoded.extend_from_slice(data);
        encoded
    }

    fn client_message(extensions: &[u8]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&CLIENT_RANDOM);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0xC02Bu16.to_be_bytes());
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);
        let mut message = vec![1, 0, 0, 0];
        message[1..4].copy_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        message.extend_from_slice(&body);
        message
    }

    fn client_extensions(ems: bool) -> Vec<u8> {
        let mut extensions = extension(17, &[0x00, 0x07, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00]);
        if ems {
            extensions.extend_from_slice(&extension(0x0017, &[]));
        }
        extensions.extend_from_slice(&extension(10, &[0x00, 0x02, 0x00, 0x17]));
        extensions.extend_from_slice(&extension(11, &[0x01, 0x00]));
        extensions.extend_from_slice(&extension(13, &[0x00, 0x02, 0x04, 0x03]));
        extensions
    }

    struct Setup {
        ems: bool,
        client_hello: Vec<u8>,
        flight: ServerFirstFlight,
        client_secret: SecretKey,
        server_secret: SecretKey,
        cke: Vec<u8>,
        client_finished: Vec<u8>,
        master: [u8; 48],
        transcript: Vec<u8>,
    }

    impl Setup {
        fn new(ems: bool) -> Self {
            let server_secret = SecretKey::from_slice(&SERVER_SCALAR).unwrap();
            let signing = SigningKey::from_bytes(&SIGNING_SCALAR.into()).unwrap();
            let client_secret = SecretKey::from_slice(&CLIENT_SCALAR).unwrap();
            let client_hello = client_message(&client_extensions(ems));
            let cert = [0x30, 0x00];
            let staple = [0xAA];
            let certificates: &[&[u8]] = &[&cert];
            let responses: &[OcspResponse<'_>] = &[OcspResponse::Der(&staple)];
            let flight = build_server_first_flight(&ServerFirstFlightInput {
                client_hello_message: &client_hello,
                server_random: SERVER_RANDOM,
                certificates,
                ocsp_responses: responses,
                ecdhe_secret: &server_secret,
                signing_key: &signing,
            })
            .unwrap();

            let point = client_secret.public_key().to_sec1_point(false);
            let mut cke_body = vec![UNCOMPRESSED_POINT_LEN as u8];
            cke_body.extend_from_slice(point.as_bytes());
            let cke = wrap_handshake_message(CLIENT_KEY_EXCHANGE, &cke_body).unwrap();

            let ske = &flight.messages[3].body;
            assert_eq!(&ske[..4], &[0x03, 0x00, 0x17, UNCOMPRESSED_POINT_LEN as u8]);
            let pms = ecdh_pre_master(&client_secret, &ske[4..69]).unwrap();

            let mut transcript = client_hello.clone();
            for message in &flight.messages {
                transcript.extend_from_slice(
                    &wrap_handshake_message(message.msg_type, &message.body).unwrap(),
                );
            }
            assert_eq!(flight.transcript, transcript);
            let ems_seed =
                ems.then(|| ems_session_hash(&[transcript.as_slice(), cke.as_slice()].concat()));
            let master = master_secret(&pms, &CLIENT_RANDOM, &SERVER_RANDOM, ems_seed.as_ref());
            assert_eq!(
                flight.transcript_sha256.as_slice(),
                Sha256::digest(&transcript).as_slice()
            );

            let client_digest: [u8; 32] =
                Sha256::digest([transcript.as_slice(), cke.as_slice()].concat()).into();
            let verify = verify_data(&master, &client_digest, b"client finished");
            let client_finished = wrap_handshake_message(FINISHED, &verify).unwrap();

            Self {
                ems,
                client_hello,
                flight,
                client_secret,
                server_secret,
                cke,
                client_finished,
                master,
                transcript,
            }
        }

        fn complete(&self) -> Result<FinishedResult, Tls12Error> {
            complete_server_handshake(
                &self.flight,
                &self.client_hello,
                &self.cke,
                &self.client_finished,
                &self.server_secret,
                &CLIENT_RANDOM,
                &SERVER_RANDOM,
                self.ems,
            )
        }
    }

    #[test]
    fn ecdh_pre_master_is_symmetric_and_rejects_invalid_points() {
        let a = SecretKey::from_slice(&CLIENT_SCALAR).unwrap();
        let b = SecretKey::from_slice(&SERVER_SCALAR).unwrap();
        let a_point = a.public_key().to_sec1_point(false);
        let b_point = b.public_key().to_sec1_point(false);
        assert_eq!(
            ecdh_pre_master(&a, b_point.as_bytes()).unwrap(),
            ecdh_pre_master(&b, a_point.as_bytes()).unwrap()
        );

        let compressed = a.public_key().to_sec1_point(true);
        assert_eq!(
            ecdh_pre_master(&a, compressed.as_bytes()),
            Err(Tls12Error::InvalidEcdhePoint)
        );
        assert_eq!(
            ecdh_pre_master(&a, &a_point.as_bytes()[..64]),
            Err(Tls12Error::InvalidEcdhePoint)
        );
        let mut wrong_tag = a_point.as_bytes().to_vec();
        wrong_tag[0] = 0x02;
        assert_eq!(
            ecdh_pre_master(&a, &wrong_tag),
            Err(Tls12Error::InvalidEcdhePoint)
        );
        let mut off_curve = vec![0x04];
        off_curve.extend_from_slice(&[0u8; 64]);
        assert_eq!(
            ecdh_pre_master(&a, &off_curve),
            Err(Tls12Error::InvalidEcdhePoint)
        );
    }

    #[test]
    fn client_key_exchange_vector_rejects_wrong_lengths() {
        let client = SecretKey::from_slice(&CLIENT_SCALAR).unwrap();
        let point = client.public_key().to_sec1_point(false);
        let mut body = vec![UNCOMPRESSED_POINT_LEN as u8];
        body.extend_from_slice(point.as_bytes());
        assert_eq!(parse_client_key_exchange(&body).unwrap(), point.as_bytes());

        for bad in [
            Vec::new(),
            vec![UNCOMPRESSED_POINT_LEN as u8],
            vec![64],
            body[..65].to_vec(),
            {
                let mut trailing = body.clone();
                trailing.push(0);
                trailing
            },
        ] {
            assert_eq!(
                parse_client_key_exchange(&bad),
                Err(Tls12Error::InvalidClientKeyExchange)
            );
        }
    }

    #[test]
    fn handshake_completes_with_and_without_ems_and_matches_independent_hash() {
        for ems in [true, false] {
            let setup = Setup::new(ems);
            let result = setup.complete().unwrap();

            assert_eq!(result.master_secret, setup.master);
            let expected_keys = key_block(&setup.master, &SERVER_RANDOM, &CLIENT_RANDOM);
            assert_eq!(
                result.key_block.client_write_key,
                expected_keys.client_write_key
            );
            assert_eq!(
                result.key_block.server_write_key,
                expected_keys.server_write_key
            );
            assert_eq!(
                result.key_block.client_write_iv,
                expected_keys.client_write_iv
            );
            assert_eq!(
                result.key_block.server_write_iv,
                expected_keys.server_write_iv
            );
            assert_eq!(&result.server_finished_message[..4], &[20, 0, 0, 12]);

            let mut joined = setup.transcript.clone();
            joined.extend_from_slice(&setup.cke);
            joined.extend_from_slice(&setup.client_finished);
            let digest: [u8; 32] = Sha256::digest(joined).into();
            let verify = verify_data(&setup.master, &digest, b"server finished");
            let expected = wrap_handshake_message(FINISHED, &verify).unwrap();
            assert_eq!(result.server_finished_message, expected);
            let ems_ack = setup.flight.messages[0]
                .body
                .windows(4)
                .any(|window| window == [0x00, 0x17, 0x00, 0x00]);
            assert_eq!(ems_ack, ems);
        }
    }

    #[test]
    fn tampered_finished_point_random_or_ems_flag_is_rejected() {
        let setup = Setup::new(true);

        let mut bad_finished = setup.client_finished.clone();
        *bad_finished.last_mut().unwrap() ^= 1;
        assert_eq!(
            complete_server_handshake(
                &setup.flight,
                &setup.client_hello,
                &setup.cke,
                &bad_finished,
                &setup.server_secret,
                &CLIENT_RANDOM,
                &SERVER_RANDOM,
                true,
            )
            .err(),
            Some(Tls12Error::FinishedVerifyFailed)
        );

        let mut bad_point = setup.cke.clone();
        bad_point[20] ^= 1;
        assert!(
            complete_server_handshake(
                &setup.flight,
                &setup.client_hello,
                &bad_point,
                &setup.client_finished,
                &setup.server_secret,
                &CLIENT_RANDOM,
                &SERVER_RANDOM,
                true,
            )
            .is_err()
        );

        // With EMS the session hash replaces the two randoms in the master
        // secret; without EMS each random is bound to the Finished check.
        let non_ems = Setup::new(false);
        let mut wrong_client_random = CLIENT_RANDOM;
        wrong_client_random[0] ^= 1;
        assert_eq!(
            complete_server_handshake(
                &non_ems.flight,
                &non_ems.client_hello,
                &non_ems.cke,
                &non_ems.client_finished,
                &non_ems.server_secret,
                &wrong_client_random,
                &SERVER_RANDOM,
                false,
            )
            .err(),
            Some(Tls12Error::FinishedVerifyFailed)
        );
        let mut wrong_server_random = SERVER_RANDOM;
        wrong_server_random[0] ^= 1;
        assert_eq!(
            complete_server_handshake(
                &non_ems.flight,
                &non_ems.client_hello,
                &non_ems.cke,
                &non_ems.client_finished,
                &non_ems.server_secret,
                &CLIENT_RANDOM,
                &wrong_server_random,
                false,
            )
            .err(),
            Some(Tls12Error::FinishedVerifyFailed)
        );
        assert_eq!(
            complete_server_handshake(
                &setup.flight,
                &setup.client_hello,
                &setup.cke,
                &setup.client_finished,
                &setup.server_secret,
                &CLIENT_RANDOM,
                &SERVER_RANDOM,
                false,
            )
            .err(),
            Some(Tls12Error::FinishedVerifyFailed)
        );
    }

    #[test]
    fn malformed_handshake_messages_are_rejected() {
        let setup = Setup::new(true);

        let mut bad_type = setup.cke.clone();
        bad_type[0] = 17;
        assert_eq!(
            complete_server_handshake(
                &setup.flight,
                &setup.client_hello,
                &bad_type,
                &setup.client_finished,
                &setup.server_secret,
                &CLIENT_RANDOM,
                &SERVER_RANDOM,
                true,
            )
            .err(),
            Some(Tls12Error::InvalidClientKeyExchange)
        );
        assert_eq!(
            complete_server_handshake(
                &setup.flight,
                &setup.client_hello,
                &setup.cke[..3],
                &setup.client_finished,
                &setup.server_secret,
                &CLIENT_RANDOM,
                &SERVER_RANDOM,
                true,
            )
            .err(),
            Some(Tls12Error::InvalidClientKeyExchange)
        );
        let mut trailing = setup.cke.clone();
        trailing.push(0);
        assert_eq!(
            complete_server_handshake(
                &setup.flight,
                &setup.client_hello,
                &trailing,
                &setup.client_finished,
                &setup.server_secret,
                &CLIENT_RANDOM,
                &SERVER_RANDOM,
                true,
            )
            .err(),
            Some(Tls12Error::InvalidClientKeyExchange)
        );
        let point = setup.client_secret.public_key().to_sec1_point(false);
        let mut long_body = vec![UNCOMPRESSED_POINT_LEN as u8];
        long_body.extend_from_slice(point.as_bytes());
        long_body.push(0);
        let long_cke = wrap_handshake_message(CLIENT_KEY_EXCHANGE, &long_body).unwrap();
        assert_eq!(
            parse_client_key_exchange(&long_body),
            Err(Tls12Error::InvalidClientKeyExchange)
        );
        assert_eq!(
            complete_server_handshake(
                &setup.flight,
                &setup.client_hello,
                &long_cke,
                &setup.client_finished,
                &setup.server_secret,
                &CLIENT_RANDOM,
                &SERVER_RANDOM,
                true,
            )
            .err(),
            Some(Tls12Error::InvalidClientKeyExchange)
        );

        let mut bad_finished_type = setup.client_finished.clone();
        bad_finished_type[0] = 21;
        assert_eq!(
            complete_server_handshake(
                &setup.flight,
                &setup.client_hello,
                &setup.cke,
                &bad_finished_type,
                &setup.server_secret,
                &CLIENT_RANDOM,
                &SERVER_RANDOM,
                true,
            )
            .err(),
            Some(Tls12Error::InvalidFinishedMessage)
        );
        let short_finished = wrap_handshake_message(FINISHED, &[0u8; 11]).unwrap();
        assert_eq!(
            complete_server_handshake(
                &setup.flight,
                &setup.client_hello,
                &setup.cke,
                &short_finished,
                &setup.server_secret,
                &CLIENT_RANDOM,
                &SERVER_RANDOM,
                true,
            )
            .err(),
            Some(Tls12Error::InvalidFinishedMessage)
        );

        let mut empty_flight = setup.flight.clone();
        empty_flight.messages.clear();
        assert_eq!(
            complete_server_handshake(
                &empty_flight,
                &setup.client_hello,
                &setup.cke,
                &setup.client_finished,
                &setup.server_secret,
                &CLIENT_RANDOM,
                &SERVER_RANDOM,
                true,
            )
            .err(),
            Some(Tls12Error::InvalidServerFirstFlight)
        );
    }
}
