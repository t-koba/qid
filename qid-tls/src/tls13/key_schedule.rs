//! RFC 8446 §7.1 TLS 1.3 key schedule derivations.
//!
//! These are offline byte computations: secrets are derived from caller-supplied
//! inputs, with no handshake state, transport, or record protection here.

use super::expand_label;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const KEY_LEN: usize = 32;
const ZEROES: [u8; KEY_LEN] = [0; KEY_LEN];

/// Failure to initialize a pseudorandom key or expand a TLS 1.3 label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The supplied secret is shorter than the SHA-256 output length.
    InvalidSecret,
    /// The shared HKDF-Expand-Label helper rejected the label inputs.
    LabelExpansion,
    /// The peer's Finished verify_data did not match this transcript.
    FinishedMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidSecret => "TLS 1.3 secret is shorter than the hash output",
            Self::LabelExpansion => "TLS 1.3 HKDF-Expand-Label failed",
            Self::FinishedMismatch => "TLS 1.3 Finished verify_data mismatch",
        })
    }
}

impl std::error::Error for Error {}

/// RFC 8446 §7.1 early secret: HKDF-Extract(0, psk).
pub fn early_secret(psk: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    extract_secret(&ZEROES, psk)
}

/// HKDF-Extract(salt, ikm) with the extracted PRK held in a zeroizing buffer.
pub fn extract_secret(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let (mut prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut secret = Zeroizing::new([0u8; KEY_LEN]);
    secret.copy_from_slice(&prk);
    prk.as_mut_slice().zeroize();
    secret
}

/// RFC 8446 §7.1 Derive-Secret via the crate's single HKDF-Expand-Label helper.
pub fn derive_secret(
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    let hkdf = Hkdf::<Sha256>::from_prk(secret).map_err(|_| Error::InvalidSecret)?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    expand_label(&hkdf, label, transcript_hash, out.as_mut()).map_err(|_| Error::LabelExpansion)?;
    Ok(out)
}

fn empty_hash() -> Zeroizing<[u8; KEY_LEN]> {
    Zeroizing::new(<[u8; KEY_LEN]>::from(Sha256::digest(b"")))
}

/// RFC 8446 §4.4.4: `finished_key = Derive-Secret(traffic_secret, "finished", "")`.
pub fn finished_key(traffic_secret: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    derive_secret(traffic_secret, b"finished", &[])
}

/// RFC 8446 §4.4.4: `verify_data = HMAC(finished_key, Hash(transcript))`.
///
/// `transcript_hash` is the 32-byte SHA-256 hash of the handshake transcript up
/// to, but not including, the Finished message being produced or checked.
pub fn finished_verify_data(
    finished_key: &[u8],
    transcript_hash: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    let mut mac = Hmac::<Sha256>::new_from_slice(finished_key).map_err(|_| Error::InvalidSecret)?;
    mac.update(transcript_hash);
    let tag = mac.finalize().into_bytes();
    let mut verify_data = Zeroizing::new([0u8; KEY_LEN]);
    verify_data.copy_from_slice(&tag);
    Ok(verify_data)
}

/// Constant-time check of a peer's Finished `verify_data` (RFC 8446 §4.4.4).
///
/// `transcript_hash` must cover all messages before that Finished message.
pub fn verify_finished(
    finished_key: &[u8],
    transcript_hash: &[u8],
    expected: &[u8],
) -> Result<(), Error> {
    let expected: [u8; KEY_LEN] = expected.try_into().map_err(|_| Error::FinishedMismatch)?;
    let actual = finished_verify_data(finished_key, transcript_hash)?;
    if bool::from(actual.ct_eq(&expected)) {
        Ok(())
    } else {
        Err(Error::FinishedMismatch)
    }
}

/// Handshake secret and the two handshake traffic secrets for one transcript.
pub struct HandshakeSecrets {
    pub handshake_secret: Zeroizing<[u8; KEY_LEN]>,
    pub client_traffic: Zeroizing<[u8; KEY_LEN]>,
    pub server_traffic: Zeroizing<[u8; KEY_LEN]>,
}

/// RFC 8446 §7.1: derive the handshake secret from the early secret and ECDHE
/// input, then the client and server handshake traffic secrets over the hash
/// of the transcript through ServerHello.
pub fn handshake_secrets(
    early_secret: &[u8],
    dhe_secret: &[u8],
    transcript_hash: &[u8],
) -> Result<HandshakeSecrets, Error> {
    // The salt for this Extract is Derive-Secret(early, "derived", ""): the
    // empty transcript is hashed, not the supplied handshake transcript.
    let empty = empty_hash();
    let derived = derive_secret(early_secret, b"derived", &empty[..])?;
    let handshake_secret = extract_secret(&derived[..], dhe_secret);
    Ok(HandshakeSecrets {
        client_traffic: derive_secret(&handshake_secret[..], b"c hs traffic", transcript_hash)?,
        server_traffic: derive_secret(&handshake_secret[..], b"s hs traffic", transcript_hash)?,
        handshake_secret,
    })
}

/// RFC 8446 §7.1: master secret from the handshake secret and SHA-256 of an
/// empty transcript as the Derive-Secret context.
pub fn master_secret(handshake_secret: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    let empty = empty_hash();
    let derived = derive_secret(handshake_secret, b"derived", &empty[..])?;
    Ok(extract_secret(&derived[..], &ZEROES))
}

/// Application traffic secret for the `"c ap traffic"` or `"s ap traffic"`
/// label; this is `derive_secret` under its RFC 8446 name.
pub fn traffic_secret(
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    derive_secret(secret, label, transcript_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8448 §3 full-handshake vectors, in derivation order.
    const ZERO_PSK: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const EARLY_SECRET: &str = "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a";
    const DHE_SECRET: &str = "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d";
    const HANDSHAKE_HASH: &str = "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8";
    const HANDSHAKE_DERIVED: &str =
        "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba";
    const HANDSHAKE_SECRET: &str =
        "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac";
    const C_HS_TRAFFIC: &str = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
    const C_HS_FINISHED_KEY: &str =
        "b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4";
    const S_HS_FINISHED_KEY: &str =
        "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8";
    const SERVER_FINISHED_TRANSCRIPT: &str =
        "edb7725fa7a3473b031ec8ef65a2485493900138a2b91291407d7951a06110ed";
    const S_FINISHED: &str = "9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718";
    const C_FINISHED: &str = "a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61";
    const S_HS_TRAFFIC: &str = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";
    const MASTER_DERIVED: &str = "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4";
    const MASTER_SECRET_VALUE: &str =
        "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919";
    const APPLICATION_HASH: &str =
        "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13";
    const C_AP_TRAFFIC: &str = "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5";
    const S_AP_TRAFFIC: &str = "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643";

    fn bytes(hex: &str) -> Vec<u8> {
        hex::decode(hex).unwrap()
    }

    fn assert_hex(secret: &Zeroizing<[u8; KEY_LEN]>, expected: &str) {
        assert_eq!(hex::encode(&secret[..]), expected);
    }

    #[test]
    fn rfc8448_key_schedule_matches_every_intermediate_value() {
        let psk = bytes(ZERO_PSK);
        assert_eq!(psk, vec![0; KEY_LEN]);
        let early = early_secret(&psk);
        assert_hex(&early, EARLY_SECRET);
        assert_hex(&extract_secret(&ZEROES, &psk), EARLY_SECRET);

        let empty = empty_hash();
        assert_eq!(
            hex::encode(&empty[..]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let derived = derive_secret(&early[..], b"derived", &empty[..]).unwrap();
        assert_hex(&derived, HANDSHAKE_DERIVED);

        let dhe = bytes(DHE_SECRET);
        assert_hex(&extract_secret(&derived[..], &dhe), HANDSHAKE_SECRET);

        let handshake_hash = bytes(HANDSHAKE_HASH);
        let secrets = handshake_secrets(&early[..], &dhe, &handshake_hash).unwrap();
        assert_hex(&secrets.handshake_secret, HANDSHAKE_SECRET);
        assert_hex(&secrets.client_traffic, C_HS_TRAFFIC);
        assert_hex(&secrets.server_traffic, S_HS_TRAFFIC);

        let master_derived =
            derive_secret(&secrets.handshake_secret[..], b"derived", &empty[..]).unwrap();
        assert_hex(&master_derived, MASTER_DERIVED);

        let master = master_secret(&secrets.handshake_secret[..]).unwrap();
        assert_hex(&master, MASTER_SECRET_VALUE);

        let application_hash = bytes(APPLICATION_HASH);
        assert_hex(
            &traffic_secret(&master[..], b"c ap traffic", &application_hash).unwrap(),
            C_AP_TRAFFIC,
        );
        assert_hex(
            &traffic_secret(&master[..], b"s ap traffic", &application_hash).unwrap(),
            S_AP_TRAFFIC,
        );
    }

    #[test]
    fn rfc8448_finished_key_and_verify_data() {
        let traffic = bytes(C_HS_TRAFFIC);
        let key = finished_key(&traffic).unwrap();
        assert_hex(&key, C_HS_FINISHED_KEY);
        // The client Finished transcript runs through the server Finished,
        // matching the application-transcript hash in the RFC 8448 trace.
        let verify_data = finished_verify_data(&key[..], &bytes(APPLICATION_HASH)).unwrap();
        assert_hex(&verify_data, C_FINISHED);
    }

    #[test]
    fn rfc8448_verifies_server_finished() {
        let traffic = bytes(S_HS_TRAFFIC);
        let key = finished_key(&traffic).unwrap();
        assert_hex(&key, S_HS_FINISHED_KEY);
        let transcript = bytes(SERVER_FINISHED_TRANSCRIPT);
        let expected = bytes(S_FINISHED);
        assert_eq!(verify_finished(&key[..], &transcript, &expected), Ok(()));

        let mut tampered = expected;
        tampered[0] ^= 1;
        assert_eq!(
            verify_finished(&key[..], &transcript, &tampered),
            Err(Error::FinishedMismatch)
        );
    }

    #[test]
    fn transcript_hash_changes_traffic_secrets() {
        let early = early_secret(&ZEROES);
        let dhe = bytes(DHE_SECRET);
        let handshake_hash = bytes(HANDSHAKE_HASH);
        let mut other_handshake_hash = handshake_hash.clone();
        other_handshake_hash[0] ^= 1;

        let base = handshake_secrets(&early[..], &dhe, &handshake_hash).unwrap();
        let other = handshake_secrets(&early[..], &dhe, &other_handshake_hash).unwrap();
        assert_ne!(*base.client_traffic, *other.client_traffic);
        assert_ne!(*base.server_traffic, *other.server_traffic);

        let master = master_secret(&base.handshake_secret[..]).unwrap();
        let application_hash = bytes(APPLICATION_HASH);
        let mut other_application_hash = application_hash.clone();
        other_application_hash[0] ^= 1;
        for (label, expected) in [
            (b"c ap traffic".as_slice(), C_AP_TRAFFIC),
            (b"s ap traffic".as_slice(), S_AP_TRAFFIC),
        ] {
            let traffic = traffic_secret(&master[..], label, &application_hash).unwrap();
            assert_hex(&traffic, expected);
            assert_ne!(
                *traffic,
                *traffic_secret(&master[..], label, &other_application_hash).unwrap()
            );
        }
    }

    #[test]
    fn rejects_short_prk() {
        let short = [0u8; KEY_LEN - 1];
        assert_eq!(
            derive_secret(&short, b"derived", &ZEROES).unwrap_err(),
            Error::InvalidSecret
        );
        assert_eq!(
            handshake_secrets(&short, &ZEROES, &ZEROES).err(),
            Some(Error::InvalidSecret)
        );
        assert_eq!(master_secret(&short).unwrap_err(), Error::InvalidSecret);
    }
}
