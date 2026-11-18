//! Strict TLS 1.3 ClientHello construction for TLS-POK (RFC 9966).
//!
//! This is offline byte assembly: the caller supplies randomness, a key share,
//! and an imported external PSK. No RNG, transport, or handshake state lives
//! here. The binder is computed over the exact ClientHello prefix required by
//! RFC 8446 §4.2.11.2.

use super::external_psk::{ImportedIdentity, imported_psk_binder};
use super::psk_extension::{
    CERT_WITH_EXTERN_PSK_TYPE, KEY_SHARE_TYPE, OfferedPsks, PRE_SHARED_KEY_TYPE,
    PSK_KEY_EXCHANGE_MODES_TYPE, PskIdentity, SUPPORTED_GROUPS_TYPE, encode_body,
};
use super::tls_pok::{CLIENT_CERTIFICATE_TYPE_TYPE, CONTEXT, RAW_PUBLIC_KEY};
use super::transcript::encode_message;
use std::fmt;

const CLIENT_HELLO: u8 = 0x01;
const LEGACY_VERSION: u16 = 0x0303;
const LEGACY_COMPRESSION_NULL: u8 = 0;
const TLS13: [u8; 2] = [0x03, 0x04];
const SUPPORTED_VERSIONS_TYPE: u16 = 0x002b;
const SIGNATURE_ALGORITHMS_TYPE: u16 = 0x000d;
const BINDER_LEN: usize = 32;
const OBFUSCATED_TICKET_AGE: u32 = 0;
const MAX_VECTOR_LEN: usize = u16::MAX as usize;

// RFC 8446 §4.2.3: ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, ed25519.
const SIGNATURE_ALGORITHMS: [u8; 6] = [0x04, 0x03, 0x08, 0x04, 0x08, 0x07];

/// Invalid or oversized ClientHello inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidSessionId,
    InvalidCipherSuite,
    InvalidKeyShare,
    InvalidImportedIdentity,
    InvalidImportedPsk,
    InvalidTlsPokIdentity,
    VectorTooLong,
    BinderDerivation,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidSessionId => "legacy_session_id exceeds 32 bytes",
            Self::InvalidCipherSuite => "cipher suite is not a TLS 1.3 suite",
            Self::InvalidKeyShare => "key_exchange entry is empty or oversized",
            Self::InvalidImportedIdentity => "imported PSK identity is invalid",
            Self::InvalidImportedPsk => "imported PSK must be 32 bytes",
            Self::InvalidTlsPokIdentity => "ImportedIdentity context must be tls13-bsk",
            Self::VectorTooLong => "ClientHello vector exceeds its wire limit",
            Self::BinderDerivation => "PSK binder derivation failed",
        })
    }
}

impl std::error::Error for Error {}

/// Inputs for a TLS 1.3 certificate plus external PSK ClientHello.
#[derive(Clone, Copy, Debug)]
pub struct ClientHelloParams<'a> {
    pub random: [u8; 32],
    pub legacy_session_id: &'a [u8],
    pub cipher_suite: u16,
    pub key_share_group: u16,
    pub key_exchange: &'a [u8],
    pub imported_identity: &'a ImportedIdentity,
    pub imported_psk: &'a [u8],
}

fn push_extension(out: &mut Vec<u8>, kind: u16, body: &[u8]) -> Result<(), Error> {
    let len = u16::try_from(body.len()).map_err(|_| Error::VectorTooLong)?;
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Ok(())
}

fn vector(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if bytes.len() > MAX_VECTOR_LEN {
        return Err(Error::VectorTooLong);
    }
    let mut out = Vec::with_capacity(bytes.len() + 2);
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(out)
}

fn key_share_body(group: u16, exchange: &[u8]) -> Result<Vec<u8>, Error> {
    if exchange.is_empty() {
        return Err(Error::InvalidKeyShare);
    }
    let mut body = group.to_be_bytes().to_vec();
    body.extend(vector(exchange)?);
    Ok(body)
}

fn extensions(params: &ClientHelloParams<'_>) -> Result<Vec<u8>, Error> {
    let identity = params
        .imported_identity
        .encode()
        .map_err(|_| Error::InvalidImportedIdentity)?;
    let offered = OfferedPsks {
        identities: vec![PskIdentity {
            identity,
            obfuscated_ticket_age: OBFUSCATED_TICKET_AGE,
        }],
        binders: vec![vec![0; BINDER_LEN]],
    };

    let mut out = Vec::new();
    push_extension(&mut out, SUPPORTED_VERSIONS_TYPE, &TLS13)?;
    push_extension(
        &mut out,
        SUPPORTED_GROUPS_TYPE,
        &vector(&params.key_share_group.to_be_bytes())?,
    )?;
    push_extension(
        &mut out,
        SIGNATURE_ALGORITHMS_TYPE,
        &vector(&SIGNATURE_ALGORITHMS)?,
    )?;
    push_extension(
        &mut out,
        PSK_KEY_EXCHANGE_MODES_TYPE,
        &[0x01, 0x01], // psk_dhe_ke (RFC 8446 §4.2.9)
    )?;
    push_extension(
        &mut out,
        KEY_SHARE_TYPE,
        &key_share_body(params.key_share_group, params.key_exchange)?,
    )?;
    push_extension(&mut out, CERT_WITH_EXTERN_PSK_TYPE, &[])?;
    // RFC 9966 §3.2: TLS-POK clients request RawPublicKey client certificates.
    push_extension(
        &mut out,
        CLIENT_CERTIFICATE_TYPE_TYPE,
        &[0x01, RAW_PUBLIC_KEY],
    )?;
    // RFC 8446 §4.2.11 and RFC 9973 §4: pre_shared_key is always last.
    push_extension(
        &mut out,
        PRE_SHARED_KEY_TYPE,
        &encode_body(&offered).map_err(|_| Error::InvalidImportedIdentity)?,
    )?;
    Ok(out)
}

/// Build a complete TLS 1.3 ClientHello handshake message.
///
/// The returned bytes include the four-byte handshake header so they can be
/// fed directly to [`super::transcript::Transcript`] and record protection.
pub fn build_cert_with_extern_psk(params: &ClientHelloParams<'_>) -> Result<Vec<u8>, Error> {
    if params.legacy_session_id.len() > 32 {
        return Err(Error::InvalidSessionId);
    }
    if params.imported_identity.context != CONTEXT {
        return Err(Error::InvalidTlsPokIdentity);
    }
    if params.imported_psk.len() != BINDER_LEN {
        return Err(Error::InvalidImportedPsk);
    }
    if !(0x1301..=0x1303).contains(&params.cipher_suite) {
        return Err(Error::InvalidCipherSuite);
    }

    let mut body = Vec::new();
    body.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
    body.extend_from_slice(&params.random);
    body.push(u8::try_from(params.legacy_session_id.len()).map_err(|_| Error::InvalidSessionId)?);
    body.extend_from_slice(params.legacy_session_id);
    body.extend_from_slice(&vector(&params.cipher_suite.to_be_bytes())?);
    body.push(LEGACY_COMPRESSION_NULL);

    let ext = extensions(params)?;
    body.extend(vector(&ext)?);

    // With pre_shared_key last, the binder is the final 32 bytes of the body.
    // RFC 8446 §4.4.1 hashes the framed message, including its four-byte
    // header and the final message length with the binder placeholder present.
    if body.len() < BINDER_LEN {
        return Err(Error::BinderDerivation);
    }
    let binder_offset = body.len() - BINDER_LEN;
    let mut framed = encode_message(CLIENT_HELLO, &body).map_err(|_| Error::VectorTooLong)?;
    let framed_binder_offset = 4 + binder_offset;
    let binder = imported_psk_binder(params.imported_psk, &framed[..framed_binder_offset])
        .map_err(|_| Error::BinderDerivation)?;
    framed[framed_binder_offset..].copy_from_slice(&binder[..]);
    Ok(framed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls13::external_psk::{import_external_psk, parse_empty_extension};
    use crate::tls13::psk_extension::parse_extension;
    use crate::tls13::tls_pok;
    use crate::tls13::transcript::split_message;

    // RFC 9966 Appendix A, prime256v1 BSK SubjectPublicKeyInfo.
    const BSK_SPKI: &str = "3039301306072a8648ce3d020106082a8648ce3d0301070322000232f2f2a0eca48fcb052714a865fcda7ee544bccfa43580b1a440ba2884cb6fd8";
    const ENCODED_IDENTITY: &str = "002005dfa52e583f11176d61a71fcc37e1d4b8dd2f4f905894077585e84bb2434a400009746c7331332d62736b03040001";

    fn fixture() -> (Vec<u8>, ImportedIdentity) {
        let spki = hex::decode(BSK_SPKI).unwrap();
        let identity = tls_pok::imported_identity(&spki).unwrap();
        (spki, identity)
    }

    fn params<'a>(identity: &'a ImportedIdentity, psk: &'a [u8]) -> ClientHelloParams<'a> {
        ClientHelloParams {
            random: [0x42; 32],
            legacy_session_id: b"",
            cipher_suite: 0x1301,
            key_share_group: 0x001d,
            key_exchange: &[0x11; 32],
            imported_identity: identity,
            imported_psk: psk,
        }
    }

    fn body(message: &[u8]) -> &[u8] {
        let (msg, rest) = split_message(message).unwrap();
        assert!(rest.is_empty());
        assert_eq!(msg.msg_type, CLIENT_HELLO);
        msg.body
    }

    fn extension_types(body: &[u8]) -> Vec<u16> {
        let mut reader = &body[2 + 32 + 1 + 2 + 2 + 1..];
        let len = usize::from(u16::from_be_bytes([reader[0], reader[1]]));
        reader = &reader[2..];
        let mut ext = &reader[..len];
        let mut types = Vec::new();
        while !ext.is_empty() {
            assert!(ext.len() >= 4);
            types.push(u16::from_be_bytes([ext[0], ext[1]]));
            let body_len = usize::from(u16::from_be_bytes([ext[2], ext[3]]));
            ext = &ext[4 + body_len..];
        }
        types
    }

    #[test]
    fn builds_certificate_external_psk_client_hello() {
        let (spki, identity) = fixture();
        let psk = import_external_psk(&spki, &identity).unwrap();
        let message = build_cert_with_extern_psk(&params(&identity, &psk)).unwrap();
        let body = body(&message);

        assert_eq!(&body[..2], &LEGACY_VERSION.to_be_bytes());
        assert_eq!(&body[2..34], &[0x42; 32]);
        assert_eq!(body[34], 0);
        assert_eq!(&body[35..39], &[0x00, 0x02, 0x13, 0x01]);
        assert_eq!(body[39], 0);
        assert_eq!(
            extension_types(body),
            vec![
                SUPPORTED_VERSIONS_TYPE,
                SUPPORTED_GROUPS_TYPE,
                SIGNATURE_ALGORITHMS_TYPE,
                PSK_KEY_EXCHANGE_MODES_TYPE,
                KEY_SHARE_TYPE,
                CERT_WITH_EXTERN_PSK_TYPE,
                CLIENT_CERTIFICATE_TYPE_TYPE,
                PRE_SHARED_KEY_TYPE,
            ]
        );

        let ext_bytes = &body[42..];
        let offered = parse_psk_extension(ext_bytes);
        assert_eq!(
            offered.identities[0].identity,
            hex::decode(ENCODED_IDENTITY).unwrap()
        );
        assert_eq!(offered.identities[0].obfuscated_ticket_age, 0);
        let binder = &offered.binders[0];
        assert_eq!(binder.len(), BINDER_LEN);

        let binder_offset = body.len() - BINDER_LEN;
        assert_eq!(&body[binder_offset..], binder.as_slice());
        let len = u32::try_from(body.len()).unwrap().to_be_bytes();
        assert_eq!(&message[..4], &[0x01, len[1], len[2], len[3]]);
        let framed_prefix = [&message[..4], &body[..binder_offset]].concat();
        let headerless_prefix = &body[..binder_offset];
        assert_ne!(framed_prefix, headerless_prefix);
        let expected = imported_psk_binder(&psk, &framed_prefix).unwrap();
        assert_eq!(binder.as_slice(), &expected[..]);

        let cert_ext = extension_body(ext_bytes, CERT_WITH_EXTERN_PSK_TYPE).unwrap();
        assert!(cert_ext.is_empty());
        assert_eq!(parse_empty_extension(cert_ext), Ok(()));
    }

    fn extension_body(extensions: &[u8], wanted: u16) -> Option<&[u8]> {
        let mut reader = extensions;
        while reader.len() >= 4 {
            let kind = u16::from_be_bytes([reader[0], reader[1]]);
            let len = usize::from(u16::from_be_bytes([reader[2], reader[3]]));
            if reader.len() < 4 + len {
                return None;
            }
            if kind == wanted {
                return Some(&reader[4..4 + len]);
            }
            reader = &reader[4 + len..];
        }
        None
    }

    fn parse_psk_extension(extensions: &[u8]) -> OfferedPsks {
        let body = extension_body(extensions, PRE_SHARED_KEY_TYPE).unwrap();
        let mut wire = vec![0x00, 0x29];
        wire.extend_from_slice(&(body.len() as u16).to_be_bytes());
        wire.extend_from_slice(body);
        parse_extension(&wire).unwrap()
    }

    #[test]
    fn binder_depends_on_identity_and_transcript() {
        let (spki, identity) = fixture();
        let psk = import_external_psk(&spki, &identity).unwrap();
        let base = build_cert_with_extern_psk(&params(&identity, &psk)).unwrap();
        let mut other = params(&identity, &psk);
        other.random[0] ^= 1;
        assert_ne!(base, build_cert_with_extern_psk(&other).unwrap());

        let other_identity = ImportedIdentity::new(vec![0x33; 32], CONTEXT.to_vec()).unwrap();
        let other_psk = import_external_psk(&spki, &other_identity).unwrap();
        assert_ne!(
            base,
            build_cert_with_extern_psk(&params(&other_identity, &other_psk)).unwrap()
        );
    }

    #[test]
    fn rejects_invalid_inputs() {
        let (spki, identity) = fixture();
        let psk = import_external_psk(&spki, &identity).unwrap();
        let bad_identity = ImportedIdentity::new(
            identity.external_identity.clone(),
            b"wrong-context".to_vec(),
        )
        .unwrap();
        assert_eq!(
            build_cert_with_extern_psk(&params(&bad_identity, &psk)).unwrap_err(),
            Error::InvalidTlsPokIdentity
        );

        let mut p = params(&identity, &psk);
        p.legacy_session_id = &[0; 33];
        assert_eq!(
            build_cert_with_extern_psk(&p).unwrap_err(),
            Error::InvalidSessionId
        );

        let mut p = params(&identity, &psk);
        p.cipher_suite = 0x002f;
        assert_eq!(
            build_cert_with_extern_psk(&p).unwrap_err(),
            Error::InvalidCipherSuite
        );

        let mut p = params(&identity, &psk);
        p.key_exchange = b"";
        assert_eq!(
            build_cert_with_extern_psk(&p).unwrap_err(),
            Error::InvalidKeyShare
        );
    }
}
