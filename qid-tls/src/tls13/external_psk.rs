//! RFC 9258 external PSK import and the RFC 9973 empty extension.
//!
//! These are offline byte computations: identity encoding, HKDF derivation and
//! extension framing. No handshake state, listener or transport lives here,
//! and this module does not implement TLS-POK authentication.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

/// Target protocol field of an RFC 9258 `ImportedIdentity`: TLS 1.3 (RFC 8446).
pub const TARGET_PROTOCOL: u16 = 0x0304;
/// Target KDF field of an RFC 9258 `ImportedIdentity`: HKDF-SHA256.
pub const TARGET_KDF: u16 = 0x0001;
/// RFC 9973 `tls_cert_with_extern_psk` extension type.
pub const EXTENSION_TYPE: u16 = 0x0021;

const SALT: [u8; 32] = [0; 32];
const KEY_LEN: usize = 32;
const EXTENSION_HEADER_LEN: usize = 4;

/// Encoded extension with type 33 and zero-length `extension_data`.
pub const EMPTY_EXTENSION: [u8; EXTENSION_HEADER_LEN] =
    [(EXTENSION_TYPE >> 8) as u8, EXTENSION_TYPE as u8, 0, 0];

/// Invalid identity input, failed derivation or malformed RFC 9973 extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    EmptyExternalIdentity,
    FieldTooLong,
    Derivation,
    InvalidExtension,
    UnsupportedTarget,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyExternalIdentity => "external identity must not be empty",
            Self::FieldTooLong => "imported identity field exceeds u16 length",
            Self::Derivation => "TLS 1.3 label expansion failed",
            Self::InvalidExtension => "invalid RFC 9973 empty extension",
            Self::UnsupportedTarget => "imported identity target must be TLS 1.3 with HKDF-SHA256",
        })
    }
}

impl std::error::Error for Error {}

/// RFC 9258 §5.1 `ImportedIdentity` fields. `new` pins the target protocol
/// and KDF; direct construction is checked again by `encode`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedIdentity {
    pub external_identity: Vec<u8>,
    pub context: Vec<u8>,
    pub target_protocol: u16,
    pub target_kdf: u16,
}

impl ImportedIdentity {
    /// Build an identity for TLS 1.3 with HKDF-SHA256.
    pub fn new(external_identity: Vec<u8>, context: Vec<u8>) -> Result<Self, Error> {
        let identity = Self {
            external_identity,
            context,
            target_protocol: TARGET_PROTOCOL,
            target_kdf: TARGET_KDF,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.target_protocol != TARGET_PROTOCOL || self.target_kdf != TARGET_KDF {
            return Err(Error::UnsupportedTarget);
        }
        if self.external_identity.is_empty() {
            return Err(Error::EmptyExternalIdentity);
        }
        if self.external_identity.len() > usize::from(u16::MAX)
            || self.context.len() > usize::from(u16::MAX)
        {
            return Err(Error::FieldTooLong);
        }
        Ok(())
    }

    /// RFC 9258 §5.1: each variable-length field carries a big-endian u16
    /// length, and the two target fields are big-endian u16 values.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let external_len = u16::try_from(self.external_identity.len())
            .map_err(|_| Error::FieldTooLong)?
            .to_be_bytes();
        let context_len = u16::try_from(self.context.len())
            .map_err(|_| Error::FieldTooLong)?
            .to_be_bytes();
        let mut encoded = Vec::with_capacity(
            EXTENSION_HEADER_LEN + self.external_identity.len() + self.context.len() + 4,
        );
        encoded.extend_from_slice(&external_len);
        encoded.extend_from_slice(&self.external_identity);
        encoded.extend_from_slice(&context_len);
        encoded.extend_from_slice(&self.context);
        encoded.extend_from_slice(&self.target_protocol.to_be_bytes());
        encoded.extend_from_slice(&self.target_kdf.to_be_bytes());
        Ok(encoded)
    }
}

/// RFC 9258 §5.1: import an external PSK into a TLS 1.3 PSK.
///
/// `epskx = HKDF-Extract(0, epsk)` and `ipsk = HKDF-Expand-Label(epskx,
/// "derived psk", SHA256(ImportedIdentity), 32)`. The key is returned in a
/// zeroizing buffer; this function performs no handshake or PSK storage.
pub fn import_external_psk(
    epsk: &[u8],
    identity: &ImportedIdentity,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let hash = Zeroizing::new(<[u8; KEY_LEN]>::from(Sha256::digest(identity.encode()?)));
    let epskx = Hkdf::<Sha256>::new(Some(&SALT), epsk);
    let mut ipsk = Zeroizing::new(vec![0u8; KEY_LEN]);
    super::expand_label(&epskx, b"derived psk", &hash[..], ipsk.as_mut())
        .map_err(|_| Error::Derivation)?;
    Ok(ipsk)
}

/// RFC 9258 §5.2 binder key for an imported PSK.
///
/// `Derive-Secret(HKDF-Extract(0, ipsk), "imp binder", "")`; RFC 8446 §7.1
/// hashes the empty Messages argument, so the label context is SHA256("").
pub fn imported_binder_key(ipsk: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    binder_key(ipsk, b"imp binder")
}

fn binder_key(ipsk: &[u8], label: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    let early_secret = Hkdf::<Sha256>::new(Some(&SALT), ipsk);
    let transcript_hash = Zeroizing::new(<[u8; KEY_LEN]>::from(Sha256::digest(b"")));
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    super::expand_label(&early_secret, label, &transcript_hash[..], out.as_mut())
        .map_err(|_| Error::Derivation)?;
    Ok(out)
}

/// RFC 8446 §4.2.11.2 / RFC 8448 PSK binder over a ClientHello prefix.
///
/// `transcript_hash = SHA256(prefix)`, `finished_key =
/// HKDF-Expand-Label(binder_key, "finished", "", 32)` and `binder =
/// HMAC-SHA256(finished_key, transcript_hash)`. The finished key and binder
/// are returned in zeroizing buffers.
pub fn psk_binder(
    binder_key: &[u8; KEY_LEN],
    transcript_prefix: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    let transcript_hash = Zeroizing::new(<[u8; KEY_LEN]>::from(Sha256::digest(transcript_prefix)));
    let prk = Hkdf::<Sha256>::from_prk(binder_key).map_err(|_| Error::Derivation)?;
    let mut finished_key = Zeroizing::new([0u8; KEY_LEN]);
    super::expand_label(&prk, b"finished", b"", finished_key.as_mut())
        .map_err(|_| Error::Derivation)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&finished_key[..]).map_err(|_| Error::Derivation)?;
    mac.update(&transcript_hash[..]);
    let mut binder = Zeroizing::new([0u8; KEY_LEN]);
    binder.copy_from_slice(&mac.finalize().into_bytes()[..]);
    Ok(binder)
}

/// RFC 9258 §5.2 binder for an imported PSK over a ClientHello prefix.
///
/// Uses the `imp binder` key from `imported_binder_key` with the RFC 8446
/// binder computation. No handshake state is involved.
pub fn imported_psk_binder(
    ipsk: &[u8],
    transcript_prefix: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    let binder_key = imported_binder_key(ipsk)?;
    psk_binder(&binder_key, transcript_prefix)
}

/// Encode the RFC 9973 `tls_cert_with_extern_psk` extension as `extension_type || 0x0000 ||`
/// empty `extension_data`; no handshake message is constructed here.
pub fn encode_empty_extension() -> [u8; EXTENSION_HEADER_LEN] {
    EMPTY_EXTENSION
}

/// Validate the `extension_data` body of an RFC 9973 extension: only exactly
/// zero bytes are accepted, never a populated body.
pub fn parse_empty_extension(data: &[u8]) -> Result<(), Error> {
    if data.is_empty() {
        Ok(())
    } else {
        Err(Error::InvalidExtension)
    }
}

/// Parse a whole framed ClientHello/ServerHello extension of type 33: u16 type,
/// u16 data length, `extension_data`. Rejects other types, truncated framing,
/// trailing bytes and any nonzero-length body.
pub fn parse_extension(wire: &[u8]) -> Result<(), Error> {
    if wire.len() < EXTENSION_HEADER_LEN {
        return Err(Error::InvalidExtension);
    }
    let extension_type = u16::from_be_bytes([wire[0], wire[1]]);
    let data_len = usize::from(u16::from_be_bytes([wire[2], wire[3]]));
    if extension_type != EXTENSION_TYPE || wire.len() != EXTENSION_HEADER_LEN + data_len {
        return Err(Error::InvalidExtension);
    }
    parse_empty_extension(&wire[EXTENSION_HEADER_LEN..])
}

#[cfg(test)]
mod tests {
    use super::*;

    // Expected bytes computed independently with Python's hashlib/hmac HKDF
    // composition; these are self-consistency anchors, not capability claims.
    const EPSK: [u8; KEY_LEN] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const EXTERNAL_IDENTITY: &[u8] = b"qid-imported-psk";
    const CONTEXT: &[u8] = b"test-context";
    const ENCODED_IDENTITY: &str =
        "00107169642d696d706f727465642d70736b000c746573742d636f6e7465787403040001";
    const IMPORTED_PSK: &str = "adcc824d73e6cb23ef83d3514b44f3633889eb2739575504dd3df929cfa607a1";
    const IMPORTED_BINDER: &str =
        "0a3afe0ceedcbedcddd46b4d6fff61d4603b3011b798c567c869df7e696b341e";

    // RFC 8448 §4 resumption PSK and the verified intermediate values of its
    // binder computation. The ClientHello prefix below is 477 bytes.
    const RFC8448_PSK: &str = "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3";
    const RFC8448_EARLY_SECRET: &str =
        "9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c";
    const RFC8448_BINDER_KEY: &str =
        "69fe131a3bbad5d63c64eebcc30e395b9d8107726a13d074e389dbc8a4e47256";
    const RFC8448_TRANSCRIPT_HASH: &str =
        "63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14";
    const RFC8448_FINISHED_KEY: &str =
        "5588673e72cb59c87d220caffe94f2dea9a3b1609f7d50e90a48227db9ed7eaa";
    const RFC8448_BINDER: &str = "3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d";
    const RFC8448_PREFIX: &str = "010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7b4bc419d7876487d95000006130113031302010001cd0000000b0009000006736572766572ff01000100000a00140012001d00170018001901000101010201030104003300260024001d0020e4ffb68ac05f8d96c99da26698346c6be16482badddafe051a66b4f18d668f0b002a0000002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c0002400100150057000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002900dd00b800b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934ae4d357fad6aacb";

    fn fixture() -> ImportedIdentity {
        ImportedIdentity::new(EXTERNAL_IDENTITY.to_vec(), CONTEXT.to_vec()).unwrap()
    }

    #[test]
    fn identity_encoding_matches_fixed_bytes() {
        assert_eq!(hex::encode(fixture().encode().unwrap()), ENCODED_IDENTITY);
    }

    #[test]
    fn identity_rejects_unsupported_or_empty_fields() {
        assert_eq!(
            ImportedIdentity::new(Vec::new(), CONTEXT.to_vec()).unwrap_err(),
            Error::EmptyExternalIdentity
        );
        assert_eq!(
            ImportedIdentity {
                external_identity: EXTERNAL_IDENTITY.to_vec(),
                context: CONTEXT.to_vec(),
                target_protocol: 0x0303,
                target_kdf: TARGET_KDF,
            }
            .encode()
            .unwrap_err(),
            Error::UnsupportedTarget
        );
        assert_eq!(
            ImportedIdentity::new(vec![0; usize::from(u16::MAX) + 1], Vec::new()).unwrap_err(),
            Error::FieldTooLong
        );
        assert_eq!(
            ImportedIdentity::new(
                EXTERNAL_IDENTITY.to_vec(),
                vec![0; usize::from(u16::MAX) + 1]
            )
            .unwrap_err(),
            Error::FieldTooLong
        );
        assert_eq!(
            ImportedIdentity {
                external_identity: Vec::new(),
                context: Vec::new(),
                target_protocol: TARGET_PROTOCOL,
                target_kdf: TARGET_KDF,
            }
            .encode()
            .unwrap_err(),
            Error::EmptyExternalIdentity
        );
    }

    #[test]
    fn imported_psk_matches_fixed_kat() {
        let ipsk = import_external_psk(&EPSK, &fixture()).unwrap();
        assert_eq!(hex::encode(&*ipsk), IMPORTED_PSK);
    }

    #[test]
    fn imported_binder_key_matches_fixed_kat() {
        let ipsk = import_external_psk(&EPSK, &fixture()).unwrap();
        let binder = imported_binder_key(&ipsk).unwrap();
        assert_eq!(hex::encode(&binder[..]), IMPORTED_BINDER);
    }

    #[test]
    fn context_and_identity_change_the_imported_key() {
        let base = import_external_psk(&EPSK, &fixture()).unwrap();
        let other_context =
            ImportedIdentity::new(EXTERNAL_IDENTITY.to_vec(), b"other-context".to_vec()).unwrap();
        let other_identity =
            ImportedIdentity::new(b"other-identity".to_vec(), CONTEXT.to_vec()).unwrap();
        assert_ne!(*base, *import_external_psk(&EPSK, &other_context).unwrap());
        assert_ne!(*base, *import_external_psk(&EPSK, &other_identity).unwrap());
    }

    fn rfc8448_psk() -> [u8; KEY_LEN] {
        hex::decode(RFC8448_PSK).unwrap().try_into().unwrap()
    }

    fn rfc8448_prefix() -> Vec<u8> {
        let prefix = hex::decode(RFC8448_PREFIX).unwrap();
        assert_eq!(prefix.len(), 477);
        prefix
    }

    fn rfc8448_binder_key() -> Zeroizing<[u8; KEY_LEN]> {
        binder_key(&rfc8448_psk(), b"res binder").unwrap()
    }

    #[test]
    fn rfc8448_binder_matches_each_intermediate_value() {
        let psk = rfc8448_psk();
        assert_eq!(hex::encode(psk), RFC8448_PSK);

        let mut mac = Hmac::<Sha256>::new_from_slice(&SALT).unwrap();
        mac.update(&psk);
        let early_secret = Zeroizing::new(<[u8; KEY_LEN]>::from(mac.finalize().into_bytes()));
        assert_eq!(hex::encode(&early_secret[..]), RFC8448_EARLY_SECRET);

        let binder_key = rfc8448_binder_key();
        assert_eq!(hex::encode(&binder_key[..]), RFC8448_BINDER_KEY);

        let prefix = rfc8448_prefix();
        let transcript_hash = Zeroizing::new(<[u8; KEY_LEN]>::from(Sha256::digest(&prefix)));
        assert_eq!(hex::encode(&transcript_hash[..]), RFC8448_TRANSCRIPT_HASH);

        let prk = Hkdf::<Sha256>::from_prk(&binder_key[..]).unwrap();
        let mut finished_key = Zeroizing::new([0u8; KEY_LEN]);
        crate::tls13::expand_label(&prk, b"finished", b"", finished_key.as_mut()).unwrap();
        assert_eq!(hex::encode(&finished_key[..]), RFC8448_FINISHED_KEY);

        assert_eq!(
            hex::encode(&psk_binder(&binder_key, &prefix).unwrap()[..]),
            RFC8448_BINDER
        );
    }

    #[test]
    fn binder_changes_with_the_transcript_prefix() {
        let binder_key = rfc8448_binder_key();
        let prefix = rfc8448_prefix();
        let mut tampered = prefix.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert_ne!(
            *psk_binder(&binder_key, &prefix).unwrap(),
            *psk_binder(&binder_key, &tampered).unwrap()
        );
    }

    #[test]
    fn imported_binder_uses_the_imported_binder_key() {
        let ipsk = import_external_psk(&EPSK, &fixture()).unwrap();
        let prefix = rfc8448_prefix();
        assert_eq!(
            *imported_psk_binder(&ipsk, &prefix).unwrap(),
            *psk_binder(&imported_binder_key(&ipsk).unwrap(), &prefix).unwrap()
        );
        assert_ne!(
            *imported_psk_binder(&ipsk, &prefix).unwrap(),
            *psk_binder(&binder_key(&ipsk, b"ext binder").unwrap(), &prefix).unwrap()
        );
    }

    #[test]
    fn empty_extension_encoding_and_body_parsing() {
        assert_eq!(encode_empty_extension(), [0x00, 0x21, 0x00, 0x00]);
        assert_eq!(EMPTY_EXTENSION, [0x00, 0x21, 0x00, 0x00]);
        assert_eq!(parse_empty_extension(b""), Ok(()));
        for len in 1..=4 {
            assert_eq!(
                parse_empty_extension(&vec![0u8; len]),
                Err(Error::InvalidExtension)
            );
        }
    }

    #[test]
    fn framed_extension_parsing_accepts_only_the_empty_body() {
        assert_eq!(parse_extension(&encode_empty_extension()), Ok(()));
        assert_eq!(
            parse_extension(&[0x00, 0x05, 0x00, 0x00]),
            Err(Error::InvalidExtension)
        );
        assert_eq!(
            parse_extension(&[0x00, 0x21, 0x00, 0x01, 0x00]),
            Err(Error::InvalidExtension)
        );
        assert_eq!(
            parse_extension(&[0x00, 0x21, 0x00, 0x00, 0x00]),
            Err(Error::InvalidExtension)
        );
        assert_eq!(
            parse_extension(&[0x00, 0x21, 0x00]),
            Err(Error::InvalidExtension)
        );
    }
}
