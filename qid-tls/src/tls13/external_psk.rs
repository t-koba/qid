//! RFC 9258 external PSK import and the RFC 9973 empty extension.
//!
//! These are offline byte computations: identity encoding, HKDF derivation and
//! extension framing. No handshake state, listener or transport lives here,
//! and this module does not implement TLS-POK authentication.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

/// Target protocol field of an RFC 9258 `ImportedIdentity`: TLS 1.3 (RFC 8446).
pub const TARGET_PROTOCOL: u16 = 0x0304;
/// Target KDF field of an RFC 9258 `ImportedIdentity`: HKDF-SHA256.
pub const TARGET_KDF: u16 = 0x0001;
/// RFC 9973 `tls_pok` extension type.
pub const EXTENSION_TYPE: u16 = 0x0021;

const SALT: [u8; 32] = [0; 32];
const LABEL_PREFIX: &[u8] = b"tls13 ";
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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyExternalIdentity => "external identity must not be empty",
            Self::FieldTooLong => "imported identity field exceeds u16 length",
            Self::Derivation => "TLS 1.3 label expansion failed",
            Self::InvalidExtension => "invalid RFC 9973 empty extension",
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

/// RFC 8446 §7.1 `HKDF-Expand-Label(secret, label, context, out.len())`.
fn expand_label(
    hkdf: &Hkdf<Sha256>,
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    let full_label_len = LABEL_PREFIX
        .len()
        .checked_add(label.len())
        .and_then(|len| u8::try_from(len).ok())
        .ok_or(Error::Derivation)?;
    let context_len = u8::try_from(context.len()).map_err(|_| Error::Derivation)?;
    let output_len = u16::try_from(out.len()).map_err(|_| Error::Derivation)?;
    hkdf.expand_multi_info(
        &[
            &output_len.to_be_bytes(),
            &[full_label_len],
            LABEL_PREFIX,
            label,
            &[context_len],
            context,
        ],
        out,
    )
    .map_err(|_| Error::Derivation)
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
    expand_label(&epskx, b"derived psk", &hash[..], ipsk.as_mut())?;
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
    expand_label(&early_secret, label, &transcript_hash[..], out.as_mut())?;
    Ok(out)
}

/// Encode the RFC 9973 `tls_pok` extension as `extension_type || 0x0000 ||`
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

    fn fixture() -> ImportedIdentity {
        ImportedIdentity::new(EXTERNAL_IDENTITY.to_vec(), CONTEXT.to_vec()).unwrap()
    }

    #[test]
    fn identity_encoding_matches_fixed_bytes() {
        assert_eq!(hex::encode(fixture().encode().unwrap()), ENCODED_IDENTITY);
    }

    #[test]
    fn identity_rejects_empty_and_oversize_fields() {
        assert_eq!(
            ImportedIdentity::new(Vec::new(), CONTEXT.to_vec()).unwrap_err(),
            Error::EmptyExternalIdentity
        );
        assert_eq!(
            ImportedIdentity::new(vec![1; usize::from(u16::MAX) + 1], CONTEXT.to_vec())
                .unwrap_err(),
            Error::FieldTooLong
        );
        assert_eq!(
            ImportedIdentity::new(
                EXTERNAL_IDENTITY.to_vec(),
                vec![2; usize::from(u16::MAX) + 1]
            )
            .unwrap_err(),
            Error::FieldTooLong
        );
        let direct = ImportedIdentity {
            external_identity: Vec::new(),
            context: Vec::new(),
            target_protocol: TARGET_PROTOCOL,
            target_kdf: TARGET_KDF,
        };
        assert_eq!(direct.encode().unwrap_err(), Error::EmptyExternalIdentity);
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

    #[test]
    fn imported_binder_differs_from_extended_binder() {
        let ipsk = import_external_psk(&EPSK, &fixture()).unwrap();
        assert_ne!(
            *binder_key(&ipsk, b"imp binder").unwrap(),
            *binder_key(&ipsk, b"ext binder").unwrap()
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
