//! Wire-level TLS 1.3 `pre_shared_key` extension handling.
//!
//! These are offline byte computations for RFC 8446 §4.2.11: the ClientHello
//! `OfferedPsks` structure, the ServerHello selected identity and the RFC 9973
//! §4 companion-extension policy. No handshake state, PSK derivation, binder
//! computation or transport lives here.

use std::fmt;

/// RFC 8446 `pre_shared_key` extension type.
pub const PRE_SHARED_KEY_TYPE: u16 = 0x0029;
/// RFC 8446 `early_data` extension type.
pub const EARLY_DATA_TYPE: u16 = 0x002a;
/// RFC 9973 `tls_cert_with_extern_psk` extension type.
pub const CERT_WITH_EXTERN_PSK_TYPE: u16 = 0x0021;
/// RFC 8446 `supported_groups` extension type.
pub const SUPPORTED_GROUPS_TYPE: u16 = 0x000a;
/// RFC 8446 `psk_key_exchange_modes` extension type.
pub const PSK_KEY_EXCHANGE_MODES_TYPE: u16 = 0x002d;
/// RFC 8446 `key_share` extension type.
pub const KEY_SHARE_TYPE: u16 = 0x0033;

const EXTENSION_HEADER_LEN: usize = 4;
const MIN_IDENTITY_LEN: usize = 1;
const MIN_BINDER_LEN: usize = 32;

/// Malformed extension bytes or a forbidden extension combination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidExtensionType,
    Truncated,
    TrailingBytes,
    VectorTooLong,
    EmptyIdentities,
    InvalidIdentityLength,
    EmptyBinders,
    InvalidBinderLength,
    BinderCountMismatch,
    InvalidSelectedIdentity,
    DuplicatePreSharedKey,
    MissingCompanionExtension,
    PreSharedKeyNotLast,
    EarlyDataConflict,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidExtensionType => "extension is not pre_shared_key",
            Self::Truncated => "pre_shared_key extension is truncated",
            Self::TrailingBytes => "pre_shared_key extension has trailing bytes",
            Self::VectorTooLong => "pre_shared_key vector exceeds u16 length",
            Self::EmptyIdentities => "pre_shared_key identities must not be empty",
            Self::InvalidIdentityLength => "PSK identity length must be 1..=65535",
            Self::EmptyBinders => "pre_shared_key binders must not be empty",
            Self::InvalidBinderLength => "PSK binder length must be 32..=255",
            Self::BinderCountMismatch => "one PSK binder is required per identity",
            Self::InvalidSelectedIdentity => "selected identity must be exactly two bytes",
            Self::DuplicatePreSharedKey => "pre_shared_key must appear only once",
            Self::MissingCompanionExtension => "RFC 9973 companion extension is missing",
            Self::PreSharedKeyNotLast => "pre_shared_key must be the last extension",
            Self::EarlyDataConflict => "early_data and tls_cert_with_extern_psk conflict",
        })
    }
}

impl std::error::Error for Error {}

/// RFC 8446 §4.2.11 `PskIdentity`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PskIdentity {
    pub identity: Vec<u8>,
    pub obfuscated_ticket_age: u32,
}

/// RFC 8446 §4.2.11 `OfferedPsks`: one binder for each offered identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfferedPsks {
    pub identities: Vec<PskIdentity>,
    pub binders: Vec<Vec<u8>>,
}

/// Read big-endian fields from an exact byte slice; every short read is fatal.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        if self.bytes.len() < len {
            return Err(Error::Truncated);
        }
        let (head, tail) = self.bytes.split_at(len);
        self.bytes = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn finish(self) -> Result<(), Error> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(Error::TrailingBytes)
        }
    }
}

fn vector_len(len: usize) -> Result<u16, Error> {
    u16::try_from(len).map_err(|_| Error::VectorTooLong)
}

/// Encode an `OfferedPsks` body: identities vector, then binders vector.
pub fn encode_body(psks: &OfferedPsks) -> Result<Vec<u8>, Error> {
    if psks.identities.is_empty() {
        return Err(Error::EmptyIdentities);
    }
    if psks.binders.is_empty() {
        return Err(Error::EmptyBinders);
    }
    if psks.identities.len() != psks.binders.len() {
        return Err(Error::BinderCountMismatch);
    }

    let mut identities_wire = Vec::new();
    for identity in &psks.identities {
        let len =
            u16::try_from(identity.identity.len()).map_err(|_| Error::InvalidIdentityLength)?;
        if usize::from(len) < MIN_IDENTITY_LEN {
            return Err(Error::InvalidIdentityLength);
        }
        identities_wire.extend_from_slice(&len.to_be_bytes());
        identities_wire.extend_from_slice(&identity.identity);
        identities_wire.extend_from_slice(&identity.obfuscated_ticket_age.to_be_bytes());
    }

    let mut binders_wire = Vec::new();
    for binder in &psks.binders {
        let len = u8::try_from(binder.len()).map_err(|_| Error::InvalidBinderLength)?;
        if usize::from(len) < MIN_BINDER_LEN {
            return Err(Error::InvalidBinderLength);
        }
        binders_wire.push(len);
        binders_wire.extend_from_slice(binder);
    }

    let mut body = Vec::with_capacity(identities_wire.len() + binders_wire.len() + 4);
    body.extend_from_slice(&vector_len(identities_wire.len())?.to_be_bytes());
    body.extend_from_slice(&identities_wire);
    body.extend_from_slice(&vector_len(binders_wire.len())?.to_be_bytes());
    body.extend_from_slice(&binders_wire);
    Ok(body)
}

/// Parse an exact `OfferedPsks` body, rejecting truncation, trailing bytes,
/// invalid field lengths, empty vectors and binder/identity count mismatches.
pub fn parse_body(body: &[u8]) -> Result<OfferedPsks, Error> {
    let mut reader = Reader::new(body);
    let identities_len = usize::from(reader.u16()?);
    let identities_wire = reader.take(identities_len)?;
    let binders_len = usize::from(reader.u16()?);
    let binders_wire = reader.take(binders_len)?;
    reader.finish()?;

    let mut reader = Reader::new(identities_wire);
    let mut identities = Vec::new();
    while !reader.is_empty() {
        let len = usize::from(reader.u16()?);
        if len < MIN_IDENTITY_LEN {
            return Err(Error::InvalidIdentityLength);
        }
        let identity = reader.take(len)?.to_vec();
        let obfuscated_ticket_age = reader.u32()?;
        identities.push(PskIdentity {
            identity,
            obfuscated_ticket_age,
        });
    }
    if identities.is_empty() {
        return Err(Error::EmptyIdentities);
    }

    let mut reader = Reader::new(binders_wire);
    let mut binders = Vec::new();
    while !reader.is_empty() {
        let len = usize::from(reader.u8()?);
        if len < MIN_BINDER_LEN {
            return Err(Error::InvalidBinderLength);
        }
        binders.push(reader.take(len)?.to_vec());
    }
    if binders.is_empty() {
        return Err(Error::EmptyBinders);
    }
    if binders.len() != identities.len() {
        return Err(Error::BinderCountMismatch);
    }

    Ok(OfferedPsks {
        identities,
        binders,
    })
}

/// Encode a whole `pre_shared_key` extension: type, u16 body length, body.
pub fn encode_extension(psks: &OfferedPsks) -> Result<Vec<u8>, Error> {
    let body = encode_body(psks)?;
    let mut wire = Vec::with_capacity(EXTENSION_HEADER_LEN + body.len());
    wire.extend_from_slice(&PRE_SHARED_KEY_TYPE.to_be_bytes());
    wire.extend_from_slice(&vector_len(body.len())?.to_be_bytes());
    wire.extend_from_slice(&body);
    Ok(wire)
}

/// Parse a whole `pre_shared_key` extension, rejecting another type, a wrong
/// declared body length, and any byte after the declared body.
pub fn parse_extension(wire: &[u8]) -> Result<OfferedPsks, Error> {
    let mut reader = Reader::new(wire);
    if reader.u16()? != PRE_SHARED_KEY_TYPE {
        return Err(Error::InvalidExtensionType);
    }
    let body_len = usize::from(reader.u16()?);
    let body = reader.take(body_len)?;
    reader.finish()?;
    parse_body(body)
}

/// Encode the ServerHello `selected_identity` as a big-endian u16.
pub fn encode_selected_identity(identity: u16) -> [u8; 2] {
    identity.to_be_bytes()
}

/// Parse a ServerHello `selected_identity` of exactly two bytes.
pub fn parse_selected_identity(wire: &[u8]) -> Result<u16, Error> {
    let bytes: [u8; 2] = wire
        .try_into()
        .map_err(|_| Error::InvalidSelectedIdentity)?;
    Ok(u16::from_be_bytes(bytes))
}

/// Enforce the RFC 9973 §4 ClientHello companion rules. Extension types are
/// supplied in wire order so extension ordering can be checked as well.
pub fn validate_client_hello_companion_extensions(types: &[u16]) -> Result<(), Error> {
    let psk_count = types
        .iter()
        .filter(|&&extension| extension == PRE_SHARED_KEY_TYPE)
        .count();
    if psk_count > 1 {
        return Err(Error::DuplicatePreSharedKey);
    }
    if psk_count == 1 && types.last() != Some(&PRE_SHARED_KEY_TYPE) {
        return Err(Error::PreSharedKeyNotLast);
    }
    if !types.contains(&CERT_WITH_EXTERN_PSK_TYPE) {
        return Ok(());
    }
    if types.contains(&EARLY_DATA_TYPE) {
        return Err(Error::EarlyDataConflict);
    }
    for required in [
        KEY_SHARE_TYPE,
        SUPPORTED_GROUPS_TYPE,
        PSK_KEY_EXCHANGE_MODES_TYPE,
        PRE_SHARED_KEY_TYPE,
    ] {
        if !types.contains(&required) {
            return Err(Error::MissingCompanionExtension);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8448 §4 full ClientHello pre_shared_key extension.
    const RFC8448_EXTENSION: &str = concat!(
        "002900dd00b800b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b0",
        "070ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861b",
        "e7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da",
        "2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c621a7914",
        "1ef5f7de6505e5bfbc388e93343694093934ae4d357fad6aacb00212",
        "03add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d"
    );
    const RFC8448_BINDER: &str = "3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d";

    fn identity_wire(identity: &[u8], age: u32) -> Vec<u8> {
        let mut wire = u16::try_from(identity.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        wire.extend_from_slice(identity);
        wire.extend_from_slice(&age.to_be_bytes());
        wire
    }

    fn binder_wire(len: u8) -> Vec<u8> {
        let mut wire = vec![0xab; usize::from(len) + 1];
        wire[0] = len;
        wire
    }

    fn frame(identities_wire: &[u8], binders_wire: &[u8]) -> Vec<u8> {
        let mut body = u16::try_from(identities_wire.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        body.extend_from_slice(identities_wire);
        body.extend_from_slice(&u16::try_from(binders_wire.len()).unwrap().to_be_bytes());
        body.extend_from_slice(binders_wire);

        let mut wire = PRE_SHARED_KEY_TYPE.to_be_bytes().to_vec();
        wire.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        wire.extend_from_slice(&body);
        wire
    }

    fn sample() -> OfferedPsks {
        OfferedPsks {
            identities: vec![PskIdentity {
                identity: vec![1, 2, 3],
                obfuscated_ticket_age: 0x0102_0304,
            }],
            binders: vec![vec![0xab; 32]],
        }
    }

    #[test]
    fn rfc8448_extension_parses_and_reencodes_exactly() {
        let wire = hex::decode(RFC8448_EXTENSION).unwrap();
        assert_eq!(wire.len(), 4 + 221);

        let psks = parse_extension(&wire).unwrap();
        assert_eq!(psks.identities.len(), 1);
        assert_eq!(psks.identities[0].identity.len(), 178);
        assert_eq!(psks.identities[0].obfuscated_ticket_age, 0xfad6_aacb);
        assert_eq!(psks.binders, vec![hex::decode(RFC8448_BINDER).unwrap()]);

        assert_eq!(encode_body(&psks).unwrap(), wire[4..]);
        assert_eq!(encode_extension(&psks).unwrap(), wire);
    }

    #[test]
    fn synthetic_extension_round_trips_through_body_and_extension() {
        let psks = sample();
        let wire = encode_extension(&psks).unwrap();
        assert_eq!(parse_body(&encode_body(&psks).unwrap()).unwrap(), psks);
        assert_eq!(parse_extension(&wire).unwrap(), psks);
        assert_eq!(wire[..2], PRE_SHARED_KEY_TYPE.to_be_bytes());
        assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 46);
    }

    #[test]
    fn rejects_wrong_extension_type() {
        let mut wire = encode_extension(&sample()).unwrap();
        wire[..2].copy_from_slice(&EARLY_DATA_TYPE.to_be_bytes());
        assert_eq!(
            parse_extension(&wire).unwrap_err(),
            Error::InvalidExtensionType
        );
    }

    #[test]
    fn rejects_truncated_wire_and_body() {
        let wire = encode_extension(&sample()).unwrap();
        assert_eq!(
            parse_extension(&wire[..wire.len() - 1]).unwrap_err(),
            Error::Truncated
        );
        assert_eq!(parse_extension(&[]).unwrap_err(), Error::Truncated);

        let mut short_declared = wire.clone();
        short_declared[3] += 1;
        assert_eq!(
            parse_extension(&short_declared).unwrap_err(),
            Error::Truncated
        );
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut wire = encode_extension(&sample()).unwrap();
        wire.push(0);
        assert_eq!(parse_extension(&wire).unwrap_err(), Error::TrailingBytes);

        let mut short_declared = encode_extension(&sample()).unwrap();
        short_declared[3] -= 1;
        assert_eq!(
            parse_extension(&short_declared).unwrap_err(),
            Error::TrailingBytes
        );
    }

    #[test]
    fn rejects_empty_identity() {
        let mut psks = sample();
        psks.identities[0].identity.clear();
        assert_eq!(
            encode_body(&psks).unwrap_err(),
            Error::InvalidIdentityLength
        );

        let wire = frame(&identity_wire(&[], 0), &binder_wire(32));
        assert_eq!(
            parse_extension(&wire).unwrap_err(),
            Error::InvalidIdentityLength
        );
    }

    #[test]
    fn rejects_binder_length_31() {
        let mut psks = sample();
        psks.binders[0] = vec![0xab; 31];
        assert_eq!(encode_body(&psks).unwrap_err(), Error::InvalidBinderLength);

        let wire = frame(&identity_wire(&[1, 2, 3], 0), &binder_wire(31));
        assert_eq!(
            parse_extension(&wire).unwrap_err(),
            Error::InvalidBinderLength
        );
    }

    #[test]
    fn rejects_mismatched_identity_and_binder_counts() {
        let mut psks = sample();
        psks.identities.push(PskIdentity {
            identity: vec![4],
            obfuscated_ticket_age: 0,
        });
        assert_eq!(encode_body(&psks).unwrap_err(), Error::BinderCountMismatch);

        let mut identities = identity_wire(&[1, 2, 3], 0);
        identities.extend_from_slice(&identity_wire(&[4], 0));
        let wire = frame(&identities, &binder_wire(32));
        assert_eq!(
            parse_extension(&wire).unwrap_err(),
            Error::BinderCountMismatch
        );
    }

    #[test]
    fn rejects_empty_and_inexact_vectors() {
        assert_eq!(
            encode_body(&OfferedPsks {
                identities: vec![],
                binders: vec![]
            })
            .unwrap_err(),
            Error::EmptyIdentities
        );
        let mut no_binders = sample();
        no_binders.binders.clear();
        assert_eq!(encode_body(&no_binders).unwrap_err(), Error::EmptyBinders);

        let wire = frame(&[], &binder_wire(32));
        assert_eq!(parse_extension(&wire).unwrap_err(), Error::EmptyIdentities);
        let wire = frame(&identity_wire(&[1], 0), &[]);
        assert_eq!(parse_extension(&wire).unwrap_err(), Error::EmptyBinders);

        let mut body = encode_body(&sample()).unwrap();
        body[1] -= 1;
        let mut wire = PRE_SHARED_KEY_TYPE.to_be_bytes().to_vec();
        wire.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        wire.extend_from_slice(&body);
        assert_eq!(parse_extension(&wire).unwrap_err(), Error::Truncated);

        let mut identities = identity_wire(&[1], 0);
        identities.push(0);
        let wire = frame(&identities, &binder_wire(32));
        assert_eq!(parse_extension(&wire).unwrap_err(), Error::Truncated);
    }

    #[test]
    fn selected_identity_is_exactly_two_bytes() {
        assert_eq!(encode_selected_identity(0x0102), [0x01, 0x02]);
        assert_eq!(parse_selected_identity(&[0x01, 0x02]).unwrap(), 0x0102);
        assert_eq!(
            parse_selected_identity(&[0x01]).unwrap_err(),
            Error::InvalidSelectedIdentity
        );
        assert_eq!(
            parse_selected_identity(&[0x01, 0x02, 0x03]).unwrap_err(),
            Error::InvalidSelectedIdentity
        );
    }

    #[test]
    fn companion_extensions_follow_rfc9973_policy() {
        let rfc8448_with_cert = [
            SUPPORTED_GROUPS_TYPE,
            KEY_SHARE_TYPE,
            PSK_KEY_EXCHANGE_MODES_TYPE,
            CERT_WITH_EXTERN_PSK_TYPE,
            PRE_SHARED_KEY_TYPE,
        ];
        assert_eq!(
            validate_client_hello_companion_extensions(&rfc8448_with_cert),
            Ok(())
        );
        assert_eq!(
            validate_client_hello_companion_extensions(&[
                SUPPORTED_GROUPS_TYPE,
                PSK_KEY_EXCHANGE_MODES_TYPE,
                CERT_WITH_EXTERN_PSK_TYPE,
                PRE_SHARED_KEY_TYPE,
            ]),
            Err(Error::MissingCompanionExtension)
        );
        assert_eq!(
            validate_client_hello_companion_extensions(&[
                SUPPORTED_GROUPS_TYPE,
                KEY_SHARE_TYPE,
                PSK_KEY_EXCHANGE_MODES_TYPE,
                CERT_WITH_EXTERN_PSK_TYPE,
                EARLY_DATA_TYPE,
                PRE_SHARED_KEY_TYPE,
            ]),
            Err(Error::EarlyDataConflict)
        );
        assert_eq!(
            validate_client_hello_companion_extensions(&[
                SUPPORTED_GROUPS_TYPE,
                KEY_SHARE_TYPE,
                PSK_KEY_EXCHANGE_MODES_TYPE,
                PRE_SHARED_KEY_TYPE,
                CERT_WITH_EXTERN_PSK_TYPE,
            ]),
            Err(Error::PreSharedKeyNotLast)
        );
        assert_eq!(
            validate_client_hello_companion_extensions(&[
                SUPPORTED_GROUPS_TYPE,
                KEY_SHARE_TYPE,
                PSK_KEY_EXCHANGE_MODES_TYPE,
                CERT_WITH_EXTERN_PSK_TYPE,
                PRE_SHARED_KEY_TYPE,
                PRE_SHARED_KEY_TYPE,
            ]),
            Err(Error::DuplicatePreSharedKey)
        );
        assert_eq!(validate_client_hello_companion_extensions(&[]), Ok(()));
    }
}
