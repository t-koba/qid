//! Strict TLS 1.3 ServerHello parsing and RFC 9973 negotiation validation.
//!
//! This is offline byte computation on a ServerHello handshake body: no
//! handshake state, key derivation, certificate parsing or transport lives
//! here.

use super::psk_extension::{
    CERT_WITH_EXTERN_PSK_TYPE, EARLY_DATA_TYPE, KEY_SHARE_TYPE, PRE_SHARED_KEY_TYPE,
    parse_selected_identity,
};
use std::fmt;

const LEGACY_VERSION: u16 = 0x0303;
const RANDOM_LEN: usize = 32;
const EXTENSION_HEADER_LEN: usize = 4;
const SUPPORTED_VERSIONS_TYPE: u16 = 0x002b;

/// ServerHello handshake fields, excluding the four-byte handshake header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerHello<'a> {
    pub legacy_version: u16,
    pub random: &'a [u8],
    pub legacy_session_id_echo: &'a [u8],
    pub cipher_suite: u16,
    pub legacy_compression_method: u8,
    pub extensions: &'a [u8],
}

/// A single RFC 8446 `KeyShareEntry` from a ServerHello.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyShare<'a> {
    pub group: u16,
    pub key_exchange: &'a [u8],
}

/// ServerHello extensions that determine key establishment and PSK policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Negotiated<'a> {
    pub selected_psk: Option<u16>,
    pub key_share: Option<KeyShare<'a>>,
    pub cert_with_extern_psk: bool,
    pub early_data: bool,
}

/// Malformed ServerHello bytes or an invalid RFC 9973 negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    TruncatedBody,
    InvalidLegacyFields,
    MalformedExtensions,
    TrailingBytes,
    DuplicateExtension,
    InvalidSelectedIdentity,
    InvalidKeyShare,
    InvalidSupportedVersions,
    InvalidNegotiation,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TruncatedBody => "ServerHello body is truncated",
            Self::InvalidLegacyFields => "ServerHello legacy fields are invalid",
            Self::MalformedExtensions => "ServerHello extensions are malformed",
            Self::TrailingBytes => "ServerHello has trailing bytes",
            Self::DuplicateExtension => "ServerHello extension appears more than once",
            Self::InvalidSelectedIdentity => "selected_identity must be exactly two bytes",
            Self::InvalidKeyShare => "key_share entry is malformed",
            Self::InvalidSupportedVersions => "supported_versions must select TLS 1.3",
            Self::InvalidNegotiation => "certificate with external PSK negotiation is invalid",
        })
    }
}

impl std::error::Error for Error {}

/// Consume exactly `len` bytes, failing if fewer remain.
fn take<'a>(remaining: &mut &'a [u8], len: usize) -> Result<&'a [u8], Error> {
    if remaining.len() < len {
        return Err(Error::TruncatedBody);
    }
    let (head, tail) = remaining.split_at(len);
    *remaining = tail;
    Ok(head)
}

fn read_u16(remaining: &mut &[u8]) -> Result<u16, Error> {
    let bytes = take(remaining, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn parse_key_share(body: &[u8]) -> Result<KeyShare<'_>, Error> {
    let mut reader = body;
    let group = read_u16(&mut reader).map_err(|_| Error::InvalidKeyShare)?;
    let exchange_len = usize::from(read_u16(&mut reader).map_err(|_| Error::InvalidKeyShare)?);
    let key_exchange = take(&mut reader, exchange_len).map_err(|_| Error::InvalidKeyShare)?;
    if !reader.is_empty() || key_exchange.is_empty() {
        return Err(Error::InvalidKeyShare);
    }
    Ok(KeyShare {
        group,
        key_exchange,
    })
}

/// Parse a ServerHello handshake body and validate its negotiated extensions.
pub fn parse(body: &[u8]) -> Result<(ServerHello<'_>, Negotiated<'_>), Error> {
    let mut reader = body;
    let legacy_version = read_u16(&mut reader)?;
    let random = take(&mut reader, RANDOM_LEN)?;
    let session_id_len = usize::from(take(&mut reader, 1)?[0]);
    if session_id_len > 32 {
        return Err(Error::InvalidLegacyFields);
    }
    let legacy_session_id_echo = take(&mut reader, session_id_len)?;
    let cipher_suite = read_u16(&mut reader)?;
    let legacy_compression_method = take(&mut reader, 1)?[0];
    if legacy_version != LEGACY_VERSION || legacy_compression_method != 0 {
        return Err(Error::InvalidLegacyFields);
    }

    let extensions_len = usize::from(read_u16(&mut reader)?);
    if extensions_len < 6 {
        return Err(Error::MalformedExtensions);
    }
    let extensions = take(&mut reader, extensions_len)?;
    if !reader.is_empty() {
        return Err(Error::TrailingBytes);
    }

    let mut selected_psk = None;
    let mut key_share = None;
    let mut cert_with_extern_psk = false;
    let mut early_data = false;
    let mut supported_versions = false;
    let mut seen = Vec::new();
    let mut remaining = extensions;
    while !remaining.is_empty() {
        if remaining.len() < EXTENSION_HEADER_LEN {
            return Err(Error::MalformedExtensions);
        }
        let kind = read_u16(&mut remaining)?;
        let body_len = usize::from(read_u16(&mut remaining)?);
        let ext_body = take(&mut remaining, body_len)?;
        if seen.contains(&kind) {
            return Err(Error::DuplicateExtension);
        }
        seen.push(kind);

        match kind {
            PRE_SHARED_KEY_TYPE => {
                selected_psk = Some(
                    parse_selected_identity(ext_body)
                        .map_err(|_| Error::InvalidSelectedIdentity)?,
                );
            }
            KEY_SHARE_TYPE => key_share = Some(parse_key_share(ext_body)?),
            CERT_WITH_EXTERN_PSK_TYPE => {
                if !ext_body.is_empty() {
                    return Err(Error::MalformedExtensions);
                }
                cert_with_extern_psk = true;
            }
            EARLY_DATA_TYPE => {
                if !ext_body.is_empty() {
                    return Err(Error::MalformedExtensions);
                }
                early_data = true;
            }
            SUPPORTED_VERSIONS_TYPE => {
                if ext_body != [0x03, 0x04] {
                    return Err(Error::InvalidSupportedVersions);
                }
                supported_versions = true;
            }
            _ => {}
        }
    }

    if !supported_versions {
        return Err(Error::InvalidSupportedVersions);
    }

    // RFC 9973 §4: the certificate extension requires both a selected PSK and
    // a key share, and never accompanies early data.
    if cert_with_extern_psk && (selected_psk.is_none() || key_share.is_none() || early_data) {
        return Err(Error::InvalidNegotiation);
    }

    Ok((
        ServerHello {
            legacy_version,
            random,
            legacy_session_id_echo,
            cipher_suite,
            legacy_compression_method,
            extensions,
        },
        Negotiated {
            selected_psk,
            key_share,
            cert_with_extern_psk,
            early_data,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8448 §3 ServerHello body: 90-byte message minus its four-byte header.
    const RFC8448_BODY: &str = concat!(
        "0303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e26928",
        "00130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f",
        "002b00020304"
    );
    const KEY_EXCHANGE: &str = "c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f";
    const KEY_SHARE_BODY: &str =
        "001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f";
    // legacy_version, random, session id, cipher suite and compression method.
    const FIXED_HEADER_LEN: usize = 2 + RANDOM_LEN + 1 + 2 + 1;

    fn rfc8448_body() -> Vec<u8> {
        hex::decode(RFC8448_BODY).unwrap()
    }

    fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut wire = kind.to_be_bytes().to_vec();
        wire.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        wire.extend_from_slice(body);
        wire
    }

    fn body_with_extensions(extensions: &[u8]) -> Vec<u8> {
        let mut body = rfc8448_body()[..FIXED_HEADER_LEN].to_vec();
        body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
        body.extend_from_slice(extensions);
        body
    }

    fn extensions(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.iter().flatten().copied().collect()
    }

    fn supported_versions() -> Vec<u8> {
        extension(SUPPORTED_VERSIONS_TYPE, &[0x03, 0x04])
    }

    #[test]
    fn parses_rfc8448_server_hello() {
        let body = rfc8448_body();
        assert_eq!(body.len(), 86);
        let (hello, negotiated) = parse(&body).unwrap();

        assert_eq!(hello.legacy_version, 0x0303);
        assert_eq!(hello.random.len(), 32);
        assert!(hello.legacy_session_id_echo.is_empty());
        assert_eq!(hello.cipher_suite, 0x1301);
        assert_eq!(hello.legacy_compression_method, 0);
        assert_eq!(hello.extensions.len(), 46);
        let key_share = negotiated.key_share.unwrap();
        assert_eq!(key_share.group, 0x001d);
        assert_eq!(key_share.key_exchange, hex::decode(KEY_EXCHANGE).unwrap());
        assert_eq!(negotiated.selected_psk, None);
        assert!(!negotiated.cert_with_extern_psk);
        assert!(!negotiated.early_data);
    }

    #[test]
    fn accepts_certificate_with_external_psk_negotiation() {
        let parts = [
            supported_versions(),
            extension(KEY_SHARE_TYPE, &hex::decode(KEY_SHARE_BODY).unwrap()),
            extension(PRE_SHARED_KEY_TYPE, &[0x00, 0x07]),
            extension(CERT_WITH_EXTERN_PSK_TYPE, &[]),
        ];
        let body = body_with_extensions(&extensions(&parts));
        let (hello, negotiated) = parse(&body).unwrap();

        assert_eq!(hello.legacy_version, 0x0303);
        assert_eq!(hello.cipher_suite, 0x1301);
        assert_eq!(negotiated.selected_psk, Some(7));
        let key_share = negotiated.key_share.unwrap();
        assert_eq!(key_share.group, 0x001d);
        assert_eq!(key_share.key_exchange, hex::decode(KEY_EXCHANGE).unwrap());
        assert!(negotiated.cert_with_extern_psk);
        assert!(!negotiated.early_data);
    }

    #[test]
    fn validates_certificate_with_external_psk_companions() {
        let key_share = extension(KEY_SHARE_TYPE, &hex::decode(KEY_SHARE_BODY).unwrap());
        let psk = extension(PRE_SHARED_KEY_TYPE, &[0x00, 0x07]);
        let cert = extension(CERT_WITH_EXTERN_PSK_TYPE, &[]);
        let early_data = extension(EARLY_DATA_TYPE, &[]);
        let version = supported_versions();
        for parts in [
            vec![version.clone(), key_share.clone(), cert.clone()],
            vec![version.clone(), psk.clone(), cert.clone()],
            vec![
                version,
                key_share.clone(),
                psk.clone(),
                early_data,
                cert.clone(),
            ],
        ] {
            let body = body_with_extensions(&extensions(&parts));
            assert_eq!(parse(&body).unwrap_err(), Error::InvalidNegotiation);
        }
    }

    #[test]
    fn rejects_malformed_extensions() {
        let key_share = extension(KEY_SHARE_TYPE, &hex::decode(KEY_SHARE_BODY).unwrap());
        let psk = extension(PRE_SHARED_KEY_TYPE, &[0x00, 0x07]);
        let cert = extension(CERT_WITH_EXTERN_PSK_TYPE, &[]);
        let nonempty_cert = extension(CERT_WITH_EXTERN_PSK_TYPE, &[0x00]);
        let version = supported_versions();
        let duplicate = extensions(&[
            version.clone(),
            key_share.clone(),
            psk.clone(),
            cert.clone(),
            cert,
        ]);

        let nonempty_cert_body = body_with_extensions(&extensions(&[
            version.clone(),
            key_share,
            psk.clone(),
            nonempty_cert,
        ]));
        assert_eq!(
            parse(&nonempty_cert_body).unwrap_err(),
            Error::MalformedExtensions
        );
        assert_eq!(
            parse(&body_with_extensions(&duplicate)).unwrap_err(),
            Error::DuplicateExtension
        );

        let rfc = rfc8448_body();
        // The declared extensions length outlives the truncated body.
        assert_eq!(
            parse(&rfc[..FIXED_HEADER_LEN + 1]).unwrap_err(),
            Error::TruncatedBody
        );
        let mut trailing = rfc;
        trailing.push(0);
        assert_eq!(parse(&trailing).unwrap_err(), Error::TrailingBytes);

        let bad_key_share = extension(KEY_SHARE_TYPE, &[0x00, 0x1d, 0x00, 0x20, 0x00]);
        assert_eq!(
            parse(&body_with_extensions(&extensions(&[
                version.clone(),
                bad_key_share
            ])))
            .unwrap_err(),
            Error::InvalidKeyShare
        );
        let empty_key_share = extension(KEY_SHARE_TYPE, &[0x00, 0x1d, 0x00, 0x00]);
        assert_eq!(
            parse(&body_with_extensions(&extensions(&[
                version.clone(),
                empty_key_share
            ])))
            .unwrap_err(),
            Error::InvalidKeyShare
        );
        assert_eq!(
            parse(&body_with_extensions(&[])).unwrap_err(),
            Error::MalformedExtensions
        );
        assert_eq!(
            parse(&body_with_extensions(&extensions(&[
                extension(KEY_SHARE_TYPE, &hex::decode(KEY_SHARE_BODY).unwrap()),
                psk
            ])))
            .unwrap_err(),
            Error::InvalidSupportedVersions
        );
    }

    #[test]
    fn rejects_invalid_legacy_fields_and_selected_identity() {
        let mut body = rfc8448_body();
        body[1] = 0x01;
        assert_eq!(parse(&body).unwrap_err(), Error::InvalidLegacyFields);

        let mut body = rfc8448_body();
        body[FIXED_HEADER_LEN - 1] = 1;
        assert_eq!(parse(&body).unwrap_err(), Error::InvalidLegacyFields);

        let body = body_with_extensions(&extensions(&[
            extension(PRE_SHARED_KEY_TYPE, &[0x00]),
            supported_versions(),
        ]));
        assert_eq!(parse(&body).unwrap_err(), Error::InvalidSelectedIdentity);

        for (length, accepted) in [(32, true), (33, false), (255, false)] {
            let mut session = rfc8448_body()[..FIXED_HEADER_LEN - 1 - 2 - 1].to_vec();
            session.push(u8::try_from(length).unwrap());
            session.extend(vec![0; length]);
            session.extend_from_slice(&rfc8448_body()[FIXED_HEADER_LEN - 3..]);
            let result = parse(&session);
            assert_eq!(result.is_ok(), accepted, "session id length {length}");
            if !accepted {
                assert_eq!(result.unwrap_err(), Error::InvalidLegacyFields);
            }
        }
    }
}
