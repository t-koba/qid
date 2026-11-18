//! Strict TLS 1.3 EncryptedExtensions parsing.
//!
//! Offline parsing only: the caller supplies the handshake body, the extension
//! types offered in its ClientHello, and whether RFC 9973
//! `tls_cert_with_extern_psk` was negotiated in the ServerHello.

use super::psk_extension::{
    CERT_WITH_EXTERN_PSK_TYPE, EARLY_DATA_TYPE, PRE_SHARED_KEY_TYPE, PSK_KEY_EXCHANGE_MODES_TYPE,
};
use std::fmt;

const KEY_SHARE_TYPE: u16 = 0x0033;
const SUPPORTED_VERSIONS_TYPE: u16 = 0x002b;
const COOKIE_TYPE: u16 = 0x002c;

/// A well-formed EncryptedExtensions response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Extension<'a> {
    pub kind: u16,
    pub body: &'a [u8],
}

/// Parameters from the surrounding handshake needed to validate responses.
#[derive(Clone, Copy, Debug)]
pub struct ParseParams<'a> {
    pub offered_extensions: &'a [u16],
    pub cert_with_extern_psk: bool,
}

/// Malformed framing or a forbidden/unrequested extension response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Malformed,
    DuplicateExtension,
    ForbiddenExtension,
    UnrequestedExtension,
    EarlyDataWithCertificatePsk,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "EncryptedExtensions framing is malformed",
            Self::DuplicateExtension => "EncryptedExtensions repeats an extension type",
            Self::ForbiddenExtension => "extension is forbidden in EncryptedExtensions",
            Self::UnrequestedExtension => "extension was not offered in the ClientHello",
            Self::EarlyDataWithCertificatePsk => "early_data conflicts with certificate plus PSK",
        })
    }
}

impl std::error::Error for Error {}

fn is_ch_sh_only(kind: u16) -> bool {
    matches!(
        kind,
        CERT_WITH_EXTERN_PSK_TYPE
            | PRE_SHARED_KEY_TYPE
            | SUPPORTED_VERSIONS_TYPE
            | KEY_SHARE_TYPE
            | PSK_KEY_EXCHANGE_MODES_TYPE
            | COOKIE_TYPE
    )
}

/// Parse an EncryptedExtensions handshake body and validate its responses.
pub fn parse<'a>(body: &'a [u8], params: ParseParams<'_>) -> Result<Vec<Extension<'a>>, Error> {
    if body.len() < 2 {
        return Err(Error::Malformed);
    }
    let extensions_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
    let mut remaining = &body[2..];
    if remaining.len() != extensions_len {
        return Err(Error::Malformed);
    }

    let mut out = Vec::new();
    while !remaining.is_empty() {
        if remaining.len() < 4 {
            return Err(Error::Malformed);
        }
        let kind = u16::from_be_bytes([remaining[0], remaining[1]]);
        let body_len = usize::from(u16::from_be_bytes([remaining[2], remaining[3]]));
        if remaining.len() < 4 + body_len {
            return Err(Error::Malformed);
        }
        let ext_body = &remaining[4..4 + body_len];
        remaining = &remaining[4 + body_len..];

        if out.iter().any(|ext: &Extension<'_>| ext.kind == kind) {
            return Err(Error::DuplicateExtension);
        }
        if is_ch_sh_only(kind) {
            return Err(Error::ForbiddenExtension);
        }
        if kind == EARLY_DATA_TYPE && params.cert_with_extern_psk {
            return Err(Error::EarlyDataWithCertificatePsk);
        }
        if !params.offered_extensions.contains(&kind) {
            return Err(Error::UnrequestedExtension);
        }
        if kind == EARLY_DATA_TYPE && !ext_body.is_empty() {
            return Err(Error::Malformed);
        }
        out.push(Extension {
            kind,
            body: ext_body,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut wire = kind.to_be_bytes().to_vec();
        wire.extend_from_slice(&(body.len() as u16).to_be_bytes());
        wire.extend_from_slice(body);
        wire
    }

    fn body(parts: &[Vec<u8>]) -> Vec<u8> {
        let extensions: Vec<u8> = parts.iter().flatten().copied().collect();
        let mut wire = (extensions.len() as u16).to_be_bytes().to_vec();
        wire.extend(extensions);
        wire
    }

    fn params(offered: &[u16], cert: bool) -> ParseParams<'_> {
        ParseParams {
            offered_extensions: offered,
            cert_with_extern_psk: cert,
        }
    }

    #[test]
    fn accepts_empty_and_offered_extensions() {
        assert!(parse(&body(&[]), params(&[], false)).unwrap().is_empty());
        let wire = body(&[
            extension(0x000a, &[0x00, 0x02, 0x00, 0x1d]),
            extension(0x0010, &[0x00, 0x03, b'h', b'2', b'3']),
        ]);
        let parsed = parse(&wire, params(&[0x000a, 0x0010], false)).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].kind, 0x000a);
        assert_eq!(parsed[1].body, &[0x00, 0x03, b'h', b'2', b'3']);
    }

    #[test]
    fn rejects_certificate_psk_and_other_ch_sh_only_extensions() {
        let wire = body(&[extension(CERT_WITH_EXTERN_PSK_TYPE, &[])]);
        assert_eq!(
            parse(&wire, params(&[CERT_WITH_EXTERN_PSK_TYPE], true)).unwrap_err(),
            Error::ForbiddenExtension
        );
        for kind in [
            PRE_SHARED_KEY_TYPE,
            SUPPORTED_VERSIONS_TYPE,
            KEY_SHARE_TYPE,
            PSK_KEY_EXCHANGE_MODES_TYPE,
            COOKIE_TYPE,
        ] {
            let wire = body(&[extension(kind, &[])]);
            assert_eq!(
                parse(&wire, params(&[kind], false)).unwrap_err(),
                Error::ForbiddenExtension
            );
        }
    }

    #[test]
    fn rejects_conflicting_and_unrequested_responses() {
        let early = extension(EARLY_DATA_TYPE, &[]);
        assert_eq!(
            parse(
                &body(std::slice::from_ref(&early)),
                params(&[EARLY_DATA_TYPE], true)
            )
            .unwrap_err(),
            Error::EarlyDataWithCertificatePsk
        );
        assert_eq!(
            parse(
                &body(&[extension(EARLY_DATA_TYPE, &[0x00])]),
                params(&[EARLY_DATA_TYPE], false)
            )
            .unwrap_err(),
            Error::Malformed
        );
        assert_eq!(
            parse(&body(&[early]), params(&[], false)).unwrap_err(),
            Error::UnrequestedExtension
        );
    }

    #[test]
    fn rejects_duplicates_and_bad_framing() {
        let alpn = extension(0x0010, &[]);
        assert_eq!(
            parse(&body(&[alpn.clone(), alpn]), params(&[0x0010], false)).unwrap_err(),
            Error::DuplicateExtension
        );
        assert_eq!(
            parse(&[], params(&[], false)).unwrap_err(),
            Error::Malformed
        );
        let mut wrong_len = body(&[extension(0x0010, &[])]);
        wrong_len[1] += 1;
        assert_eq!(
            parse(&wrong_len, params(&[0x0010], false)).unwrap_err(),
            Error::Malformed
        );
        let mut trailing = body(&[extension(0x0010, &[])]);
        trailing.push(0);
        assert_eq!(
            parse(&trailing, params(&[0x0010], false)).unwrap_err(),
            Error::Malformed
        );
        let short = vec![0x00, 0x04, 0x00, 0x10];
        assert_eq!(
            parse(&short, params(&[0x0010], false)).unwrap_err(),
            Error::Malformed
        );
    }
}
