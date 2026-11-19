//! Strict TLS 1.3 CertificateRequest framing.
//!
//! RFC 9966 requires the TLS-POK server to request client authentication. This
//! module validates the handshake body and exposes the context that the client
//! must copy into its own Certificate message.

use std::fmt;

/// Signature scheme required from a TLS-POK client using a P-256 BSK.
pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
const SIGNATURE_ALGORITHMS: u16 = 0x000d;

/// One extension in a CertificateRequest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Extension<'a> {
    pub kind: u16,
    pub body: &'a [u8],
}

/// A parsed CertificateRequest message body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateRequest<'a> {
    pub certificate_request_context: &'a [u8],
    pub extensions: Vec<Extension<'a>>,
}

/// Malformed CertificateRequest framing or an unusable signature_algorithms list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    TrailingBytes,
    MalformedExtensions,
    DuplicateExtension,
    MissingSignatureAlgorithms,
    /// The scheme list offered by the server, retained for diagnostics.
    UnsupportedSignatureScheme(Vec<u16>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSignatureScheme(offered) => {
                f.write_str("CertificateRequest does not offer ecdsa_secp256r1_sha256 (offered:")?;
                for scheme in offered {
                    write!(f, " {scheme:04x}")?;
                }
                f.write_str(")")
            }
            other => f.write_str(match other {
                Self::Truncated => "CertificateRequest message is truncated",
                Self::TrailingBytes => "CertificateRequest message has trailing bytes",
                Self::MalformedExtensions => "CertificateRequest extensions are malformed",
                Self::DuplicateExtension => "CertificateRequest repeats an extension type",
                Self::MissingSignatureAlgorithms => "CertificateRequest omits signature_algorithms",
                Self::UnsupportedSignatureScheme(_) => unreachable!(),
            }),
        }
    }
}

impl std::error::Error for Error {}

fn signature_algorithms_allows_p256(body: &[u8]) -> bool {
    if body.len() < 4 || !body.len().is_multiple_of(2) {
        return false;
    }
    let count = usize::from(u16::from_be_bytes([body[0], body[1]]));
    if count == 0 || count * 2 + 2 != body.len() {
        return false;
    }
    body[2..]
        .chunks_exact(2)
        .any(|scheme| u16::from_be_bytes([scheme[0], scheme[1]]) == ECDSA_SECP256R1_SHA256)
}

/// The schemes named by a signature_algorithms extension, for error reports.
fn offered_signature_schemes(body: &[u8]) -> Vec<u16> {
    if body.len() < 2 {
        return Vec::new();
    }
    let count = usize::from(u16::from_be_bytes([body[0], body[1]]));
    body[2..]
        .chunks_exact(2)
        .take(count)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect()
}

/// Parse an exact CertificateRequest handshake body.
pub fn parse(body: &[u8]) -> Result<CertificateRequest<'_>, Error> {
    if body.is_empty() {
        return Err(Error::Truncated);
    }
    let context_len = usize::from(body[0]);
    if body.len() < 3 + context_len {
        return Err(Error::Truncated);
    }
    let context = &body[1..1 + context_len];
    let extensions_len = usize::from(u16::from_be_bytes([
        body[1 + context_len],
        body[2 + context_len],
    ]));
    if body.len() < 3 + context_len + extensions_len {
        return Err(Error::Truncated);
    }
    if body.len() != 3 + context_len + extensions_len {
        return Err(Error::TrailingBytes);
    }
    let mut remaining = &body[3 + context_len..];
    if extensions_len < 2 {
        return Err(Error::MalformedExtensions);
    }

    let mut extensions = Vec::new();
    let mut seen_signature_algorithms = false;
    while !remaining.is_empty() {
        if remaining.len() < 4 {
            return Err(Error::MalformedExtensions);
        }
        let kind = u16::from_be_bytes([remaining[0], remaining[1]]);
        let len = usize::from(u16::from_be_bytes([remaining[2], remaining[3]]));
        if remaining.len() < 4 + len {
            return Err(Error::MalformedExtensions);
        }
        if extensions
            .iter()
            .any(|extension: &Extension<'_>| extension.kind == kind)
        {
            return Err(Error::DuplicateExtension);
        }
        let ext_body = &remaining[4..4 + len];
        if kind == SIGNATURE_ALGORITHMS {
            seen_signature_algorithms = true;
            if !signature_algorithms_allows_p256(ext_body) {
                return Err(Error::UnsupportedSignatureScheme(
                    offered_signature_schemes(ext_body),
                ));
            }
        }
        extensions.push(Extension {
            kind,
            body: ext_body,
        });
        remaining = &remaining[4 + len..];
    }
    if !seen_signature_algorithms {
        return Err(Error::MissingSignatureAlgorithms);
    }
    Ok(CertificateRequest {
        certificate_request_context: context,
        extensions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(context: &[u8], extensions: &[u8]) -> Vec<u8> {
        let mut out = vec![context.len() as u8];
        out.extend_from_slice(context);
        out.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        out.extend_from_slice(extensions);
        out
    }

    fn signature_algorithms() -> Vec<u8> {
        let ext = vec![0x00, 0x0d, 0x00, 0x06, 0x00, 0x02, 0x04, 0x03, 0x08, 0x04];
        ext
    }

    #[test]
    fn parses_tls13_certificate_request() {
        let mut extensions = signature_algorithms();
        extensions.extend_from_slice(&[0x00, 0x2f, 0x00, 0x00]);
        let bytes = body(b"req", &extensions);
        let request = parse(&bytes).unwrap();
        assert_eq!(request.certificate_request_context, b"req");
        assert_eq!(request.extensions.len(), 2);
        assert_eq!(request.extensions[0].kind, SIGNATURE_ALGORITHMS);
        assert_eq!(request.extensions[1].kind, 0x002f);
    }

    #[test]
    fn rejects_malformed_requests() {
        assert_eq!(parse(&[]).unwrap_err(), Error::Truncated);
        let valid = signature_algorithms();
        let mut trailing = body(&[], &valid);
        trailing.push(0);
        assert_eq!(parse(&trailing).unwrap_err(), Error::TrailingBytes);
        assert_eq!(
            parse(&body(&[], &[])).unwrap_err(),
            Error::MalformedExtensions
        );
        assert_eq!(
            parse(&body(&[], &[0x00, 0x2f, 0x00, 0x00])).unwrap_err(),
            Error::MissingSignatureAlgorithms
        );
        let mut duplicate = signature_algorithms();
        duplicate.extend_from_slice(&signature_algorithms());
        assert_eq!(
            parse(&body(&[], &duplicate)).unwrap_err(),
            Error::DuplicateExtension
        );
        let mut wrong = signature_algorithms();
        wrong[6] = 0x08;
        wrong[7] = 0x04;
        assert_eq!(
            parse(&body(&[], &wrong)).unwrap_err(),
            Error::UnsupportedSignatureScheme(vec![0x0804, 0x0804])
        );
    }
}
