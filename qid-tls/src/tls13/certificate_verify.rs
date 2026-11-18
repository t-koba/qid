//! Strict TLS 1.3 CertificateVerify framing and signature-input construction.
//!
//! Signature verification belongs to the cryptography layer; this module only
//! checks wire framing and builds the RFC 8446 §4.4.3 signed byte string.

use std::fmt;

/// Signature scheme identifying the algorithm used by a CertificateVerify.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureScheme(pub u16);

impl SignatureScheme {
    pub const RSA_PSS_RSAE_SHA256: Self = Self(0x0804);
    pub const ECDSA_SECP256R1_SHA256: Self = Self(0x0403);
    pub const ECDSA_SECP384R1_SHA384: Self = Self(0x0503);
    pub const ECDSA_SECP521R1_SHA512: Self = Self(0x0603);
    pub const ED25519: Self = Self(0x0807);
    pub const ED448: Self = Self(0x0808);
}

/// Which side produced a CertificateVerify message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateVerifySender {
    Client,
    Server,
}

/// A parsed CertificateVerify message body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateVerify<'a> {
    pub algorithm: SignatureScheme,
    pub signature: &'a [u8],
}

/// Malformed CertificateVerify framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    EmptySignature,
    TrailingBytes,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "CertificateVerify message is truncated",
            Self::EmptySignature => "CertificateVerify signature is empty",
            Self::TrailingBytes => "CertificateVerify message has trailing bytes",
        })
    }
}

impl std::error::Error for Error {}

/// Parse an exact CertificateVerify handshake body.
pub fn parse(body: &[u8]) -> Result<CertificateVerify<'_>, Error> {
    if body.len() < 4 {
        return Err(Error::Truncated);
    }
    let algorithm = SignatureScheme(u16::from_be_bytes([body[0], body[1]]));
    let signature_len = usize::from(u16::from_be_bytes([body[2], body[3]]));
    if signature_len == 0 {
        return Err(Error::EmptySignature);
    }
    if body.len() < 4 + signature_len {
        return Err(Error::Truncated);
    }
    if body.len() > 4 + signature_len {
        return Err(Error::TrailingBytes);
    }
    Ok(CertificateVerify {
        algorithm,
        signature: &body[4..],
    })
}

/// Build the RFC 8446 §4.4.3 byte string signed by a CertificateVerify.
pub fn signed_content(sender: CertificateVerifySender, transcript_hash: &[u8; 32]) -> Vec<u8> {
    let context = match sender {
        CertificateVerifySender::Client => b"TLS 1.3, client CertificateVerify",
        CertificateVerifySender::Server => b"TLS 1.3, server CertificateVerify",
    };
    let mut out = Vec::with_capacity(64 + 1 + context.len() + 1 + transcript_hash.len());
    out.extend_from_slice(&[0x20; 64]);
    out.extend_from_slice(context);
    out.push(0x00);
    out.extend_from_slice(transcript_hash);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8448 §3 server CertificateVerify handshake message (136 octets).
    const RFC8448_CERTIFICATE_VERIFY: &str = concat!(
        "0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff",
        "52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4",
        "f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c9ea58c181e81",
        "8e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3"
    );

    #[test]
    fn parses_rfc8448_server_certificate_verify() {
        let message = hex::decode(RFC8448_CERTIFICATE_VERIFY).unwrap();
        assert_eq!(message.len(), 136);
        assert_eq!(message[0], 0x0f);
        assert_eq!(
            usize::from(message[1]) << 16 | usize::from(message[2]) << 8 | usize::from(message[3]),
            132
        );

        let parsed = parse(&message[4..]).unwrap();
        assert_eq!(parsed.algorithm, SignatureScheme::RSA_PSS_RSAE_SHA256);
        assert_eq!(parsed.signature.len(), 128);
        assert_eq!(&parsed.signature[..4], &[0x5a, 0x74, 0x7c, 0x5d]);
    }

    #[test]
    fn builds_signed_content() {
        let hash = [0xa5; 32];
        let client = signed_content(CertificateVerifySender::Client, &hash);
        assert_eq!(client.len(), 64 + 33 + 1 + 32);
        assert!(client[..64].iter().all(|byte| *byte == 0x20));
        assert_eq!(&client[64..97], b"TLS 1.3, client CertificateVerify");
        assert_eq!(client[97], 0);
        assert_eq!(&client[98..], &hash);

        let server = signed_content(CertificateVerifySender::Server, &hash);
        assert_eq!(&server[64..97], b"TLS 1.3, server CertificateVerify");
    }

    #[test]
    fn rejects_malformed_certificate_verify() {
        assert_eq!(parse(&[]).unwrap_err(), Error::Truncated);
        assert_eq!(
            parse(&[0x04, 0x03, 0x00, 0x00]).unwrap_err(),
            Error::EmptySignature
        );
        let short_signature = vec![0x04, 0x03, 0x00, 0x05, 0x42, 0x43];
        assert_eq!(parse(&short_signature).unwrap_err(), Error::Truncated);
        let trailing = vec![0x04, 0x03, 0x00, 0x01, 0x42, 0x00];
        assert_eq!(parse(&trailing).unwrap_err(), Error::TrailingBytes);
    }
}
