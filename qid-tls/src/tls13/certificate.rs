//! Strict TLS 1.3 Certificate message parsing and raw public key checking.
//!
//! Offline framing only: this module never parses X.509 or validates a
//! signature. For TLS-POK the certificate payload is an RFC 7250 raw public
//! key (a DER `SubjectPublicKeyInfo`), checked byte-for-byte against the key
//! that produced the external PSK identity.

use std::fmt;

const U24_HEADER_LEN: usize = 3;
const EXTENSION_HEADER_LEN: usize = 4;

/// One RFC 8446 `CertificateEntry`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateEntry<'a> {
    pub cert_data: &'a [u8],
    pub extensions: &'a [u8],
}

/// A parsed Certificate message body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate<'a> {
    pub certificate_request_context: &'a [u8],
    pub entries: Vec<CertificateEntry<'a>>,
}

/// Malformed Certificate framing or a raw public key mismatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    TrailingBytes,
    EmptyCertificate,
    MalformedExtensions,
    RawPublicKeyMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "Certificate message is truncated",
            Self::TrailingBytes => "Certificate message has trailing bytes",
            Self::EmptyCertificate => "CertificateEntry cert_data is empty",
            Self::MalformedExtensions => "CertificateEntry extensions are malformed",
            Self::RawPublicKeyMismatch => "raw public key differs from the TLS-POK BSK",
        })
    }
}

impl std::error::Error for Error {}

fn take_u24(remaining: &mut &[u8]) -> Result<usize, Error> {
    if remaining.len() < U24_HEADER_LEN {
        return Err(Error::Truncated);
    }
    let bytes = &remaining[..U24_HEADER_LEN];
    *remaining = &remaining[U24_HEADER_LEN..];
    Ok(usize::from(bytes[0]) << 16 | usize::from(bytes[1]) << 8 | usize::from(bytes[2]))
}

fn take<'a>(remaining: &mut &'a [u8], len: usize) -> Result<&'a [u8], Error> {
    if remaining.len() < len {
        return Err(Error::Truncated);
    }
    let (head, tail) = remaining.split_at(len);
    *remaining = tail;
    Ok(head)
}

fn validate_extensions(mut bytes: &[u8]) -> Result<(), Error> {
    while !bytes.is_empty() {
        if bytes.len() < EXTENSION_HEADER_LEN {
            return Err(Error::MalformedExtensions);
        }
        let len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        let _ =
            take(&mut bytes, EXTENSION_HEADER_LEN + len).map_err(|_| Error::MalformedExtensions)?;
    }
    Ok(())
}

/// Parse an exact Certificate handshake body, rejecting malformed vectors.
pub fn parse(body: &[u8]) -> Result<Certificate<'_>, Error> {
    let mut reader = body;
    if reader.is_empty() {
        return Err(Error::Truncated);
    }
    let context_len = usize::from(reader[0]);
    reader = &reader[1..];
    let context = take(&mut reader, context_len)?;

    let list_len = take_u24(&mut reader)?;
    let mut list = take(&mut reader, list_len)?;
    if !reader.is_empty() {
        return Err(Error::TrailingBytes);
    }

    let mut entries = Vec::new();
    while !list.is_empty() {
        let cert_len = take_u24(&mut list)?;
        if cert_len == 0 {
            return Err(Error::EmptyCertificate);
        }
        let cert_data = take(&mut list, cert_len)?;
        if list.len() < 2 {
            return Err(Error::Truncated);
        }
        let ext_len = usize::from(u16::from_be_bytes([list[0], list[1]]));
        list = &list[2..];
        let extensions = take(&mut list, ext_len)?;
        validate_extensions(extensions)?;
        entries.push(CertificateEntry {
            cert_data,
            extensions,
        });
    }
    Ok(Certificate {
        certificate_request_context: context,
        entries,
    })
}

/// Check that a TLS-POK client Certificate carries exactly the BSK raw public
/// key used to derive the imported PSK identity, with no extensions.
pub fn parse_raw_public_key(body: &[u8], expected_spki: &[u8]) -> Result<(), Error> {
    let cert = parse(body)?;
    if !cert.certificate_request_context.is_empty()
        || cert.entries.len() != 1
        || !cert.entries[0].extensions.is_empty()
        || cert.entries[0].cert_data != expected_spki
    {
        return Err(Error::RawPublicKeyMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8448 §3 server Certificate handshake message (445 octets, including
    // its four-byte header). The certificate is X.509 here; TLS-POK uses a raw
    // public key in the same framing.
    const RFC8448_CERTIFICATE: &str = concat!(
        "0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a8648",
        "86f70d01010b0500300e310c300a06035504031303727361301e170d313630373330",
        "3031323335395a170d3236303733303031323335395a300e310c300a060355040313",
        "0372736130819f300d06092a864886f70d010101050003818d0030818902818100b4",
        "bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a",
        "91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b",
        "018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6",
        "d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a3018",
        "30090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d",
        "01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d",
        "2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a030151567260",
        "96fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb",
        "2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4d",
        "e10000",
    );
    const BSK_SPKI: &str = "3039301306072a8648ce3d020106082a8648ce3d0301070322000232f2f2a0eca48fcb052714a865fcda7ee544bccfa43580b1a440ba2884cb6fd8";

    fn raw_public_key_message(spki: &[u8]) -> Vec<u8> {
        let mut body = vec![0x00];
        let mut list = Vec::new();
        list.extend_from_slice(&(spki.len() as u32).to_be_bytes()[1..]);
        list.extend_from_slice(spki);
        list.extend_from_slice(&[0x00, 0x00]);
        body.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..]);
        body.extend(list);
        body
    }

    #[test]
    fn parses_rfc8448_server_certificate() {
        let message = hex::decode(RFC8448_CERTIFICATE).unwrap();
        assert_eq!(message.len(), 445);
        assert_eq!(message[0], 0x0b);
        assert_eq!(
            usize::from(message[1]) << 16 | usize::from(message[2]) << 8 | usize::from(message[3]),
            441
        );

        let cert = parse(&message[4..]).unwrap();
        assert!(cert.certificate_request_context.is_empty());
        assert_eq!(cert.entries.len(), 1);
        assert_eq!(cert.entries[0].cert_data.len(), 432);
        assert_eq!(&cert.entries[0].cert_data[..2], &[0x30, 0x82]);
        assert!(cert.entries[0].extensions.is_empty());
    }

    #[test]
    fn checks_tls_pok_raw_public_key() {
        let spki = hex::decode(BSK_SPKI).unwrap();
        let body = raw_public_key_message(&spki);
        assert_eq!(parse_raw_public_key(&body, &spki), Ok(()));
        assert_eq!(
            parse_raw_public_key(&body, &[0x00; 32]),
            Err(Error::RawPublicKeyMismatch)
        );
    }

    #[test]
    fn rejects_malformed_certificates() {
        let spki = hex::decode(BSK_SPKI).unwrap();
        let mut body = raw_public_key_message(&spki);
        body.push(0);
        assert_eq!(parse(&body).unwrap_err(), Error::TrailingBytes);
        assert_eq!(parse(&body[..3]).unwrap_err(), Error::Truncated);

        let mut empty = vec![0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
        empty.pop();
        assert_eq!(parse(&empty).unwrap_err(), Error::Truncated);

        let mut zero_cert = vec![0x00, 0x00, 0x00, 0x05];
        zero_cert.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(parse(&zero_cert).unwrap_err(), Error::EmptyCertificate);

        let mut bad_ext = vec![0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x01];
        bad_ext.extend_from_slice(&spki[..1]);
        bad_ext.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]);
        assert_eq!(parse(&bad_ext).unwrap_err(), Error::MalformedExtensions);
    }
}
