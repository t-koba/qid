//! Strict TLS 1.3 handshake-message framing and transcript hashing.
//!
//! These are offline byte computations for RFC 8446 §§4.4.1 and 5.4: one
//! message is `msg_type || 3-byte length || body`, and a transcript is the
//! SHA-256 hash of complete encoded messages in wire order. No handshake
//! state machine, record protection or transport lives here.

use sha2::{Digest, Sha256};
use std::fmt;

/// Largest handshake body representable by the RFC 8446 three-byte length.
pub const MAX_HANDSHAKE_BODY_LEN: usize = 0x00ff_ffff;

const HEADER_LEN: usize = 4;

/// Invalid handshake-message bytes or an unencodable body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Fewer than four bytes are available for the type and length fields.
    TruncatedHeader,
    /// The declared body length exceeds the supplied bytes.
    TruncatedBody,
    /// Bytes follow one complete message where exactly one is required.
    TrailingBytes,
    /// The body does not fit the three-byte length field.
    BodyTooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TruncatedHeader => "TLS 1.3 handshake header is truncated",
            Self::TruncatedBody => "TLS 1.3 handshake body length exceeds input",
            Self::TrailingBytes => "TLS 1.3 handshake message has trailing bytes",
            Self::BodyTooLarge => "TLS 1.3 handshake body exceeds the 24-bit maximum",
        })
    }
}

impl std::error::Error for Error {}

/// One framed RFC 8446 §5.4 handshake message and its exact wire bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandshakeMessage<'a> {
    pub msg_type: u8,
    pub body: &'a [u8],
    pub encoded: &'a [u8],
}

/// Split one complete message from the front of `input`.
///
/// The returned message borrows only from `input`; any bytes after its body
/// are returned as the remainder.
pub fn split_message(input: &[u8]) -> Result<(HandshakeMessage<'_>, &[u8]), Error> {
    let (header, _) = input
        .split_at_checked(HEADER_LEN)
        .ok_or(Error::TruncatedHeader)?;
    let body_len =
        (usize::from(header[1]) << 16) | (usize::from(header[2]) << 8) | usize::from(header[3]);
    let (encoded, remaining) = input
        .split_at_checked(HEADER_LEN + body_len)
        .ok_or(Error::TruncatedBody)?;
    Ok((
        HandshakeMessage {
            msg_type: header[0],
            body: &encoded[HEADER_LEN..],
            encoded,
        },
        remaining,
    ))
}

/// Frame one message as type, 24-bit big-endian length, then body.
pub fn encode_message(msg_type: u8, body: &[u8]) -> Result<Vec<u8>, Error> {
    if body.len() > MAX_HANDSHAKE_BODY_LEN {
        return Err(Error::BodyTooLarge);
    }
    let length = u32::try_from(body.len()).map_err(|_| Error::BodyTooLarge)?;
    let [_, high, middle, low] = length.to_be_bytes();
    let mut encoded = Vec::with_capacity(HEADER_LEN + body.len());
    encoded.push(msg_type);
    encoded.extend_from_slice(&[high, middle, low]);
    encoded.extend_from_slice(body);
    Ok(encoded)
}

/// Running SHA-256 hash of a TLS 1.3 handshake transcript.
#[derive(Clone)]
pub struct Transcript {
    sha256: Sha256,
}

impl Transcript {
    /// Start the empty transcript.
    pub fn new() -> Self {
        Self {
            sha256: Sha256::new(),
        }
    }

    /// Append exactly one complete encoded message, rejecting trailing bytes.
    ///
    /// A failed update leaves the transcript unchanged.
    pub fn update(&mut self, encoded_message: &[u8]) -> Result<(), Error> {
        let (message, remaining) = split_message(encoded_message)?;
        if !remaining.is_empty() {
            return Err(Error::TrailingBytes);
        }
        self.sha256.update(message.encoded);
        Ok(())
    }

    /// Hash of all messages appended so far (RFC 8446 §4.4.1).
    pub fn hash(&self) -> [u8; 32] {
        self.sha256.clone().finalize().into()
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8448 §3: ClientHello and ServerHello from the full-handshake trace.
    const CLIENT_HELLO: &str = "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001";
    const SERVER_HELLO: &str = "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304";
    const TRANSCRIPT_HASH: &str =
        "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8";

    fn bytes(hex: &str) -> Vec<u8> {
        hex::decode(hex).unwrap()
    }

    #[test]
    fn rfc8448_transcript_through_server_hello() {
        let client_hello = bytes(CLIENT_HELLO);
        let server_hello = bytes(SERVER_HELLO);
        assert_eq!(client_hello.len(), 196);
        assert_eq!(server_hello.len(), 90);

        let concatenated = [client_hello.as_slice(), server_hello.as_slice()].concat();
        let (first, remaining) = split_message(&concatenated).unwrap();
        assert_eq!(first.encoded, client_hello);
        assert_eq!(remaining, server_hello);

        let mut transcript = Transcript::new();
        transcript.update(&client_hello).unwrap();
        transcript.update(&server_hello).unwrap();
        assert_eq!(hex::encode(transcript.hash()), TRANSCRIPT_HASH);
        assert_eq!(
            hex::encode(Transcript::default().hash()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn encoded_messages_round_trip_through_split() {
        for hex_message in [CLIENT_HELLO, SERVER_HELLO] {
            let original = bytes(hex_message);
            let (parsed, remaining) = split_message(&original).unwrap();
            assert!(remaining.is_empty());
            let encoded = encode_message(parsed.msg_type, parsed.body).unwrap();
            assert_eq!(encoded, original);
            let (reparsed, remaining) = split_message(&encoded).unwrap();
            assert!(remaining.is_empty());
            assert_eq!(reparsed, parsed);
        }
    }

    #[test]
    fn malformed_input_is_rejected_without_changing_the_hash() {
        let client_hello = bytes(CLIENT_HELLO);
        let mut transcript = Transcript::new();
        transcript.update(&client_hello).unwrap();
        let before = transcript.hash();

        assert_eq!(split_message(&[]), Err(Error::TruncatedHeader));
        assert_eq!(
            split_message(&client_hello[..3]),
            Err(Error::TruncatedHeader)
        );
        assert_eq!(
            split_message(&client_hello[..client_hello.len() - 1]),
            Err(Error::TruncatedBody)
        );

        let oversize = vec![0u8; MAX_HANDSHAKE_BODY_LEN + 1];
        assert_eq!(encode_message(0x01, &oversize), Err(Error::BodyTooLarge));

        let mut with_trailing = client_hello.clone();
        with_trailing.push(0);
        assert_eq!(transcript.update(&with_trailing), Err(Error::TrailingBytes));
        assert_eq!(transcript.update(&[]), Err(Error::TruncatedHeader));
        assert_eq!(
            transcript.update(&client_hello[..client_hello.len() - 1]),
            Err(Error::TruncatedBody)
        );
        assert_eq!(transcript.hash(), before);
    }
}
