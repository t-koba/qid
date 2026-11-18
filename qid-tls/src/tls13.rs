//! TLS 1.3 protected-record reading and writing for `TLS_AES_128_GCM_SHA256`.

pub mod external_psk;
pub mod key_schedule;
pub mod psk_extension;
pub mod server_hello;
pub mod transcript;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Tag};
use hkdf::{Hkdf, InvalidLength};
use sha2::Sha256;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

const HEADER_LEN: usize = 5;
const TAG_LEN: usize = 16;
// RFC 8446 §§5.1, 5.2, and 5.4: fragment, ciphertext, and padded plaintext limits.
const MAX_CIPHERTEXT: usize = (1 << 14) + 256;
const MAX_INNER_PLAINTEXT: usize = (1 << 14) + 1;
const ALERT: u8 = 0x15;
const HANDSHAKE: u8 = 0x16;
const APPLICATION_DATA: u8 = 0x17;

type RecordKey = Zeroizing<[u8; 16]>;
type RecordIv = [u8; 12];

/// Failure to initialize an epoch or protect or open a protected record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordError {
    KeyDerivation,
    EpochClosed,
    InvalidCiphertext,
    AuthenticationFailed,
    InvalidInnerPlaintext,
    RecordProtectionFailed,
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::KeyDerivation => "TLS 1.3 record key derivation failed",
            Self::EpochClosed => "TLS 1.3 epoch is closed",
            Self::InvalidCiphertext => "invalid TLS 1.3 ciphertext framing",
            Self::AuthenticationFailed => "TLS 1.3 record authentication failed",
            Self::InvalidInnerPlaintext => "invalid TLS 1.3 inner plaintext",
            Self::RecordProtectionFailed => "TLS 1.3 record protection failed",
        })
    }
}

impl std::error::Error for RecordError {}

/// Authenticated record content with the inner record-type octet and padding removed.
pub struct InnerPlaintext<'a> {
    pub content_type: u8,
    pub content: &'a [u8],
}

/// Read state for one direction under one TLS 1.3 traffic secret.
///
/// The caller supplies a new traffic secret for each key change and must enforce the
/// cipher suite's usage limits (RFC 8446 §5.5); sequence exhaustion is not a rekey policy.
/// Epochs must be swapped only on a record boundary: messages immediately preceding a key
/// change are aligned to a record boundary (RFC 8446 §5.1), so a read epoch is never
/// changed in the middle of a record.
pub struct ReadEpoch {
    cipher: Aes128Gcm,
    iv: RecordIv,
    next_sequence: Option<u64>,
}

impl ReadEpoch {
    /// Derive the read key and IV and start at record sequence zero.
    pub fn aes_128_gcm_sha256(traffic_secret: &[u8; 32]) -> Result<Self, RecordError> {
        let (key, iv) = derive_key_iv(traffic_secret)?;
        Ok(Self {
            cipher: Aes128Gcm::new((&*key).into()),
            iv,
            next_sequence: Some(0),
        })
    }

    /// Authenticate and decrypt exactly one complete TLSCiphertext in place.
    ///
    /// Any error closes the epoch and zeros the entire supplied buffer. After the
    /// last representable sequence number, subsequent opens also fail and zero the buffer.
    pub fn open<'a>(&mut self, record: &'a mut [u8]) -> Result<InnerPlaintext<'a>, RecordError> {
        // A sequence is restored only on success, so every error is terminal.
        let result = self
            .next_sequence
            .take()
            .ok_or(RecordError::EpochClosed)
            .and_then(|sequence| {
                let (content_type, content_len) = self.authenticate(record, sequence)?;
                self.next_sequence = sequence.checked_add(1);
                Ok((content_type, content_len))
            });
        match result {
            Ok((content_type, content_len)) => Ok(InnerPlaintext {
                content_type,
                content: &record[HEADER_LEN..][..content_len],
            }),
            Err(error) => {
                record.zeroize();
                Err(error)
            }
        }
    }

    fn authenticate(&self, record: &mut [u8], sequence: u64) -> Result<(u8, usize), RecordError> {
        let (header, encrypted) = record
            .split_at_mut_checked(HEADER_LEN)
            .ok_or(RecordError::InvalidCiphertext)?;
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if header[..3] != [APPLICATION_DATA, 0x03, 0x03]
            || length != encrypted.len()
            || !(TAG_LEN + 1..=MAX_CIPHERTEXT).contains(&length)
        {
            return Err(RecordError::InvalidCiphertext);
        }

        let mut nonce = self.iv;
        for (octet, seq_octet) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
            *octet ^= seq_octet;
        }
        let (plaintext, tag) = encrypted.split_at_mut(length - TAG_LEN);
        self.cipher
            .decrypt_in_place_detached((&nonce).into(), header, plaintext, Tag::from_slice(tag))
            .map_err(|_| RecordError::AuthenticationFailed)?;

        if plaintext.len() > MAX_INNER_PLAINTEXT {
            return Err(RecordError::InvalidInnerPlaintext);
        }
        let type_index = plaintext
            .iter()
            .rposition(|&octet| octet != 0)
            .ok_or(RecordError::InvalidInnerPlaintext)?;
        let content_type = plaintext[type_index];
        match content_type {
            APPLICATION_DATA => Ok((content_type, type_index)),
            ALERT | HANDSHAKE if type_index != 0 => Ok((content_type, type_index)),
            _ => Err(RecordError::InvalidInnerPlaintext),
        }
    }
}

/// Write state for one direction under one TLS 1.3 traffic secret.
///
/// Like [`ReadEpoch`], this epoch is valid only for one key installation. The
/// caller replaces it at a key change (RFC 8446 §5.1) and enforces the cipher
/// suite's usage limits (RFC 8446 §5.5); sequence exhaustion merely closes the
/// epoch rather than wrapping the nonce.
pub struct WriteEpoch {
    cipher: Aes128Gcm,
    iv: RecordIv,
    next_sequence: Option<u64>,
}

impl WriteEpoch {
    /// Derive the write key and IV and start at record sequence zero.
    pub fn aes_128_gcm_sha256(traffic_secret: &[u8; 32]) -> Result<Self, RecordError> {
        let (key, iv) = derive_key_iv(traffic_secret)?;
        Ok(Self {
            cipher: Aes128Gcm::new((&*key).into()),
            iv,
            next_sequence: Some(0),
        })
    }

    /// Protect one inner plaintext and append a complete TLSCiphertext to `out`.
    ///
    /// The outer header is always `APPLICATION_DATA || 0x03 0x03 || length`
    /// (RFC 8446 §5.2); the inner content type is appended to the content with
    /// no padding. Only record types permitted by RFC 8446 §5.1 are accepted,
    /// and ALERT and HANDSHAKE must carry content. Once a sequence is taken,
    /// any failure closes the epoch so the same nonce is never reused.
    pub fn protect(
        &mut self,
        content_type: u8,
        content: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), RecordError> {
        match content_type {
            APPLICATION_DATA => {}
            ALERT | HANDSHAKE if !content.is_empty() => {}
            _ => return Err(RecordError::InvalidInnerPlaintext),
        }
        // The inner type octet is part of the plaintext (RFC 8446 §5.1).
        if content.len() >= MAX_INNER_PLAINTEXT {
            return Err(RecordError::InvalidInnerPlaintext);
        }
        let sequence = self.next_sequence.take().ok_or(RecordError::EpochClosed)?;
        let length = u16::try_from(content.len() + 1 + TAG_LEN)
            .map_err(|_| RecordError::InvalidInnerPlaintext)?;
        let [msb, lsb] = length.to_be_bytes();
        let header = [APPLICATION_DATA, 0x03, 0x03, msb, lsb];

        let mut inner = Zeroizing::new(Vec::with_capacity(content.len() + 1));
        inner.extend_from_slice(content);
        inner.push(content_type);
        let mut nonce = self.iv;
        for (octet, seq_octet) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
            *octet ^= seq_octet;
        }
        let tag = self
            .cipher
            .encrypt_in_place_detached((&nonce).into(), &header, &mut inner)
            .map_err(|_| RecordError::RecordProtectionFailed)?;
        self.next_sequence = sequence.checked_add(1);

        out.extend_from_slice(&header);
        out.extend_from_slice(&inner);
        out.extend_from_slice(&tag);
        Ok(())
    }
}

fn derive_key_iv(traffic_secret: &[u8; 32]) -> Result<(RecordKey, RecordIv), RecordError> {
    let hkdf = Hkdf::<Sha256>::from_prk(traffic_secret).map_err(|_| RecordError::KeyDerivation)?;
    let mut key = RecordKey::default();
    let mut iv = RecordIv::default();
    expand_label(&hkdf, b"key", b"", key.as_mut()).map_err(|_| RecordError::KeyDerivation)?;
    expand_label(&hkdf, b"iv", b"", &mut iv).map_err(|_| RecordError::KeyDerivation)?;
    Ok((key, iv))
}

// RFC 8446 §7.1: the single HKDF-Expand-Label encoder for this crate.
pub(crate) fn expand_label(
    hkdf: &Hkdf<Sha256>,
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), InvalidLength> {
    const PREFIX: &[u8] = b"tls13 ";
    let length = u16::try_from(out.len()).map_err(|_| InvalidLength)?;
    let label_len = u8::try_from(PREFIX.len() + label.len()).map_err(|_| InvalidLength)?;
    let context_len = u8::try_from(context.len()).map_err(|_| InvalidLength)?;
    hkdf.expand_multi_info(
        &[
            &length.to_be_bytes(),
            &[label_len],
            PREFIX,
            label,
            &[context_len],
            context,
        ],
        out,
    )
}

#[cfg(test)]
mod tests;
