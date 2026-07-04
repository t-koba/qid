//! Bitstring Status List (W3C vc-bitstring-status-list).
//!
//! Implements the typed entry and list primitives defined in the W3C
//! Verifiable Credentials Bitstring Status List v1.0 candidate
//! recommendation. Status entries are 1 bit, 2 bits, 4 bits, 8 bits,
//! 16 bits, 32 bits, 64 bits, or 128 bits wide; this module supports
//! the canonical 1-bit "revocation" entry and provides helpers for
//! constructing, compressing, and parsing the base64url-encoded
//! GZIP-compressed bitstring that travels with the credential.

use base64::Engine;
use flate2::Compression;
use flate2::read::{GzDecoder, GzEncoder};
use qid_core::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};
use std::io::Read;

const STATUS_PURPOSE_REVOCATION: &str = "revocation";
const STATUS_PURPOSE_SUSPENSION: &str = "suspension";
const STATUS_PURPOSE_REFRESH: &str = "refresh";

const STATUS_SET: u8 = 0x01;
const STATUS_UNSET: u8 = 0x00;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BitstringStatusListCredential {
    pub id: String,
    pub issuer: String,
    pub valid_from: Option<u64>,
    pub valid_until: Option<u64>,
    pub status_purpose: String,
    pub encoded_list: String,
    /// Base64url-encoded GZIP-compressed bitstring (statusPurpose entry).
    #[serde(default)]
    pub ttl: Option<u64>,
}

impl BitstringStatusListCredential {
    pub fn revocation_list_uri(&self) -> &str {
        &self.id
    }

    pub fn revocation_purpose(&self) -> bool {
        self.status_purpose == STATUS_PURPOSE_REVOCATION
    }
}

/// Encode a list of booleans (true = revoked) as a Bitstring Status
/// List credential payload per W3C vc-bitstring-status-list §4.1.
pub fn encode_bitstring_status_list(entries: &[bool], issuer: &str, valid_from: u64) -> String {
    let bytes: Vec<u8> = entries
        .chunks(8)
        .map(|chunk| {
            let mut byte = 0u8;
            for (idx, value) in chunk.iter().enumerate() {
                if *value {
                    byte |= 1 << (7 - idx);
                }
            }
            byte
        })
        .collect();
    // GZIP-compress the bitstring (W3C vc-bitstring-status-list §4.1)
    let mut encoder = GzEncoder::new(&bytes[..], Compression::default());
    let mut compressed = Vec::new();
    encoder
        .read_to_end(&mut compressed)
        .expect("GZIP compression succeeds");
    let credential = BitstringStatusListCredential {
        id: format!("urn:uuid:{}", ulid::Ulid::new()),
        issuer: issuer.to_string(),
        valid_from: Some(valid_from),
        valid_until: None,
        status_purpose: STATUS_PURPOSE_REVOCATION.to_string(),
        encoded_list: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&compressed),
        ttl: Some(86_400),
    };
    serde_json::to_string(&credential).expect("Bitstring Status List serializes")
}
/// Decode a Bitstring Status List entry at `index`. Returns `true`
/// when the bit is set (e.g. the credential is revoked), `false`
/// otherwise.
pub fn decode_bitstring_status_entry(encoded_list: &str, index: usize) -> QidResult<bool> {
    let compressed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_list)
        .map_err(|e| QidError::Internal {
            message: format!("Bitstring Status List base64 decode failed: {e}"),
        })?;
    // GZIP-decompress (W3C vc-bitstring-status-list §4.1)
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut bytes = Vec::new();
    decoder
        .read_to_end(&mut bytes)
        .map_err(|e| QidError::Internal {
            message: format!("Bitstring Status List GZIP decompress failed: {e}"),
        })?;
    let byte_index = index / 8;
    let bit_index = 7 - (index % 8);
    let byte = bytes
        .get(byte_index)
        .copied()
        .ok_or_else(|| QidError::Internal {
            message: format!("Bitstring Status List index {index} is out of range"),
        })?;
    Ok((byte >> bit_index) & 1 == STATUS_SET)
}

/// Set a bit in a Bitstring Status List payload. Returns the new
/// encoded base64url string.
pub fn set_bitstring_status_entry(
    encoded_list: &str,
    index: usize,
    value: bool,
) -> QidResult<String> {
    let compressed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_list)
        .map_err(|e| QidError::Internal {
            message: format!("Bitstring Status List base64 decode failed: {e}"),
        })?;
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut bytes = Vec::new();
    decoder
        .read_to_end(&mut bytes)
        .map_err(|e| QidError::Internal {
            message: format!("Bitstring Status List GZIP decompress failed: {e}"),
        })?;
    let byte_index = index / 8;
    let bit_index = 7 - (index % 8);
    if byte_index >= bytes.len() {
        return Err(QidError::Internal {
            message: format!("Bitstring Status List index {index} is out of range"),
        });
    }
    if value {
        bytes[byte_index] |= 1 << bit_index;
    } else {
        bytes[byte_index] &= !(1 << bit_index);
    }
    // Re-compress with GZIP and base64url-encode
    let mut encoder = GzEncoder::new(&bytes[..], Compression::default());
    let mut compressed_out = Vec::new();
    encoder
        .read_to_end(&mut compressed_out)
        .map_err(|e| QidError::Internal {
            message: format!("Bitstring Status List GZIP re-compress failed: {e}"),
        })?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&compressed_out))
}

/// Compute the index that should be assigned to a new credential in a
/// pre-allocated Bitstring Status List. The size of the list is
/// derived from the encoded base64url length.
pub fn next_bitstring_index(encoded_list: &str) -> QidResult<usize> {
    let compressed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_list)
        .map_err(|e| QidError::Internal {
            message: format!("Bitstring Status List base64 decode failed: {e}"),
        })?;
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut bytes = Vec::new();
    decoder
        .read_to_end(&mut bytes)
        .map_err(|e| QidError::Internal {
            message: format!("Bitstring Status List GZIP decompress failed: {e}"),
        })?;
    Ok(bytes.len() * 8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_decodes_round_trip() {
        let entries = vec![false, true, true, false, true, false, false, true, true];
        let json = encode_bitstring_status_list(&entries, "https://issuer.example", 1_700_000_000);
        let credential: BitstringStatusListCredential = serde_json::from_str(&json).unwrap();
        assert!(credential.revocation_purpose());
        for (idx, expected) in entries.iter().enumerate() {
            assert_eq!(
                decode_bitstring_status_entry(&credential.encoded_list, idx).unwrap(),
                *expected
            );
        }
    }

    #[test]
    fn set_entry_updates_bit() {
        let entries = vec![false; 16];
        let json = encode_bitstring_status_list(&entries, "https://issuer.example", 1);
        let mut credential: BitstringStatusListCredential = serde_json::from_str(&json).unwrap();
        credential.encoded_list =
            set_bitstring_status_entry(&credential.encoded_list, 3, true).unwrap();
        assert!(decode_bitstring_status_entry(&credential.encoded_list, 3).unwrap());
        credential.encoded_list =
            set_bitstring_status_entry(&credential.encoded_list, 3, false).unwrap();
        assert!(!decode_bitstring_status_entry(&credential.encoded_list, 3).unwrap());
    }
}
