//! Strict, bounded parsing of Kerberos keytab version 2 files.
//!
//! This module is deliberately independent of any Kerberos implementation:
//! it names the RFC encryption types and extracts service keys, while key
//! derivation, replay handling and acceptor behaviour belong elsewhere.
//! The size cap is a defensive read bound, not a protocol limit.

use std::{
    fmt,
    fs::File,
    io::{Read, Take},
    path::Path,
};

use zeroize::Zeroizing;

/// Defensive bound on keytab input; it is not a Kerberos protocol limit.
pub const MAX_KEYTAB_BYTES: usize = 1024 * 1024;

/// Kerberos encryption types accepted by this strict keytab parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeytabEnctype {
    /// `aes128-cts-hmac-sha1-96` (RFC 3962).
    Aes128CtsHmacSha196,
    /// `aes256-cts-hmac-sha1-96` (RFC 3962).
    Aes256CtsHmacSha196,
    /// `aes128-cts-hmac-sha256-128` (RFC 8009).
    Aes128CtsHmacSha256128,
    /// `aes256-cts-hmac-sha384-192` (RFC 8009).
    Aes256CtsHmacSha384192,
}

impl KeytabEnctype {
    /// The enctype number used on the wire and in keytabs (RFC 3961 §8).
    pub fn rfc_number(self) -> i32 {
        match self {
            Self::Aes128CtsHmacSha196 => 17,
            Self::Aes256CtsHmacSha196 => 18,
            Self::Aes128CtsHmacSha256128 => 19,
            Self::Aes256CtsHmacSha384192 => 20,
        }
    }

    /// The exact key length required for this enctype in a keytab.
    pub fn expected_key_len(self) -> usize {
        match self {
            Self::Aes128CtsHmacSha196 | Self::Aes128CtsHmacSha256128 => 16,
            Self::Aes256CtsHmacSha196 | Self::Aes256CtsHmacSha384192 => 32,
        }
    }

    fn from_number(number: i32) -> Option<Self> {
        match number {
            17 => Some(Self::Aes128CtsHmacSha196),
            18 => Some(Self::Aes256CtsHmacSha196),
            19 => Some(Self::Aes128CtsHmacSha256128),
            20 => Some(Self::Aes256CtsHmacSha384192),
            _ => None,
        }
    }
}

/// A service key extracted from a validated keytab record.
pub struct KeytabServiceKey {
    /// Principal components joined by `/`, without the realm.
    pub principal: String,
    /// Principal realm.
    pub realm: String,
    /// Key version number.
    pub kvno: u32,
    /// Encryption type of `key`.
    pub enctype: KeytabEnctype,
    key: Zeroizing<Vec<u8>>,
}

impl KeytabServiceKey {
    /// The raw key bytes. Avoid copying them into diagnosable values.
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

impl fmt::Debug for KeytabServiceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeytabServiceKey")
            .field("principal", &self.principal)
            .field("realm", &self.realm)
            .field("kvno", &self.kvno)
            .field("enctype", &self.enctype)
            .finish_non_exhaustive()
    }
}

/// A fully validated set of keytab service keys.
pub struct StrictKeytab {
    keys: Vec<KeytabServiceKey>,
}

impl StrictKeytab {
    /// The validated service keys, in keytab order.
    pub fn keys(&self) -> &[KeytabServiceKey] {
        &self.keys
    }
}

impl fmt::Debug for StrictKeytab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StrictKeytab")
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

/// Path-free and detail-free keytab failures, safe to log or return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeytabError {
    /// The file could not be opened or read.
    Unavailable,
    /// The input exceeds the defensive size bound.
    TooLarge,
    /// The file is not a version 2 keytab.
    UnsupportedVersion,
    /// The framing or a record is malformed.
    Malformed,
    /// No usable service keys were found.
    NoKeys,
}

impl fmt::Display for KeytabError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Unavailable => "keytab unavailable",
            Self::TooLarge => "keytab exceeds bound",
            Self::UnsupportedVersion => "unsupported keytab version",
            Self::Malformed => "malformed keytab",
            Self::NoKeys => "keytab has no usable service keys",
        };
        f.write_str(message)
    }
}

impl std::error::Error for KeytabError {}

/// Parse a version 2 keytab from memory with strict, bounded validation.
pub fn parse_keytab(input: &[u8]) -> Result<StrictKeytab, KeytabError> {
    if input.len() > MAX_KEYTAB_BYTES {
        return Err(KeytabError::TooLarge);
    }
    if input.len() < 2 || input[0] != 0x05 || input[1] != 0x02 {
        return Err(KeytabError::UnsupportedVersion);
    }

    let mut cursor = Cursor::new(input, 2);
    let mut keys = Vec::new();
    while cursor.remaining() != 0 {
        let record_size = cursor.i32()?;
        if record_size == 0 {
            return Err(KeytabError::Malformed);
        }
        if record_size < 0 {
            let hole_size =
                usize::try_from(record_size.unsigned_abs()).map_err(|_| KeytabError::Malformed)?;
            cursor.take(hole_size)?;
            continue;
        }

        let record_size = usize::try_from(record_size).map_err(|_| KeytabError::Malformed)?;
        let record = cursor.take(record_size)?;
        keys.push(parse_entry(record)?);
    }
    if keys.is_empty() {
        return Err(KeytabError::NoKeys);
    }

    Ok(StrictKeytab { keys })
}

/// Read and parse a keytab file without exposing its path in any error.
pub fn load_keytab(path: &Path) -> Result<StrictKeytab, KeytabError> {
    let file = File::open(path).map_err(|_| KeytabError::Unavailable)?;
    let mut bytes = Zeroizing::new(Vec::new());
    let mut limited: Take<File> = file.take((MAX_KEYTAB_BYTES as u64) + 1);
    limited
        .read_to_end(&mut bytes)
        .map_err(|_| KeytabError::Unavailable)?;
    parse_keytab(&bytes)
}

fn parse_entry(input: &[u8]) -> Result<KeytabServiceKey, KeytabError> {
    let mut cursor = Cursor::new(input, 0);
    let component_count = usize::from(cursor.u16()?);
    if component_count == 0 || component_count > cursor.remaining() / 3 {
        return Err(KeytabError::Malformed);
    }

    let realm = cursor.string()?;
    if realm.contains('@') {
        return Err(KeytabError::Malformed);
    }
    let mut principal = String::new();
    for index in 0..component_count {
        let component = cursor.string()?;
        if component.contains('/') || component.contains('@') {
            return Err(KeytabError::Malformed);
        }
        if index != 0 {
            principal.push('/');
        }
        principal.push_str(component);
    }

    // The name type and timestamp are not used here, but both fields must be
    // present and structurally complete.
    let _name_type = cursor.u32()?;
    let _timestamp = cursor.u32()?;
    let kvno8 = u32::from(cursor.u8()?);
    let enctype_number = i32::from(cursor.u16()?);
    let enctype = KeytabEnctype::from_number(enctype_number).ok_or(KeytabError::Malformed)?;
    let key_len = usize::from(cursor.u16()?);
    if key_len != enctype.expected_key_len() {
        return Err(KeytabError::Malformed);
    }
    let key = Zeroizing::new(cursor.take(key_len)?.to_vec());
    let kvno = match cursor.remaining() {
        0 => kvno8,
        4 => match cursor.u32()? {
            0 => kvno8,
            value => value,
        },
        _ => return Err(KeytabError::Malformed),
    };
    if cursor.remaining() != 0 {
        return Err(KeytabError::Malformed);
    }

    Ok(KeytabServiceKey {
        principal,
        realm: realm.to_owned(),
        kvno,
        enctype,
        key,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], offset: usize) -> Self {
        Self { bytes, offset }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], KeytabError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(KeytabError::Malformed)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(KeytabError::Malformed)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, KeytabError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, KeytabError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, KeytabError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn i32(&mut self) -> Result<i32, KeytabError> {
        let bytes = self.take(4)?;
        Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn string(&mut self) -> Result<&'a str, KeytabError> {
        let length = usize::from(self.u16()?);
        let value = std::str::from_utf8(self.take(length)?).map_err(|_| KeytabError::Malformed)?;
        if value.is_empty() || value.contains('\0') {
            return Err(KeytabError::Malformed);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_KEYTAB_BYTES, parse_keytab};
    use krb5::{
        Keytab,
        acceptor::{EncType, ServiceKey},
    };

    const TEST_KEY: [u8; 16] = [0x5a; 16];

    fn valid_keytab() -> Vec<u8> {
        let mut keytab = Keytab::new();
        keytab.add(ServiceKey::new(
            "HTTP/acceptor.qid.test",
            "QID.MIT.TEST",
            5,
            EncType::AES128CtsHmacSha196,
            TEST_KEY.to_vec(),
        ));
        keytab.to_bytes()
    }

    fn enctype_offset(bytes: &[u8]) -> Option<usize> {
        let mut offset = 6usize;
        let component_count = usize::from(u16::from_be_bytes([
            *bytes.get(offset)?,
            *bytes.get(offset + 1)?,
        ]));
        offset = offset.checked_add(2)?;
        let realm_len = usize::from(u16::from_be_bytes([
            *bytes.get(offset)?,
            *bytes.get(offset + 1)?,
        ]));
        offset = offset.checked_add(2)?.checked_add(realm_len)?;
        for _ in 0..component_count {
            let component_len = usize::from(u16::from_be_bytes([
                *bytes.get(offset)?,
                *bytes.get(offset + 1)?,
            ]));
            offset = offset.checked_add(2)?.checked_add(component_len)?;
        }
        offset.checked_add(8 + 1)
    }

    #[test]
    fn parses_valid_entries_and_skips_a_bounded_hole() {
        let valid = valid_keytab();
        let parsed = parse_keytab(&valid).unwrap_or_else(|_| panic!("valid fixture rejected"));
        assert_eq!(parsed.keys().len(), 1);
        let key = &parsed.keys()[0];
        assert_eq!(key.principal, "HTTP/acceptor.qid.test");
        assert_eq!(key.realm, "QID.MIT.TEST");
        assert_eq!(key.kvno, 5);
        assert_eq!(key.enctype.rfc_number(), 17);
        assert_eq!(key.key(), TEST_KEY);

        let mut with_hole = vec![0x05, 0x02, 0xff, 0xff, 0xff, 0xff, 0xaa];
        with_hole.extend_from_slice(&valid[2..]);
        let parsed = parse_keytab(&with_hole).unwrap_or_else(|_| panic!("valid hole rejected"));
        assert_eq!(parsed.keys().len(), 1);
    }

    #[test]
    fn rejects_truncation_overflow_and_malformed_entries() {
        let valid = valid_keytab();
        for end in 0..valid.len() {
            assert!(
                parse_keytab(&valid[..end]).is_err(),
                "accepted truncated length {end}"
            );
        }

        let mut min_hole = vec![0x05, 0x02];
        min_hole.extend_from_slice(&i32::MIN.to_be_bytes());
        assert!(parse_keytab(&min_hole).is_err());

        let mut oversized_record = vec![0x05, 0x02];
        oversized_record.extend_from_slice(&i32::MAX.to_be_bytes());
        assert!(parse_keytab(&oversized_record).is_err());

        let mut empty_record = vec![0x05, 0x02, 0, 0, 0, 0];
        assert!(parse_keytab(&empty_record).is_err());
        empty_record[5] = 1;
        assert!(parse_keytab(&empty_record).is_err());

        assert!(parse_keytab(&[0x05, 0x02]).is_err());

        let mut bad_version = valid.clone();
        bad_version[1] = 1;
        assert!(parse_keytab(&bad_version).is_err());

        let mut bad_utf8 = valid.clone();
        bad_utf8[10] = 0xff;
        assert!(parse_keytab(&bad_utf8).is_err());

        let mut unknown_enctype = valid.clone();
        let enctype = enctype_offset(&unknown_enctype)
            .unwrap_or_else(|| panic!("test keytab has no enctype field"));
        unknown_enctype[enctype..enctype + 2].copy_from_slice(&999u16.to_be_bytes());
        assert!(parse_keytab(&unknown_enctype).is_err());

        let mut wrong_key_size = valid.clone();
        let enctype = enctype_offset(&wrong_key_size)
            .unwrap_or_else(|| panic!("test keytab has no enctype field"));
        wrong_key_size[enctype + 2..enctype + 4].copy_from_slice(&15u16.to_be_bytes());
        assert!(parse_keytab(&wrong_key_size).is_err());

        let mut trailing_record_byte = valid;
        trailing_record_byte.push(0);
        assert!(parse_keytab(&trailing_record_byte).is_err());

        let too_large = vec![0; MAX_KEYTAB_BYTES + 1];
        assert!(parse_keytab(&too_large).is_err());
    }

    #[test]
    fn debug_output_never_contains_key_material() {
        let parsed =
            parse_keytab(&valid_keytab()).unwrap_or_else(|_| panic!("valid fixture rejected"));
        let key = &parsed.keys()[0];
        let key_debug = format!("{key:?}");
        let keytab_debug = format!("{parsed:?}");
        let ascii_key = String::from_utf8_lossy(&TEST_KEY);
        assert!(!key_debug.contains(ascii_key.as_ref()), "{key_debug}");
        assert!(!keytab_debug.contains(ascii_key.as_ref()), "{keytab_debug}");
        assert!(!key_debug.contains("5a5a"), "{key_debug}");
        assert!(!keytab_debug.contains("5a5a"), "{keytab_debug}");
        assert!(key_debug.contains("principal"));
        assert!(keytab_debug.contains("StrictKeytab"));
    }
}
