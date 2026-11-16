//! Test-only prototype of a bounded, strict keytab-v2 loader.
//!
//! The 1 MiB input cap is a fixture bound, not a production configuration
//! policy. The pinned krb5 `Keytab` still owns ordinary `Vec<u8>` keys and
//! does not zeroize them on drop; this wrapper deliberately exposes neither
//! `Debug` nor `Clone` but cannot change that upstream ownership behavior.
use krb5::{
    Keytab,
    acceptor::{EncType, ServiceKey},
};
use std::{
    fs::File,
    io::{Read, Take},
    ops::Deref,
    path::Path,
};
use zeroize::Zeroizing;

const MAX_KEYTAB_BYTES: usize = 1024 * 1024;

/// Private owner that keeps the keytab out of public/debuggable state.
pub(super) struct KeytabOwner(Keytab);

impl Deref for KeytabOwner {
    type Target = Keytab;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Read no more than the fixture bound and never include the path in errors.
pub(super) fn load(path: &Path) -> Result<KeytabOwner, &'static str> {
    let file = File::open(path).map_err(|_| "keytab unavailable")?;
    let mut bytes = Zeroizing::new(Vec::new());
    let mut limited: Take<File> = file.take((MAX_KEYTAB_BYTES as u64) + 1);
    limited
        .read_to_end(&mut bytes)
        .map_err(|_| "keytab read failed")?;
    parse(&bytes)
}

fn parse(input: &[u8]) -> Result<KeytabOwner, &'static str> {
    if input.len() > MAX_KEYTAB_BYTES {
        return Err("keytab exceeds fixture bound");
    }
    if input.len() < 2 || input[0] != 0x05 || input[1] != 0x02 {
        return Err("unsupported keytab version");
    }

    let mut cursor = Cursor::new(input, 2);
    let mut entries = Vec::new();
    while cursor.remaining() != 0 {
        let record_size = cursor.i32()?;
        if record_size == 0 {
            return Err("empty keytab record");
        }
        if record_size < 0 {
            let hole_size = usize::try_from(record_size.unsigned_abs())
                .map_err(|_| "invalid keytab hole size")?;
            cursor.take(hole_size)?;
            continue;
        }

        let record_size = usize::try_from(record_size).map_err(|_| "invalid record size")?;
        let record = cursor.take(record_size)?;
        entries.push(parse_entry(record)?);
    }
    if entries.is_empty() {
        return Err("keytab has no usable service keys");
    }

    // Delay construction of krb5 ServiceKeys until every record is validated.
    // The staged key buffers zeroize on errors and after copying into krb5.
    let mut keytab = Keytab::new();
    for entry in entries {
        keytab.add(ServiceKey::new(
            entry.principal,
            entry.realm,
            entry.kvno,
            entry.enctype,
            entry.key.as_slice().to_vec(),
        ));
    }
    Ok(KeytabOwner(keytab))
}

struct ParsedEntry {
    principal: String,
    realm: String,
    kvno: u32,
    enctype: EncType,
    key: Zeroizing<Vec<u8>>,
}

fn parse_entry(input: &[u8]) -> Result<ParsedEntry, &'static str> {
    let mut cursor = Cursor::new(input, 0);
    let component_count = usize::from(cursor.u16()?);
    if component_count == 0 || component_count > cursor.remaining() / 3 {
        return Err("invalid principal component count");
    }

    let realm = cursor.string()?;
    if realm.contains('@') {
        return Err("ambiguous keytab realm");
    }
    let mut principal = String::new();
    for index in 0..component_count {
        let component = cursor.string()?;
        if component.contains('/') || component.contains('@') {
            return Err("ambiguous keytab principal component");
        }
        if index != 0 {
            principal.push('/');
        }
        principal.push_str(component);
    }

    // The current acceptor does not use keytab name type or timestamp, but
    // both fields must be present and structurally complete.
    let _name_type = cursor.u32()?;
    let _timestamp = cursor.u32()?;
    let kvno8 = u32::from(cursor.u8()?);
    let enctype_number = i32::from(cursor.u16()?);
    let (enctype, expected_key_len) = match enctype_number {
        17 => (EncType::AES128CtsHmacSha196, 16),
        18 => (EncType::AES256CtsHmacSha196, 32),
        19 => (EncType::AES128CtsHmacSha256128, 16),
        20 => (EncType::AES256CtsHmacSha384192, 32),
        _ => return Err("unsupported keytab enctype"),
    };
    let key_len = usize::from(cursor.u16()?);
    if key_len != expected_key_len {
        return Err("invalid key length for keytab enctype");
    }
    let key = Zeroizing::new(cursor.take(key_len)?.to_vec());
    let kvno = match cursor.remaining() {
        0 => kvno8,
        4 => match cursor.u32()? {
            0 => kvno8,
            value => value,
        },
        _ => return Err("invalid trailing keytab entry data"),
    };
    if cursor.remaining() != 0 {
        return Err("trailing keytab entry data");
    }

    Ok(ParsedEntry {
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

    fn take(&mut self, length: usize) -> Result<&'a [u8], &'static str> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or("keytab offset overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or("truncated keytab data")?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, &'static str> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, &'static str> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, &'static str> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn i32(&mut self) -> Result<i32, &'static str> {
        let bytes = self.take(4)?;
        Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn string(&mut self) -> Result<&'a str, &'static str> {
        let length = usize::from(self.u16()?);
        let value = std::str::from_utf8(self.take(length)?).map_err(|_| "invalid keytab UTF-8")?;
        if value.is_empty() || value.contains('\0') {
            return Err("empty or NUL keytab name field");
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{Keytab, MAX_KEYTAB_BYTES, parse};
    use krb5::acceptor::{EncType, ServiceKey};

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
        let parsed = parse(&valid).unwrap_or_else(|_| panic!("valid fixture rejected"));
        assert_eq!(parsed.keys().len(), 1);
        let key = &parsed.keys()[0];
        assert_eq!(key.principal, "HTTP/acceptor.qid.test");
        assert_eq!(key.realm, "QID.MIT.TEST");
        assert_eq!(key.kvno, 5);
        assert!(key.key.as_slice() == TEST_KEY);

        let mut with_hole = vec![0x05, 0x02, 0xff, 0xff, 0xff, 0xff, 0xaa];
        with_hole.extend_from_slice(&valid[2..]);
        let parsed = parse(&with_hole).unwrap_or_else(|_| panic!("valid hole rejected"));
        assert_eq!(parsed.keys().len(), 1);
    }

    #[test]
    fn rejects_truncation_overflow_and_malformed_entries() {
        let valid = valid_keytab();
        for end in 0..valid.len() {
            assert!(
                parse(&valid[..end]).is_err(),
                "accepted truncated length {end}"
            );
        }

        let mut min_hole = vec![0x05, 0x02];
        min_hole.extend_from_slice(&i32::MIN.to_be_bytes());
        assert!(parse(&min_hole).is_err());

        let mut oversized_record = vec![0x05, 0x02];
        oversized_record.extend_from_slice(&i32::MAX.to_be_bytes());
        assert!(parse(&oversized_record).is_err());

        let mut empty_record = vec![0x05, 0x02, 0, 0, 0, 0];
        assert!(parse(&empty_record).is_err());
        empty_record[5] = 1;
        assert!(parse(&empty_record).is_err());

        let mut bad_version = valid.clone();
        bad_version[1] = 1;
        assert!(parse(&bad_version).is_err());

        let mut bad_utf8 = valid.clone();
        bad_utf8[10] = 0xff;
        assert!(parse(&bad_utf8).is_err());

        let mut unknown_enctype = valid.clone();
        let enctype = enctype_offset(&unknown_enctype)
            .unwrap_or_else(|| panic!("test keytab has no enctype field"));
        unknown_enctype[enctype..enctype + 2].copy_from_slice(&999u16.to_be_bytes());
        assert!(parse(&unknown_enctype).is_err());

        let mut wrong_key_size = valid.clone();
        let enctype = enctype_offset(&wrong_key_size)
            .unwrap_or_else(|| panic!("test keytab has no enctype field"));
        wrong_key_size[enctype + 2..enctype + 4].copy_from_slice(&15u16.to_be_bytes());
        assert!(parse(&wrong_key_size).is_err());

        let mut trailing_record_byte = valid;
        trailing_record_byte.push(0);
        assert!(parse(&trailing_record_byte).is_err());

        let too_large = vec![0; MAX_KEYTAB_BYTES + 1];
        assert!(parse(&too_large).is_err());
    }
}
