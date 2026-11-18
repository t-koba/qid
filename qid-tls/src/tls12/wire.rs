//! TLS 1.2 handshake record reassembly and RFC 5246 §7.4.1.2 ClientHello parsing.

use super::{
    DEFAULT_REASSEMBLY_BUDGET, MAX_CIPHER_SUITE_BYTES, MAX_COMPRESSION_METHODS,
    MAX_RECORD_FRAGMENT, MAX_SESSION_ID, MAX_U16, MAX_U24, Tls12Error,
};

const RECORD_HEADER_LEN: usize = 5;
const HANDSHAKE_RECORD: u8 = 0x16;

/// One complete handshake message: the u8 type and the u24-length body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeMessage {
    pub msg_type: u8,
    pub body: Vec<u8>,
}

/// Reassembles handshake fragments from TLS 1.2 records into whole messages.
///
/// An error leaves the buffered state unchanged. Fragment boundaries do not
/// affect the messages returned: records are concatenated before parsing.
pub struct HandshakeReassembler {
    budget: usize,
    pending: Vec<u8>,
}

impl Default for HandshakeReassembler {
    fn default() -> Self {
        Self::with_budget(DEFAULT_REASSEMBLY_BUDGET)
    }
}

impl HandshakeReassembler {
    /// Use the default resource budget (not an RFC limit).
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum number of buffered handshake bytes. This is a local
    /// resource budget, independent of the RFC's u24 message-size maximum.
    pub fn with_budget(budget: usize) -> Self {
        Self {
            budget,
            pending: Vec::new(),
        }
    }

    /// Consume one or more handshake records and return every message completed
    /// by those records, in wire order. Incomplete messages stay buffered.
    pub fn push_records(&mut self, records: &[u8]) -> Result<Vec<HandshakeMessage>, Tls12Error> {
        let mut work = self.pending.clone();
        let mut position = 0;
        while position < records.len() {
            if records.len() - position < RECORD_HEADER_LEN {
                return Err(Tls12Error::TruncatedRecord);
            }
            let header = &records[position..position + RECORD_HEADER_LEN];
            if header[0] != HANDSHAKE_RECORD {
                return Err(Tls12Error::UnexpectedContentType);
            }
            if header[1] != 0x03 || !(0x01..=0x03).contains(&header[2]) {
                return Err(Tls12Error::InvalidRecordVersion);
            }
            let fragment_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            if fragment_len > MAX_RECORD_FRAGMENT {
                return Err(Tls12Error::RecordTooLarge);
            }
            position += RECORD_HEADER_LEN;
            let fragment_end = position
                .checked_add(fragment_len)
                .ok_or(Tls12Error::TruncatedRecord)?;
            let fragment = records
                .get(position..fragment_end)
                .ok_or(Tls12Error::TruncatedRecord)?;
            if work.len().saturating_add(fragment_len) > self.budget {
                return Err(Tls12Error::BufferBudgetExceeded);
            }
            work.extend_from_slice(fragment);
            position = fragment_end;
        }
        let messages = take_complete_messages(&mut work, self.budget)?;
        self.pending = work;
        Ok(messages)
    }

    /// Fail if the stream ends with an incomplete handshake message.
    pub fn finish(&self) -> Result<(), Tls12Error> {
        if self.pending.is_empty() {
            Ok(())
        } else {
            Err(Tls12Error::TruncatedHandshake)
        }
    }
}

fn take_complete_messages(
    work: &mut Vec<u8>,
    budget: usize,
) -> Result<Vec<HandshakeMessage>, Tls12Error> {
    let mut messages = Vec::new();
    while work.len() >= 4 {
        let msg_type = work[0];
        let body_len = u32::from_be_bytes([0, work[1], work[2], work[3]]) as usize;
        if body_len > MAX_U24 || body_len > budget.saturating_sub(4) {
            return Err(Tls12Error::MessageTooLarge);
        }
        let total = body_len.checked_add(4).ok_or(Tls12Error::MessageTooLarge)?;
        if work.len() < total {
            break;
        }
        let body = work[4..total].to_vec();
        work.drain(..total);
        messages.push(HandshakeMessage { msg_type, body });
    }
    Ok(messages)
}

/// A ClientHello body (the bytes after the handshake header).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHello<'a> {
    pub legacy_version: [u8; 2],
    pub random: &'a [u8],
    pub session_id: &'a [u8],
    pub cipher_suites: Vec<u16>,
    pub compression_methods: &'a [u8],
    pub extensions: Vec<Extension<'a>>,
}

/// One ClientHello extension: its type and raw extension_data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Extension<'a> {
    pub ext_type: u16,
    pub data: &'a [u8],
}

/// Parse one RFC 5246 §7.4.1.2 ClientHello body, rejecting trailing bytes.
pub fn parse_client_hello(body: &[u8]) -> Result<ClientHello<'_>, Tls12Error> {
    let mut reader = Reader::new(body);
    let version = reader.take(2, Tls12Error::TruncatedClientHello)?;
    let legacy_version = [version[0], version[1]];
    if legacy_version[0] != 0x03 || !(0x01..=0x03).contains(&legacy_version[1]) {
        return Err(Tls12Error::UnsupportedVersion);
    }
    let random = reader.take(32, Tls12Error::TruncatedClientHello)?;
    let session_id = reader.vector_u8(0, MAX_SESSION_ID, Tls12Error::InvalidSessionId)?;
    let suites = reader.vector_u16(2, MAX_CIPHER_SUITE_BYTES, Tls12Error::InvalidCipherSuites)?;
    if suites.len() % 2 != 0 {
        return Err(Tls12Error::InvalidCipherSuites);
    }
    let cipher_suites = suites
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    let compression_methods = reader.vector_u8(
        1,
        MAX_COMPRESSION_METHODS,
        Tls12Error::InvalidCompressionMethods,
    )?;
    let extensions = if reader.remaining() == 0 {
        Vec::new()
    } else {
        let block = reader.vector_u16(0, MAX_U16, Tls12Error::InvalidExtensions)?;
        reader.finish(Tls12Error::InvalidExtensions)?;
        parse_extensions(block)?
    };
    Ok(ClientHello {
        legacy_version,
        random,
        session_id,
        cipher_suites,
        compression_methods,
        extensions,
    })
}

fn parse_extensions(mut block: &[u8]) -> Result<Vec<Extension<'_>>, Tls12Error> {
    let mut extensions = Vec::new();
    let mut seen_types: Vec<u16> = Vec::new();
    while !block.is_empty() {
        if block.len() < 4 {
            return Err(Tls12Error::InvalidExtensions);
        }
        let ext_type = u16::from_be_bytes([block[0], block[1]]);
        match seen_types.binary_search(&ext_type) {
            Ok(_) => return Err(Tls12Error::DuplicateExtension),
            Err(index) => seen_types.insert(index, ext_type),
        }
        let data_len = usize::from(u16::from_be_bytes([block[2], block[3]]));
        let end = data_len
            .checked_add(4)
            .ok_or(Tls12Error::InvalidExtensions)?;
        let data = block.get(4..end).ok_or(Tls12Error::InvalidExtensions)?;
        block = &block[end..];
        extensions.push(Extension { ext_type, data });
    }
    Ok(extensions)
}

/// Bounded reader for length-prefixed wire data.
pub(super) struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub(super) fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    pub(super) fn remaining(&self) -> usize {
        self.data.len() - self.position
    }

    pub(super) fn take(&mut self, len: usize, error: Tls12Error) -> Result<&'a [u8], Tls12Error> {
        let end = self.position.checked_add(len).ok_or(error)?;
        let slice = self.data.get(self.position..end).ok_or(error)?;
        self.position = end;
        Ok(slice)
    }

    pub(super) fn u8(&mut self, error: Tls12Error) -> Result<u8, Tls12Error> {
        Ok(self.take(1, error)?[0])
    }

    pub(super) fn u16(&mut self, error: Tls12Error) -> Result<usize, Tls12Error> {
        let bytes = self.take(2, error)?;
        Ok(usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
    }

    pub(super) fn vector_u8(
        &mut self,
        min: usize,
        max: usize,
        error: Tls12Error,
    ) -> Result<&'a [u8], Tls12Error> {
        let len = usize::from(self.u8(error)?);
        if !(min..=max).contains(&len) {
            return Err(error);
        }
        self.take(len, error)
    }

    pub(super) fn vector_u16(
        &mut self,
        min: usize,
        max: usize,
        error: Tls12Error,
    ) -> Result<&'a [u8], Tls12Error> {
        let len = self.u16(error)?;
        if !(min..=max).contains(&len) {
            return Err(error);
        }
        self.take(len, error)
    }

    pub(super) fn finish(self, error: Tls12Error) -> Result<(), Tls12Error> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(error)
        }
    }
}
