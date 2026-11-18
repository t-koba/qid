//! RFC 6961 §2.2 status_request_v2 parsing and §3 CertificateStatus encoding.
//!
//! Only the `ocsp_multi` request with empty ResponderID list and empty
//! Extensions is usable here. Nonce and responder selection are not supported.

use super::wire::Reader;
use super::{
    Extension, MAX_U24, OCSP, OCSP_MULTI, STATUS_REQUEST, STATUS_REQUEST_V2, STATUS_REQUEST_V2_ACK,
    Tls12Error, u24_bytes,
};

/// A parsed `CertificateStatusRequestListV2`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusRequestV2<'a> {
    pub items: Vec<StatusRequestItem<'a>>,
}

/// One validated `CertificateStatusRequestItemV2`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusRequestItem<'a> {
    pub status_type: u8,
    /// Validated, still length-prefixed `ResponderID` entries; empty means none.
    pub responder_ids: &'a [u8],
    /// Raw `Extensions` contents; empty means none.
    pub request_extensions: &'a [u8],
}

/// What this milestone is prepared to acknowledge in ServerHello.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusSelection {
    /// Informational: legacy status_request (5) was offered by the client.
    pub legacy_status_request_offered: bool,
    /// True only for a usable `ocsp_multi` item with both vectors empty.
    pub ocsp_multi_usable: bool,
}

impl StatusSelection {
    /// The only acknowledgement produced here: extension 17 with empty data.
    /// Legacy status_request is never acknowledged, so both cannot be acked.
    pub fn server_hello_extension(&self) -> Option<[u8; 4]> {
        self.ocsp_multi_usable.then_some(STATUS_REQUEST_V2_ACK)
    }
}

/// One encoding slot of an `OCSPResponseList`; `Missing` is a zero-length slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OcspResponse<'a> {
    /// A non-empty DER-encoded OCSPResponse.
    Der(&'a [u8]),
    /// An intentionally empty staple slot for this certificate.
    Missing,
}

/// Parse `extension_data` of status_request_v2 with strict nested lengths.
pub fn parse_status_request_v2(data: &[u8]) -> Result<StatusRequestV2<'_>, Tls12Error> {
    let mut outer = Reader::new(data);
    let list_len = outer.u16(Tls12Error::InvalidStatusRequest)?;
    if list_len != outer.remaining() {
        return Err(Tls12Error::InvalidStatusRequest);
    }
    let mut list = Reader::new(outer.take(list_len, Tls12Error::InvalidStatusRequest)?);
    let mut items = Vec::new();
    let mut seen_types: Vec<u8> = Vec::new();
    while list.remaining() > 0 {
        let status_type = list.u8(Tls12Error::InvalidStatusRequest)?;
        if status_type != OCSP && status_type != OCSP_MULTI {
            return Err(Tls12Error::UnsupportedStatusType);
        }
        if seen_types.contains(&status_type) {
            return Err(Tls12Error::DuplicateStatusType);
        }
        seen_types.push(status_type);
        let request_len = list.u16(Tls12Error::InvalidStatusRequest)?;
        let request = list.take(request_len, Tls12Error::InvalidStatusRequest)?;
        items.push(parse_ocsp_status_request(status_type, request)?);
    }
    // RFC 6961 §2.2: certificate_status_req_list<1..2^16-1>.
    if items.is_empty() {
        return Err(Tls12Error::InvalidStatusRequest);
    }
    Ok(StatusRequestV2 { items })
}

fn parse_ocsp_status_request<'a>(
    status_type: u8,
    request: &'a [u8],
) -> Result<StatusRequestItem<'a>, Tls12Error> {
    let mut reader = Reader::new(request);
    let ids_len = reader.u16(Tls12Error::InvalidStatusRequest)?;
    let responder_ids = reader.take(ids_len, Tls12Error::InvalidStatusRequest)?;
    validate_responder_ids(responder_ids)?;
    let extensions_len = reader.u16(Tls12Error::InvalidStatusRequest)?;
    let request_extensions = reader.take(extensions_len, Tls12Error::InvalidStatusRequest)?;
    // The item's request_length must match the parsed OCSPStatusRequest exactly.
    reader.finish(Tls12Error::InvalidStatusRequest)?;
    Ok(StatusRequestItem {
        status_type,
        responder_ids,
        request_extensions,
    })
}

fn validate_responder_ids(mut ids: &[u8]) -> Result<(), Tls12Error> {
    while !ids.is_empty() {
        if ids.len() < 2 {
            return Err(Tls12Error::InvalidStatusRequest);
        }
        let id_len = usize::from(u16::from_be_bytes([ids[0], ids[1]]));
        // RFC 6961: ResponderID<1..2^16-1>, so an empty ID is not legal.
        if id_len == 0 || ids.len() < 2 + id_len {
            return Err(Tls12Error::InvalidStatusRequest);
        }
        ids = &ids[2 + id_len..];
    }
    Ok(())
}

/// Select an acknowledgement from a parsed ClientHello's extension list.
///
/// Duplicate status extensions are rejected. When both legacy and v2 are
/// offered, only the v2 acknowledgement can be returned.
pub fn select_status_request(extensions: &[Extension<'_>]) -> Result<StatusSelection, Tls12Error> {
    let mut legacy_offered = false;
    let mut v2_data = None;
    for extension in extensions {
        match extension.ext_type {
            STATUS_REQUEST => {
                if legacy_offered {
                    return Err(Tls12Error::DuplicateExtension);
                }
                legacy_offered = true;
            }
            STATUS_REQUEST_V2 => {
                if v2_data.is_some() {
                    return Err(Tls12Error::DuplicateExtension);
                }
                v2_data = Some(extension.data);
            }
            _ => {}
        }
    }
    let ocsp_multi_usable = match v2_data {
        Some(data) => parse_status_request_v2(data)?
            .items
            .iter()
            .any(is_usable_ocsp_multi),
        None => false,
    };
    Ok(StatusSelection {
        legacy_status_request_offered: legacy_offered,
        ocsp_multi_usable,
    })
}

fn is_usable_ocsp_multi(item: &StatusRequestItem<'_>) -> bool {
    item.status_type == OCSP_MULTI
        && item.responder_ids.is_empty()
        && item.request_extensions.is_empty()
}

/// Build the body of an RFC 6961 `CertificateStatus` message with
/// `status_type = ocsp_multi(2)`: a u24-length OCSPResponseList of u24-length
/// responses. The four-byte handshake header is NOT included.
///
/// `responses` corresponds to the first certificate, second certificate, and
/// so on, in order. Its length must be between one and `cert_count`.
pub fn build_certificate_status_multi(
    cert_count: usize,
    responses: &[OcspResponse<'_>],
) -> Result<Vec<u8>, Tls12Error> {
    if responses.is_empty() {
        return Err(Tls12Error::InvalidCertificateStatus);
    }
    if responses.len() > cert_count {
        return Err(Tls12Error::TooManyResponses);
    }
    if responses.len() > MAX_U24 {
        return Err(Tls12Error::InvalidCertificateStatus);
    }
    let mut list_len = 0usize;
    for response in responses {
        let der = match response {
            OcspResponse::Missing => &[][..],
            OcspResponse::Der(der) => {
                if der.is_empty() {
                    return Err(Tls12Error::EmptyResponse);
                }
                der
            }
        };
        if der.len() > MAX_U24 {
            return Err(Tls12Error::InvalidCertificateStatus);
        }
        list_len = list_len
            .checked_add(der.len())
            .and_then(|sum| sum.checked_add(3))
            .ok_or(Tls12Error::InvalidCertificateStatus)?;
        if list_len > MAX_U24 {
            return Err(Tls12Error::InvalidCertificateStatus);
        }
    }
    let mut body = Vec::with_capacity(4 + list_len);
    body.push(OCSP_MULTI);
    body.extend_from_slice(&u24_bytes(list_len));
    for response in responses {
        let der: &[u8] = match response {
            OcspResponse::Missing => &[],
            OcspResponse::Der(der) => der,
        };
        body.extend_from_slice(&u24_bytes(der.len()));
        body.extend_from_slice(der);
    }
    Ok(body)
}

/// Wrap a handshake body with the u8 type and u24 length prefix.
pub fn wrap_handshake_message(msg_type: u8, body: &[u8]) -> Result<Vec<u8>, Tls12Error> {
    if body.len() > MAX_U24 {
        return Err(Tls12Error::MessageTooLarge);
    }
    let mut message = Vec::with_capacity(4 + body.len());
    message.push(msg_type);
    message.extend_from_slice(&u24_bytes(body.len()));
    message.extend_from_slice(body);
    Ok(message)
}
