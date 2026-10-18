//! Diameter base protocol (RFC 6733).

use qid_core::error::{QidError, QidResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiameterHeader {
    pub version: u8,
    pub command_code: u32,
    pub application_id: u32,
    pub hop_by_hop_id: u32,
    pub end_to_end_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiameterMessage {
    pub header: DiameterHeader,
    pub avps: Vec<DiameterAvp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiameterAvp {
    pub code: u32,
    pub vendor_id: Option<u32>,
    pub data: Vec<u8>,
}

pub fn parse_diameter_header(data: &[u8]) -> QidResult<DiameterHeader> {
    if data.len() < 20 {
        return Err(QidError::BadRequest {
            message: "Diameter header too short".to_string(),
        });
    }
    Ok(DiameterHeader {
        version: data[0],
        command_code: ((data[1] as u32) << 16) | ((data[2] as u32) << 8) | (data[3] as u32),
        application_id: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
        hop_by_hop_id: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
        end_to_end_id: u32::from_be_bytes([data[16], data[17], data[18], data[19]]),
    })
}

pub fn parse_diameter_avps(data: &[u8]) -> QidResult<Vec<DiameterAvp>> {
    let mut avps = Vec::new();
    let mut offset = 20;
    while offset + 8 <= data.len() {
        let code = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let flags = data[offset + 4];
        if (flags & 0x80) != 0 && offset + 12 > data.len() {
            return Err(QidError::BadRequest {
                message: "Diameter AVP vendor identifier truncated".to_string(),
            });
        }
        let vendor_id = if (flags & 0x80) != 0 {
            Some(u32::from_be_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
            ]))
        } else {
            None
        };
        let header_size = if vendor_id.is_some() { 12 } else { 8 };
        let len =
            u32::from_be_bytes([0, data[offset + 5], data[offset + 6], data[offset + 7]]) as usize;
        if len < header_size {
            return Err(QidError::BadRequest {
                message: "Diameter AVP length is smaller than its header".to_string(),
            });
        }
        // AVP wire size rounds up to a 32-bit boundary; the padding bytes are
        // not counted in the length field but must be present. Checked
        // arithmetic keeps malformed lengths fail-closed on any platform.
        let stride = match len.checked_add(3) {
            Some(padded) => padded & !3,
            None => {
                return Err(QidError::BadRequest {
                    message: "Diameter AVP truncated".to_string(),
                });
            }
        };
        let end = match offset.checked_add(stride) {
            Some(end) if end <= data.len() => end,
            _ => {
                return Err(QidError::BadRequest {
                    message: "Diameter AVP truncated".to_string(),
                });
            }
        };
        let data_start = offset + header_size;
        let data_end = offset + len;
        avps.push(DiameterAvp {
            code,
            vendor_id,
            data: data[data_start..data_end].to_vec(),
        });
        offset = end;
    }
    Ok(avps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diameter_header_parse() {
        let data = vec![
            0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        ];
        let header = parse_diameter_header(&data).unwrap();
        assert_eq!(header.version, 1);
        assert_eq!(header.command_code, 1);
    }

    #[test]
    fn diameter_header_too_short() {
        assert!(parse_diameter_header(&[0u8; 19]).is_err());
    }

    fn avp_bytes(code: u32, vendor: Option<u32>, payload: &[u8]) -> Vec<u8> {
        let header_len = if vendor.is_some() { 12 } else { 8 };
        let mut out = Vec::new();
        out.extend_from_slice(&code.to_be_bytes());
        out.push(if vendor.is_some() { 0x80 } else { 0x00 });
        let len = (header_len + payload.len()) as u32;
        out.extend_from_slice(&len.to_be_bytes()[1..]);
        if let Some(vendor) = vendor {
            out.extend_from_slice(&vendor.to_be_bytes());
        }
        out.extend_from_slice(payload);
        out.resize(len as usize + (4 - len as usize % 4) % 4, 0);
        out
    }

    fn avp_message(payloads: &[Vec<u8>]) -> Vec<u8> {
        let mut message = vec![0u8; 20];
        for payload in payloads {
            message.extend_from_slice(payload);
        }
        message
    }

    #[test]
    fn diameter_avps_reject_truncated_framing() {
        // Vendor flag set but fewer than 12 bytes remain: must fail, never panic.
        let mut truncated = vec![0u8; 20];
        truncated.extend_from_slice(&1u32.to_be_bytes());
        truncated.extend_from_slice(&[0x80, 0x00, 0x00, 0x08]);
        assert!(parse_diameter_avps(&truncated).is_err());
        // Declared length smaller than the AVP header is malformed.
        let mut bad_len = vec![0u8; 20];
        bad_len.extend_from_slice(&1u32.to_be_bytes());
        bad_len.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]);
        assert!(parse_diameter_avps(&bad_len).is_err());
        // Payload cut short of the declared length fails closed.
        let mut cut = avp_bytes(1, None, &[0xAA, 0xBB]);
        cut.pop();
        assert!(parse_diameter_avps(&avp_message(&[cut])).is_err());
    }

    #[test]
    fn diameter_avps_stride_on_32_bit_boundaries() {
        // 8-byte header plus 1-byte payload declares length 9 but occupies 12
        // wire bytes; the next AVP must decode from the padded offset.
        let first = avp_bytes(1, Some(0x9), &[0xAA]);
        let second = avp_bytes(2, None, &[0xBB, 0xCC]);
        let parsed = parse_diameter_avps(&avp_message(&[first, second])).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!((parsed[0].code, parsed[0].vendor_id), (1, Some(0x9)));
        assert_eq!(parsed[0].data, vec![0xAA]);
        assert_eq!((parsed[1].code, parsed[1].vendor_id), (2, None));
        assert_eq!(parsed[1].data, vec![0xBB, 0xCC]);
    }
}
