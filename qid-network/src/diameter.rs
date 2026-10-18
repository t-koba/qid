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
        let data_start = offset + header_size;
        let real_len = if len < header_size { header_size } else { len };
        let data_end = (data_start + (real_len - header_size)).min(data.len());
        avps.push(DiameterAvp {
            code,
            vendor_id,
            data: data[data_start..data_end].to_vec(),
        });
        offset += real_len;
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
}
