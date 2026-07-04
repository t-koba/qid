//! RFC 7239 Forwarded HTTP Header.

use crate::error::QidResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForwardedElement {
    pub for_: Option<String>,
    pub by: Option<String>,
    pub host: Option<String>,
    pub proto: Option<String>,
}

pub fn parse_forwarded_header(value: &str) -> QidResult<Vec<ForwardedElement>> {
    let mut elements = Vec::new();
    for part in value.split(',') {
        let mut elem = ForwardedElement {
            for_: None,
            by: None,
            host: None,
            proto: None,
        };
        for pair in part.split(';') {
            let pair = pair.trim();
            if let Some(eq) = pair.find('=') {
                let key = pair[..eq].trim().to_lowercase();
                let val = pair[eq + 1..].trim().trim_matches('"');
                match key.as_str() {
                    "for" => elem.for_ = Some(val.to_string()),
                    "by" => elem.by = Some(val.to_string()),
                    "host" => elem.host = Some(val.to_string()),
                    "proto" => elem.proto = Some(val.to_string()),
                    _ => {}
                }
            }
        }
        elements.push(elem);
    }
    Ok(elements)
}

pub fn serialize_forwarded_header(elements: &[ForwardedElement]) -> String {
    elements
        .iter()
        .map(|e| {
            let mut parts = Vec::new();
            if let Some(ref v) = e.for_ {
                parts.push(format!("for=\"{v}\""));
            }
            if let Some(ref v) = e.by {
                parts.push(format!("by=\"{v}\""));
            }
            if let Some(ref v) = e.host {
                parts.push(format!("host=\"{v}\""));
            }
            if let Some(ref v) = e.proto {
                parts.push(format!("proto={v}"));
            }
            parts.join("; ")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_forwarded_single() {
        let elements =
            parse_forwarded_header("for=192.0.2.43;proto=https;by=203.0.113.43").unwrap();
        assert_eq!(elements.len(), 1);
        assert_eq!(elements[0].for_.as_deref(), Some("192.0.2.43"));
        assert_eq!(elements[0].proto.as_deref(), Some("https"));
    }

    #[test]
    fn parse_forwarded_multi() {
        let elements = parse_forwarded_header("for=192.0.2.43, for=198.51.100.17").unwrap();
        assert_eq!(elements.len(), 2);
    }

    #[test]
    fn serialize_round_trip() {
        let elements = vec![ForwardedElement {
            for_: Some("192.0.2.43".to_string()),
            by: Some("203.0.113.43".to_string()),
            host: Some("example.com".to_string()),
            proto: Some("https".to_string()),
        }];
        let serialized = serialize_forwarded_header(&elements);
        let parsed = parse_forwarded_header(&serialized).unwrap();
        assert_eq!(parsed[0].for_, elements[0].for_);
    }
}
