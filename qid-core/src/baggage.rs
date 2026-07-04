use crate::error::{QidError, QidResult};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct BaggageEntry {
    pub value: String,
    pub properties: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Baggage {
    pub entries: HashMap<String, BaggageEntry>,
}

pub fn parse_baggage_header(header: &str) -> QidResult<Baggage> {
    let mut entries = HashMap::new();
    if header.trim().is_empty() {
        return Ok(Baggage { entries });
    }
    for pair in header.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let parts: Vec<&str> = pair.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(QidError::BadRequest {
                message: format!("invalid baggage entry format: {pair}"),
            });
        }
        let name = url_decode(parts[0].trim());
        let value_and_props = parts[1].trim();
        let (raw_value, properties) = match value_and_props.split_once(';') {
            Some((v, props)) => (v.trim(), props),
            None => (value_and_props, ""),
        };
        let value = url_decode(raw_value);
        let mut props_map = HashMap::new();
        if !properties.is_empty() {
            for prop in properties.split(';') {
                let prop = prop.trim();
                if prop.is_empty() {
                    continue;
                }
                let prop_parts: Vec<&str> = prop.splitn(2, '=').collect();
                if prop_parts.len() != 2 {
                    return Err(QidError::BadRequest {
                        message: format!("invalid baggage property format: {prop}"),
                    });
                }
                props_map.insert(
                    url_decode(prop_parts[0].trim()),
                    url_decode(prop_parts[1].trim()),
                );
            }
        }
        entries.insert(
            name,
            BaggageEntry {
                value,
                properties: props_map,
            },
        );
    }
    Ok(Baggage { entries })
}

pub fn serialize_baggage(baggage: &Baggage) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut sorted_names: Vec<&String> = baggage.entries.keys().collect();
    sorted_names.sort();
    for name in sorted_names {
        let entry = &baggage.entries[name];
        let mut s = format!("{}={}", url_encode(name), url_encode(&entry.value));
        let mut sorted_prop_keys: Vec<&String> = entry.properties.keys().collect();
        sorted_prop_keys.sort();
        for key in sorted_prop_keys {
            let val = &entry.properties[key];
            s.push_str(&format!(";{}={}", url_encode(key), url_encode(val)));
        }
        parts.push(s);
    }
    parts.join(",")
}

fn url_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            let hi = chars.next().and_then(|c| c.to_digit(16));
            let lo = chars.next().and_then(|c| c.to_digit(16));
            match (hi, lo) {
                (Some(h), Some(l)) => result.push(char::from((h * 16 + l) as u8)),
                _ => result.push(ch),
            }
        } else {
            result.push(ch);
        }
    }
    result
}

fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'~' => {
                result.push(b as char);
            }
            b' ' => result.push_str("%20"),
            _ => {
                result.push_str(&format!("%{b:02X}"));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_entry() {
        let b = parse_baggage_header("key=value").unwrap();
        assert_eq!(b.entries.len(), 1);
        assert_eq!(b.entries["key"].value, "value");
        assert!(b.entries["key"].properties.is_empty());
    }

    #[test]
    fn parses_multiple_entries() {
        let b = parse_baggage_header("key1=val1,key2=val2").unwrap();
        assert_eq!(b.entries.len(), 2);
        assert_eq!(b.entries["key1"].value, "val1");
        assert_eq!(b.entries["key2"].value, "val2");
    }

    #[test]
    fn parses_entry_with_properties() {
        let b = parse_baggage_header("key=value;prop1=abc;prop2=def").unwrap();
        assert_eq!(b.entries["key"].value, "value");
        assert_eq!(b.entries["key"].properties["prop1"], "abc");
        assert_eq!(b.entries["key"].properties["prop2"], "def");
    }

    #[test]
    fn parses_url_encoded_values() {
        let b = parse_baggage_header("key=hello%20world").unwrap();
        assert_eq!(b.entries["key"].value, "hello world");
    }

    #[test]
    fn parses_empty_header() {
        let b = parse_baggage_header("").unwrap();
        assert!(b.entries.is_empty());
    }

    #[test]
    fn parses_whitespace_header() {
        let b = parse_baggage_header("  ").unwrap();
        assert!(b.entries.is_empty());
    }

    #[test]
    fn rejects_malformed_entry() {
        assert!(parse_baggage_header("badformat").is_err());
    }

    #[test]
    fn roundtrip_preserves_data() {
        let mut entries = HashMap::new();
        let mut props = HashMap::new();
        props.insert("p1".to_string(), "v1".to_string());
        props.insert("p2".to_string(), "v2".to_string());
        entries.insert(
            "key1".to_string(),
            BaggageEntry {
                value: "val1".to_string(),
                properties: props,
            },
        );
        entries.insert(
            "key2".to_string(),
            BaggageEntry {
                value: "val2".to_string(),
                properties: HashMap::new(),
            },
        );
        let baggage = Baggage { entries };
        let serialized = serialize_baggage(&baggage);
        let parsed = parse_baggage_header(&serialized).unwrap();
        assert_eq!(parsed, baggage);
    }

    #[test]
    fn serializes_in_sorted_order() {
        let mut entries = HashMap::new();
        entries.insert(
            "b".to_string(),
            BaggageEntry {
                value: "2".to_string(),
                properties: HashMap::new(),
            },
        );
        entries.insert(
            "a".to_string(),
            BaggageEntry {
                value: "1".to_string(),
                properties: HashMap::new(),
            },
        );
        let baggage = Baggage { entries };
        let s = serialize_baggage(&baggage);
        assert_eq!(s, "a=1,b=2");
    }
}
