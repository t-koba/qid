//! RFC 9651 Structured Fields for HTTP.

use crate::error::{QidError, QidResult};

#[derive(Debug, Clone, PartialEq)]
pub enum SfItem {
    Boolean(bool),
    Integer(i64),
    Decimal(f64),
    String(String),
    Token(String),
    ByteSeq(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct SfParameter {
    pub key: String,
    pub value: SfItem,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SfInnerList {
    pub items: Vec<SfItem>,
    pub parameters: Vec<SfParameter>,
}

pub fn parse_sf_string(input: &str) -> QidResult<String> {
    let input = input.trim();
    if !input.starts_with('"') || !input.ends_with('"') {
        return Err(QidError::BadRequest {
            message: "SF string must be quoted".to_string(),
        });
    }
    let inner = &input[1..input.len() - 1];
    let mut result = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                _ => {
                    return Err(QidError::BadRequest {
                        message: "invalid escape in SF string".to_string(),
                    });
                }
            }
        } else {
            result.push(c);
        }
    }
    Ok(result)
}

pub fn serialize_sf_string(value: &str) -> String {
    let escaped: String = value
        .chars()
        .map(|c| match c {
            '"' => "\\\"".to_string(),
            '\\' => "\\\\".to_string(),
            c => c.to_string(),
        })
        .collect();
    format!("\"{escaped}\"")
}

pub fn parse_sf_token(input: &str) -> QidResult<&str> {
    let input = input.trim();
    if input.is_empty() || !input.starts_with(|c: char| c.is_ascii_alphabetic() || c == '*') {
        return Err(QidError::BadRequest {
            message: "invalid SF token".to_string(),
        });
    }
    let end = input
        .find(|c: char| !c.is_ascii_alphanumeric() && !"-.*".contains(c))
        .unwrap_or(input.len());
    Ok(&input[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sf_string_round_trip() {
        let input = "\"hello world\"";
        let parsed = parse_sf_string(input).unwrap();
        assert_eq!(parsed, "hello world");
        let serialized = serialize_sf_string(&parsed);
        assert_eq!(serialized, input);
    }

    #[test]
    fn sf_string_with_escapes() {
        let input = "\"foo\\\"bar\"";
        let parsed = parse_sf_string(input).unwrap();
        assert_eq!(parsed, "foo\"bar");
    }

    #[test]
    fn sf_token_valid() {
        let token = parse_sf_token("application/json").unwrap();
        assert_eq!(token, "application");
    }

    #[test]
    fn sf_token_invalid() {
        assert!(parse_sf_token("123abc").is_err());
    }
}
