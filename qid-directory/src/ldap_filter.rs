//! RFC 4515 LDAP filter parser.
//!
//! Implements a recursive-descent parser that converts an LDAP filter
//! string into an AST, validates it, and can re-serialize with proper
//! value escaping. Replaces the ad-hoc `sanitize_admin_search_filter`.

use qid_core::error::{QidError, QidResult};

// ---------------------------------------------------------------------------
// AST types
// ---------------------------------------------------------------------------

/// An RFC 4515 filter expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdapFilter {
    And(Vec<LdapFilter>),
    Or(Vec<LdapFilter>),
    Not(Box<LdapFilter>),
    Present(String),
    Equality(String, String),
    Substring(String, SubstringValue),
    GreaterOrEqual(String, String),
    LessOrEqual(String, String),
}

/// Components of a substring filter (RFC 4515 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstringValue {
    pub initial: Option<String>,
    pub any: Vec<String>,
    pub final_: Option<String>,
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn remaining(&self) -> &'a str {
        &self.input[self.pos..]
    }

    fn peek(&self) -> Option<char> {
        self.remaining().chars().next()
    }

    fn advance(&mut self) {
        if let Some(c) = self.remaining().chars().next() {
            self.pos += c.len_utf8();
        }
    }

    fn expect_char(&mut self, expected: char) -> QidResult<()> {
        match self.peek() {
            Some(c) if c == expected => {
                self.advance();
                Ok(())
            }
            Some(c) => Err(QidError::BadRequest {
                message: format!(
                    "LDAP filter: expected '{}' at position {}, got '{}'",
                    expected, self.pos, c
                ),
            }),
            None => Err(QidError::BadRequest {
                message: format!(
                    "LDAP filter: unexpected end of filter at position {}, expected '{}'",
                    self.pos, expected
                ),
            }),
        }
    }

    fn parse_filter(&mut self) -> QidResult<LdapFilter> {
        self.expect_char('(')?;
        let filter = self.parse_filter_inner()?;
        self.expect_char(')')?;
        Ok(filter)
    }

    fn parse_filter_inner(&mut self) -> QidResult<LdapFilter> {
        match self.peek() {
            Some('&') => {
                self.advance();
                let mut children = Vec::new();
                while self.peek() == Some('(') {
                    children.push(self.parse_filter()?);
                }
                if children.is_empty() {
                    return Err(QidError::BadRequest {
                        message: "LDAP filter: '&' (and) requires at least one sub-filter"
                            .to_string(),
                    });
                }
                Ok(LdapFilter::And(children))
            }
            Some('|') => {
                self.advance();
                let mut children = Vec::new();
                while self.peek() == Some('(') {
                    children.push(self.parse_filter()?);
                }
                if children.is_empty() {
                    return Err(QidError::BadRequest {
                        message: "LDAP filter: '|' (or) requires at least one sub-filter"
                            .to_string(),
                    });
                }
                Ok(LdapFilter::Or(children))
            }
            Some('!') => {
                self.advance();
                let child = self.parse_filter()?;
                Ok(LdapFilter::Not(Box::new(child)))
            }
            _ => self.parse_simple_filter(),
        }
    }

    fn parse_simple_filter(&mut self) -> QidResult<LdapFilter> {
        let attr = self.parse_attr()?;

        match self.peek() {
            Some('=') => {
                self.advance();
                if self.peek() == Some('*') && self.check_substring_only_star() {
                    // attribute=*  → present
                    self.advance();
                    return Ok(LdapFilter::Present(attr));
                }
                self.parse_equality_or_substring(attr)
            }
            Some('~') => {
                self.advance();
                self.expect_char('=')?;
                let value = self.parse_value();
                Ok(LdapFilter::Equality(attr, value))
            }
            Some('>') => {
                self.advance();
                self.expect_char('=')?;
                let value = self.parse_value();
                Ok(LdapFilter::GreaterOrEqual(attr, value))
            }
            Some('<') => {
                self.advance();
                self.expect_char('=')?;
                let value = self.parse_value();
                Ok(LdapFilter::LessOrEqual(attr, value))
            }
            Some(':') => {
                // extensible match (basic form): attr:=value or attr:dn:=value
                // For simplicity, parse as equality.
                self.advance();
                while self.peek() == Some(':') || self.peek() == Some('.') {
                    self.advance();
                }
                self.expect_char('=')?;
                let value = self.parse_value();
                Ok(LdapFilter::Equality(attr, value))
            }
            Some(c) => Err(QidError::BadRequest {
                message: format!(
                    "LDAP filter: unexpected character '{}' after attribute '{}' at position {}",
                    c, attr, self.pos
                ),
            }),
            None => Err(QidError::BadRequest {
                message: format!("LDAP filter: unexpected end after attribute '{}'", attr),
            }),
        }
    }

    fn parse_equality_or_substring(&mut self, attr: String) -> QidResult<LdapFilter> {
        let value_start = self.pos;
        let mut has_wildcard = false;

        let mut chars = self.remaining().chars().peekable();
        while let Some(&c) = chars.peek() {
            if c == ')' {
                break;
            }
            if c == '\\' {
                chars.next();
                chars.next();
                chars.next();
            } else if c == '*' {
                has_wildcard = true;
                chars.next();
            } else {
                chars.next();
            }
        }
        let consumed = self.remaining().len() - chars.count();
        self.pos += consumed;

        if !has_wildcard {
            let value = &self.input[value_start..self.pos];
            let unescaped = unescape_filter_value(value)?;
            return Ok(LdapFilter::Equality(attr, unescaped));
        }

        // Parse substring
        let value = &self.input[value_start..self.pos];
        let mut initial = None;
        let mut any = Vec::new();
        let mut final_ = None;
        let mut current = String::new();
        let mut after_star = false;

        for ch in value.chars() {
            match ch {
                '*' => {
                    if !after_star {
                        if initial.is_none() && any.is_empty() {
                            initial = Some(std::mem::take(&mut current));
                        } else {
                            any.push(std::mem::take(&mut current));
                        }
                        after_star = true;
                    } else {
                        any.push(std::mem::take(&mut current));
                    }
                }
                _ => {
                    current.push(ch);
                }
            }
        }
        if !current.is_empty() || !after_star {
            final_ = Some(current);
        }

        Ok(LdapFilter::Substring(
            attr,
            SubstringValue {
                initial: initial
                    .filter(|s| !s.is_empty())
                    .map(|s| unescape_filter_value(&s))
                    .transpose()?,
                any: any
                    .into_iter()
                    .filter(|s| !s.is_empty())
                    .map(|s| unescape_filter_value(&s))
                    .collect::<QidResult<Vec<_>>>()?,
                final_: final_
                    .filter(|s| !s.is_empty())
                    .map(|s| unescape_filter_value(&s))
                    .transpose()?,
            },
        ))
    }

    fn parse_attr(&mut self) -> QidResult<String> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                self.advance();
            } else {
                break;
            }
        }
        let attr = &self.input[start..self.pos];
        if attr.is_empty() {
            return Err(QidError::BadRequest {
                message: format!("LDAP filter: empty attribute at position {}", self.pos),
            });
        }
        Ok(attr.to_string())
    }

    fn parse_value(&mut self) -> String {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c == ')' {
                break;
            }
            self.advance();
        }
        let raw = &self.input[start..self.pos];
        unescape_filter_value(raw).unwrap_or(raw.to_string())
    }

    /// Check if remaining input is just `*` followed by `)`.
    fn check_substring_only_star(&self) -> bool {
        let mut chars = self.remaining().chars();
        chars.next() == Some('*') && chars.next() == Some(')')
    }
}

/// Unescape RFC 4515 hex-escaped characters (e.g. `\2a` → `*`).
fn unescape_filter_value(raw: &str) -> QidResult<String> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let hi = chars.next().and_then(|c| c.to_digit(16));
            let lo = chars.next().and_then(|c| c.to_digit(16));
            match (hi, lo) {
                (Some(h), Some(l)) => out.push(char::from((h * 16 + l) as u8)),
                _ => {
                    return Err(QidError::BadRequest {
                        message: "LDAP filter: invalid escape sequence in filter value".to_string(),
                    });
                }
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

/// Escape a filter value for safe inclusion in an LDAP search filter.
fn escape_filter_value_value(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

impl LdapFilter {
    pub fn to_filter_string(&self) -> String {
        match self {
            LdapFilter::And(children) => {
                let inner: String = children.iter().map(|c| c.to_filter_string()).collect();
                format!("(&{inner})")
            }
            LdapFilter::Or(children) => {
                let inner: String = children.iter().map(|c| c.to_filter_string()).collect();
                format!("(|{inner})")
            }
            LdapFilter::Not(child) => format!("(!{})", child.to_filter_string()),
            LdapFilter::Present(attr) => format!("({attr}=*)"),
            LdapFilter::Equality(attr, value) => {
                format!("({attr}={})", escape_filter_value_value(value))
            }
            LdapFilter::Substring(attr, sub) => {
                let initial = sub
                    .initial
                    .as_deref()
                    .map(escape_filter_value_value)
                    .unwrap_or_default();
                let any: String = sub
                    .any
                    .iter()
                    .map(|s| format!("*{}", escape_filter_value_value(s)))
                    .collect();
                let final_ = sub
                    .final_
                    .as_deref()
                    .map(|s| format!("*{}", escape_filter_value_value(s)))
                    .unwrap_or_default();
                // Determine if we need a trailing `*` when there's an any list
                // but no final element.
                let trailing = if sub.final_.is_some() {
                    String::new()
                } else if sub.initial.is_some() || !sub.any.is_empty() {
                    "*".to_string()
                } else {
                    String::new()
                };
                format!("({attr}={initial}{any}{final_}{trailing})")
            }
            LdapFilter::GreaterOrEqual(attr, value) => {
                format!("({attr}>={})", escape_filter_value_value(value))
            }
            LdapFilter::LessOrEqual(attr, value) => {
                format!("({attr}<={})", escape_filter_value_value(value))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse an RFC 4515 LDAP filter string into an AST.
pub fn parse_ldap_filter(input: &str) -> QidResult<LdapFilter> {
    let mut parser = Parser::new(input.trim());
    let filter = parser.parse_filter()?;
    if !parser.remaining().trim().is_empty() {
        return Err(QidError::BadRequest {
            message: format!(
                "LDAP filter: unexpected trailing content '{}'",
                parser.remaining().trim()
            ),
        });
    }
    Ok(filter)
}

/// Validate an RFC 4515 filter string.
pub fn validate_ldap_filter(input: &str) -> QidResult<()> {
    parse_ldap_filter(input)?;
    Ok(())
}

/// Parse a filter string, re-serialize with proper value escaping.
/// Provides injection-safe output suitable for use in LDAP search.
pub fn sanitize_admin_search_filter(filter: &str) -> QidResult<String> {
    let ast = parse_ldap_filter(filter)?;
    Ok(ast.to_filter_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_equality() {
        let ast = parse_ldap_filter("(uid=alice)").unwrap();
        assert_eq!(
            ast,
            LdapFilter::Equality("uid".to_string(), "alice".to_string())
        );
        assert_eq!(ast.to_filter_string(), "(uid=alice)");
    }

    #[test]
    fn parse_present() {
        let ast = parse_ldap_filter("(uid=*)").unwrap();
        assert_eq!(ast, LdapFilter::Present("uid".to_string()));
        assert_eq!(ast.to_filter_string(), "(uid=*)");
    }

    #[test]
    fn parse_and() {
        let ast = parse_ldap_filter("(&(uid=alice)(objectClass=user))").unwrap();
        assert_eq!(
            ast,
            LdapFilter::And(vec![
                LdapFilter::Equality("uid".to_string(), "alice".to_string()),
                LdapFilter::Equality("objectClass".to_string(), "user".to_string()),
            ])
        );
    }

    #[test]
    fn parse_or() {
        let ast = parse_ldap_filter("(|(uid=alice)(uid=bob))").unwrap();
        assert_eq!(
            ast,
            LdapFilter::Or(vec![
                LdapFilter::Equality("uid".to_string(), "alice".to_string()),
                LdapFilter::Equality("uid".to_string(), "bob".to_string()),
            ])
        );
    }

    #[test]
    fn parse_not() {
        let ast = parse_ldap_filter("(!(uid=admin))").unwrap();
        assert_eq!(
            ast,
            LdapFilter::Not(Box::new(LdapFilter::Equality(
                "uid".to_string(),
                "admin".to_string()
            )))
        );
    }

    #[test]
    fn parse_greater_or_equal() {
        let ast = parse_ldap_filter("(uid>=a)").unwrap();
        assert_eq!(
            ast,
            LdapFilter::GreaterOrEqual("uid".to_string(), "a".to_string())
        );
    }

    #[test]
    fn parse_less_or_equal() {
        let ast = parse_ldap_filter("(uid<=z)").unwrap();
        assert_eq!(
            ast,
            LdapFilter::LessOrEqual("uid".to_string(), "z".to_string())
        );
    }

    #[test]
    fn parse_substring_initial() {
        let ast = parse_ldap_filter("(uid=abc*)").unwrap();
        assert_eq!(
            ast,
            LdapFilter::Substring(
                "uid".to_string(),
                SubstringValue {
                    initial: Some("abc".to_string()),
                    any: vec![],
                    final_: None,
                }
            )
        );
    }

    #[test]
    fn parse_substring_any() {
        let ast = parse_ldap_filter("(uid=*abc*)").unwrap();
        assert_eq!(
            ast,
            LdapFilter::Substring(
                "uid".to_string(),
                SubstringValue {
                    initial: None,
                    any: vec!["abc".to_string()],
                    final_: None,
                }
            )
        );
    }

    #[test]
    fn parse_substring_final() {
        let ast = parse_ldap_filter("(uid=*abc)").unwrap();
        assert_eq!(
            ast,
            LdapFilter::Substring(
                "uid".to_string(),
                SubstringValue {
                    initial: None,
                    any: vec![],
                    final_: Some("abc".to_string()),
                }
            )
        );
    }

    #[test]
    fn parse_substring_all_parts() {
        let ast = parse_ldap_filter("(uid=a*b*c)").unwrap();
        assert_eq!(
            ast,
            LdapFilter::Substring(
                "uid".to_string(),
                SubstringValue {
                    initial: Some("a".to_string()),
                    any: vec!["b".to_string()],
                    final_: Some("c".to_string()),
                }
            )
        );
    }

    #[test]
    fn sanitize_preserves_substring_wildcard() {
        // In RFC 4515, `*` inside a value is a substring wildcard.
        let result = sanitize_admin_search_filter("(uid=admin*)").unwrap();
        assert_eq!(result, "(uid=admin*)");
    }

    #[test]
    fn sanitize_preserves_complex_filter() {
        let input = "(&(objectClass=user)(!(mail=*)))";
        let result = sanitize_admin_search_filter(input).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn reject_empty_filter() {
        assert!(parse_ldap_filter("").is_err());
    }

    #[test]
    fn reject_mismatched_parens() {
        assert!(parse_ldap_filter("(uid=alice").is_err());
    }

    #[test]
    fn and_requires_children() {
        assert!(parse_ldap_filter("(&)").is_err());
    }

    #[test]
    fn or_requires_children() {
        assert!(parse_ldap_filter("(|)").is_err());
    }

    #[test]
    fn escape_special_chars_in_value() {
        // Parentheses in values must be escaped per RFC 4515.
        let result = sanitize_admin_search_filter("(cn=foo\\28bar\\29)").unwrap();
        assert_eq!(result, "(cn=foo\\28bar\\29)");
    }

    #[test]
    fn rejects_unescaped_parens_in_value() {
        // Without escaping, `(` is treated as a sub-filter start.
        let err = sanitize_admin_search_filter("(cn=foo(bar))").unwrap_err();
        assert!(err.message().contains("LDAP filter"));
    }
}
