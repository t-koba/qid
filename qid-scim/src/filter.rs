//! SCIM 2.0 filter parsing and helpers.

use qid_core::error::{QidError, QidResult};

#[derive(Debug)]
pub(crate) struct EqFilter<'a> {
    pub(crate) attribute: &'a str,
    pub(crate) value: EqFilterValue,
}

#[derive(Debug)]
pub(crate) enum EqFilterValue {
    String(String),
    Bool(bool),
}

const ENTERPRISE_USER_SCHEMA_FILTER_PREFIX: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:";

const MAX_FILTER_LENGTH: usize = 2048;

pub(crate) fn parse_eq_filter<'a>(
    filter: &'a str,
    allowed_attributes: &[&str],
) -> QidResult<EqFilter<'a>> {
    if filter.len() > MAX_FILTER_LENGTH {
        return Err(QidError::BadRequest {
            message: format!("SCIM filter exceeds maximum length of {MAX_FILTER_LENGTH}"),
        });
    }
    let unquoted = without_quoted_values(filter);
    for op in &[
        " and ", " or ", " pr", " lt ", " gt ", " le ", " ge ", " ne ",
    ] {
        if unquoted.contains(op) {
            return Err(QidError::BadRequest {
                message: format!("unsupported SCIM filter operator: {op}"),
            });
        }
    }
    let (attribute, value) =
        filter
            .trim()
            .split_once(" eq ")
            .ok_or_else(|| QidError::BadRequest {
                message: "unsupported SCIM filter".to_string(),
            })?;
    if !allowed_attributes.contains(&attribute) {
        return Err(QidError::BadRequest {
            message: format!("unsupported SCIM filter attribute {attribute}"),
        });
    }
    let value = parse_eq_filter_value(value.trim())?;
    Ok(EqFilter { attribute, value })
}

/// The filter with the quoted values blanked out, so an operator word inside a
/// quoted value is not read as an operator.
fn without_quoted_values(filter: &str) -> String {
    let mut out = String::with_capacity(filter.len());
    let mut quoted = false;
    let mut escaped = false;
    for ch in filter.chars() {
        if quoted {
            out.push(' ');
        } else {
            out.push(ch);
        }
        if escaped {
            escaped = false;
        } else if quoted && ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            quoted = !quoted;
        }
    }
    out
}

pub(crate) fn parse_eq_filter_value(value: &str) -> QidResult<EqFilterValue> {
    if let Some(value) = value.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return Ok(EqFilterValue::String(unescape_filter_value(value)?));
    }
    match value {
        "true" => Ok(EqFilterValue::Bool(true)),
        "false" => Ok(EqFilterValue::Bool(false)),
        _ => Err(QidError::BadRequest {
            message: "SCIM filter value must be a quoted string or boolean".to_string(),
        }),
    }
}

/// The value of a quoted filter value, with its JSON escapes decoded, so a
/// value that carries a quote matches the stored value.
fn unescape_filter_value(value: &str) -> QidResult<String> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(|e| QidError::BadRequest {
        message: format!("SCIM filter value is not a valid quoted string: {e}"),
    })
}

pub(crate) fn string_filter_matches(filter: &EqFilterValue, value: &str) -> bool {
    matches!(filter, EqFilterValue::String(expected) if *expected == value)
}

pub(crate) fn bool_filter_matches(filter: &EqFilterValue, value: bool) -> bool {
    matches!(filter, EqFilterValue::Bool(expected) if *expected == value)
}

pub(crate) fn enterprise_filter_attribute(attribute: &str) -> Option<&str> {
    attribute
        .strip_prefix("enterprise.")
        .or_else(|| attribute.strip_prefix(ENTERPRISE_USER_SCHEMA_FILTER_PREFIX))
}
