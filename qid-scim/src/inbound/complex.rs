//! Validation of the advertised complex attribute containers.
//!
//! The schema discovery promises a `name` object, an `emails` array and a
//! `members` array with typed subattributes. A write that supplies another
//! shape is a client error, not a value to store and normalize later.

use super::schemas::{EMAIL_SUBATTRIBUTES, NAME_SUBATTRIBUTES};
use qid_core::error::QidError;
use serde_json::Value;

fn invalid(attribute: &str, expected: &str) -> QidError {
    QidError::BadRequest {
        message: format!("{attribute} must be {expected}"),
    }
}

/// Validate the supplied complex containers of a User write.
pub(crate) fn validate_user_complex(
    name: Option<&Value>,
    emails: Option<&Value>,
) -> Result<(), QidError> {
    if let Some(name) = name {
        validate_name(name)?;
    }
    if let Some(emails) = emails {
        validate_emails(emails)?;
    }
    Ok(())
}

/// Validate the supplied complex container of a Group write.
pub(crate) fn validate_group_complex(members: Option<&Value>) -> Result<(), QidError> {
    if let Some(members) = members {
        validate_members(members)?;
    }
    Ok(())
}

/// Check a complex container against the advertised attribute table. A name
/// the table does not advertise is rejected, so the advertised schema stays
/// the only vocabulary a write may use.
fn validate_subattributes(
    value: &Value,
    attribute: &str,
    table: &[(&str, &str)],
) -> Result<(), QidError> {
    let Some(object) = value.as_object() else {
        return Err(invalid(attribute, "an object"));
    };
    for (key, item) in object {
        let Some((_, ty)) = table.iter().find(|(name, _)| *name == key) else {
            return Err(invalid(
                &format!("{attribute}.{key}"),
                "an advertised attribute",
            ));
        };
        let (valid, expected) = match *ty {
            "boolean" => (item.is_boolean(), "a boolean"),
            _ => (item.is_string(), "a string"),
        };
        if !valid {
            return Err(invalid(&format!("{attribute}.{key}"), expected));
        }
    }
    Ok(())
}

/// The `name` container holds the advertised string subattributes.
pub(crate) fn validate_name(value: &Value) -> Result<(), QidError> {
    validate_subattributes(value, "name", &NAME_SUBATTRIBUTES)
}

/// The `emails` container is an array of the advertised email subattributes.
pub(crate) fn validate_emails(value: &Value) -> Result<(), QidError> {
    let Some(items) = value.as_array() else {
        return Err(invalid("emails", "an array"));
    };
    for item in items {
        validate_subattributes(item, "emails", &EMAIL_SUBATTRIBUTES)?;
    }
    Ok(())
}

/// The `enterprise` extension is an object; a sequence would be stored as it
/// arrived instead of the advertised shape.
pub(crate) fn validate_enterprise(enterprise: Option<&Value>) -> Result<(), QidError> {
    if let Some(enterprise) = enterprise
        && !enterprise.is_object()
    {
        return Err(invalid("enterprise", "an object"));
    }
    Ok(())
}

/// The `members` container is an array of member objects.
pub(crate) fn validate_members(value: &Value) -> Result<(), QidError> {
    let Some(items) = value.as_array() else {
        return Err(invalid("members", "an array"));
    };
    for item in items {
        validate_member(item)?;
    }
    Ok(())
}

/// A member is an object. PATCH `add` accepts one member or a list of them.
pub(crate) fn validate_member(value: &Value) -> Result<(), QidError> {
    if !value.is_object() {
        return Err(invalid("members", "an array of objects"));
    }
    Ok(())
}
