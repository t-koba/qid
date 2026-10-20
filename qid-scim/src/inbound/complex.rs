//! Validation of the advertised complex attribute containers.
//!
//! The schema discovery promises a `name` object, an `emails` array and a
//! `members` array with typed subattributes. A write that supplies another
//! shape is a client error, not a value to store and normalize later.

use qid_core::error::QidError;
use serde_json::Value;

/// The advertised `name` subattributes, all strings.
const NAME_ATTRIBUTES: [&str; 6] = [
    "formatted",
    "familyName",
    "givenName",
    "middleName",
    "honorificPrefix",
    "honorificSuffix",
];
/// The advertised `emails` subattributes; `primary` is the only boolean.
const EMAIL_ATTRIBUTES: [&str; 4] = ["value", "display", "type", "primary"];

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

/// The `name` container is an object whose advertised subattributes are strings.
pub(crate) fn validate_name(value: &Value) -> Result<(), QidError> {
    let Some(object) = value.as_object() else {
        return Err(invalid("name", "an object"));
    };
    for (key, item) in object {
        if NAME_ATTRIBUTES.contains(&key.as_str()) && !item.is_string() {
            return Err(invalid(&format!("name.{key}"), "a string"));
        }
    }
    Ok(())
}

/// The `emails` container is an array of objects whose `primary` subattribute
/// is a boolean and whose other advertised subattributes are strings.
pub(crate) fn validate_emails(value: &Value) -> Result<(), QidError> {
    let Some(items) = value.as_array() else {
        return Err(invalid("emails", "an array"));
    };
    for item in items {
        let Some(object) = item.as_object() else {
            return Err(invalid("emails", "an array of objects"));
        };
        for (key, entry) in object {
            if !EMAIL_ATTRIBUTES.contains(&key.as_str()) {
                continue;
            }
            let boolean = key == "primary";
            let valid = if boolean {
                entry.is_boolean()
            } else {
                entry.is_string()
            };
            if !valid {
                return Err(invalid(
                    &format!("emails.{key}"),
                    if boolean { "a boolean" } else { "a string" },
                ));
            }
        }
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
