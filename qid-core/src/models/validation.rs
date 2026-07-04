use crate::error::{QidError, QidResult};
use url::Url;

pub(crate) fn require_non_empty(field: &str, value: &str) -> QidResult<()> {
    if value.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: format!("{field} must not be empty"),
        });
    }
    Ok(())
}

pub(crate) fn validate_hostname(field: &str, hostname: &str) -> QidResult<()> {
    require_non_empty(field, hostname)?;
    let url = Url::parse(&format!("https://{hostname}")).map_err(|_| QidError::BadRequest {
        message: format!("{field} must be a valid DNS hostname"),
    })?;
    if url.host_str() != Some(hostname)
        || hostname.contains('/')
        || hostname.contains(':')
        || hostname.ends_with('.')
    {
        return Err(QidError::BadRequest {
            message: format!("{field} must be a bare DNS hostname"),
        });
    }
    Ok(())
}

pub(crate) fn validate_custom_domain_status(status: &str) -> QidResult<()> {
    require_non_empty("custom domain verification_status", status)?;
    if !matches!(
        status,
        "pending" | "verified" | "active" | "failed" | "suspended"
    ) {
        return Err(QidError::BadRequest {
            message: "custom domain verification_status is not allowed".to_string(),
        });
    }
    Ok(())
}

pub(crate) fn require_lower_hex_sha256(field: &str, value: &str) -> QidResult<()> {
    require_non_empty(field, value)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(QidError::BadRequest {
            message: format!("{field} must be 64 lowercase hex characters"),
        });
    }
    Ok(())
}

pub(crate) fn validate_hex_color(field: &str, color: &str) -> QidResult<()> {
    require_non_empty(field, color)?;
    let Some(hex) = color.strip_prefix('#') else {
        return Err(QidError::BadRequest {
            message: format!("{field} must be a #RRGGBB color"),
        });
    };
    if hex.len() != 6 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(QidError::BadRequest {
            message: format!("{field} must be a #RRGGBB color"),
        });
    }
    Ok(())
}

pub(crate) fn validate_optional_uri(field: &str, uri: Option<&str>) -> QidResult<()> {
    let Some(uri) = uri else {
        return Ok(());
    };
    require_non_empty(field, uri)?;
    let url = Url::parse(uri).map_err(|_| QidError::BadRequest {
        message: format!("{field} must be a valid URL"),
    })?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err(QidError::BadRequest {
            message: format!("{field} must use http or https"),
        });
    }
    Ok(())
}

pub(crate) fn require_json_string(value: &serde_json::Value, key: &str) -> QidResult<String> {
    let string = value
        .get(key)
        .and_then(|value| value.as_str())
        .ok_or_else(|| QidError::BadRequest {
            message: format!("connector config_json.{key} is required"),
        })?;
    require_non_empty(&format!("connector config_json.{key}"), string)?;
    Ok(string.to_string())
}

pub(crate) fn require_json_string_url(value: &serde_json::Value, key: &str) -> QidResult<String> {
    let string = require_json_string(value, key)?;
    let url = Url::parse(&string).map_err(|_| QidError::BadRequest {
        message: format!("connector config_json.{key} must be a valid URL"),
    })?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err(QidError::BadRequest {
            message: format!("connector config_json.{key} must use http or https"),
        });
    }
    Ok(string)
}

pub(crate) fn require_json_array(name: &str, value: &serde_json::Value) -> QidResult<()> {
    if value.is_array() {
        Ok(())
    } else {
        Err(QidError::BadRequest {
            message: format!("{name} must be an array"),
        })
    }
}

pub(crate) fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
