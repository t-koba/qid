//! Inbound SCIM 2.0 endpoint handlers.

mod bulk;
mod complex;
mod groups;
mod list;
mod schemas;
mod users;
mod write;

pub(crate) use bulk::bulk;
pub(crate) use groups::{
    create_group, delete_group, get_group, list_groups, patch_group, replace_group,
};
pub(crate) use schemas::{resource_types, schemas, service_provider_config};
pub(crate) use users::{create_user, delete_user, get_user, list_users, patch_user, replace_user};

use qid_core::error::QidError;
use serde::Deserialize;

pub(crate) const MAX_LIST_RESULTS: usize = 200;
pub(crate) const MAX_BULK_OPERATIONS: usize = 100;

pub(crate) fn default_realm() -> String {
    "corp".to_string()
}

pub(crate) fn realm_opt(
    c: Option<&crate::ScimRequestContext>,
    r: Option<String>,
) -> Option<String> {
    c.map(|c| c.realm_id.clone()).or(r)
}

fn default_bulk_fail_on_errors() -> usize {
    1
}

#[derive(Debug, Deserialize)]
pub(crate) struct ListQuery {
    #[serde(default = "default_realm")]
    pub(crate) realm: String,
    #[serde(default)]
    pub(crate) start_index: Option<usize>,
    #[serde(default)]
    pub(crate) count: Option<usize>,
    #[serde(default)]
    pub(crate) filter: Option<String>,
    /// RFC 9865 §4.2: opaque pagination cursor returned by a previous
    /// call to the same endpoint. When present, `startIndex` is ignored.
    #[serde(default)]
    pub(crate) cursor: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct DeleteQuery {
    #[serde(default)]
    pub(crate) hard_delete: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PatchRequest {
    #[serde(default, rename = "Operations")]
    pub(crate) operations: Vec<PatchOperation>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PatchOperation {
    pub(crate) op: String,
    #[serde(default)]
    pub(crate) path: Option<String>,
    #[serde(default)]
    pub(crate) value: Option<serde_json::Value>,
}

/// SCIM user create/replace payload. There is intentionally no
/// `directory_provider_id` field: ownership is server-owned and never
/// accepted from clients (including inside `enterprise`).
#[derive(Debug, Deserialize)]
pub(crate) struct CreateUser {
    #[serde(default)]
    pub(crate) realm: Option<String>,
    #[serde(rename = "externalId")]
    #[serde(default)]
    pub(crate) external_id: Option<String>,
    #[serde(rename = "userName")]
    pub(crate) user_name: String,
    #[serde(default)]
    pub(crate) name: Option<serde_json::Value>,
    #[serde(default)]
    pub(crate) emails: Option<serde_json::Value>,
    #[serde(
        default,
        rename = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
    )]
    pub(crate) enterprise: Option<serde_json::Value>,
    #[serde(default)]
    pub(crate) active: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateGroup {
    #[serde(default)]
    pub(crate) realm: Option<String>,
    #[serde(rename = "displayName")]
    pub(crate) display_name: String,
    #[serde(default)]
    pub(crate) members: Option<serde_json::Value>,
}

/// SCIM Device create payload. The attribute names are the ones the schema
/// discovery advertises, and an unknown name is rejected instead of dropped.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateDevice {
    #[serde(default)]
    pub(crate) realm: Option<String>,
    /// Optional client-chosen id; the server assigns one when it is absent.
    #[serde(default)]
    pub(crate) id: Option<String>,
    #[serde(default, rename = "schemas")]
    pub(crate) schemas: Option<Vec<String>>,
    #[serde(default, rename = "displayName")]
    pub(crate) display_name: Option<String>,
    #[serde(
        default,
        rename = "urn:ietf:params:scim:schemas:extension:device:2.0:Device"
    )]
    pub(crate) extension: Option<DeviceExtension>,
}

/// RFC 9944 device extension attributes.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceExtension {
    #[serde(default)]
    pub(crate) manufacturer: Option<String>,
    #[serde(default)]
    pub(crate) model: Option<String>,
    #[serde(default)]
    pub(crate) os: Option<String>,
    #[serde(default, rename = "osVersion")]
    pub(crate) os_version: Option<String>,
    #[serde(default, rename = "lastSeen")]
    pub(crate) last_seen: Option<u64>,
}

/// SCIM EventSubscription create payload. `createdAt` is server-owned, so a
/// supplied value is accepted and ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateEventSubscription {
    #[serde(default)]
    pub(crate) realm: Option<String>,
    /// Optional client-chosen id; the server assigns one when it is absent.
    #[serde(default)]
    pub(crate) id: Option<String>,
    #[serde(default, rename = "schemas")]
    pub(crate) schemas: Option<Vec<String>>,
    /// Server-owned: a supplied value is accepted and ignored.
    #[serde(default, rename = "createdAt")]
    pub(crate) _created_at: Option<u64>,
    #[serde(rename = "callback")]
    pub(crate) callback_url: String,
    #[serde(rename = "eventTypes")]
    pub(crate) event_types: Vec<String>,
    #[serde(default = "default_enabled")]
    pub(crate) enabled: bool,
}

fn default_enabled() -> bool {
    true
}

/// Deserialize a payload that must be a JSON object. A derived struct would
/// otherwise accept a JSON sequence and map it positionally onto its fields.
pub(crate) fn parse_object<T: serde::de::DeserializeOwned>(
    raw: serde_json::Value,
    description: &str,
) -> Result<T, QidError> {
    if !raw.is_object() {
        return Err(QidError::BadRequest {
            message: format!("{description} must be a JSON object"),
        });
    }
    serde_json::from_value(raw).map_err(|e| QidError::BadRequest {
        message: format!("invalid {description} data: {e}"),
    })
}

pub(crate) fn string_value(
    value: Option<serde_json::Value>,
    field: &str,
) -> Result<String, QidError> {
    value
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .ok_or_else(|| QidError::BadRequest {
            message: format!("{field} must be a string"),
        })
}

pub(crate) fn bool_value(value: Option<serde_json::Value>, field: &str) -> Result<bool, QidError> {
    value
        .and_then(|value| value.as_bool())
        .ok_or_else(|| QidError::BadRequest {
            message: format!("{field} must be a boolean"),
        })
}

pub(crate) fn unsupported_patch(op: &str, path: &str) -> QidError {
    QidError::BadRequest {
        message: format!("unsupported SCIM PATCH operation {op} {path}"),
    }
}

/// Schemas with implemented User behavior.
pub(crate) const CORE_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub(crate) const ENTERPRISE_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

/// Fail closed when a payload carries a schema without implemented behavior.
///
/// `CreateUser` serde intentionally ignores unknown fields, so the raw value
/// must be inspected first: an unsupported `schemas` entry or any top-level
/// URN key other than the Enterprise extension is rejected with a static
/// error that never echoes client-supplied values. Ordinary unknown fields
/// without a URN keep their existing lenient behavior.
pub(crate) fn unsupported_schema_error() -> QidError {
    QidError::BadRequest {
        message: "unsupported SCIM schema extension".to_string(),
    }
}

fn has_urn_scheme(value: &str) -> bool {
    value
        .get(..4)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("urn:"))
}

pub(crate) fn reject_unsupported_user_extensions(raw: &serde_json::Value) -> Result<(), QidError> {
    let Some(object) = raw.as_object() else {
        return Ok(());
    };
    if let Some(schemas) = object.get("schemas") {
        let Some(entries) = schemas.as_array() else {
            return Err(unsupported_schema_error());
        };
        for entry in entries {
            let supported = entry
                .as_str()
                .is_some_and(|id| id == CORE_USER_SCHEMA || id == ENTERPRISE_SCHEMA);
            if !supported {
                return Err(unsupported_schema_error());
            }
        }
    }
    if object
        .keys()
        .any(|key| has_urn_scheme(key) && key != ENTERPRISE_SCHEMA)
    {
        return Err(unsupported_schema_error());
    }
    Ok(())
}

/// Validate the raw User payload and deserialize it without widening
/// `deny_unknown_fields` to other fields.
pub(crate) fn parse_create_user(raw: serde_json::Value) -> Result<CreateUser, QidError> {
    reject_unsupported_user_extensions(&raw)?;
    parse_object(raw, "user")
}

/// Reject a `schemas` array that names a schema the endpoint does not
/// implement, so an unsupported schema never reaches storage.
pub(crate) fn reject_unsupported_schemas(
    schemas: Option<&[String]>,
    supported: &[&str],
) -> Result<(), QidError> {
    let Some(entries) = schemas else {
        return Ok(());
    };
    for entry in entries {
        if !supported.contains(&entry.as_str()) {
            return Err(unsupported_schema_error());
        }
    }
    Ok(())
}

/// Validate the raw Group payload and deserialize it.
pub(crate) fn parse_create_group(raw: serde_json::Value) -> Result<CreateGroup, QidError> {
    parse_object(raw, "group")
}

/// Validate the raw Device payload and deserialize it. The advertised
/// attribute names are the only accepted ones.
pub(crate) fn parse_create_device(raw: serde_json::Value) -> Result<CreateDevice, QidError> {
    // The extension container is an object; a sequence would be mapped
    // positionally onto its attributes.
    if let Some(extension) = raw.get(crate::RFC_9944_DEVICE_SCHEMA)
        && !extension.is_object()
    {
        return Err(QidError::BadRequest {
            message: "device extension must be a JSON object".to_string(),
        });
    }
    let req: CreateDevice = parse_object(raw, "device")?;
    reject_unsupported_schemas(
        req.schemas.as_deref(),
        &[crate::CORE_DEVICE_SCHEMA, crate::RFC_9944_DEVICE_SCHEMA],
    )?;
    Ok(req)
}

/// Validate the raw EventSubscription payload and deserialize it. The
/// advertised attribute names are the only accepted ones.
pub(crate) fn parse_create_event_subscription(
    raw: serde_json::Value,
) -> Result<CreateEventSubscription, QidError> {
    let req: CreateEventSubscription = parse_object(raw, "event subscription")?;
    reject_unsupported_schemas(
        req.schemas.as_deref(),
        &[crate::RFC_9967_EVENT_SUBSCRIPTION_SCHEMA],
    )?;
    Ok(req)
}
