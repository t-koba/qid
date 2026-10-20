//! Inbound SCIM 2.0 endpoint handlers.

mod bulk;
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

fn default_realm() -> String {
    "corp".to_string()
}

fn realm_opt(c: Option<&crate::ScimRequestContext>, r: Option<String>) -> Option<String> {
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

/// Schemas with implemented User behavior.
pub(crate) const CORE_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub(crate) const ENTERPRISE_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

/// Fail closed when a User payload carries an extension without behavior.
///
/// `CreateUser` serde intentionally ignores unknown fields, so the raw value
/// must be inspected first: an unsupported `schemas` entry or any top-level
/// URN key other than the Enterprise extension is rejected with a static
/// error that never echoes client-supplied values. Ordinary unknown fields
/// without a URN keep their existing lenient behavior.
pub(crate) fn unsupported_user_schema_error() -> QidError {
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
            return Err(unsupported_user_schema_error());
        };
        for entry in entries {
            let supported = entry
                .as_str()
                .is_some_and(|id| id == CORE_USER_SCHEMA || id == ENTERPRISE_SCHEMA);
            if !supported {
                return Err(unsupported_user_schema_error());
            }
        }
    }
    if object
        .keys()
        .any(|key| has_urn_scheme(key) && key != ENTERPRISE_SCHEMA)
    {
        return Err(unsupported_user_schema_error());
    }
    Ok(())
}

/// Validate the raw User payload and deserialize it without widening
/// `deny_unknown_fields` to other fields.
pub(crate) fn parse_create_user(raw: serde_json::Value) -> Result<CreateUser, QidError> {
    reject_unsupported_user_extensions(&raw)?;
    serde_json::from_value::<CreateUser>(raw).map_err(|e| QidError::BadRequest {
        message: format!("invalid user data: {e}"),
    })
}
