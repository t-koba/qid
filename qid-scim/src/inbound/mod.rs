//! Inbound SCIM 2.0 endpoint handlers.

mod bulk;
mod groups;
mod schemas;
mod users;

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

#[derive(Debug, Deserialize)]
pub(crate) struct CreateUser {
    #[serde(default = "default_realm")]
    pub(crate) realm: String,
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
    #[serde(default = "default_realm")]
    pub(crate) realm: String,
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
