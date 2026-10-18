use serde::{Deserialize, Serialize};

/// A SCIM user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimUser {
    pub id: String,
    pub realm_id: String,
    pub external_id: Option<String>,
    pub user_name: String,
    pub name_json: serde_json::Value,
    pub emails_json: serde_json::Value,
    #[serde(default)]
    pub enterprise_json: serde_json::Value,
    /// Server-owned directory provider that owns this user for lifecycle
    /// reconciliation. Never accepted from SCIM clients and never rendered
    /// in SCIM responses; directory sync is the only writer.
    #[serde(default)]
    pub directory_provider_id: Option<String>,
    pub active: bool,
}

/// A SCIM group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroup {
    pub id: String,
    pub realm_id: String,
    pub display_name: String,
    pub members_json: serde_json::Value,
}

/// A FedCM identity record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FedCmIdentity {
    pub id: String,
    pub realm_id: String,
    pub account_id: String,
    pub email: String,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub picture_url: Option<String>,
    pub approved_clients: Vec<String>,
}
