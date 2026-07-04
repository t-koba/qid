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
