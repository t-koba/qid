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
    /// Server-owned authoritative deprovision timestamp (seconds since epoch).
    /// Directory/HR lifecycle is the only writer; SCIM clients can neither
    /// set nor clear it. The wire `enterprise` extension only projects this
    /// value and never acts as authority. Legacy `enterprise_json`
    /// `deprovisioned_at` markers from before this field existed are not
    /// trusted and are never backfilled: old rows read as `None` until a new
    /// lifecycle transition stamps them. Preserve historical evidence only
    /// through an explicit reviewed migration.
    #[serde(default)]
    pub deprovisioned_at: Option<u64>,
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

#[cfg(test)]
mod tests {
    use super::ScimUser;

    #[test]
    fn legacy_users_default_server_owned_lifecycle_fields_and_ignore_legacy_timestamp_as_authority()
    {
        let user: ScimUser = serde_json::from_value(serde_json::json!({
            "id": "legacy-user",
            "realm_id": "corp",
            "external_id": "uid=legacy,dc=example,dc=com",
            "user_name": "legacy@example.com",
            "name_json": {},
            "emails_json": [],
            "enterprise_json": {"deprovisioned_at": 1_050},
            "active": false
        }))
        .unwrap();

        assert_eq!(user.directory_provider_id, None);
        assert_eq!(user.deprovisioned_at, None);
        assert_eq!(user.enterprise_json["deprovisioned_at"], 1_050);
    }
}
