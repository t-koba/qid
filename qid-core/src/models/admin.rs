use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Admin {
    pub id: String,
    pub tenant_id: String,
    pub subject: String,
    pub roles: Vec<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminElevation {
    pub id: String,
    pub tenant_id: String,
    pub admin_id: String,
    pub acr: Option<String>,
    pub amr: Vec<String>,
    pub elevation_expires_at: u64,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminApproval {
    pub id: String,
    pub tenant_id: String,
    pub approver_admin_id: String,
    pub target_admin_id: String,
    pub reason: Option<String>,
    pub approved_at: u64,
    pub expires_at: u64,
    pub consumed: bool,
}
