use serde::{Deserialize, Serialize};

use crate::error::{QidError, QidResult};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct TenantId(pub String);

impl TenantId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for TenantId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for TenantId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct RealmId(pub String);

impl RealmId {
    pub fn new(value: String) -> QidResult<Self> {
        if value.trim().is_empty() {
            return Err(QidError::BadRequest {
                message: "RealmId must not be empty".to_string(),
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for RealmId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for RealmId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}
