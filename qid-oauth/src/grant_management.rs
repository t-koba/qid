//! OAuth 2.0 Grant Management API.

use qid_core::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Grant {
    pub id: String,
    pub client_id: String,
    pub subject: String,
    pub resource: Option<String>,
    pub scopes: Vec<String>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantRequest {
    pub grant_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantResponse {
    pub grants: Vec<Grant>,
}

pub fn filter_grants_by_client(grants: &[Grant], client_id: &str) -> Vec<Grant> {
    grants
        .iter()
        .filter(|g| g.client_id == client_id)
        .cloned()
        .collect()
}

pub fn revoke_grant(grants: &mut [Grant], grant_id: &str) -> QidResult<()> {
    let grant = grants
        .iter_mut()
        .find(|g| g.id == grant_id)
        .ok_or_else(|| QidError::NotFound {
            resource: format!("grant {grant_id}"),
        })?;
    grant.revoked = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_filter_by_client() {
        let grants = vec![
            Grant {
                id: "g1".to_string(),
                client_id: "client-a".to_string(),
                subject: "user-1".to_string(),
                resource: None,
                scopes: vec!["read".to_string()],
                created_at: 1000,
                expires_at: None,
                revoked: false,
            },
            Grant {
                id: "g2".to_string(),
                client_id: "client-b".to_string(),
                subject: "user-1".to_string(),
                resource: None,
                scopes: vec!["write".to_string()],
                created_at: 1000,
                expires_at: None,
                revoked: false,
            },
        ];
        let filtered = filter_grants_by_client(&grants, "client-a");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "g1");
    }

    #[test]
    fn grant_revocation() {
        let mut grants = vec![Grant {
            id: "g1".to_string(),
            client_id: "client-a".to_string(),
            subject: "user-1".to_string(),
            resource: None,
            scopes: vec![],
            created_at: 1000,
            expires_at: None,
            revoked: false,
        }];
        revoke_grant(&mut grants, "g1").unwrap();
        assert!(grants[0].revoked);
    }
}
