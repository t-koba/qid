use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::{
    oauth::{Device, ServiceAccount},
    workload::WorkloadIdentity,
};

/// A user account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub realm_id: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub display_name: Option<String>,
    #[serde(default)]
    pub failed_login_attempts: u32,
    #[serde(default)]
    pub locked_until: Option<u64>,
    /// Organization identifier for the `org` claim in assertions (§13.2).
    #[serde(default)]
    pub org: Option<String>,
}

/// A unified subject reference for humans, service accounts, devices, and workloads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subject {
    pub id: String,
    pub realm_id: String,
    pub kind: SubjectKind,
    pub display: Option<String>,
    #[serde(default)]
    pub identifiers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    User,
    ServiceAccount,
    Device,
    Workload,
}

impl Subject {
    pub fn stable_key(&self) -> String {
        format!("{}:{}:{}", self.realm_id, self.kind.as_str(), self.id)
    }

    pub fn from_user(user: &User) -> Self {
        let mut identifiers = BTreeMap::new();
        if let Some(email) = &user.email {
            identifiers.insert("email".to_string(), email.clone());
        }
        Self {
            id: user.id.clone(),
            realm_id: user.realm_id.clone(),
            kind: SubjectKind::User,
            display: user.display_name.clone().or_else(|| user.email.clone()),
            identifiers,
        }
    }

    pub fn from_service_account(service_account: &ServiceAccount) -> Self {
        let mut identifiers = BTreeMap::new();
        identifiers.insert("client_id".to_string(), service_account.client_id.clone());
        Self {
            id: service_account.id.clone(),
            realm_id: service_account.realm_id.clone(),
            kind: SubjectKind::ServiceAccount,
            display: service_account.description.clone(),
            identifiers,
        }
    }

    pub fn from_device(device: &Device) -> Self {
        let mut identifiers = BTreeMap::new();
        identifiers.insert("user_id".to_string(), device.user_id.clone());
        identifiers.insert("device_type".to_string(), device.device_type.clone());
        Self {
            id: device.id.clone(),
            realm_id: device.realm_id.clone(),
            kind: SubjectKind::Device,
            display: device.device_name.clone(),
            identifiers,
        }
    }

    pub fn from_workload(workload: &WorkloadIdentity) -> Self {
        let mut identifiers = BTreeMap::new();
        identifiers.insert("spiffe_id".to_string(), workload.spiffe_id.clone());
        identifiers.insert("trust_domain".to_string(), workload.trust_domain.clone());
        Self {
            id: workload.id.clone(),
            realm_id: workload.realm_id.clone(),
            kind: SubjectKind::Workload,
            display: workload.description.clone(),
            identifiers,
        }
    }
}

impl SubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::ServiceAccount => "service_account",
            Self::Device => "device",
            Self::Workload => "workload",
        }
    }
}

#[cfg(test)]
mod subject_tests {
    use super::*;

    #[test]
    fn subject_from_user_preserves_realm_display_and_email_identifier() {
        let user = User {
            id: "user-1".to_string(),
            realm_id: "corp".to_string(),
            email: Some("alice@example.com".to_string()),
            email_verified: true,
            display_name: Some("Alice".to_string()),
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        };

        let subject = Subject::from_user(&user);

        assert_eq!(subject.kind, SubjectKind::User);
        assert_eq!(subject.stable_key(), "corp:user:user-1");
        assert_eq!(subject.display.as_deref(), Some("Alice"));
        assert_eq!(
            subject.identifiers.get("email").map(String::as_str),
            Some("alice@example.com")
        );
    }

    #[test]
    fn subject_from_machine_entities_uses_authoritative_identifiers() {
        let service_account = ServiceAccount {
            id: "sa-1".to_string(),
            client_id: "client-1".to_string(),
            realm_id: "corp".to_string(),
            description: Some("Batch processor".to_string()),
            created_at: 100,
        };
        let device = Device {
            id: "device-1".to_string(),
            user_id: "user-1".to_string(),
            realm_id: "corp".to_string(),
            device_name: Some("Laptop".to_string()),
            device_type: "macos".to_string(),
            posture: vec!["disk_encrypted".to_string()],
            registered_at: 100,
            last_seen_at: 120,
        };
        let workload = WorkloadIdentity {
            id: "workload-1".to_string(),
            realm_id: "corp".to_string(),
            spiffe_id: "spiffe://prod.example/ns/default/sa/api".to_string(),
            description: Some("API".to_string()),
            trust_domain: "prod.example".to_string(),
            authorities_json: serde_json::json!({ "bundle": "prod" }),
        };

        let service_subject = Subject::from_service_account(&service_account);
        let device_subject = Subject::from_device(&device);
        let workload_subject = Subject::from_workload(&workload);

        assert_eq!(
            service_subject
                .identifiers
                .get("client_id")
                .map(String::as_str),
            Some("client-1")
        );
        assert_eq!(
            device_subject
                .identifiers
                .get("user_id")
                .map(String::as_str),
            Some("user-1")
        );
        assert_eq!(
            workload_subject
                .identifiers
                .get("spiffe_id")
                .map(String::as_str),
            Some("spiffe://prod.example/ns/default/sa/api")
        );
        assert_eq!(workload_subject.stable_key(), "corp:workload:workload-1");
    }
}
