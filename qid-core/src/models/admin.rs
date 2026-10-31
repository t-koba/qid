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
    pub source_session_id: Option<String>,
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

impl AdminElevation {
    /// Validate stored provenance; assurance, roles and elevation policy remain
    /// the consumer's responsibility. Never substitute a different live session.
    pub fn source_session_is_valid(
        &self,
        admin: &Admin,
        session: &super::Session,
        user: &super::User,
        realm_tenant: Option<&str>,
        now: u64,
    ) -> bool {
        self.source_session_id
            .as_deref()
            .is_some_and(|id| !id.trim().is_empty() && id == session.id)
            && self.admin_id == admin.id
            && self.tenant_id == admin.tenant_id
            && admin.subject == session.user_id
            && session.user_id == user.id
            && session.realm_id == user.realm_id
            && realm_tenant == Some(admin.tenant_id.as_str())
            && session.is_active(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Session, User};

    #[test]
    fn source_session_requires_exact_current_identity_and_inclusive_deadlines() {
        let admin = Admin {
            id: "admin".into(),
            tenant_id: "tenant".into(),
            subject: "user".into(),
            roles: vec![],
            created_at: 0,
        };
        let elevation = AdminElevation {
            id: "elevation".into(),
            admin_id: admin.id.clone(),
            tenant_id: admin.tenant_id.clone(),
            source_session_id: Some("source".into()),
            acr: None,
            amr: vec![],
            elevation_expires_at: 200,
            created_at: 0,
        };
        let session = Session {
            id: "source".into(),
            realm_id: "realm".into(),
            user_id: "user".into(),
            auth_time: 0,
            acr: None,
            amr: vec![],
            idle_expires_at: 100,
            absolute_expires_at: 100,
            revoked: false,
            created_at: 0,
            cnf: None,
        };
        let user = User {
            id: "user".into(),
            realm_id: "realm".into(),
            email: None,
            email_verified: false,
            display_name: None,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        };
        assert!(elevation.source_session_is_valid(&admin, &session, &user, Some("tenant"), 100));
        assert!(!elevation.source_session_is_valid(&admin, &session, &user, Some("tenant"), 101));
        for case in [
            "unbound",
            "empty",
            "blank",
            "other_session",
            "admin",
            "tenant",
            "subject",
            "user",
            "realm",
            "realm_tenant",
            "missing_tenant",
            "revoked",
            "idle",
            "absolute",
        ] {
            let (mut e, mut s, mut u) = (elevation.clone(), session.clone(), user.clone());
            let mut tenant = Some("tenant");
            match case {
                "unbound" => e.source_session_id = None,
                "empty" => e.source_session_id = Some(String::new()),
                "blank" => e.source_session_id = Some(" ".into()),
                "other_session" => s.id = "other".into(),
                "admin" => e.admin_id = "other".into(),
                "tenant" => e.tenant_id = "other".into(),
                "subject" => s.user_id = "other".into(),
                "user" => u.id = "other".into(),
                "realm" => u.realm_id = "other".into(),
                "realm_tenant" => tenant = Some("other"),
                "missing_tenant" => tenant = None,
                "revoked" => s.revoked = true,
                "idle" => s.idle_expires_at = 99,
                "absolute" => s.absolute_expires_at = 99,
                _ => unreachable!(),
            }
            assert!(
                !e.source_session_is_valid(&admin, &s, &u, tenant, 100),
                "{case}"
            );
        }
    }
}
