//! Core data models for qid.

mod admin;
mod audit;
mod auth;
mod ciam;
mod iga;
mod oauth;
mod rebac;
mod saas;
mod scim;
mod subject;
mod validation;
mod workload;

pub use admin::{Admin, AdminApproval, AdminElevation};
pub use audit::{
    AuditChainVerification, AuditEvent, AuditRetentionConfig, AuditRetentionEnforcementPlan,
    plan_audit_retention_enforcement, verify_audit_chain_linked, verify_audit_chain_ordered,
    verify_audit_chains_by_realm,
};
pub use auth::{
    Client, ClientType, PasswordCredential, default_client_jwks, default_token_endpoint_auth_method,
};
pub use ciam::{
    CiamConsentGrant, CiamIdentityLink, CiamProgressiveProfile, CiamVerificationChallengeRecord,
    PasswordResetToken,
};
pub use iga::{
    IgaAccessGrantRecord, IgaAccessPackageRecord, IgaAccessRequestRecord,
    IgaAccessReviewCampaignRecord, IgaAccessReviewDecisionRecord, IgaApprovalRecord,
    IgaCertificationRecord, IgaEntitlementRecord, IgaFindingRecord, IgaJitPrivilegeGrantRecord,
};
pub use oauth::{
    AccessToken, AuthorizationCode, BackchannelAuthenticationGrant, Device,
    DeviceAuthorizationGrant, ParRequest, ServiceAccount, Session, TokenFamily, TokenFormat,
    TotpCredential, VcCredentialStatusRecord, WebAuthnCredential,
    default_device_poll_interval_seconds,
};
pub use rebac::{
    CheckRequest, CheckResponse, ExpandNode, ExpandRequest, ExpandResponse, ReadRequest,
    ReadResponse, RelationshipTuple, SubjectRef, TupleDeleteRequest, TupleWriteRequest,
};
pub use saas::{
    AppCatalogEntry, CiamBrand, ComplianceEvidencePack, CustomDomain, DelegatedTenantAdmin,
    MarketplaceConnector, MarketplaceConnectorType, PolicyBundle, UsageBillingEvent,
    default_custom_domain_verification_status,
};
pub use scim::{FedCmIdentity, ScimGroup, ScimUser};
pub use subject::{Subject, SubjectKind, User};
pub use workload::{WorkloadCertificate, WorkloadIdentity};

#[cfg(test)]
mod iga_record_tests {
    use super::*;

    #[test]
    fn iga_access_request_requires_json_arrays_and_expiry_order() {
        let request = IgaAccessRequestRecord {
            id: "req_1".to_string(),
            tenant_id: "tenant_1".to_string(),
            subject: "user_1".to_string(),
            entitlement: "app:admin".to_string(),
            reason: Some("Need access".to_string()),
            status: "pending".to_string(),
            approval_steps_json: serde_json::json!([{"approver":"manager"}]),
            violations_json: serde_json::json!([]),
            expires_at_epoch_seconds: Some(1_700_086_400),
            created_at_epoch_seconds: 1_700_000_000,
        };
        request.validate().unwrap();

        let mut invalid = request.clone();
        invalid.approval_steps_json = serde_json::json!({});
        assert!(invalid.validate().is_err());

        invalid = request;
        invalid.expires_at_epoch_seconds = Some(invalid.created_at_epoch_seconds);
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn iga_approval_and_grant_validate_decision_and_expiry_order() {
        let approval = IgaApprovalRecord {
            id: "approval_1".to_string(),
            tenant_id: "tenant_1".to_string(),
            request_id: "req_1".to_string(),
            approver: "manager_1".to_string(),
            decision: "approved".to_string(),
            approved_at_epoch_seconds: 1_700_000_100,
            expires_at_epoch_seconds: Some(1_700_086_400),
            reason: Some("Approved".to_string()),
        };
        approval.validate().unwrap();

        let mut invalid_approval = approval.clone();
        invalid_approval.decision = "maybe".to_string();
        assert!(invalid_approval.validate().is_err());

        invalid_approval = approval;
        invalid_approval.expires_at_epoch_seconds =
            Some(invalid_approval.approved_at_epoch_seconds);
        assert!(invalid_approval.validate().is_err());

        let grant = IgaAccessGrantRecord {
            id: "grant_1".to_string(),
            tenant_id: "tenant_1".to_string(),
            request_id: "req_1".to_string(),
            subject: "user_1".to_string(),
            entitlement: "app:admin".to_string(),
            granted_at_epoch_seconds: 1_700_000_200,
            expires_at_epoch_seconds: Some(1_700_086_400),
            approval_ids: vec!["approval_1".to_string()],
            revoked: false,
        };
        grant.validate().unwrap();

        let mut invalid_grant = grant;
        invalid_grant.approval_ids = vec!["".to_string()];
        assert!(invalid_grant.validate().is_err());
    }

    #[test]
    fn iga_entitlement_rejects_invalid_risk_and_self_conflict() {
        let entitlement = IgaEntitlementRecord {
            id: "app:erp:admin".to_string(),
            tenant_id: "tenant_1".to_string(),
            display_name: "ERP administrator".to_string(),
            owner: "finance-ops".to_string(),
            risk_level: "high".to_string(),
            conflicting_entitlements: vec!["app:erp:audit".to_string()],
            max_duration_seconds: Some(3600),
            active: true,
        };
        entitlement.validate().unwrap();

        let mut invalid = entitlement.clone();
        invalid.risk_level = "severe".to_string();
        assert!(invalid.validate().is_err());

        invalid = entitlement.clone();
        invalid.conflicting_entitlements = vec![invalid.id.clone()];
        assert!(invalid.validate().is_err());

        invalid = entitlement;
        invalid.max_duration_seconds = Some(0);
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn iga_access_package_requires_entitlements_policy_object_and_duration() {
        let package = IgaAccessPackageRecord {
            id: "pkg_erp_admin".to_string(),
            tenant_id: "tenant_1".to_string(),
            display_name: "ERP administration".to_string(),
            owner: "finance-ops".to_string(),
            entitlement_ids: vec!["app:erp:admin".to_string()],
            approval_policy_json: serde_json::json!({
                "steps": [{"approver": "manager"}]
            }),
            max_duration_seconds: Some(3600),
            active: true,
        };
        package.validate().unwrap();

        let mut invalid = package.clone();
        invalid.entitlement_ids.clear();
        assert!(invalid.validate().is_err());

        invalid = package.clone();
        invalid.approval_policy_json = serde_json::json!([]);
        assert!(invalid.validate().is_err());

        invalid = package;
        invalid.max_duration_seconds = Some(0);
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn iga_jit_privilege_requires_reason_expiry_constraints_and_distinct_approver() {
        let grant = IgaJitPrivilegeGrantRecord {
            id: "jit_1".to_string(),
            tenant_id: "tenant_1".to_string(),
            subject: "user_1".to_string(),
            entitlement: "app:erp:admin".to_string(),
            requested_by: "user_1".to_string(),
            approved_by: Some("manager_1".to_string()),
            reason: "Emergency maintenance".to_string(),
            issued_at_epoch_seconds: 1_700_000_000,
            expires_at_epoch_seconds: 1_700_000_900,
            revoked: false,
            constraints_json: serde_json::json!({"ticket": "INC-1"}),
        };
        grant.validate().unwrap();

        let mut invalid = grant.clone();
        invalid.approved_by = Some("user_1".to_string());
        assert!(invalid.validate().is_err());

        invalid = grant.clone();
        invalid.expires_at_epoch_seconds = invalid.issued_at_epoch_seconds;
        assert!(invalid.validate().is_err());

        invalid = grant;
        invalid.constraints_json = serde_json::json!([]);
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn iga_access_review_campaign_requires_subjects_and_due_order() {
        let campaign = IgaAccessReviewCampaignRecord {
            id: "review_1".to_string(),
            tenant_id: "tenant_1".to_string(),
            reviewer: "auditor_1".to_string(),
            subjects_json: serde_json::json!([
                {"subject":"user_1","recommendation":"certify"}
            ]),
            status: "open".to_string(),
            created_at_epoch_seconds: 1_700_000_000,
            due_at_epoch_seconds: Some(1_700_086_400),
        };
        campaign.validate().unwrap();

        let mut invalid = campaign.clone();
        invalid.subjects_json = serde_json::json!({});
        assert!(invalid.validate().is_err());

        invalid = campaign.clone();
        invalid.status = "pending".to_string();
        assert!(invalid.validate().is_err());

        invalid = campaign;
        invalid.due_at_epoch_seconds = Some(invalid.created_at_epoch_seconds);
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn iga_access_review_decision_requires_known_decision() {
        let decision = IgaAccessReviewDecisionRecord {
            id: "decision_1".to_string(),
            tenant_id: "tenant_1".to_string(),
            campaign_id: "review_1".to_string(),
            subject: "user_1".to_string(),
            reviewer: "auditor_1".to_string(),
            decision: "certify".to_string(),
            reason: Some("Looks correct".to_string()),
            decided_at_epoch_seconds: 1_700_000_000,
        };
        decision.validate().unwrap();

        let mut invalid = decision.clone();
        invalid.decision = "maybe".to_string();
        assert!(invalid.validate().is_err());

        invalid = decision;
        invalid.decided_at_epoch_seconds = 0;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn iga_certification_requires_known_type_decision_and_object_evidence() {
        let certification = IgaCertificationRecord {
            id: "certification_1".to_string(),
            tenant_id: "tenant_1".to_string(),
            certification_type: "manager".to_string(),
            campaign_id: Some("campaign_1".to_string()),
            subject: "user_1".to_string(),
            entitlement: "app:erp:admin".to_string(),
            certifier: "manager_1".to_string(),
            decision: "certify".to_string(),
            reason: Some("Still needed".to_string()),
            evidence_json: serde_json::json!({"source": "manager_certification"}),
            decided_at_epoch_seconds: 1_700_000_000,
        };
        certification.validate().unwrap();

        let mut invalid = certification.clone();
        invalid.certification_type = "peer".to_string();
        assert!(invalid.validate().is_err());

        invalid = certification.clone();
        invalid.decision = "maybe".to_string();
        assert!(invalid.validate().is_err());

        invalid = certification;
        invalid.evidence_json = serde_json::json!([]);
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn iga_finding_requires_known_type_severity_and_object_evidence() {
        let finding = IgaFindingRecord {
            id: "finding_1".to_string(),
            tenant_id: "tenant_1".to_string(),
            finding_type: "dormant_account".to_string(),
            subject: "user_1".to_string(),
            severity: "high".to_string(),
            evidence_json: serde_json::json!({"inactive_for_seconds": 1_000}),
            detected_at_epoch_seconds: 1_700_000_000,
            resolved: false,
        };
        finding.validate().unwrap();

        let mut invalid = finding.clone();
        invalid.finding_type = "unknown".to_string();
        assert!(invalid.validate().is_err());

        invalid = finding.clone();
        invalid.severity = "urgent".to_string();
        assert!(invalid.validate().is_err());

        invalid = finding;
        invalid.evidence_json = serde_json::json!([]);
        assert!(invalid.validate().is_err());
    }
}
