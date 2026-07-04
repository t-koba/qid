use qid_core::models::*;

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct IgaEntitlementRow {
    tenant_id: String,
    id: String,
    display_name: String,
    owner: String,
    risk_level: String,
    conflicting_entitlements_json: String,
    max_duration_seconds: Option<i64>,
    active: i64,
}

impl From<IgaEntitlementRow> for IgaEntitlementRecord {
    fn from(row: IgaEntitlementRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            display_name: row.display_name,
            owner: row.owner,
            risk_level: row.risk_level,
            conflicting_entitlements: serde_json::from_str(&row.conflicting_entitlements_json)
                .unwrap_or_default(),
            max_duration_seconds: row.max_duration_seconds.map(|value| value as u64),
            active: row.active != 0,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct IgaAccessPackageRow {
    id: String,
    tenant_id: String,
    display_name: String,
    owner: String,
    entitlement_ids_json: String,
    approval_policy_json: String,
    max_duration_seconds: Option<i64>,
    active: i64,
}

impl From<IgaAccessPackageRow> for IgaAccessPackageRecord {
    fn from(row: IgaAccessPackageRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            display_name: row.display_name,
            owner: row.owner,
            entitlement_ids: serde_json::from_str(&row.entitlement_ids_json).unwrap_or_default(),
            approval_policy_json: serde_json::from_str(&row.approval_policy_json)
                .unwrap_or_else(|_| serde_json::json!({})),
            max_duration_seconds: row.max_duration_seconds.map(|value| value as u64),
            active: row.active != 0,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct IgaAccessRequestRow {
    id: String,
    tenant_id: String,
    subject: String,
    entitlement: String,
    reason: Option<String>,
    status: String,
    approval_steps_json: String,
    violations_json: String,
    expires_at_epoch_seconds: Option<i64>,
    created_at_epoch_seconds: i64,
}

impl From<IgaAccessRequestRow> for IgaAccessRequestRecord {
    fn from(row: IgaAccessRequestRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            subject: row.subject,
            entitlement: row.entitlement,
            reason: row.reason,
            status: row.status,
            approval_steps_json: serde_json::from_str(&row.approval_steps_json)
                .unwrap_or_else(|_| serde_json::json!([])),
            violations_json: serde_json::from_str(&row.violations_json)
                .unwrap_or_else(|_| serde_json::json!([])),
            expires_at_epoch_seconds: row.expires_at_epoch_seconds.map(|value| value as u64),
            created_at_epoch_seconds: row.created_at_epoch_seconds as u64,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct IgaApprovalRow {
    id: String,
    tenant_id: String,
    request_id: String,
    approver: String,
    decision: String,
    approved_at_epoch_seconds: i64,
    expires_at_epoch_seconds: Option<i64>,
    reason: Option<String>,
}

impl From<IgaApprovalRow> for IgaApprovalRecord {
    fn from(row: IgaApprovalRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            request_id: row.request_id,
            approver: row.approver,
            decision: row.decision,
            approved_at_epoch_seconds: row.approved_at_epoch_seconds as u64,
            expires_at_epoch_seconds: row.expires_at_epoch_seconds.map(|value| value as u64),
            reason: row.reason,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct IgaAccessGrantRow {
    id: String,
    tenant_id: String,
    request_id: String,
    subject: String,
    entitlement: String,
    granted_at_epoch_seconds: i64,
    expires_at_epoch_seconds: Option<i64>,
    approval_ids_json: String,
    revoked: i64,
}

impl From<IgaAccessGrantRow> for IgaAccessGrantRecord {
    fn from(row: IgaAccessGrantRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            request_id: row.request_id,
            subject: row.subject,
            entitlement: row.entitlement,
            granted_at_epoch_seconds: row.granted_at_epoch_seconds as u64,
            expires_at_epoch_seconds: row.expires_at_epoch_seconds.map(|value| value as u64),
            approval_ids: serde_json::from_str(&row.approval_ids_json).unwrap_or_default(),
            revoked: row.revoked != 0,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct IgaJitPrivilegeGrantRow {
    id: String,
    tenant_id: String,
    subject: String,
    entitlement: String,
    requested_by: String,
    approved_by: Option<String>,
    reason: String,
    issued_at_epoch_seconds: i64,
    expires_at_epoch_seconds: i64,
    revoked: i64,
    constraints_json: String,
}

impl From<IgaJitPrivilegeGrantRow> for IgaJitPrivilegeGrantRecord {
    fn from(row: IgaJitPrivilegeGrantRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            subject: row.subject,
            entitlement: row.entitlement,
            requested_by: row.requested_by,
            approved_by: row.approved_by,
            reason: row.reason,
            issued_at_epoch_seconds: row.issued_at_epoch_seconds as u64,
            expires_at_epoch_seconds: row.expires_at_epoch_seconds as u64,
            revoked: row.revoked != 0,
            constraints_json: serde_json::from_str(&row.constraints_json)
                .unwrap_or_else(|_| serde_json::json!({})),
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct IgaAccessReviewCampaignRow {
    id: String,
    tenant_id: String,
    reviewer: String,
    subjects_json: String,
    status: String,
    created_at_epoch_seconds: i64,
    due_at_epoch_seconds: Option<i64>,
}

impl From<IgaAccessReviewCampaignRow> for IgaAccessReviewCampaignRecord {
    fn from(row: IgaAccessReviewCampaignRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            reviewer: row.reviewer,
            subjects_json: serde_json::from_str(&row.subjects_json)
                .unwrap_or_else(|_| serde_json::json!([])),
            status: row.status,
            created_at_epoch_seconds: row.created_at_epoch_seconds as u64,
            due_at_epoch_seconds: row.due_at_epoch_seconds.map(|value| value as u64),
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct IgaAccessReviewDecisionRow {
    id: String,
    tenant_id: String,
    campaign_id: String,
    subject: String,
    reviewer: String,
    decision: String,
    reason: Option<String>,
    decided_at_epoch_seconds: i64,
}

impl From<IgaAccessReviewDecisionRow> for IgaAccessReviewDecisionRecord {
    fn from(row: IgaAccessReviewDecisionRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            campaign_id: row.campaign_id,
            subject: row.subject,
            reviewer: row.reviewer,
            decision: row.decision,
            reason: row.reason,
            decided_at_epoch_seconds: row.decided_at_epoch_seconds as u64,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct IgaCertificationRow {
    id: String,
    tenant_id: String,
    certification_type: String,
    campaign_id: Option<String>,
    subject: String,
    entitlement: String,
    certifier: String,
    decision: String,
    reason: Option<String>,
    evidence_json: String,
    decided_at_epoch_seconds: i64,
}

impl From<IgaCertificationRow> for IgaCertificationRecord {
    fn from(row: IgaCertificationRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            certification_type: row.certification_type,
            campaign_id: row.campaign_id,
            subject: row.subject,
            entitlement: row.entitlement,
            certifier: row.certifier,
            decision: row.decision,
            reason: row.reason,
            evidence_json: serde_json::from_str(&row.evidence_json)
                .unwrap_or_else(|_| serde_json::json!({})),
            decided_at_epoch_seconds: row.decided_at_epoch_seconds as u64,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct IgaFindingRow {
    id: String,
    tenant_id: String,
    finding_type: String,
    subject: String,
    severity: String,
    evidence_json: String,
    detected_at_epoch_seconds: i64,
    resolved: i64,
}

impl From<IgaFindingRow> for IgaFindingRecord {
    fn from(row: IgaFindingRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            finding_type: row.finding_type,
            subject: row.subject,
            severity: row.severity,
            evidence_json: serde_json::from_str(&row.evidence_json)
                .unwrap_or_else(|_| serde_json::json!({})),
            detected_at_epoch_seconds: row.detected_at_epoch_seconds as u64,
            resolved: row.resolved != 0,
        }
    }
}
