use super::validation::{require_json_array, require_non_empty};
use crate::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};

/// Persistent IGA access request snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IgaAccessRequestRecord {
    pub id: String,
    pub tenant_id: String,
    pub subject: String,
    pub entitlement: String,
    pub reason: Option<String>,
    pub status: String,
    pub approval_steps_json: serde_json::Value,
    pub violations_json: serde_json::Value,
    pub expires_at_epoch_seconds: Option<u64>,
    pub created_at_epoch_seconds: u64,
}

impl IgaAccessRequestRecord {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("IGA access request id", &self.id)?;
        require_non_empty("IGA access request tenant_id", &self.tenant_id)?;
        require_non_empty("IGA access request subject", &self.subject)?;
        require_non_empty("IGA access request entitlement", &self.entitlement)?;
        require_non_empty("IGA access request status", &self.status)?;
        require_json_array(
            "IGA access request approval_steps_json",
            &self.approval_steps_json,
        )?;
        require_json_array("IGA access request violations_json", &self.violations_json)?;
        if self.created_at_epoch_seconds == 0 {
            return Err(QidError::BadRequest {
                message: "IGA access request created_at_epoch_seconds must be set".to_string(),
            });
        }
        if let Some(expires_at) = self.expires_at_epoch_seconds
            && expires_at <= self.created_at_epoch_seconds
        {
            return Err(QidError::BadRequest {
                message: "IGA access request expires_at_epoch_seconds must be after created_at_epoch_seconds".to_string(),
            });
        }
        Ok(())
    }
}

/// Persistent tenant-scoped IGA entitlement catalog entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IgaEntitlementRecord {
    pub id: String,
    pub tenant_id: String,
    pub display_name: String,
    pub owner: String,
    pub risk_level: String,
    pub conflicting_entitlements: Vec<String>,
    pub max_duration_seconds: Option<u64>,
    pub active: bool,
}

impl IgaEntitlementRecord {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("IGA entitlement id", &self.id)?;
        require_non_empty("IGA entitlement tenant_id", &self.tenant_id)?;
        require_non_empty("IGA entitlement display_name", &self.display_name)?;
        require_non_empty("IGA entitlement owner", &self.owner)?;
        match self.risk_level.as_str() {
            "low" | "medium" | "high" | "critical" => {}
            _ => {
                return Err(QidError::BadRequest {
                    message: "IGA entitlement risk_level must be low, medium, high, or critical"
                        .to_string(),
                });
            }
        }
        for entitlement in &self.conflicting_entitlements {
            require_non_empty("IGA entitlement conflicting_entitlement", entitlement)?;
            if entitlement == &self.id {
                return Err(QidError::BadRequest {
                    message: "IGA entitlement must not conflict with itself".to_string(),
                });
            }
        }
        if self
            .max_duration_seconds
            .is_some_and(|duration| duration == 0)
        {
            return Err(QidError::BadRequest {
                message: "IGA entitlement max_duration_seconds must be greater than zero"
                    .to_string(),
            });
        }
        Ok(())
    }
}

/// Persistent tenant-scoped IGA access package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IgaAccessPackageRecord {
    pub id: String,
    pub tenant_id: String,
    pub display_name: String,
    pub owner: String,
    pub entitlement_ids: Vec<String>,
    pub approval_policy_json: serde_json::Value,
    pub max_duration_seconds: Option<u64>,
    pub active: bool,
}

impl IgaAccessPackageRecord {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("IGA access package id", &self.id)?;
        require_non_empty("IGA access package tenant_id", &self.tenant_id)?;
        require_non_empty("IGA access package display_name", &self.display_name)?;
        require_non_empty("IGA access package owner", &self.owner)?;
        if self.entitlement_ids.is_empty() {
            return Err(QidError::BadRequest {
                message: "IGA access package entitlement_ids must not be empty".to_string(),
            });
        }
        for entitlement_id in &self.entitlement_ids {
            require_non_empty("IGA access package entitlement_id", entitlement_id)?;
        }
        if !self.approval_policy_json.is_object() {
            return Err(QidError::BadRequest {
                message: "IGA access package approval_policy_json must be an object".to_string(),
            });
        }
        if self
            .max_duration_seconds
            .is_some_and(|duration| duration == 0)
        {
            return Err(QidError::BadRequest {
                message: "IGA access package max_duration_seconds must be greater than zero"
                    .to_string(),
            });
        }
        Ok(())
    }
}

/// Persistent IGA just-in-time privilege grant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IgaJitPrivilegeGrantRecord {
    pub id: String,
    pub tenant_id: String,
    pub subject: String,
    pub entitlement: String,
    pub requested_by: String,
    pub approved_by: Option<String>,
    pub reason: String,
    pub issued_at_epoch_seconds: u64,
    pub expires_at_epoch_seconds: u64,
    pub revoked: bool,
    pub constraints_json: serde_json::Value,
}

impl IgaJitPrivilegeGrantRecord {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("IGA JIT privilege id", &self.id)?;
        require_non_empty("IGA JIT privilege tenant_id", &self.tenant_id)?;
        require_non_empty("IGA JIT privilege subject", &self.subject)?;
        require_non_empty("IGA JIT privilege entitlement", &self.entitlement)?;
        require_non_empty("IGA JIT privilege requested_by", &self.requested_by)?;
        require_non_empty("IGA JIT privilege reason", &self.reason)?;
        if let Some(approved_by) = &self.approved_by {
            require_non_empty("IGA JIT privilege approved_by", approved_by)?;
            if approved_by == &self.subject {
                return Err(QidError::BadRequest {
                    message: "IGA JIT privilege approved_by must not be the subject".to_string(),
                });
            }
        }
        if self.issued_at_epoch_seconds == 0 {
            return Err(QidError::BadRequest {
                message: "IGA JIT privilege issued_at_epoch_seconds must be set".to_string(),
            });
        }
        if self.expires_at_epoch_seconds <= self.issued_at_epoch_seconds {
            return Err(QidError::BadRequest {
                message: "IGA JIT privilege expires_at_epoch_seconds must be after issued_at_epoch_seconds".to_string(),
            });
        }
        if !self.constraints_json.is_object() {
            return Err(QidError::BadRequest {
                message: "IGA JIT privilege constraints_json must be an object".to_string(),
            });
        }
        Ok(())
    }
}

/// Persistent IGA approval decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IgaApprovalRecord {
    pub id: String,
    pub tenant_id: String,
    pub request_id: String,
    pub approver: String,
    pub decision: String,
    pub approved_at_epoch_seconds: u64,
    pub expires_at_epoch_seconds: Option<u64>,
    pub reason: Option<String>,
}

impl IgaApprovalRecord {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("IGA approval id", &self.id)?;
        require_non_empty("IGA approval tenant_id", &self.tenant_id)?;
        require_non_empty("IGA approval request_id", &self.request_id)?;
        require_non_empty("IGA approval approver", &self.approver)?;
        match self.decision.as_str() {
            "approved" | "rejected" => {}
            _ => {
                return Err(QidError::BadRequest {
                    message: "IGA approval decision must be approved or rejected".to_string(),
                });
            }
        }
        if self.approved_at_epoch_seconds == 0 {
            return Err(QidError::BadRequest {
                message: "IGA approval approved_at_epoch_seconds must be set".to_string(),
            });
        }
        if let Some(expires_at) = self.expires_at_epoch_seconds
            && expires_at <= self.approved_at_epoch_seconds
        {
            return Err(QidError::BadRequest {
                message:
                    "IGA approval expires_at_epoch_seconds must be after approved_at_epoch_seconds"
                        .to_string(),
            });
        }
        Ok(())
    }
}

/// Persistent IGA time-bound grant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IgaAccessGrantRecord {
    pub id: String,
    pub tenant_id: String,
    pub request_id: String,
    pub subject: String,
    pub entitlement: String,
    pub granted_at_epoch_seconds: u64,
    pub expires_at_epoch_seconds: Option<u64>,
    pub approval_ids: Vec<String>,
    pub revoked: bool,
}

impl IgaAccessGrantRecord {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("IGA access grant id", &self.id)?;
        require_non_empty("IGA access grant tenant_id", &self.tenant_id)?;
        require_non_empty("IGA access grant request_id", &self.request_id)?;
        require_non_empty("IGA access grant subject", &self.subject)?;
        require_non_empty("IGA access grant entitlement", &self.entitlement)?;
        if self.granted_at_epoch_seconds == 0 {
            return Err(QidError::BadRequest {
                message: "IGA access grant granted_at_epoch_seconds must be set".to_string(),
            });
        }
        if let Some(expires_at) = self.expires_at_epoch_seconds
            && expires_at <= self.granted_at_epoch_seconds
        {
            return Err(QidError::BadRequest {
                message: "IGA access grant expires_at_epoch_seconds must be after granted_at_epoch_seconds".to_string(),
            });
        }
        for approval_id in &self.approval_ids {
            require_non_empty("IGA access grant approval_id", approval_id)?;
        }
        Ok(())
    }
}

/// Persistent IGA access review campaign snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IgaAccessReviewCampaignRecord {
    pub id: String,
    pub tenant_id: String,
    pub reviewer: String,
    pub subjects_json: serde_json::Value,
    pub status: String,
    pub created_at_epoch_seconds: u64,
    pub due_at_epoch_seconds: Option<u64>,
}

impl IgaAccessReviewCampaignRecord {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("IGA access review campaign id", &self.id)?;
        require_non_empty("IGA access review campaign tenant_id", &self.tenant_id)?;
        require_non_empty("IGA access review campaign reviewer", &self.reviewer)?;
        match self.status.as_str() {
            "open" | "closed" => {}
            _ => {
                return Err(QidError::BadRequest {
                    message: "IGA access review campaign status must be open or closed".to_string(),
                });
            }
        }
        require_json_array(
            "IGA access review campaign subjects_json",
            &self.subjects_json,
        )?;
        if self.created_at_epoch_seconds == 0 {
            return Err(QidError::BadRequest {
                message: "IGA access review campaign created_at_epoch_seconds must be set"
                    .to_string(),
            });
        }
        if let Some(due_at) = self.due_at_epoch_seconds
            && due_at <= self.created_at_epoch_seconds
        {
            return Err(QidError::BadRequest {
                message: "IGA access review campaign due_at_epoch_seconds must be after created_at_epoch_seconds".to_string(),
            });
        }
        Ok(())
    }
}

/// Persistent IGA access review decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IgaAccessReviewDecisionRecord {
    pub id: String,
    pub tenant_id: String,
    pub campaign_id: String,
    pub subject: String,
    pub reviewer: String,
    pub decision: String,
    pub reason: Option<String>,
    pub decided_at_epoch_seconds: u64,
}

impl IgaAccessReviewDecisionRecord {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("IGA access review decision id", &self.id)?;
        require_non_empty("IGA access review decision tenant_id", &self.tenant_id)?;
        require_non_empty("IGA access review decision campaign_id", &self.campaign_id)?;
        require_non_empty("IGA access review decision subject", &self.subject)?;
        require_non_empty("IGA access review decision reviewer", &self.reviewer)?;
        match self.decision.as_str() {
            "certify" | "revoke" | "exception" => {}
            _ => {
                return Err(QidError::BadRequest {
                    message: "IGA access review decision must be certify, revoke, or exception"
                        .to_string(),
                });
            }
        }
        if self.decided_at_epoch_seconds == 0 {
            return Err(QidError::BadRequest {
                message: "IGA access review decision decided_at_epoch_seconds must be set"
                    .to_string(),
            });
        }
        Ok(())
    }
}

/// Persistent IGA certification or attestation decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IgaCertificationRecord {
    pub id: String,
    pub tenant_id: String,
    pub certification_type: String,
    pub campaign_id: Option<String>,
    pub subject: String,
    pub entitlement: String,
    pub certifier: String,
    pub decision: String,
    pub reason: Option<String>,
    pub evidence_json: serde_json::Value,
    pub decided_at_epoch_seconds: u64,
}

impl IgaCertificationRecord {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("IGA certification id", &self.id)?;
        require_non_empty("IGA certification tenant_id", &self.tenant_id)?;
        require_non_empty("IGA certification subject", &self.subject)?;
        require_non_empty("IGA certification entitlement", &self.entitlement)?;
        require_non_empty("IGA certification certifier", &self.certifier)?;
        match self.certification_type.as_str() {
            "manager" | "application_owner" | "privileged_role" => {}
            _ => {
                return Err(QidError::BadRequest {
                    message: "IGA certification type must be manager, application_owner, or privileged_role".to_string(),
                });
            }
        }
        match self.decision.as_str() {
            "certify" | "revoke" | "exception" => {}
            _ => {
                return Err(QidError::BadRequest {
                    message: "IGA certification decision must be certify, revoke, or exception"
                        .to_string(),
                });
            }
        }
        if !self.evidence_json.is_object() {
            return Err(QidError::BadRequest {
                message: "IGA certification evidence_json must be an object".to_string(),
            });
        }
        if self.decided_at_epoch_seconds == 0 {
            return Err(QidError::BadRequest {
                message: "IGA certification decided_at_epoch_seconds must be set".to_string(),
            });
        }
        Ok(())
    }
}

/// Persistent IGA risk finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IgaFindingRecord {
    pub id: String,
    pub tenant_id: String,
    pub finding_type: String,
    pub subject: String,
    pub severity: String,
    pub evidence_json: serde_json::Value,
    pub detected_at_epoch_seconds: u64,
    pub resolved: bool,
}

impl IgaFindingRecord {
    pub fn validate(&self) -> QidResult<()> {
        require_non_empty("IGA finding id", &self.id)?;
        require_non_empty("IGA finding tenant_id", &self.tenant_id)?;
        require_non_empty("IGA finding subject", &self.subject)?;
        match self.finding_type.as_str() {
            "dormant_account" | "orphaned_service_account" | "sod_conflict" => {}
            _ => {
                return Err(QidError::BadRequest {
                    message:
                        "IGA finding type must be dormant_account, orphaned_service_account, or sod_conflict"
                            .to_string(),
                });
            }
        }
        match self.severity.as_str() {
            "low" | "medium" | "high" | "critical" => {}
            _ => {
                return Err(QidError::BadRequest {
                    message: "IGA finding severity must be low, medium, high, or critical"
                        .to_string(),
                });
            }
        }
        if !self.evidence_json.is_object() {
            return Err(QidError::BadRequest {
                message: "IGA finding evidence_json must be an object".to_string(),
            });
        }
        if self.detected_at_epoch_seconds == 0 {
            return Err(QidError::BadRequest {
                message: "IGA finding detected_at_epoch_seconds must be set".to_string(),
            });
        }
        Ok(())
    }
}
