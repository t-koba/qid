use axum::{Json, http::StatusCode, response::IntoResponse};
use qid_core::{models::IgaEntitlementRecord, state::SharedState};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AccessReviewDecision {
    Certify,
    Revoke,
    Exception,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CertificationType {
    Manager,
    ApplicationOwner,
    PrivilegedRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entitlement {
    pub id: String,
    pub display_name: String,
    pub owner: String,
    pub risk_level: EntitlementRiskLevel,
    #[serde(default)]
    pub conflicting_entitlements: Vec<String>,
    #[serde(default)]
    pub max_duration_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EntitlementRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessRequestEvaluation {
    pub request_id: String,
    pub subject: String,
    pub entitlement: String,
    pub status: AccessRequestStatus,
    pub approval_steps: Vec<ApprovalStep>,
    pub violations: Vec<String>,
    pub expires_at_epoch_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessPackageEvaluation {
    pub request_id: String,
    pub subject: String,
    pub access_package_id: String,
    pub status: AccessRequestStatus,
    pub approval_steps: Vec<ApprovalStep>,
    pub violations: Vec<String>,
    pub expires_at_epoch_seconds: Option<u64>,
    pub entitlements: Vec<AccessRequestEvaluation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessRequestStatus {
    AutoApproved,
    ApprovalRequired,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalStep {
    pub approver: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessApprovalRecord {
    pub id: String,
    pub request_id: String,
    pub approver: String,
    pub decision: AccessApprovalDecision,
    pub approved_at_epoch_seconds: u64,
    #[serde(default)]
    pub expires_at_epoch_seconds: Option<u64>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessApprovalDecision {
    Approved,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalValidation {
    pub valid: bool,
    pub missing_approvers: Vec<String>,
    pub rejected_approvers: Vec<String>,
    pub violations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeBoundAccessGrant {
    pub id: String,
    pub request_id: String,
    pub subject: String,
    pub entitlement: String,
    pub granted_at_epoch_seconds: u64,
    pub expires_at_epoch_seconds: Option<u64>,
    pub approvals: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessReviewCampaign {
    pub id: String,
    pub reviewer: String,
    pub subjects: Vec<AccessReviewSubject>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessReviewSubject {
    pub subject: String,
    pub entitlements: Vec<String>,
    pub recommendation: AccessReviewRecommendation,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessReviewRecommendation {
    Certify,
    Revoke,
    Investigate,
}

pub fn default_entitlement_catalog() -> Vec<Entitlement> {
    vec![
        Entitlement {
            id: "app:erp:read".to_string(),
            display_name: "ERP read access".to_string(),
            owner: "finance-ops".to_string(),
            risk_level: EntitlementRiskLevel::Low,
            conflicting_entitlements: Vec::new(),
            max_duration_seconds: Some(90 * 24 * 60 * 60),
        },
        Entitlement {
            id: "app:erp:admin".to_string(),
            display_name: "ERP administrator".to_string(),
            owner: "finance-ops".to_string(),
            risk_level: EntitlementRiskLevel::High,
            conflicting_entitlements: vec!["app:erp:audit".to_string()],
            max_duration_seconds: Some(7 * 24 * 60 * 60),
        },
        Entitlement {
            id: "app:erp:audit".to_string(),
            display_name: "ERP audit reviewer".to_string(),
            owner: "internal-audit".to_string(),
            risk_level: EntitlementRiskLevel::High,
            conflicting_entitlements: vec!["app:erp:admin".to_string()],
            max_duration_seconds: Some(30 * 24 * 60 * 60),
        },
    ]
}

pub fn evaluate_access_request(
    subject: &str,
    entitlement_id: &str,
    current_entitlements: &[String],
    requested_duration_seconds: Option<u64>,
    catalog: &[Entitlement],
) -> AccessRequestEvaluation {
    let request_id = ulid::Ulid::new().to_string();
    let mut violations = Vec::new();
    let Some(entitlement) = catalog.iter().find(|item| item.id == entitlement_id) else {
        return AccessRequestEvaluation {
            request_id,
            subject: subject.to_string(),
            entitlement: entitlement_id.to_string(),
            status: AccessRequestStatus::Rejected,
            approval_steps: Vec::new(),
            violations: vec!["unknown_entitlement".to_string()],
            expires_at_epoch_seconds: None,
        };
    };

    let current: HashSet<&str> = current_entitlements.iter().map(String::as_str).collect();
    for conflict in &entitlement.conflicting_entitlements {
        if current.contains(conflict.as_str()) {
            violations.push(format!("sod_conflict:{conflict}"));
        }
    }

    let effective_duration = match (requested_duration_seconds, entitlement.max_duration_seconds) {
        (Some(requested), Some(max)) if requested > max => {
            violations.push("duration_exceeds_entitlement_max".to_string());
            Some(max)
        }
        (Some(requested), _) => Some(requested),
        (None, max) => max,
    };

    let approval_steps = approval_steps_for(entitlement, &violations);
    let status = if !violations.is_empty() && entitlement.risk_level >= EntitlementRiskLevel::High {
        AccessRequestStatus::Rejected
    } else if approval_steps.is_empty() {
        AccessRequestStatus::AutoApproved
    } else {
        AccessRequestStatus::ApprovalRequired
    };

    AccessRequestEvaluation {
        request_id,
        subject: subject.to_string(),
        entitlement: entitlement_id.to_string(),
        status,
        approval_steps,
        violations,
        expires_at_epoch_seconds: effective_duration.map(|duration| now_seconds() + duration),
    }
}

pub fn build_access_package_evaluation(
    request_id: String,
    subject: &str,
    access_package_id: &str,
    entitlements: Vec<AccessRequestEvaluation>,
) -> AccessPackageEvaluation {
    let mut approval_steps = Vec::new();
    let mut seen_approvers = HashSet::new();
    let mut violations = Vec::new();
    let mut expires_at_epoch_seconds: Option<u64> = None;
    let mut status = AccessRequestStatus::AutoApproved;

    for evaluation in &entitlements {
        for step in &evaluation.approval_steps {
            let key = format!("{}:{}", step.approver, step.reason);
            if seen_approvers.insert(key) {
                approval_steps.push(step.clone());
            }
        }
        for violation in &evaluation.violations {
            violations.push(format!("{}:{violation}", evaluation.entitlement));
        }
        expires_at_epoch_seconds = match (
            expires_at_epoch_seconds,
            evaluation.expires_at_epoch_seconds,
        ) {
            (Some(current), Some(candidate)) => Some(current.min(candidate)),
            (None, Some(candidate)) => Some(candidate),
            (current, None) => current,
        };
        status = match (&status, &evaluation.status) {
            (_, AccessRequestStatus::Rejected) => AccessRequestStatus::Rejected,
            (AccessRequestStatus::AutoApproved, AccessRequestStatus::ApprovalRequired) => {
                AccessRequestStatus::ApprovalRequired
            }
            (current, _) => current.clone(),
        };
    }

    AccessPackageEvaluation {
        request_id,
        subject: subject.to_string(),
        access_package_id: access_package_id.to_string(),
        status,
        approval_steps,
        violations,
        expires_at_epoch_seconds,
        entitlements,
    }
}

pub fn validate_access_request_approvals(
    evaluation: &AccessRequestEvaluation,
    approvals: &[AccessApprovalRecord],
    now_epoch_seconds: u64,
) -> ApprovalValidation {
    let mut violations = Vec::new();
    let mut missing_approvers = Vec::new();
    let mut rejected_approvers = Vec::new();

    if evaluation.status == AccessRequestStatus::Rejected {
        violations.push("request_rejected".to_string());
    }

    let mut approved_by: HashMap<&str, &AccessApprovalRecord> = HashMap::new();
    for approval in approvals {
        if approval.id.trim().is_empty() {
            violations.push("approval_id_empty".to_string());
        }
        if approval.request_id != evaluation.request_id {
            violations.push(format!("approval_request_mismatch:{}", approval.id));
            continue;
        }
        if approval.approver == evaluation.subject {
            violations.push(format!("self_approval:{}", approval.approver));
        }
        if approval.approved_at_epoch_seconds > now_epoch_seconds {
            violations.push(format!("approval_in_future:{}", approval.id));
        }
        if approval
            .expires_at_epoch_seconds
            .is_some_and(|expires_at| expires_at <= now_epoch_seconds)
        {
            violations.push(format!("approval_expired:{}", approval.id));
        }
        match approval.decision {
            AccessApprovalDecision::Approved => {
                approved_by.insert(approval.approver.as_str(), approval);
            }
            AccessApprovalDecision::Rejected => rejected_approvers.push(approval.approver.clone()),
        }
    }

    for step in &evaluation.approval_steps {
        if !approved_by.contains_key(step.approver.as_str()) {
            missing_approvers.push(step.approver.clone());
        }
    }
    missing_approvers.sort();
    missing_approvers.dedup();
    rejected_approvers.sort();
    rejected_approvers.dedup();
    violations.sort();
    violations.dedup();

    ApprovalValidation {
        valid: violations.is_empty()
            && missing_approvers.is_empty()
            && rejected_approvers.is_empty(),
        missing_approvers,
        rejected_approvers,
        violations,
    }
}

pub(crate) fn issue_grants_for_evaluation(
    evaluation: &AccessRequestEvaluation,
    approvals: &[AccessApprovalRecord],
    now_epoch_seconds: u64,
) -> Vec<TimeBoundAccessGrant> {
    issue_time_bound_access_grant(evaluation, approvals, now_epoch_seconds)
        .into_iter()
        .collect()
}

pub fn issue_time_bound_access_grant(
    evaluation: &AccessRequestEvaluation,
    approvals: &[AccessApprovalRecord],
    now_epoch_seconds: u64,
) -> Result<TimeBoundAccessGrant, ApprovalValidation> {
    let validation = validate_access_request_approvals(evaluation, approvals, now_epoch_seconds);
    if !validation.valid {
        return Err(validation);
    }
    Ok(TimeBoundAccessGrant {
        id: ulid::Ulid::new().to_string(),
        request_id: evaluation.request_id.clone(),
        subject: evaluation.subject.clone(),
        entitlement: evaluation.entitlement.clone(),
        granted_at_epoch_seconds: now_epoch_seconds,
        expires_at_epoch_seconds: evaluation.expires_at_epoch_seconds,
        approvals: approvals
            .iter()
            .filter(|approval| approval.request_id == evaluation.request_id)
            .map(|approval| approval.id.clone())
            .collect(),
    })
}

pub fn build_access_review_campaign(
    id: impl Into<String>,
    reviewer: impl Into<String>,
    assignments: &HashMap<String, Vec<String>>,
    catalog: &[Entitlement],
    dormant_subjects: &[String],
    orphan_subjects: &[String],
) -> AccessReviewCampaign {
    let dormant: HashSet<&str> = dormant_subjects.iter().map(String::as_str).collect();
    let orphan: HashSet<&str> = orphan_subjects.iter().map(String::as_str).collect();
    let high_risk: HashSet<&str> = catalog
        .iter()
        .filter(|entitlement| entitlement.risk_level >= EntitlementRiskLevel::High)
        .map(|entitlement| entitlement.id.as_str())
        .collect();

    let mut subjects = assignments
        .iter()
        .map(|(subject, entitlements)| {
            let mut reasons = Vec::new();
            if dormant.contains(subject.as_str()) {
                reasons.push("dormant_subject".to_string());
            }
            if orphan.contains(subject.as_str()) {
                reasons.push("orphan_subject".to_string());
            }
            if entitlements
                .iter()
                .any(|entitlement| high_risk.contains(entitlement.as_str()))
            {
                reasons.push("high_risk_entitlement".to_string());
            }
            for conflict in sod_conflicts(entitlements, catalog) {
                reasons.push(format!("sod_conflict:{conflict}"));
            }

            let recommendation = if reasons
                .iter()
                .any(|reason| reason == "orphan_subject" || reason.starts_with("sod_conflict:"))
            {
                AccessReviewRecommendation::Revoke
            } else if reasons.is_empty() {
                AccessReviewRecommendation::Certify
            } else {
                AccessReviewRecommendation::Investigate
            };

            AccessReviewSubject {
                subject: subject.clone(),
                entitlements: entitlements.clone(),
                recommendation,
                reasons,
            }
        })
        .collect::<Vec<_>>();
    subjects.sort_by(|a, b| a.subject.cmp(&b.subject));

    AccessReviewCampaign {
        id: id.into(),
        reviewer: reviewer.into(),
        subjects,
    }
}

fn approval_steps_for(entitlement: &Entitlement, violations: &[String]) -> Vec<ApprovalStep> {
    let mut steps = Vec::new();
    if entitlement.risk_level >= EntitlementRiskLevel::Medium {
        steps.push(ApprovalStep {
            approver: entitlement.owner.clone(),
            reason: "owner_approval_required".to_string(),
        });
    }
    if entitlement.risk_level >= EntitlementRiskLevel::High || !violations.is_empty() {
        steps.push(ApprovalStep {
            approver: "security-admin".to_string(),
            reason: "security_approval_required".to_string(),
        });
    }
    steps
}

fn sod_conflicts(entitlements: &[String], catalog: &[Entitlement]) -> Vec<String> {
    let assigned: HashSet<&str> = entitlements.iter().map(String::as_str).collect();
    let mut conflicts = Vec::new();
    for entitlement in catalog {
        if !assigned.contains(entitlement.id.as_str()) {
            continue;
        }
        for conflict in &entitlement.conflicting_entitlements {
            if assigned.contains(conflict.as_str()) {
                conflicts.push(format!("{}+{}", entitlement.id, conflict));
            }
        }
    }
    conflicts.sort();
    conflicts.dedup();
    conflicts
}

pub(crate) fn now_seconds() -> u64 {
    qid_core::util::now_seconds()
}

pub(crate) async fn catalog_for_tenant<R: Repository>(
    state: &SharedState<R>,
    tenant_id: &str,
) -> qid_core::error::QidResult<Vec<Entitlement>> {
    let stored = state.repo.list_iga_entitlements(tenant_id).await?;
    let active: Vec<_> = stored
        .into_iter()
        .filter(|entitlement| entitlement.active)
        .map(entitlement_from_record)
        .collect();
    if active.is_empty() {
        Ok(default_entitlement_catalog())
    } else {
        Ok(active)
    }
}

pub(crate) async fn revoke_active_grants_for_subject_entitlements<R: Repository>(
    state: &SharedState<R>,
    tenant_id: &str,
    subject: &str,
    entitlements: &[String],
) -> qid_core::error::QidResult<Vec<String>> {
    let grants = state
        .repo
        .list_iga_access_grants(tenant_id, Some(subject))
        .await?;
    let entitlement_filter: HashSet<&str> = entitlements.iter().map(String::as_str).collect();
    let mut revoked = Vec::new();
    for grant in grants.into_iter().filter(|grant| {
        !grant.revoked
            && (entitlement_filter.is_empty()
                || entitlement_filter.contains(grant.entitlement.as_str()))
    }) {
        state
            .repo
            .revoke_iga_access_grant(tenant_id, &grant.id)
            .await?;
        revoked.push(grant.id);
    }
    Ok(revoked)
}

pub(crate) fn entitlement_from_record(record: IgaEntitlementRecord) -> Entitlement {
    Entitlement {
        id: record.id,
        display_name: record.display_name,
        owner: record.owner,
        risk_level: risk_level_from_str(&record.risk_level),
        conflicting_entitlements: record.conflicting_entitlements,
        max_duration_seconds: record.max_duration_seconds,
    }
}

pub(crate) fn risk_level_as_str(risk_level: &EntitlementRiskLevel) -> &'static str {
    match risk_level {
        EntitlementRiskLevel::Low => "low",
        EntitlementRiskLevel::Medium => "medium",
        EntitlementRiskLevel::High => "high",
        EntitlementRiskLevel::Critical => "critical",
    }
}

pub(crate) fn risk_level_from_str(value: &str) -> EntitlementRiskLevel {
    match value {
        "medium" => EntitlementRiskLevel::Medium,
        "high" => EntitlementRiskLevel::High,
        "critical" => EntitlementRiskLevel::Critical,
        _ => EntitlementRiskLevel::Low,
    }
}

pub(crate) fn default_true() -> bool {
    true
}

pub(crate) fn default_access_package_approval_policy() -> serde_json::Value {
    serde_json::json!({})
}

pub(crate) fn default_jit_constraints() -> serde_json::Value {
    serde_json::json!({})
}

pub(crate) fn default_certification_evidence() -> serde_json::Value {
    serde_json::json!({})
}

pub(crate) fn default_dormant_threshold_seconds() -> u64 {
    90 * 24 * 60 * 60
}

pub(crate) fn resolve_tenant_id<R>(
    explicit: Option<&str>,
    state: &SharedState<R>,
) -> Result<String, ()> {
    if let Some(tenant_id) = explicit.filter(|tenant_id| !tenant_id.trim().is_empty()) {
        return Ok(tenant_id.to_string());
    }
    state
        .first_realm()
        .and_then(|realm| realm.tenant_id.clone())
        .ok_or(())
}

pub(crate) fn tenant_scope_unavailable_response() -> axum::response::Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "error": "tenant_scope_unavailable"
        })),
    )
        .into_response()
}

pub(crate) fn unauthorized_response(error: &str) -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "error": error
        })),
    )
        .into_response()
}

pub(crate) fn bad_request_response(error: &str) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": error
        })),
    )
        .into_response()
}

pub(crate) fn not_found_response(error: &str) -> axum::response::Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": error
        })),
    )
        .into_response()
}

pub(crate) fn storage_error_response(
    operation: &str,
    error: qid_core::error::QidError,
) -> axum::response::Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "error": "storage_error",
            "operation": operation,
            "message": error.to_string()
        })),
    )
        .into_response()
}

pub(crate) fn access_request_status_as_str(status: &AccessRequestStatus) -> &'static str {
    match status {
        AccessRequestStatus::AutoApproved => "auto_approved",
        AccessRequestStatus::ApprovalRequired => "approval_required",
        AccessRequestStatus::Rejected => "rejected",
    }
}

pub(crate) fn approval_decision_as_str(decision: &AccessApprovalDecision) -> &'static str {
    match decision {
        AccessApprovalDecision::Approved => "approved",
        AccessApprovalDecision::Rejected => "rejected",
    }
}

pub(crate) fn access_review_decision_as_str(decision: &AccessReviewDecision) -> &'static str {
    match decision {
        AccessReviewDecision::Certify => "certify",
        AccessReviewDecision::Revoke => "revoke",
        AccessReviewDecision::Exception => "exception",
    }
}

pub(crate) fn certification_type_as_str(certification_type: &CertificationType) -> &'static str {
    match certification_type {
        CertificationType::Manager => "manager",
        CertificationType::ApplicationOwner => "application_owner",
        CertificationType::PrivilegedRole => "privileged_role",
    }
}
