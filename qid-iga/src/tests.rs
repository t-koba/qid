use super::*;
use qid_core::util::now_seconds;
use std::collections::HashMap;

#[test]
fn low_risk_entitlement_can_be_auto_approved() {
    let catalog = default_entitlement_catalog();
    let evaluation = evaluate_access_request("user-1", "app:erp:read", &[], Some(3600), &catalog);

    assert_eq!(evaluation.status, AccessRequestStatus::AutoApproved);
    assert!(evaluation.approval_steps.is_empty());
    assert!(evaluation.violations.is_empty());
    assert!(evaluation.expires_at_epoch_seconds.is_some());
}

#[test]
fn approval_records_must_satisfy_required_steps_before_grant() {
    let catalog = default_entitlement_catalog();
    let evaluation = evaluate_access_request("user-1", "app:erp:admin", &[], Some(3600), &catalog);
    assert_eq!(evaluation.status, AccessRequestStatus::ApprovalRequired);
    assert_eq!(evaluation.approval_steps.len(), 2);

    let now = now_seconds();
    let owner_approval = AccessApprovalRecord {
        id: "approval-owner".to_string(),
        request_id: evaluation.request_id.clone(),
        approver: "finance-ops".to_string(),
        decision: AccessApprovalDecision::Approved,
        approved_at_epoch_seconds: now,
        expires_at_epoch_seconds: Some(now + 300),
        reason: Some("owner approved".to_string()),
    };
    let missing_security =
        validate_access_request_approvals(&evaluation, std::slice::from_ref(&owner_approval), now);
    assert!(!missing_security.valid);
    assert_eq!(missing_security.missing_approvers, vec!["security-admin"]);

    let security_approval = AccessApprovalRecord {
        id: "approval-security".to_string(),
        request_id: evaluation.request_id.clone(),
        approver: "security-admin".to_string(),
        decision: AccessApprovalDecision::Approved,
        approved_at_epoch_seconds: now,
        expires_at_epoch_seconds: Some(now + 300),
        reason: Some("security approved".to_string()),
    };
    let grant =
        issue_time_bound_access_grant(&evaluation, &[owner_approval, security_approval], now)
            .expect("grant should be issued");
    assert_eq!(grant.subject, "user-1");
    assert_eq!(grant.entitlement, "app:erp:admin");
    assert_eq!(grant.approvals.len(), 2);
    assert!(grant.expires_at_epoch_seconds.is_some());
}

#[test]
fn approval_validation_rejects_self_stale_and_rejected_approvals() {
    let catalog = default_entitlement_catalog();
    let evaluation = evaluate_access_request("user-1", "app:erp:admin", &[], Some(3600), &catalog);
    let now = now_seconds();
    let approvals = vec![
        AccessApprovalRecord {
            id: "approval-self".to_string(),
            request_id: evaluation.request_id.clone(),
            approver: "user-1".to_string(),
            decision: AccessApprovalDecision::Approved,
            approved_at_epoch_seconds: now,
            expires_at_epoch_seconds: Some(now + 300),
            reason: None,
        },
        AccessApprovalRecord {
            id: "approval-stale".to_string(),
            request_id: evaluation.request_id.clone(),
            approver: "finance-ops".to_string(),
            decision: AccessApprovalDecision::Approved,
            approved_at_epoch_seconds: now - 600,
            expires_at_epoch_seconds: Some(now - 1),
            reason: None,
        },
        AccessApprovalRecord {
            id: "approval-rejected".to_string(),
            request_id: evaluation.request_id.clone(),
            approver: "security-admin".to_string(),
            decision: AccessApprovalDecision::Rejected,
            approved_at_epoch_seconds: now,
            expires_at_epoch_seconds: Some(now + 300),
            reason: None,
        },
    ];

    let validation = validate_access_request_approvals(&evaluation, &approvals, now);
    assert!(!validation.valid);
    assert!(
        validation
            .violations
            .contains(&"self_approval:user-1".to_string())
    );
    assert!(
        validation
            .violations
            .contains(&"approval_expired:approval-stale".to_string())
    );
    assert_eq!(validation.rejected_approvers, vec!["security-admin"]);
}

#[test]
fn high_risk_conflict_is_rejected() {
    let catalog = default_entitlement_catalog();
    let evaluation = evaluate_access_request(
        "user-1",
        "app:erp:admin",
        &["app:erp:audit".to_string()],
        Some(60 * 24 * 60 * 60),
        &catalog,
    );

    assert_eq!(evaluation.status, AccessRequestStatus::Rejected);
    assert!(
        evaluation
            .violations
            .contains(&"sod_conflict:app:erp:audit".to_string())
    );
    assert!(
        evaluation
            .violations
            .contains(&"duration_exceeds_entitlement_max".to_string())
    );
}

#[test]
fn access_review_recommends_revocation_for_orphan_and_sod_conflict() {
    let catalog = default_entitlement_catalog();
    let assignments = HashMap::from([(
        "user-1".to_string(),
        vec!["app:erp:admin".to_string(), "app:erp:audit".to_string()],
    )]);

    let campaign = build_access_review_campaign(
        "review-1",
        "manager-1",
        &assignments,
        &catalog,
        &[],
        &["user-1".to_string()],
    );

    assert_eq!(campaign.subjects.len(), 1);
    assert_eq!(
        campaign.subjects[0].recommendation,
        AccessReviewRecommendation::Revoke
    );
    assert!(
        campaign.subjects[0]
            .reasons
            .contains(&"orphan_subject".to_string())
    );
    assert!(
        campaign.subjects[0]
            .reasons
            .iter()
            .any(|reason| reason.starts_with("sod_conflict:"))
    );
}
