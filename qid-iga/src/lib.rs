//! Identity governance and administration surface.
#![forbid(unsafe_code)]

mod engine;
mod rebac;
mod routes;

pub use engine::{
    AccessApprovalDecision, AccessApprovalRecord, AccessPackageEvaluation, AccessRequestEvaluation,
    AccessRequestStatus, AccessReviewCampaign, AccessReviewRecommendation, AccessReviewSubject,
    ApprovalStep, ApprovalValidation, Entitlement, EntitlementRiskLevel, TimeBoundAccessGrant,
    build_access_package_evaluation, build_access_review_campaign, default_entitlement_catalog,
    evaluate_access_request, issue_time_bound_access_grant, validate_access_request_approvals,
};
pub use rebac::{
    CheckResult, RebacEvaluatorBridge, check as rebac_check, check_batch, delete_tuples,
    expand as rebac_expand, rebac_evaluator_from_repo, write_tuples,
};
pub use routes::iga_routes;

#[cfg(test)]
mod tests;
