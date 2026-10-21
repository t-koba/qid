use qid_core::config::DecisionCacheClass;
use qid_policy::Decision;

#[test]
fn the_decision_class_follows_whether_the_request_proceeds() {
    for decision in [Decision::Allow, Decision::AuditOnly] {
        assert_eq!(
            decision.cache_class(),
            DecisionCacheClass::Positive,
            "{decision:?} lets the request proceed"
        );
    }
    for decision in [
        Decision::Deny,
        Decision::Quarantine,
        Decision::StepUp,
        Decision::ConsentRequired,
        Decision::LocalResponse,
        Decision::ApprovalRequired,
        Decision::Conditional,
    ] {
        assert_eq!(
            decision.cache_class(),
            DecisionCacheClass::Negative,
            "{decision:?} refuses the request"
        );
    }
}
