use qid_core::config::DecisionCacheClass;
use qid_policy::Decision;

#[test]
fn the_decision_class_separates_stable_outcomes_from_transient_refusals() {
    // A positive class means a stable or held outcome, not a grant. Quarantine
    // is deliberately positive because it is a held outcome, while the PEP
    // still reports it to the wire as a deny.
    for decision in [Decision::Allow, Decision::AuditOnly, Decision::Quarantine] {
        assert_eq!(
            decision.cache_class(),
            DecisionCacheClass::Positive,
            "{decision:?} is a stable or held outcome"
        );
    }
    for decision in [
        Decision::Deny,
        Decision::StepUp,
        Decision::ConsentRequired,
        Decision::LocalResponse,
        Decision::ApprovalRequired,
        Decision::Conditional,
    ] {
        assert_eq!(
            decision.cache_class(),
            DecisionCacheClass::Negative,
            "{decision:?} is a transient refusal or challenge"
        );
    }
}
