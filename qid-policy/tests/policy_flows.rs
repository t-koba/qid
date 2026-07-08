#![cfg(feature = "cedar-embedded")]

use qid_policy::{CedarEmbeddedPolicyEngine, Decision, PolicyContext, PolicyEngine};

#[tokio::test]
async fn cedar_decision_enforces_scope_and_tenant_context() {
    let engine = CedarEmbeddedPolicyEngine::new(vec![
        r#"
permit(
    principal == User::"alice",
    action == Action::"read",
    resource == Resource::"tenant-a-payroll"
)
when {
    context.groups.contains("finance") &&
    context.risk_score < 50
};
"#
        .to_string(),
    ]);

    let allowed = PolicyContext {
        subject_id: Some("alice".to_string()),
        groups: vec!["finance".to_string()],
        risk_score: Some(10),
        resource_host: Some("tenant-a-payroll".to_string()),
        resource_action: Some("read".to_string()),
        pep_registration: Some("edge-a".to_string()),
        ..PolicyContext::default()
    };
    let allowed_decision = engine.decide(&allowed).await;
    assert_eq!(allowed_decision.decision, Decision::Allow);
    assert!(
        allowed_decision
            .trace
            .iter()
            .any(|entry| entry.contains("matched policy"))
    );

    let cross_tenant = PolicyContext {
        resource_host: Some("tenant-b-payroll".to_string()),
        ..allowed.clone()
    };
    assert_eq!(engine.decide(&cross_tenant).await.decision, Decision::Deny);

    let missing_scope = PolicyContext {
        groups: vec!["engineering".to_string()],
        ..allowed.clone()
    };
    assert_eq!(engine.decide(&missing_scope).await.decision, Decision::Deny);

    let high_risk = PolicyContext {
        risk_score: Some(80),
        ..allowed
    };
    assert_eq!(engine.decide(&high_risk).await.decision, Decision::Deny);
}
