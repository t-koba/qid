use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::models::{
    Decision, DecisionDetails, PepPolicyActions, PolicyBundle, PolicyContext, PolicyEngine,
    RebacEvaluator, Rule, RuleType, condition_matches, evaluate_expression,
};

#[derive(Clone)]
pub struct NativePolicyEngine {
    bundle: Option<PolicyBundle>,
    bundle_id: String,
    rebac_evaluator: Option<Arc<dyn RebacEvaluator>>,
}

impl NativePolicyEngine {
    pub fn new() -> Self {
        Self {
            bundle: None,
            bundle_id: "default".to_string(),
            rebac_evaluator: None,
        }
    }

    pub fn load(&mut self, bundle: PolicyBundle, bundle_id: impl Into<String>) {
        self.bundle = Some(bundle);
        self.bundle_id = bundle_id.into();
    }

    /// Attach a ReBAC evaluator so that rules containing
    /// `Expression::RebacCheck` can be evaluated.
    pub fn with_rebac_evaluator(mut self, evaluator: Arc<dyn RebacEvaluator>) -> Self {
        self.rebac_evaluator = Some(evaluator);
        self
    }
}

impl Default for NativePolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for NativePolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativePolicyEngine")
            .field("bundle_id", &self.bundle_id)
            .field("has_bundle", &self.bundle.is_some())
            .field("has_rebac", &self.rebac_evaluator.is_some())
            .finish()
    }
}

#[async_trait::async_trait]
impl PolicyEngine for NativePolicyEngine {
    async fn decide(&self, ctx: &PolicyContext) -> DecisionDetails {
        let _start = std::time::Instant::now();
        let mut matched_rules: Vec<String> = Vec::new();
        let mut trace: Vec<String> = Vec::new();

        if let Some(bundle) = &self.bundle {
            for rule in &bundle.rules {
                if rule.rule_type == RuleType::Forbid {
                    trace.push(format!("Evaluating forbid rule: {}", rule.name));
                    if rule_matches(rule, ctx, self.rebac_evaluator.as_deref()).await {
                        trace.push(format!("Rule {}: MATCH (forbid)", rule.name));
                        matched_rules.push(rule.name.clone());
                        record_metrics(_start);
                        return DecisionDetails {
                            obligations: Vec::new(),
                            context: None,
                            decision: Decision::Deny,
                            policy_id: rule.name.clone(),
                            rate_limit_profile: None,
                            policy_tags: vec![format!("qid:forbid:{}", rule.name)],
                            inject_headers: None,
                            pep: rule.pep.clone(),
                            matched_rules,
                            trace,
                        };
                    }
                    trace.push(format!("Rule {}: no match", rule.name));
                }
            }

            for rule in &bundle.rules {
                if rule.rule_type == RuleType::StepUp {
                    trace.push(format!("Evaluating step-up rule: {}", rule.name));
                    if rule_matches(rule, ctx, self.rebac_evaluator.as_deref()).await {
                        trace.push(format!("Rule {}: MATCH (step-up)", rule.name));
                        matched_rules.push(rule.name.clone());
                        record_metrics(_start);
                        return DecisionDetails {
                            obligations: Vec::new(),
                            context: None,
                            decision: Decision::StepUp,
                            policy_id: rule.name.clone(),
                            rate_limit_profile: None,
                            policy_tags: vec![format!("qid:step-up:{}", rule.name)],
                            inject_headers: None,
                            pep: rule.pep.clone(),
                            matched_rules,
                            trace,
                        };
                    }
                    trace.push(format!("Rule {}: no match", rule.name));
                }
            }

            for rule in &bundle.rules {
                if rule.rule_type == RuleType::Allow {
                    trace.push(format!("Evaluating allow rule: {}", rule.name));
                    if rule_matches(rule, ctx, self.rebac_evaluator.as_deref()).await {
                        trace.push(format!("Rule {}: MATCH (allow)", rule.name));
                        matched_rules.push(rule.name.clone());
                        record_metrics(_start);
                        return DecisionDetails {
                            obligations: Vec::new(),
                            context: None,
                            decision: Decision::Allow,
                            policy_id: rule.name.clone(),
                            rate_limit_profile: rule.rate_limit_profile.clone(),
                            policy_tags: vec![format!("qid:allow:{}", rule.name)],
                            inject_headers: rule.inject_headers.clone(),
                            pep: rule.pep.clone(),
                            matched_rules,
                            trace,
                        };
                    }
                    trace.push(format!("Rule {}: no match", rule.name));
                }
            }
        }

        trace.push("No matching rule; default deny".to_string());
        record_metrics(_start);
        DecisionDetails {
            obligations: Vec::new(),
            context: None,
            decision: Decision::Deny,
            policy_id: self.bundle_id.clone(),
            rate_limit_profile: None,
            policy_tags: vec!["qid:default-deny".to_string()],
            inject_headers: None,
            pep: PepPolicyActions::default(),
            matched_rules,
            trace,
        }
    }
}

fn record_metrics(start: std::time::Instant) {
    metrics::histogram!("qid_policy_decision_duration_seconds")
        .record(start.elapsed().as_secs_f64());
}

fn rule_matches<'a>(
    rule: &'a Rule,
    ctx: &'a PolicyContext,
    rebac: Option<&'a dyn RebacEvaluator>,
) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
    Box::pin(async move {
        if !action_matches(&rule.action, ctx.resource_action.as_deref().unwrap_or("")) {
            return false;
        }

        if let Some(ref host) = rule.resource_host
            && !host_matches(host, ctx.resource_host.as_deref().unwrap_or(""))
        {
            return false;
        }

        for condition in &rule.conditions {
            if !condition_matches(condition, ctx) {
                return false;
            }
        }

        if let Some(ref expr) = rule.expression
            && !evaluate_expression(expr, ctx, rebac).await
        {
            return false;
        }

        true
    })
}

fn action_matches(pattern: &str, action: &str) -> bool {
    pattern == "*" || pattern == action
}

fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..];
        return host.ends_with(suffix);
    }
    pattern == host
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Condition, Decision, Expression, PolicyBundle, PolicyContext, RuleType};
    use serde_json::Value;

    fn make_allow_rule(name: &str) -> Rule {
        Rule {
            name: name.to_string(),
            rule_type: RuleType::Allow,
            action: "*".to_string(),
            resource_host: None,
            conditions: vec![],
            expression: None,
            rate_limit_profile: None,
            inject_headers: None,
            pep: PepPolicyActions::default(),
        }
    }

    fn make_forbid_rule(name: &str) -> Rule {
        Rule {
            name: name.to_string(),
            rule_type: RuleType::Forbid,
            action: "*".to_string(),
            resource_host: None,
            conditions: vec![],
            expression: None,
            rate_limit_profile: None,
            inject_headers: None,
            pep: PepPolicyActions::default(),
        }
    }

    fn parse_policy_bundle(value: serde_json::Value) -> PolicyBundle {
        match serde_json::from_value(value) {
            Ok(bundle) => bundle,
            Err(err) => panic!("policy bundle test fixture must be valid: {err}"),
        }
    }

    #[tokio::test]
    async fn test_allow_decision() {
        let mut engine = NativePolicyEngine::new();
        let bundle = PolicyBundle {
            version: "1".to_string(),
            rules: vec![make_allow_rule("test-allow")],
            default_decision: Decision::Deny,
        };
        engine.load(bundle, "test".to_string());
        let ctx = PolicyContext::default();
        let result = engine.decide(&ctx).await;
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.policy_id, "test-allow");
    }

    #[tokio::test]
    async fn test_default_deny() {
        let engine = NativePolicyEngine::new();
        let ctx = PolicyContext::default();
        let result = engine.decide(&ctx).await;
        assert_eq!(result.decision, Decision::Deny);
    }

    #[tokio::test]
    async fn test_forbid_overrides_allow() {
        let mut engine = NativePolicyEngine::new();
        let bundle = PolicyBundle {
            version: "1".to_string(),
            rules: vec![make_allow_rule("allow-all"), make_forbid_rule("forbid-all")],
            default_decision: Decision::Deny,
        };
        engine.load(bundle, "test".to_string());
        let ctx = PolicyContext::default();
        let result = engine.decide(&ctx).await;
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.policy_id, "forbid-all");
    }

    #[tokio::test]
    async fn test_condition_group_match() {
        let mut engine = NativePolicyEngine::new();
        let bundle = PolicyBundle {
            version: "1".to_string(),
            rules: vec![Rule {
                name: "admin-access".to_string(),
                rule_type: RuleType::Allow,
                action: "*".to_string(),
                resource_host: None,
                conditions: vec![Condition {
                    field: "group".to_string(),
                    op: "equals".to_string(),
                    value: Value::String("admin".to_string()),
                }],
                expression: None,
                rate_limit_profile: None,
                inject_headers: None,
                pep: PepPolicyActions::default(),
            }],
            default_decision: Decision::Deny,
        };
        engine.load(bundle, "test".to_string());
        let ctx = PolicyContext {
            groups: vec!["admin".to_string()],
            ..PolicyContext::default()
        };
        let result = engine.decide(&ctx).await;
        assert_eq!(result.decision, Decision::Allow);

        let ctx_no_admin = PolicyContext {
            groups: vec!["user".to_string()],
            ..PolicyContext::default()
        };
        let result_no_admin = engine.decide(&ctx_no_admin).await;
        assert_eq!(result_no_admin.decision, Decision::Deny);
    }

    #[tokio::test]
    async fn test_action_specific_rule() {
        let mut engine = NativePolicyEngine::new();
        let bundle = PolicyBundle {
            version: "1".to_string(),
            rules: vec![Rule {
                name: "read-only".to_string(),
                rule_type: RuleType::Allow,
                action: "read".to_string(),
                resource_host: None,
                conditions: vec![],
                expression: None,
                rate_limit_profile: None,
                inject_headers: None,
                pep: PepPolicyActions::default(),
            }],
            default_decision: Decision::Deny,
        };
        engine.load(bundle, "test".to_string());
        let ctx_read = PolicyContext {
            resource_action: Some("read".to_string()),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&ctx_read).await.decision, Decision::Allow);
        let ctx_write = PolicyContext {
            resource_action: Some("write".to_string()),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&ctx_write).await.decision, Decision::Deny);
    }

    #[tokio::test]
    async fn test_pep_actions_are_loaded_from_matching_rule() {
        let bundle = parse_policy_bundle(serde_json::json!({
            "version": "1",
            "default_decision": "deny",
            "rules": [{
                "name": "finance-egress",
                "type": "allow",
                "action": "forward.connect",
                "resource_host": "*.finance.example.com",
                "pep": {
                    "override_upstream": "https://finance-upstream.example.com",
                    "timeout_override_ms": 2500,
                    "mirror_upstreams": ["https://mirror.example.com"],
                    "force_inspect": true,
                    "force_tunnel": false,
                    "cache_bypass": true
                }
            }]
        }));
        let mut engine = NativePolicyEngine::new();
        engine.load(bundle, "test".to_string());

        let result = engine
            .decide(&PolicyContext {
                resource_action: Some("forward.connect".to_string()),
                resource_host: Some("api.finance.example.com".to_string()),
                ..PolicyContext::default()
            })
            .await;

        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(
            result.pep.override_upstream.as_deref(),
            Some("https://finance-upstream.example.com")
        );
        assert_eq!(result.pep.timeout_override_ms, Some(2500));
        assert_eq!(
            result.pep.mirror_upstreams,
            vec!["https://mirror.example.com"]
        );
        assert_eq!(result.pep.force_inspect, Some(true));
        assert_eq!(result.pep.force_tunnel, Some(false));
        assert_eq!(result.pep.cache_bypass, Some(true));
    }

    #[tokio::test]
    async fn test_pep_actions_accept_canonical_rule_field() {
        let bundle = parse_policy_bundle(serde_json::json!({
            "version": "1",
            "default_decision": "deny",
            "rules": [{
                "name": "pep-egress",
                "type": "allow",
                "action": "forward.connect",
                "pep": {
                    "force_tunnel": true
                },
                "conditions": [{
                    "field": "pep_registration",
                    "op": "equals",
                    "value": "egress-main"
                }]
            }]
        }));
        let mut engine = NativePolicyEngine::new();
        engine.load(bundle, "test".to_string());

        let result = engine
            .decide(&PolicyContext {
                resource_action: Some("forward.connect".to_string()),
                pep_registration: Some("egress-main".to_string()),
                ..PolicyContext::default()
            })
            .await;

        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.pep.force_tunnel, Some(true));
    }

    #[tokio::test]
    async fn test_condition_numeric_operators() {
        let mut engine = NativePolicyEngine::new();
        let bundle = PolicyBundle {
            version: "1".to_string(),
            rules: vec![
                Rule {
                    name: "high-risk".to_string(),
                    rule_type: RuleType::Forbid,
                    action: "*".to_string(),
                    resource_host: None,
                    conditions: vec![Condition {
                        field: "risk_score".to_string(),
                        op: "gt".to_string(),
                        value: Value::Number(serde_json::Number::from(80u64)),
                    }],
                    expression: None,
                    rate_limit_profile: None,
                    inject_headers: None,
                    pep: PepPolicyActions::default(),
                },
                make_allow_rule("allow-all"),
            ],
            default_decision: Decision::Deny,
        };
        engine.load(bundle, "test".to_string());
        let high_risk = PolicyContext {
            risk_score: Some(90),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&high_risk).await.decision, Decision::Deny);
        let low_risk = PolicyContext {
            risk_score: Some(10),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&low_risk).await.decision, Decision::Allow);
    }

    #[tokio::test]
    async fn test_expression_and_operator() {
        let mut engine = NativePolicyEngine::new();
        let expr = Expression::And {
            and: vec![
                Expression::Condition(Condition {
                    field: "group".to_string(),
                    op: "equals".to_string(),
                    value: Value::String("admin".to_string()),
                }),
                Expression::Condition(Condition {
                    field: "acr".to_string(),
                    op: "equals".to_string(),
                    value: Value::String("2".to_string()),
                }),
            ],
        };
        let bundle = PolicyBundle {
            version: "1".to_string(),
            rules: vec![Rule {
                name: "admin-high-acr".to_string(),
                rule_type: RuleType::Allow,
                action: "*".to_string(),
                resource_host: None,
                conditions: vec![],
                expression: Some(expr),
                rate_limit_profile: None,
                inject_headers: None,
                pep: PepPolicyActions::default(),
            }],
            default_decision: Decision::Deny,
        };
        engine.load(bundle, "test".to_string());

        let matching = PolicyContext {
            groups: vec!["admin".to_string()],
            acr: Some("2".to_string()),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&matching).await.decision, Decision::Allow);

        let not_matching = PolicyContext {
            groups: vec!["admin".to_string()],
            acr: Some("1".to_string()),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&not_matching).await.decision, Decision::Deny);
    }

    #[tokio::test]
    async fn test_expression_or_operator() {
        let expr = Expression::Or {
            or: vec![
                Expression::Condition(Condition {
                    field: "group".to_string(),
                    op: "equals".to_string(),
                    value: Value::String("admin".to_string()),
                }),
                Expression::Condition(Condition {
                    field: "group".to_string(),
                    op: "equals".to_string(),
                    value: Value::String("superadmin".to_string()),
                }),
            ],
        };
        let bundle = PolicyBundle {
            version: "1".to_string(),
            rules: vec![Rule {
                name: "admin-or-superadmin".to_string(),
                rule_type: RuleType::Allow,
                action: "*".to_string(),
                resource_host: None,
                conditions: vec![],
                expression: Some(expr),
                rate_limit_profile: None,
                inject_headers: None,
                pep: PepPolicyActions::default(),
            }],
            default_decision: Decision::Deny,
        };
        let mut engine = NativePolicyEngine::new();
        engine.load(bundle, "test".to_string());

        let matching = PolicyContext {
            groups: vec!["superadmin".to_string()],
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&matching).await.decision, Decision::Allow);

        let not_matching = PolicyContext {
            groups: vec!["user".to_string()],
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&not_matching).await.decision, Decision::Deny);
    }

    #[tokio::test]
    async fn test_expression_not_operator() {
        let expr = Expression::Not {
            not: Box::new(Expression::Condition(Condition {
                field: "group".to_string(),
                op: "equals".to_string(),
                value: Value::String("blocked".to_string()),
            })),
        };
        let bundle = PolicyBundle {
            version: "1".to_string(),
            rules: vec![Rule {
                name: "not-blocked".to_string(),
                rule_type: RuleType::Allow,
                action: "*".to_string(),
                resource_host: None,
                conditions: vec![],
                expression: Some(expr),
                rate_limit_profile: None,
                inject_headers: None,
                pep: PepPolicyActions::default(),
            }],
            default_decision: Decision::Deny,
        };
        let mut engine = NativePolicyEngine::new();
        engine.load(bundle, "test".to_string());

        let matching = PolicyContext {
            groups: vec!["admin".to_string()],
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&matching).await.decision, Decision::Allow);

        let blocked = PolicyContext {
            groups: vec!["blocked".to_string()],
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&blocked).await.decision, Decision::Deny);
    }

    #[tokio::test]
    async fn test_expression_conditions_fallback() {
        let mut engine = NativePolicyEngine::new();
        let bundle = PolicyBundle {
            version: "1".to_string(),
            rules: vec![Rule {
                name: "legacy-rule".to_string(),
                rule_type: RuleType::Allow,
                action: "*".to_string(),
                resource_host: None,
                conditions: vec![Condition {
                    field: "group".to_string(),
                    op: "equals".to_string(),
                    value: Value::String("legacy".to_string()),
                }],
                expression: None,
                rate_limit_profile: None,
                inject_headers: None,
                pep: PepPolicyActions::default(),
            }],
            default_decision: Decision::Deny,
        };
        engine.load(bundle, "test".to_string());

        let matching = PolicyContext {
            groups: vec!["legacy".to_string()],
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&matching).await.decision, Decision::Allow);

        let not_matching = PolicyContext {
            groups: vec!["other".to_string()],
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&not_matching).await.decision, Decision::Deny);
    }

    #[tokio::test]
    async fn test_field_path_resolves_dotted_context_path() {
        let ctx = PolicyContext {
            groups: vec!["finance".to_string()],
            posture: vec!["managed".to_string()],
            acr: Some("phishing-resistant".to_string()),
            risk_score: Some(30),
            resource_host: Some("api.finance.example.com".to_string()),
            resource_action: Some("egress.connect".to_string()),
            ..PolicyContext::default()
        };
        assert_eq!(
            ctx.resolve_field_path("group"),
            vec![Value::String("finance".to_string())]
        );
        assert_eq!(
            ctx.resolve_field_path("device.posture"),
            vec![Value::String("managed".to_string())]
        );
        assert_eq!(
            ctx.resolve_field_path("auth.acr"),
            vec![Value::String("phishing-resistant".to_string())]
        );
        assert_eq!(
            ctx.resolve_field_path("risk.score"),
            vec![Value::Number(30.into())]
        );
        assert_eq!(
            ctx.resolve_field_path("resource.host"),
            vec![Value::String("api.finance.example.com".to_string())]
        );
        assert!(ctx.in_group("finance"));
        assert!(!ctx.in_group("engineering"));
        assert!(ctx.action_matches("egress.connect"));
        assert!(!ctx.action_matches("app.read"));
        assert!(ctx.host_matches("*.finance.example.com"));
        assert!(!ctx.host_matches("*.engineering.example.com"));
    }

    #[tokio::test]
    async fn test_expression_in_group_shortcut() {
        let mut engine = NativePolicyEngine::new();
        let bundle = PolicyBundle {
            version: "1".to_string(),
            rules: vec![Rule {
                name: "group-rule".to_string(),
                rule_type: RuleType::Allow,
                action: "*".to_string(),
                resource_host: None,
                conditions: vec![],
                expression: Some(Expression::InGroup {
                    in_group: "finance".to_string(),
                }),
                rate_limit_profile: None,
                inject_headers: None,
                pep: PepPolicyActions::default(),
            }],
            default_decision: Decision::Deny,
        };
        engine.load(bundle, "test".to_string());
        let ctx = PolicyContext {
            groups: vec!["finance".to_string()],
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&ctx).await.decision, Decision::Allow);
        let not_member = PolicyContext {
            groups: vec!["engineering".to_string()],
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&not_member).await.decision, Decision::Deny);
    }

    #[tokio::test]
    async fn test_expression_action_shortcut() {
        let mut engine = NativePolicyEngine::new();
        let bundle = PolicyBundle {
            version: "1".to_string(),
            rules: vec![Rule {
                name: "action-rule".to_string(),
                rule_type: RuleType::Allow,
                action: "*".to_string(),
                resource_host: None,
                conditions: vec![],
                expression: Some(Expression::MatchAction {
                    action: "egress.connect".to_string(),
                }),
                rate_limit_profile: None,
                inject_headers: None,
                pep: PepPolicyActions::default(),
            }],
            default_decision: Decision::Deny,
        };
        engine.load(bundle, "test".to_string());
        let ctx = PolicyContext {
            resource_action: Some("egress.connect".to_string()),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&ctx).await.decision, Decision::Allow);
        let wrong_action = PolicyContext {
            resource_action: Some("app.read".to_string()),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&wrong_action).await.decision, Decision::Deny);
    }

    #[tokio::test]
    async fn test_expression_field_path_with_like_operator() {
        let mut engine = NativePolicyEngine::new();
        let bundle = PolicyBundle {
            version: "1".to_string(),
            rules: vec![Rule {
                name: "host-rule".to_string(),
                rule_type: RuleType::Allow,
                action: "*".to_string(),
                resource_host: None,
                conditions: vec![],
                expression: Some(Expression::FieldCondition {
                    field: "resource.host".to_string(),
                    op: "like".to_string(),
                    value: Value::String("*.finance.example.com".to_string()),
                }),
                rate_limit_profile: None,
                inject_headers: None,
                pep: PepPolicyActions::default(),
            }],
            default_decision: Decision::Deny,
        };
        engine.load(bundle, "test".to_string());
        let ctx = PolicyContext {
            resource_host: Some("api.finance.example.com".to_string()),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&ctx).await.decision, Decision::Allow);
        let wrong_host = PolicyContext {
            resource_host: Some("evil.example.com".to_string()),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&wrong_host).await.decision, Decision::Deny);
    }

    // --- ReBAC integration tests ---

    /// A mock ReBAC evaluator that returns true when the relationship
    /// tuple exists in its internal map.
    struct MockRebacEvaluator {
        /// Map from "namespace:object_id#relation:subject_namespace:subject_id" -> allowed
        tuples: std::collections::HashMap<String, bool>,
    }

    #[async_trait::async_trait]
    impl RebacEvaluator for MockRebacEvaluator {
        async fn check(
            &self,
            namespace: &str,
            object_id: &str,
            relation: &str,
            subject_namespace: &str,
            subject_id: &str,
        ) -> bool {
            let key =
                format!("{namespace}:{object_id}#{relation}:{subject_namespace}:{subject_id}");
            self.tuples.get(&key).copied().unwrap_or(false)
        }
    }

    #[tokio::test]
    async fn test_rebac_check_expression_allows_when_tuple_exists() {
        let mut tuples = std::collections::HashMap::new();
        tuples.insert("doc:doc-1#owner:user:alice".to_string(), true);
        let evaluator = Arc::new(MockRebacEvaluator { tuples });

        let mut engine = NativePolicyEngine::new().with_rebac_evaluator(evaluator);
        let bundle = PolicyBundle {
            version: "1".to_string(),
            rules: vec![Rule {
                name: "owner-access".to_string(),
                rule_type: RuleType::Allow,
                action: "*".to_string(),
                resource_host: None,
                conditions: vec![],
                expression: Some(Expression::RebacCheck {
                    namespace: "doc".to_string(),
                    object_id: "doc-1".to_string(),
                    relation: "owner".to_string(),
                    subject_namespace: "user".to_string(),
                }),
                rate_limit_profile: None,
                inject_headers: None,
                pep: PepPolicyActions::default(),
            }],
            default_decision: Decision::Deny,
        };
        engine.load(bundle, "test".to_string());

        let ctx = PolicyContext {
            subject_id: Some("alice".to_string()),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&ctx).await.decision, Decision::Allow);
    }

    #[tokio::test]
    async fn test_rebac_check_expression_denies_when_tuple_missing() {
        let tuples = std::collections::HashMap::new(); // empty
        let evaluator = Arc::new(MockRebacEvaluator { tuples });

        let mut engine = NativePolicyEngine::new().with_rebac_evaluator(evaluator);
        let bundle = PolicyBundle {
            version: "1".to_string(),
            rules: vec![Rule {
                name: "owner-access".to_string(),
                rule_type: RuleType::Allow,
                action: "*".to_string(),
                resource_host: None,
                conditions: vec![],
                expression: Some(Expression::RebacCheck {
                    namespace: "doc".to_string(),
                    object_id: "doc-1".to_string(),
                    relation: "owner".to_string(),
                    subject_namespace: "user".to_string(),
                }),
                rate_limit_profile: None,
                inject_headers: None,
                pep: PepPolicyActions::default(),
            }],
            default_decision: Decision::Deny,
        };
        engine.load(bundle, "test".to_string());

        let ctx = PolicyContext {
            subject_id: Some("bob".to_string()),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&ctx).await.decision, Decision::Deny);
    }

    #[tokio::test]
    async fn test_rebac_check_expression_denies_when_no_subject_id() {
        let tuples = std::collections::HashMap::new();
        let evaluator = Arc::new(MockRebacEvaluator { tuples });

        let mut engine = NativePolicyEngine::new().with_rebac_evaluator(evaluator);
        let bundle = PolicyBundle {
            version: "1".to_string(),
            rules: vec![Rule {
                name: "owner-access".to_string(),
                rule_type: RuleType::Allow,
                action: "*".to_string(),
                resource_host: None,
                conditions: vec![],
                expression: Some(Expression::RebacCheck {
                    namespace: "doc".to_string(),
                    object_id: "doc-1".to_string(),
                    relation: "owner".to_string(),
                    subject_namespace: "user".to_string(),
                }),
                rate_limit_profile: None,
                inject_headers: None,
                pep: PepPolicyActions::default(),
            }],
            default_decision: Decision::Deny,
        };
        engine.load(bundle, "test".to_string());

        let ctx = PolicyContext::default(); // no subject_id
        assert_eq!(engine.decide(&ctx).await.decision, Decision::Deny);
    }

    #[tokio::test]
    async fn test_rebac_forbid_overrides_allow() {
        let mut tuples = std::collections::HashMap::new();
        tuples.insert("doc:doc-1#viewer:user:mallory".to_string(), true);
        let evaluator = Arc::new(MockRebacEvaluator { tuples });

        let mut engine = NativePolicyEngine::new().with_rebac_evaluator(evaluator);
        let bundle = PolicyBundle {
            version: "1".to_string(),
            rules: vec![
                Rule {
                    name: "block-mallory".to_string(),
                    rule_type: RuleType::Forbid,
                    action: "*".to_string(),
                    resource_host: None,
                    conditions: vec![],
                    expression: Some(Expression::RebacCheck {
                        namespace: "doc".to_string(),
                        object_id: "doc-1".to_string(),
                        relation: "viewer".to_string(),
                        subject_namespace: "user".to_string(),
                    }),
                    rate_limit_profile: None,
                    inject_headers: None,
                    pep: PepPolicyActions::default(),
                },
                Rule {
                    name: "allow-all".to_string(),
                    rule_type: RuleType::Allow,
                    action: "*".to_string(),
                    resource_host: None,
                    conditions: vec![],
                    expression: None,
                    rate_limit_profile: None,
                    inject_headers: None,
                    pep: PepPolicyActions::default(),
                },
            ],
            default_decision: Decision::Deny,
        };
        engine.load(bundle, "test".to_string());

        let ctx = PolicyContext {
            subject_id: Some("mallory".to_string()),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&ctx).await.decision, Decision::Deny);
        assert_eq!(engine.decide(&ctx).await.policy_id, "block-mallory");
    }

    /// Determinism property: the same input always produces the same decision.
    #[tokio::test]
    async fn test_native_policy_is_deterministic() {
        let mut engine = NativePolicyEngine::new();
        let bundle = PolicyBundle {
            version: "1".to_string(),
            rules: vec![
                make_allow_rule("allow-all"),
                make_forbid_rule("forbid-mallory"),
            ],
            default_decision: Decision::Deny,
        };
        engine.load(bundle, "test".to_string());
        let ctx = PolicyContext {
            subject_id: Some("mallory".to_string()),
            ..PolicyContext::default()
        };
        let first = engine.decide(&ctx).await;
        let second = engine.decide(&ctx).await;
        assert_eq!(
            first.decision, second.decision,
            "native policy engine must be deterministic"
        );
        assert_eq!(
            first.policy_id, second.policy_id,
            "native policy engine must produce the same policy_id"
        );
    }

    /// Differential consistency: NativePolicyEngine with default-deny and
    /// no loaded bundle must produce Deny (same as Cedar/Rego defaults).
    #[tokio::test]
    async fn test_default_deny_consistent_across_contexts() {
        let engine = NativePolicyEngine::new();
        // No bundle loaded → engine uses default_decision = Deny.
        let ctx_a = PolicyContext {
            subject_id: Some("user-a".to_string()),
            ..PolicyContext::default()
        };
        let ctx_b = PolicyContext {
            subject_id: Some("user-b".to_string()),
            ..PolicyContext::default()
        };
        assert_eq!(
            engine.decide(&ctx_a).await.decision,
            Decision::Deny,
            "no-bundle Native must default-deny"
        );
        assert_eq!(
            engine.decide(&ctx_b).await.decision,
            Decision::Deny,
            "no-bundle Native must default-deny for any subject"
        );
    }
}
