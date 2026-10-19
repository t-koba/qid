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

        // No rule matched: honor the bundle's configured default instead of
        // silently denying. Without a bundle there is no configuration to
        // honor, so fail closed.
        let default = self
            .bundle
            .as_ref()
            .map(|bundle| bundle.default_decision.clone())
            .unwrap_or(Decision::Deny);
        trace.push(format!("No matching rule; default {}", default.as_str()));
        record_metrics(_start);
        DecisionDetails {
            obligations: Vec::new(),
            context: None,
            decision: default.clone(),
            policy_id: self.bundle_id.clone(),
            rate_limit_profile: None,
            policy_tags: vec![format!("qid:default-{}", default.as_str())],
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

        // A rule matches only on positively established evidence; absent
        // inputs (`None`) never satisfy a rule.
        for condition in &rule.conditions {
            if condition_matches(condition, ctx) != Some(true) {
                return false;
            }
        }

        if let Some(ref expr) = rule.expression
            && evaluate_expression(expr, ctx, rebac).await != Some(true)
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
    async fn test_condition_numeric_thresholds_compare_faithfully() {
        fn condition(op: &str, threshold: Value) -> Condition {
            Condition {
                field: "risk_score".to_string(),
                op: op.to_string(),
                value: threshold,
            }
        }
        fn ctx_with_score(score: u64) -> PolicyContext {
            PolicyContext {
                risk_score: Some(score),
                ..PolicyContext::default()
            }
        }
        let frac = |f: f64| Value::Number(serde_json::Number::from_f64(f).unwrap());
        let int = |u: u64| Value::Number(serde_json::Number::from(u));

        // Fractional thresholds must not coerce to zero: 0 gte 0.5 is false,
        // 10 lt 10.5 is true, 10 gt 10.5 is false.
        assert_eq!(
            condition_matches(&condition("gte", frac(0.5)), &ctx_with_score(0)),
            Some(false)
        );
        assert_eq!(
            condition_matches(&condition("lt", frac(10.5)), &ctx_with_score(10)),
            Some(true)
        );
        assert_eq!(
            condition_matches(&condition("gt", frac(10.5)), &ctx_with_score(10)),
            Some(false)
        );
        assert_eq!(
            condition_matches(&condition("gt", frac(10.5)), &ctx_with_score(11)),
            Some(true)
        );
        // Negative thresholds compare faithfully against unsigned scores.
        let neg = Value::Number(serde_json::Number::from(-1i64));
        assert_eq!(
            condition_matches(&condition("gt", neg.clone()), &ctx_with_score(10)),
            Some(true)
        );
        assert_eq!(
            condition_matches(&condition("lt", neg), &ctx_with_score(10)),
            Some(false)
        );
        // Large integers stay exact: u64 precision must survive comparison.
        // (A float-only comparison would round both sides to the same f64.)
        assert_eq!(
            condition_matches(
                &condition("gt", int(u64::MAX - 1)),
                &ctx_with_score(u64::MAX)
            ),
            Some(true)
        );
        assert_eq!(
            condition_matches(&condition("gte", int(u64::MAX)), &ctx_with_score(u64::MAX)),
            Some(true)
        );
        // Non-numeric thresholds never match a numeric comparison.
        assert_eq!(
            condition_matches(
                &condition("gt", Value::String("80".to_string())),
                &ctx_with_score(90)
            ),
            Some(false)
        );
    }

    #[tokio::test]
    async fn test_forbid_rule_with_fractional_threshold() {
        let mut engine = NativePolicyEngine::new();
        let bundle = PolicyBundle {
            version: "1".to_string(),
            rules: vec![
                Rule {
                    name: "fractional-risk".to_string(),
                    rule_type: RuleType::Forbid,
                    action: "*".to_string(),
                    resource_host: None,
                    conditions: vec![Condition {
                        field: "risk_score".to_string(),
                        op: "gt".to_string(),
                        value: Value::Number(serde_json::Number::from_f64(10.5).unwrap()),
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
        let below = PolicyContext {
            risk_score: Some(10),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&below).await.decision, Decision::Allow);
        let above = PolicyContext {
            risk_score: Some(11),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&above).await.decision, Decision::Deny);
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
            Some(vec![Value::String("finance".to_string())])
        );
        assert_eq!(
            ctx.resolve_field_path("device.posture"),
            Some(vec![Value::String("managed".to_string())])
        );
        assert_eq!(
            ctx.resolve_field_path("auth.acr"),
            Some(vec![Value::String("phishing-resistant".to_string())])
        );
        assert_eq!(
            ctx.resolve_field_path("risk.score"),
            Some(vec![Value::Number(30.into())])
        );
        assert_eq!(
            ctx.resolve_field_path("resource.host"),
            Some(vec![Value::String("api.finance.example.com".to_string())])
        );
        // Absent inputs resolve to absence, never to favorable stand-ins.
        let empty = PolicyContext::default();
        assert_eq!(empty.resolve_field_path("risk.score"), None);
        assert_eq!(empty.resolve_field_path("auth.age_seconds"), None);
        assert_eq!(empty.resolve_field_path("subject"), None);
        assert_eq!(empty.resolve_field_path("group"), Some(vec![]));
        assert_eq!(empty.resolve_field_path("no.such.field"), None);
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
        ) -> qid_core::error::QidResult<bool> {
            let key =
                format!("{namespace}:{object_id}#{relation}:{subject_namespace}:{subject_id}");
            Ok(self.tuples.get(&key).copied().unwrap_or(false))
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

    /// Evaluator that always reports a storage failure. The expression
    /// evaluator must map it to unknown, never to evidence.
    struct FailingRebacEvaluator;

    #[async_trait::async_trait]
    impl RebacEvaluator for FailingRebacEvaluator {
        async fn check(
            &self,
            _namespace: &str,
            _object_id: &str,
            _relation: &str,
            _subject_namespace: &str,
            _subject_id: &str,
        ) -> qid_core::error::QidResult<bool> {
            Err(qid_core::error::QidError::Storage {
                message: "rebac unavailable".to_string(),
            })
        }
    }

    fn negated_rebac_allow_rule() -> Rule {
        Rule {
            name: "non-member-access".to_string(),
            rule_type: RuleType::Allow,
            action: "*".to_string(),
            resource_host: None,
            conditions: vec![],
            expression: Some(Expression::Not {
                not: Box::new(Expression::RebacCheck {
                    namespace: "doc".to_string(),
                    object_id: "doc-1".to_string(),
                    relation: "viewer".to_string(),
                    subject_namespace: "user".to_string(),
                }),
            }),
            rate_limit_profile: None,
            inject_headers: None,
            pep: PepPolicyActions::default(),
        }
    }

    #[tokio::test]
    async fn test_negated_rebac_check_does_not_match_on_evaluator_error() {
        let evaluator = Arc::new(FailingRebacEvaluator);
        let mut engine = NativePolicyEngine::new().with_rebac_evaluator(evaluator);
        let bundle = PolicyBundle {
            version: "1".to_string(),
            rules: vec![negated_rebac_allow_rule()],
            default_decision: Decision::Deny,
        };
        engine.load(bundle, "test".to_string());

        let ctx = PolicyContext {
            subject_id: Some("alice".to_string()),
            ..PolicyContext::default()
        };
        // Unknown under negation stays unknown: no match, default Deny holds.
        assert_eq!(engine.decide(&ctx).await.decision, Decision::Deny);
    }

    #[tokio::test]
    async fn test_negated_rebac_check_matches_on_established_false() {
        let tuples = std::collections::HashMap::new(); // Ok(false): established absence
        let evaluator = Arc::new(MockRebacEvaluator { tuples });
        let mut engine = NativePolicyEngine::new().with_rebac_evaluator(evaluator);
        let bundle = PolicyBundle {
            version: "1".to_string(),
            rules: vec![negated_rebac_allow_rule()],
            default_decision: Decision::Deny,
        };
        engine.load(bundle, "test".to_string());

        let ctx = PolicyContext {
            subject_id: Some("bob".to_string()),
            ..PolicyContext::default()
        };
        // Genuine Ok(false) is counter-evidence, so the negation satisfies the rule.
        assert_eq!(engine.decide(&ctx).await.decision, Decision::Allow);
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

    fn allow_rule(name: &str, conditions: Vec<Condition>) -> Rule {
        Rule {
            name: name.to_string(),
            rule_type: RuleType::Allow,
            action: "*".to_string(),
            resource_host: None,
            conditions,
            expression: None,
            rate_limit_profile: None,
            inject_headers: None,
            pep: PepPolicyActions::default(),
        }
    }

    fn number_condition(field: &str, op: &str, value: u64) -> Condition {
        Condition {
            field: field.to_string(),
            op: op.to_string(),
            value: Value::Number(value.into()),
        }
    }

    #[tokio::test]
    async fn absent_risk_and_age_cannot_satisfy_allow_rule() {
        let mut engine = NativePolicyEngine::new();
        engine.load(
            PolicyBundle {
                version: "1".to_string(),
                rules: vec![allow_rule(
                    "low-risk-fresh",
                    vec![
                        number_condition("risk.score", "<=", 10),
                        number_condition("auth.age_seconds", "<", 300),
                    ],
                )],
                default_decision: Decision::Deny,
            },
            "test".to_string(),
        );

        // Missing evidence is not zero risk or fresh authentication.
        assert_eq!(
            engine.decide(&PolicyContext::default()).await.decision,
            Decision::Deny
        );
        let fresh = PolicyContext {
            risk_score: Some(5),
            auth_age_seconds: Some(100),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&fresh).await.decision, Decision::Allow);
        let stale = PolicyContext {
            risk_score: Some(5),
            auth_age_seconds: Some(1_000),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&stale).await.decision, Decision::Deny);
    }

    #[tokio::test]
    async fn negation_over_absent_evidence_does_not_match() {
        let mut engine = NativePolicyEngine::new();
        let mut rule = allow_rule("not-high-risk", vec![]);
        rule.expression = Some(Expression::Not {
            not: Box::new(Expression::FieldCondition {
                field: "risk.score".to_string(),
                op: ">".to_string(),
                value: Value::Number(100.into()),
            }),
        });
        engine.load(
            PolicyBundle {
                version: "1".to_string(),
                rules: vec![rule],
                default_decision: Decision::Deny,
            },
            "test".to_string(),
        );

        // Unknown risk is neither established low nor high: no match.
        assert_eq!(
            engine.decide(&PolicyContext::default()).await.decision,
            Decision::Deny
        );
        let low = PolicyContext {
            risk_score: Some(50),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&low).await.decision, Decision::Allow);
        let high = PolicyContext {
            risk_score: Some(200),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&high).await.decision, Decision::Deny);
    }

    #[tokio::test]
    async fn forbid_rule_ignores_absent_evidence() {
        let mut engine = NativePolicyEngine::new();
        engine.load(
            PolicyBundle {
                version: "1".to_string(),
                rules: vec![Rule {
                    name: "block-high-risk".to_string(),
                    rule_type: RuleType::Forbid,
                    action: "*".to_string(),
                    resource_host: None,
                    conditions: vec![number_condition("risk.score", ">", 100)],
                    expression: None,
                    rate_limit_profile: None,
                    inject_headers: None,
                    pep: PepPolicyActions::default(),
                }],
                default_decision: Decision::Allow,
            },
            "test".to_string(),
        );

        // Unknown risk cannot trigger the forbid rule; the configured
        // default applies instead.
        let details = engine.decide(&PolicyContext::default()).await;
        assert_eq!(details.decision, Decision::Allow);
        assert!(
            details
                .policy_tags
                .contains(&"qid:default-allow".to_string())
        );
        let high = PolicyContext {
            risk_score: Some(200),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&high).await.decision, Decision::Deny);
    }

    #[tokio::test]
    async fn no_match_honors_configured_default_decision() {
        let mut engine = NativePolicyEngine::new();
        engine.load(
            PolicyBundle {
                version: "1".to_string(),
                rules: vec![allow_rule(
                    "finance-only",
                    vec![Condition {
                        field: "group".to_string(),
                        op: "equals".to_string(),
                        value: Value::String("finance".to_string()),
                    }],
                )],
                default_decision: Decision::StepUp,
            },
            "test".to_string(),
        );

        let details = engine.decide(&PolicyContext::default()).await;
        assert_eq!(details.decision, Decision::StepUp);
        assert!(
            details
                .policy_tags
                .contains(&"qid:default-step_up".to_string())
        );
        assert!(
            details
                .trace
                .iter()
                .any(|line| line.contains("default step_up")),
            "trace must name the applied default, got: {:?}",
            details.trace
        );
    }

    #[test]
    fn decision_names_round_trip_and_reject_unknown() {
        for decision in [
            Decision::Allow,
            Decision::Deny,
            Decision::StepUp,
            Decision::ConsentRequired,
            Decision::LocalResponse,
            Decision::ApprovalRequired,
            Decision::Quarantine,
            Decision::AuditOnly,
            Decision::Conditional,
        ] {
            assert_eq!(Decision::parse(decision.as_str()), Some(decision));
        }
        assert_eq!(Decision::parse("bogus"), None);
        assert_eq!(Decision::parse(""), None);
        assert_eq!(Decision::parse("ALLOW"), None);
    }

    fn expression_rule(name: &str, expression: Expression) -> Rule {
        Rule {
            name: name.to_string(),
            rule_type: RuleType::Allow,
            action: "*".to_string(),
            resource_host: None,
            conditions: vec![],
            expression: Some(expression),
            rate_limit_profile: None,
            inject_headers: None,
            pep: PepPolicyActions::default(),
        }
    }

    fn risk_above(value: u64) -> Expression {
        Expression::FieldCondition {
            field: "risk.score".to_string(),
            op: ">".to_string(),
            value: Value::Number(value.into()),
        }
    }

    fn group_is(name: &str) -> Expression {
        Expression::FieldCondition {
            field: "group".to_string(),
            op: "equals".to_string(),
            value: Value::String(name.to_string()),
        }
    }

    #[tokio::test]
    async fn or_with_absent_evidence_stays_unknown() {
        let mut engine = NativePolicyEngine::new();
        engine.load(
            PolicyBundle {
                version: "1".to_string(),
                rules: vec![expression_rule(
                    "risky-or-finance",
                    Expression::Or {
                        or: vec![risk_above(100), group_is("finance")],
                    },
                )],
                default_decision: Decision::Deny,
            },
            "test".to_string(),
        );

        // Absent risk with a non-matching group is unknown, not a match:
        // absence must not satisfy a disjunction.
        assert_eq!(
            engine.decide(&PolicyContext::default()).await.decision,
            Decision::Deny
        );
        let finance = PolicyContext {
            groups: vec!["finance".to_string()],
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&finance).await.decision, Decision::Allow);
        let risky = PolicyContext {
            risk_score: Some(200),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&risky).await.decision, Decision::Allow);
    }

    #[tokio::test]
    async fn and_with_absent_evidence_stays_unknown() {
        let mut engine = NativePolicyEngine::new();
        engine.load(
            PolicyBundle {
                version: "1".to_string(),
                rules: vec![expression_rule(
                    "risky-finance",
                    Expression::And {
                        and: vec![risk_above(100), group_is("finance")],
                    },
                )],
                default_decision: Decision::Deny,
            },
            "test".to_string(),
        );

        assert_eq!(
            engine.decide(&PolicyContext::default()).await.decision,
            Decision::Deny
        );
        let both = PolicyContext {
            groups: vec!["finance".to_string()],
            risk_score: Some(200),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&both).await.decision, Decision::Allow);
        // Established counter-evidence still denies the conjunction even
        // when the other input is absent.
        let low_unknown_group = PolicyContext {
            risk_score: Some(10),
            ..PolicyContext::default()
        };
        assert_eq!(
            engine.decide(&low_unknown_group).await.decision,
            Decision::Deny
        );
    }

    #[tokio::test]
    async fn negation_over_conjunction_with_absent_evidence_does_not_match() {
        let mut engine = NativePolicyEngine::new();
        engine.load(
            PolicyBundle {
                version: "1".to_string(),
                rules: vec![expression_rule(
                    "not-risky-finance",
                    Expression::Not {
                        not: Box::new(Expression::And {
                            and: vec![risk_above(100), group_is("finance")],
                        }),
                    },
                )],
                default_decision: Decision::Deny,
            },
            "test".to_string(),
        );

        // And(absent, true) is unknown, so its negation is unknown too:
        // absent evidence never satisfies the rule through negation.
        let finance_unknown_risk = PolicyContext {
            groups: vec!["finance".to_string()],
            ..PolicyContext::default()
        };
        assert_eq!(
            engine.decide(&finance_unknown_risk).await.decision,
            Decision::Deny
        );
        // Established counter-evidence annihilates the conjunction even
        // with the other input absent, so the negation matches soundly.
        assert_eq!(
            engine.decide(&PolicyContext::default()).await.decision,
            Decision::Allow
        );
        let plain = PolicyContext {
            groups: vec!["engineering".to_string()],
            risk_score: Some(10),
            ..PolicyContext::default()
        };
        assert_eq!(engine.decide(&plain).await.decision, Decision::Allow);
    }
}
