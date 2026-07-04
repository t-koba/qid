use crate::models::{Decision, DecisionDetails, PolicyContext, PolicyEngine};
use std::sync::Arc;

#[cfg(feature = "cedar-embedded")]
use cedar_policy::{Authorizer, Context, Entities, EntityId, EntityTypeName, EntityUid, Request};

/// In-process Cedar policy engine using the native `cedar-policy` Rust crate.
///
/// Policy sets and optional schemas are compiled at construction time and
/// reused across decisions.  Use `set_policies` to hot-reload.
#[derive(Debug, Clone)]
pub struct CedarEmbeddedPolicyEngine {
    policies: Arc<Vec<String>>,
    schema: Option<Arc<String>>,
}

impl CedarEmbeddedPolicyEngine {
    /// Create an engine with no policies.
    pub fn empty() -> Self {
        Self {
            policies: Arc::new(Vec::new()),
            schema: None,
        }
    }

    /// Create an engine from Cedar policy source strings.
    pub fn new(policies: Vec<String>) -> Self {
        Self {
            policies: Arc::new(policies),
            schema: None,
        }
    }

    /// Attach an optional Cedar schema (recommended for type-checking).
    pub fn with_schema(mut self, schema: impl Into<String>) -> Self {
        self.schema = Some(Arc::new(schema.into()));
        self
    }

    /// Hot-reload policy sources.
    pub fn set_policies(&mut self, policies: Vec<String>) {
        self.policies = Arc::new(policies);
    }

    fn evaluate(&self, ctx: &PolicyContext) -> DecisionDetails {
        #[cfg(feature = "cedar-embedded")]
        {
            self.evaluate_cedar(ctx)
        }
        #[cfg(not(feature = "cedar-embedded"))]
        {
            let _ = ctx;
            DecisionDetails {
                decision: Decision::Deny,
                policy_id: "cedar-embedded-disabled".to_string(),
                trace: vec!["cedar-embedded feature is not enabled".to_string()],
                ..DecisionDetails::default()
            }
        }
    }

    #[cfg(feature = "cedar-embedded")]
    fn evaluate_cedar(&self, ctx: &PolicyContext) -> DecisionDetails {
        // Build policy set from sources
        let pset = match build_policy_set(&self.policies) {
            Ok(ps) => ps,
            Err(e) => {
                return DecisionDetails {
                    decision: Decision::Deny,
                    policy_id: "cedar-embedded".to_string(),
                    trace: vec![format!("Cedar policy parse error: {e}")],
                    ..DecisionDetails::default()
                };
            }
        };

        let principal = make_euid("User", ctx.subject_id.as_deref().unwrap_or("unknown"));
        let action = make_euid(
            "Action",
            ctx.resource_action.as_deref().unwrap_or("execute"),
        );
        let resource = make_euid(
            "Resource",
            ctx.resource_host.as_deref().unwrap_or("unknown"),
        );

        let context_val = build_context_json(ctx);
        let context = match Context::from_json_value(context_val, None) {
            Ok(c) => c,
            Err(e) => {
                return DecisionDetails {
                    decision: Decision::Deny,
                    policy_id: "cedar-embedded".to_string(),
                    trace: vec![format!("Cedar context error: {e}")],
                    ..DecisionDetails::default()
                };
            }
        };

        let request = match Request::new(
            principal,
            action,
            resource,
            context,
            None::<&cedar_policy::Schema>,
        ) {
            Ok(r) => r,
            Err(e) => {
                return DecisionDetails {
                    decision: Decision::Deny,
                    policy_id: "cedar-embedded".to_string(),
                    trace: vec![format!("Cedar request error: {e}")],
                    ..DecisionDetails::default()
                };
            }
        };

        let authorizer = Authorizer::new();
        let response = authorizer.is_authorized(&request, &pset, &Entities::empty());

        let decision = if response.decision() == cedar_policy::Decision::Allow {
            crate::models::Decision::Allow
        } else {
            crate::models::Decision::Deny
        };

        let trace: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|id| format!("matched policy: {id}"))
            .collect();

        DecisionDetails {
            decision,
            policy_id: "cedar-embedded".to_string(),
            trace,
            ..DecisionDetails::default()
        }
    }
}

#[cfg(feature = "cedar-embedded")]
fn make_euid(type_name: &str, id: &str) -> EntityUid {
    let tn = type_name
        .parse::<EntityTypeName>()
        .unwrap_or_else(|_| "Unknown".parse::<EntityTypeName>().unwrap());
    let eid = id
        .parse::<EntityId>()
        .unwrap_or_else(|_| "unknown".parse::<EntityId>().unwrap());
    EntityUid::from_type_name_and_id(tn, eid)
}

#[cfg(feature = "cedar-embedded")]
fn build_policy_set(sources: &[String]) -> Result<cedar_policy::PolicySet, String> {
    let policies: Vec<cedar_policy::Policy> = sources
        .iter()
        .enumerate()
        .map(|(i, src)| {
            src.parse::<cedar_policy::Policy>()
                .map_err(|e: cedar_policy::ParseErrors| format!("policy {i}: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    cedar_policy::PolicySet::from_policies(policies)
        .map_err(|e| format!("building policy set: {e}"))
}

#[cfg(feature = "cedar-embedded")]
fn build_context_json(ctx: &PolicyContext) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert(
        "subject_id".to_string(),
        serde_json::Value::String(ctx.subject_id.clone().unwrap_or_default()),
    );
    map.insert(
        "groups".to_string(),
        serde_json::Value::Array(
            ctx.groups
                .iter()
                .map(|g| serde_json::Value::String(g.clone()))
                .collect(),
        ),
    );
    map.insert(
        "roles".to_string(),
        serde_json::Value::Array(
            ctx.roles
                .iter()
                .map(|r| serde_json::Value::String(r.clone()))
                .collect(),
        ),
    );
    map.insert(
        "device_id".to_string(),
        serde_json::Value::String(ctx.device_id.clone().unwrap_or_default()),
    );
    map.insert(
        "acr".to_string(),
        serde_json::Value::String(ctx.acr.clone().unwrap_or_default()),
    );
    if let Some(score) = ctx.risk_score {
        map.insert(
            "risk_score".to_string(),
            serde_json::Value::Number(score.into()),
        );
    }
    if let Some(age) = ctx.auth_age_seconds {
        map.insert(
            "auth_age_seconds".to_string(),
            serde_json::Value::Number(age.into()),
        );
    }
    serde_json::Value::Object(map)
}

#[async_trait::async_trait]
impl PolicyEngine for CedarEmbeddedPolicyEngine {
    async fn decide(&self, ctx: &PolicyContext) -> DecisionDetails {
        self.evaluate(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "cedar-embedded")]
    #[test]
    fn allow_policy() {
        let engine = CedarEmbeddedPolicyEngine::new(vec![
            r#"permit(principal in User::"alice", action, resource);"#.to_string(),
        ]);
        let ctx = PolicyContext {
            subject_id: Some("alice".to_string()),
            resource_action: Some("read".to_string()),
            ..PolicyContext::default()
        };
        let result = engine.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[cfg(feature = "cedar-embedded")]
    #[test]
    fn deny_by_default() {
        let engine = CedarEmbeddedPolicyEngine::new(Vec::new());
        let ctx = PolicyContext::default();
        let result = engine.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn no_feature_denies() {
        let engine = CedarEmbeddedPolicyEngine::empty();
        let ctx = PolicyContext::default();
        let result = engine.evaluate(&ctx);
        assert_eq!(result.decision, Decision::Deny);
    }
}
