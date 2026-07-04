use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    #[default]
    Deny,
    StepUp,
    ConsentRequired,
    LocalResponse,
    ApprovalRequired,
    Quarantine,
    AuditOnly,
    /// AuthZEN §4: a decision that depends on additional runtime information
    /// supplied by the PEP. The `obligations` field on `DecisionDetails`
    /// carries the typed shape of the required input.
    Conditional,
}

/// AuthZEN §7.1 typed obligation. Each obligation carries a namespace and
/// version, an opaque name, and a JSON payload that the PEP knows how to
/// interpret. INTEROP §3 forbids using bare string obligations because
/// the PEP cannot negotiate the shape of the requested input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TypedObligation {
    pub namespace: String,
    pub version: String,
    pub name: String,
    #[serde(default)]
    pub capability: Option<String>,
    #[serde(default)]
    pub payload: Value,
}

/// AuthZEN §7.1 typed decision context extension. Lets the PDP return
/// structured per-decision context such as `evaluator`, `reason_admin`,
/// or a custom capability hint without flattening the response to
/// untyped strings.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionContextExtension {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_admin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_user: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DecisionDetails {
    pub decision: Decision,
    pub policy_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_profile: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub policy_tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inject_headers: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "PepPolicyActions::is_empty")]
    pub pep: PepPolicyActions,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub matched_rules: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub trace: Vec<String>,
    /// AuthZEN §7.1 typed obligations. INTEROP §3 mandates namespace and
    /// version metadata on every obligation so the PEP can negotiate
    /// compatibility.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligations: Vec<TypedObligation>,
    /// AuthZEN §7.1 typed decision-context extension. Free-form, but
    /// preserves the well-known `evaluator` and `reason_*` fields as
    /// first-class JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<DecisionContextExtension>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PepPolicyActions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_upstream: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_override_ms: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub mirror_upstreams: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_inspect: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_tunnel: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_bypass: Option<bool>,
}

impl PepPolicyActions {
    pub fn is_empty(&self) -> bool {
        self.override_upstream.is_none()
            && self.timeout_override_ms.is_none()
            && self.mirror_upstreams.is_empty()
            && self.force_inspect.is_none()
            && self.force_tunnel.is_none()
            && self.cache_bypass.is_none()
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PolicyContext {
    pub subject_id: Option<String>,
    pub groups: Vec<String>,
    pub roles: Vec<String>,
    pub entitlements: Vec<String>,
    pub device_id: Option<String>,
    pub posture: Vec<String>,
    pub acr: Option<String>,
    pub auth_age_seconds: Option<u64>,
    pub risk_score: Option<u64>,
    pub resource_host: Option<String>,
    pub resource_action: Option<String>,
    pub pep_registration: Option<String>,
}

impl PolicyContext {
    pub fn effective_pep_registration(&self) -> Option<&str> {
        self.pep_registration.as_deref()
    }

    pub fn resolve_field_path(&self, path: &str) -> Vec<Value> {
        let normalized = path.strip_prefix("context.").unwrap_or(path);
        match normalized {
            "group" | "groups" => self
                .groups
                .iter()
                .map(|s| Value::String(s.clone()))
                .collect(),
            "role" | "roles" => self
                .roles
                .iter()
                .map(|s| Value::String(s.clone()))
                .collect(),
            "posture" | "device.posture" => self
                .posture
                .iter()
                .map(|s| Value::String(s.clone()))
                .collect(),
            "acr" | "auth.acr" => vec![Value::String(self.acr.clone().unwrap_or_default())],
            "auth_age_seconds" | "auth.age_seconds" => {
                vec![Value::Number(self.auth_age_seconds.unwrap_or(0).into())]
            }
            "risk_score" | "risk.score" => {
                vec![Value::Number(self.risk_score.unwrap_or(0).into())]
            }
            "resource.host" => vec![Value::String(
                self.resource_host.clone().unwrap_or_default(),
            )],
            "resource.action" => vec![Value::String(
                self.resource_action.clone().unwrap_or_default(),
            )],
            "subject_id" | "subject" | "principal" => {
                vec![Value::String(self.subject_id.clone().unwrap_or_default())]
            }
            "device_id" | "device.id" => {
                vec![Value::String(self.device_id.clone().unwrap_or_default())]
            }
            "pep_registration" | "pep.registration" => vec![Value::String(
                self.effective_pep_registration()
                    .unwrap_or_default()
                    .to_string(),
            )],
            _ => Vec::new(),
        }
    }

    pub fn in_group(&self, group_name: &str) -> bool {
        self.groups.iter().any(|g| g == group_name)
    }

    pub fn action_matches(&self, action_pattern: &str) -> bool {
        match &self.resource_action {
            Some(actual) => {
                if action_pattern == "*" {
                    return true;
                }
                action_pattern == actual
            }
            None => false,
        }
    }

    pub fn host_matches(&self, host_pattern: &str) -> bool {
        match &self.resource_host {
            Some(actual) => glob_match(host_pattern, actual),
            None => false,
        }
    }
}

fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return value == suffix || value.ends_with(&format!(".{suffix}"));
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return value == prefix || value.starts_with(&format!("{prefix}/"));
    }
    pattern == value
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyBundle {
    pub version: String,
    pub rules: Vec<Rule>,
    pub default_decision: Decision,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(rename = "type")]
    pub rule_type: RuleType,
    pub action: String,
    #[serde(default)]
    pub resource_host: Option<String>,
    #[serde(default)]
    pub conditions: Vec<Condition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expression: Option<Expression>,
    #[serde(default)]
    pub rate_limit_profile: Option<String>,
    #[serde(default)]
    pub inject_headers: Option<HashMap<String, String>>,
    #[serde(default)]
    pub pep: PepPolicyActions,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleType {
    Allow,
    Forbid,
    StepUp,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Condition {
    pub field: String,
    pub op: String,
    pub value: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Expression {
    Condition(Condition),
    And {
        and: Vec<Expression>,
    },
    Or {
        or: Vec<Expression>,
    },
    Not {
        not: Box<Expression>,
    },
    InGroup {
        in_group: String,
    },
    MatchAction {
        action: String,
    },
    FieldCondition {
        field: String,
        op: String,
        value: Value,
    },
    /// Evaluate a ReBAC relationship check.
    ///
    /// The subject_id is taken from `PolicyContext.subject_id`.
    RebacCheck {
        namespace: String,
        object_id: String,
        relation: String,
        subject_namespace: String,
    },
}

impl Expression {
    pub fn from_value(v: &Value) -> Option<Self> {
        serde_json::from_value(v.clone()).ok()
    }
}

pub(crate) fn condition_matches(condition: &Condition, ctx: &PolicyContext) -> bool {
    let value = ctx.resolve_field_path(&condition.field);

    match condition.op.as_str() {
        "equals" | "==" => value.iter().any(|v| v == &condition.value),
        "contains" | "has" => value.iter().any(|v| match (v, &condition.value) {
            (Value::String(s), Value::String(target)) => s == target,
            _ => false,
        }),
        "in" | "member_of" => match &condition.value {
            Value::Array(arr) => value.iter().any(|v| arr.contains(v)),
            Value::String(group) => ctx.in_group(group),
            _ => false,
        },
        "like" | "matches" => match (value.first(), &condition.value) {
            (Some(Value::String(s)), Value::String(pattern)) => glob_match(pattern, s),
            _ => false,
        },
        "lt" | "<" => match (value.first(), &condition.value) {
            (Some(Value::Number(a)), Value::Number(b)) => {
                a.as_u64().unwrap_or(0) < b.as_u64().unwrap_or(0)
            }
            _ => false,
        },
        "gt" | ">" => match (value.first(), &condition.value) {
            (Some(Value::Number(a)), Value::Number(b)) => {
                a.as_u64().unwrap_or(0) > b.as_u64().unwrap_or(0)
            }
            _ => false,
        },
        "gte" | ">=" => match (value.first(), &condition.value) {
            (Some(Value::Number(a)), Value::Number(b)) => {
                a.as_u64().unwrap_or(0) >= b.as_u64().unwrap_or(0)
            }
            _ => false,
        },
        "lte" | "<=" => match (value.first(), &condition.value) {
            (Some(Value::Number(a)), Value::Number(b)) => {
                a.as_u64().unwrap_or(0) <= b.as_u64().unwrap_or(0)
            }
            _ => false,
        },
        _ => false,
    }
}

pub(crate) fn evaluate_expression<'a>(
    expr: &'a Expression,
    ctx: &'a PolicyContext,
    rebac: Option<&'a dyn RebacEvaluator>,
) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
    Box::pin(async move {
        match expr {
            Expression::Condition(c) => condition_matches(c, ctx),
            Expression::And { and } => {
                for e in and {
                    if !evaluate_expression(e, ctx, rebac).await {
                        return false;
                    }
                }
                true
            }
            Expression::Or { or } => {
                for e in or {
                    if evaluate_expression(e, ctx, rebac).await {
                        return true;
                    }
                }
                false
            }
            Expression::Not { not } => !evaluate_expression(not, ctx, rebac).await,
            Expression::InGroup { in_group } => ctx.in_group(in_group),
            Expression::MatchAction { action } => ctx.action_matches(action),
            Expression::FieldCondition { field, op, value } => {
                field_condition_matches(field, op, value, ctx)
            }
            Expression::RebacCheck {
                namespace,
                object_id,
                relation,
                subject_namespace,
            } => {
                let Some(rebac) = rebac else {
                    return false;
                };
                let Some(subject_id) = ctx.subject_id.as_deref() else {
                    return false;
                };
                rebac
                    .check(
                        namespace,
                        object_id,
                        relation,
                        subject_namespace,
                        subject_id,
                    )
                    .await
            }
        }
    })
}

fn field_condition_matches(field: &str, op: &str, value: &Value, ctx: &PolicyContext) -> bool {
    let cond = Condition {
        field: field.to_string(),
        op: op.to_string(),
        value: value.clone(),
    };
    condition_matches(&cond, ctx)
}

#[async_trait::async_trait]
pub trait PolicyEngine: Send + Sync {
    async fn decide(&self, ctx: &PolicyContext) -> DecisionDetails;
    async fn explain(&self, ctx: &PolicyContext) -> DecisionDetails {
        self.decide(ctx).await
    }
}

/// Async evaluator for ReBAC relationship checks.
///
/// Used by the policy engine to evaluate relationship tuples during
/// rule matching.  Implementations typically call the ReBAC `check`
/// function over a `RebacRepository`.
#[async_trait::async_trait]
pub trait RebacEvaluator: Send + Sync {
    async fn check(
        &self,
        namespace: &str,
        object_id: &str,
        relation: &str,
        subject_namespace: &str,
        subject_id: &str,
    ) -> bool;
}
