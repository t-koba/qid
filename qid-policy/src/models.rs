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

impl Decision {
    /// Snake-case name matching the serialized form (`allow`, `step_up`, …).
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::StepUp => "step_up",
            Decision::ConsentRequired => "consent_required",
            Decision::LocalResponse => "local_response",
            Decision::ApprovalRequired => "approval_required",
            Decision::Quarantine => "quarantine",
            Decision::AuditOnly => "audit_only",
            Decision::Conditional => "conditional",
        }
    }

    /// Parse a snake-case decision name; `None` for unknown values so
    /// configuration surfaces reject them instead of ignoring them.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "allow" => Some(Decision::Allow),
            "deny" => Some(Decision::Deny),
            "step_up" => Some(Decision::StepUp),
            "consent_required" => Some(Decision::ConsentRequired),
            "local_response" => Some(Decision::LocalResponse),
            "approval_required" => Some(Decision::ApprovalRequired),
            "quarantine" => Some(Decision::Quarantine),
            "audit_only" => Some(Decision::AuditOnly),
            "conditional" => Some(Decision::Conditional),
            _ => None,
        }
    }
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

    /// Resolve a field path to its evidence values, or `None` when the input
    /// is absent. Absence is never replaced with a favorable stand-in: an
    /// unknown risk score is not zero risk, and a missing authentication age
    /// is not fresh authentication. Present-but-empty lists stay `Some`.
    pub fn resolve_field_path(&self, path: &str) -> Option<Vec<Value>> {
        let normalized = path.strip_prefix("context.").unwrap_or(path);
        match normalized {
            "group" | "groups" => Some(
                self.groups
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
            "role" | "roles" => Some(
                self.roles
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
            "posture" | "device.posture" => Some(
                self.posture
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
            "acr" | "auth.acr" => self.acr.clone().map(|acr| vec![Value::String(acr)]),
            "auth_age_seconds" | "auth.age_seconds" => self
                .auth_age_seconds
                .map(|age| vec![Value::Number(age.into())]),
            "risk_score" | "risk.score" => self
                .risk_score
                .map(|score| vec![Value::Number(score.into())]),
            "resource.host" => self
                .resource_host
                .clone()
                .map(|host| vec![Value::String(host)]),
            "resource.action" => self
                .resource_action
                .clone()
                .map(|action| vec![Value::String(action)]),
            "subject_id" | "subject" | "principal" => self
                .subject_id
                .clone()
                .map(|subject| vec![Value::String(subject)]),
            "device_id" | "device.id" => self
                .device_id
                .clone()
                .map(|device| vec![Value::String(device)]),
            "pep_registration" | "pep.registration" => self
                .effective_pep_registration()
                .map(|registration| vec![Value::String(registration.to_string())]),
            _ => None,
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

/// Whether a condition holds: `Some(true/false)` on present evidence,
/// `None` when the referenced field is absent. Absent evidence never
/// satisfies a rule on its own — not even under negation.
pub(crate) fn condition_matches(condition: &Condition, ctx: &PolicyContext) -> Option<bool> {
    let value = ctx.resolve_field_path(&condition.field)?;

    Some(match condition.op.as_str() {
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
    })
}

/// Evaluate an expression with Kleene three-valued logic: `Some(true)`
/// only on positively established evidence, `Some(false)` on established
/// counter-evidence, and `None` when an input is absent. In particular
/// `Not` over absent evidence is unknown — never a match — so missing risk
/// or authentication age cannot satisfy a rule through negation either.
pub(crate) fn evaluate_expression<'a>(
    expr: &'a Expression,
    ctx: &'a PolicyContext,
    rebac: Option<&'a dyn RebacEvaluator>,
) -> Pin<Box<dyn Future<Output = Option<bool>> + Send + 'a>> {
    Box::pin(async move {
        match expr {
            Expression::Condition(c) => condition_matches(c, ctx),
            Expression::And { and } => {
                let mut unknown = false;
                for e in and {
                    match evaluate_expression(e, ctx, rebac).await {
                        Some(false) => return Some(false),
                        None => unknown = true,
                        Some(true) => {}
                    }
                }
                // Absent evidence keeps the conjunction unknown, never false:
                // only established counter-evidence (above) denies the match.
                if unknown { None } else { Some(true) }
            }
            Expression::Or { or } => {
                let mut unknown = false;
                for e in or {
                    match evaluate_expression(e, ctx, rebac).await {
                        Some(true) => return Some(true),
                        None => unknown = true,
                        Some(false) => {}
                    }
                }
                // Absent evidence keeps the disjunction unknown, never true:
                // only established evidence (above) grants the match.
                if unknown { None } else { Some(false) }
            }
            Expression::Not { not } => evaluate_expression(not, ctx, rebac).await.map(|v| !v),
            Expression::InGroup { in_group } => Some(ctx.in_group(in_group)),
            Expression::MatchAction { action } => Some(ctx.action_matches(action)),
            Expression::FieldCondition { field, op, value } => {
                field_condition_matches(field, op, value, ctx)
            }
            Expression::RebacCheck {
                namespace,
                object_id,
                relation,
                subject_namespace,
            } => {
                let rebac = rebac?;
                let subject_id = ctx.subject_id.as_deref()?;
                Some(
                    rebac
                        .check(
                            namespace,
                            object_id,
                            relation,
                            subject_namespace,
                            subject_id,
                        )
                        .await,
                )
            }
        }
    })
}

fn field_condition_matches(
    field: &str,
    op: &str,
    value: &Value,
    ctx: &PolicyContext,
) -> Option<bool> {
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
