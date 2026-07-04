use crate::models::{Decision, DecisionDetails, PolicyContext, PolicyEngine};

/// OPA / Rego language version that this adapter speaks. INTEROP §3
/// requires pinning the Rego version to keep bundles reproducible across
/// deployments. The pinned version is advertised via the
/// `X-Qid-Rego-Version` header and validated against the agent's
/// `X-Opa-Version` response header.
pub const REGO_LANGUAGE_VERSION: &str = "1.0.0";
pub const OPA_VERSION_HEADER: &str = "x-opa-version";
pub const QID_REGO_VERSION_HEADER: &str = "x-qid-rego-version";

#[derive(Debug, Clone)]
pub struct RegoPolicyEngine {
    opa_url: String,
    decision_path: String,
}

impl RegoPolicyEngine {
    pub fn new(opa_url: impl Into<String>, decision_path: impl Into<String>) -> Self {
        Self {
            opa_url: opa_url.into(),
            decision_path: decision_path.into(),
        }
    }
}

impl Default for RegoPolicyEngine {
    fn default() -> Self {
        Self {
            opa_url: "http://localhost:8181".to_string(),
            decision_path: "qid/decision".to_string(),
        }
    }
}

#[async_trait::async_trait]
impl PolicyEngine for RegoPolicyEngine {
    async fn decide(&self, ctx: &PolicyContext) -> DecisionDetails {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("reqwest client build");
        let input = serde_json::json!({
            "input": {
                "subject": ctx.subject_id,
                "groups": ctx.groups,
                "roles": ctx.roles,
                "entitlements": ctx.entitlements,
                "device_id": ctx.device_id,
                "posture": ctx.posture,
                "acr": ctx.acr,
                "auth_age_seconds": ctx.auth_age_seconds,
                "risk_score": ctx.risk_score,
                "resource": {
                    "host": ctx.resource_host,
                    "action": ctx.resource_action,
                },
                "pep": {
                    "registration": ctx.pep_registration,
                },
            }
        });
        let url = format!(
            "{}/v1/data/{}",
            self.opa_url.trim_end_matches('/'),
            self.decision_path
        );
        let mut request = client.post(&url).json(&input);
        request = request.header(QID_REGO_VERSION_HEADER, REGO_LANGUAGE_VERSION);
        match request.send().await {
            Ok(resp) => {
                let agent_version = resp
                    .headers()
                    .get(OPA_VERSION_HEADER)
                    .and_then(|value| value.to_str().ok())
                    .map(|value| value.to_string());
                if let Some(agent) = &agent_version
                    && !agent_version_matches(agent, REGO_LANGUAGE_VERSION)
                {
                    tracing::warn!(
                        opa_version = %agent,
                        rego_pin = REGO_LANGUAGE_VERSION,
                        "OPA agent version does not match pinned Rego language version"
                    );
                }
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                let allow = body["result"]["allow"].as_bool().unwrap_or(false);
                let decision = if allow {
                    Decision::Allow
                } else {
                    Decision::Deny
                };
                let policy_id = body["result"]["policy_id"]
                    .as_str()
                    .unwrap_or("opa")
                    .to_string();
                let mut trace = vec![format!("OPA decision from {url}")];
                trace.push(format!("rego_language_version={REGO_LANGUAGE_VERSION}"));
                if let Some(agent) = agent_version {
                    trace.push(format!("opa_version={agent}"));
                }
                DecisionDetails {
                    decision,
                    policy_id,
                    trace,
                    ..DecisionDetails::default()
                }
            }
            Err(e) => DecisionDetails {
                decision: Decision::Deny,
                policy_id: "opa-error".to_string(),
                policy_tags: vec!["qid:opa:error".to_string()],
                trace: vec![format!("OPA request failed: {e}")],
                ..DecisionDetails::default()
            },
        }
    }
}

fn agent_version_matches(agent: &str, pinned: &str) -> bool {
    let agent_major = agent
        .trim_start_matches('v')
        .split('.')
        .next()
        .unwrap_or("");
    let pinned_major = pinned.split('.').next().unwrap_or("");
    !agent_major.is_empty() && agent_major == pinned_major
}
