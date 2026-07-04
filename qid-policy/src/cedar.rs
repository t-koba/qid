use crate::models::{Decision, DecisionDetails, PolicyContext, PolicyEngine};

/// Cedar language version that this adapter speaks. INTEROP §3 mandates a
/// pinned language version so policy bundles are reproducible across
/// deployments and over time. The version is emitted in every request as
/// the `X-Qid-Cedar-Version` header and matched against the response
/// `X-Cedar-Agent-Version` header when one is returned.
pub const CEDAR_LANGUAGE_VERSION: &str = "3.4.0";
pub const CEDAR_AGENT_HEADER: &str = "x-cedar-agent-version";
pub const QID_CEDAR_VERSION_HEADER: &str = "x-qid-cedar-version";

#[derive(Debug, Clone)]
pub struct CedarPolicyEngine {
    cedar_url: String,
    decision_path: String,
}

impl CedarPolicyEngine {
    pub fn new(cedar_url: impl Into<String>, decision_path: impl Into<String>) -> Self {
        Self {
            cedar_url: cedar_url.into(),
            decision_path: decision_path.into(),
        }
    }
}

impl Default for CedarPolicyEngine {
    fn default() -> Self {
        Self {
            cedar_url: "http://localhost:8282".to_string(),
            decision_path: "qid/decision".to_string(),
        }
    }
}

#[async_trait::async_trait]
impl PolicyEngine for CedarPolicyEngine {
    async fn decide(&self, ctx: &PolicyContext) -> DecisionDetails {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("reqwest client build");
        let input = serde_json::json!({
            "principal": ctx.subject_id,
            "action": ctx.resource_action,
            "resource": {
                "host": ctx.resource_host,
                "type": "route",
            },
            "context": {
                "groups": ctx.groups,
                "roles": ctx.roles,
                "entitlements": ctx.entitlements,
                "device_id": ctx.device_id,
                "posture": ctx.posture,
                "acr": ctx.acr,
                "auth_age_seconds": ctx.auth_age_seconds,
                "risk_score": ctx.risk_score,
                "pep_registration": ctx.pep_registration,
            },
        });
        let url = format!(
            "{}/v1/data/{}",
            self.cedar_url.trim_end_matches('/'),
            self.decision_path
        );
        let mut request = client.post(&url).json(&input);
        request = request.header(QID_CEDAR_VERSION_HEADER, CEDAR_LANGUAGE_VERSION);
        match request.send().await {
            Ok(resp) => {
                let agent_version = resp
                    .headers()
                    .get(CEDAR_AGENT_HEADER)
                    .and_then(|value| value.to_str().ok())
                    .map(|value| value.to_string());
                if let Some(agent) = &agent_version
                    && !agent_version_matches(agent, CEDAR_LANGUAGE_VERSION)
                {
                    tracing::warn!(
                        cedar_agent = %agent,
                        cedar_pin = CEDAR_LANGUAGE_VERSION,
                        "Cedar agent version does not match pinned language version"
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
                    .unwrap_or("cedar")
                    .to_string();
                let mut trace = vec![format!("Cedar decision from {url}")];
                trace.push(format!("cedar_language_version={CEDAR_LANGUAGE_VERSION}"));
                if let Some(agent) = agent_version {
                    trace.push(format!("cedar_agent_version={agent}"));
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
                policy_id: "cedar-error".to_string(),
                trace: vec![format!("Cedar adapter error: {e}")],
                ..DecisionDetails::default()
            },
        }
    }
}

fn agent_version_matches(agent: &str, pinned: &str) -> bool {
    // The pinned version is `<major>.<minor>.<patch>`. We require the agent
    // to advertise a version that starts with the pinned major version so
    // bundle compatibility is preserved while still permitting forward
    // patch updates within the same minor.
    let agent_major = agent.split('.').next().unwrap_or("");
    let pinned_major = pinned.split('.').next().unwrap_or("");
    !agent_major.is_empty() && agent_major == pinned_major
}
