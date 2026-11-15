//! Outbound SCIM provisioning.

mod execution;
mod mapping;
mod orphan;
mod reconcile;
mod remote;
mod transport;
pub use remote::{OutboundInventoryLimits, list_outbound_resources, lookup_outbound_resource};

pub use execution::{
    OutboundProvisioningExecutionPlan, build_outbound_scim_request,
    execute_outbound_user_provisioning, plan_outbound_retry, plan_outbound_user_execution,
};
pub use mapping::{
    OutboundAttributeSource, OutboundUserMapping, default_outbound_user_mapping,
    plan_outbound_user_provisioning, render_outbound_user,
};
pub use orphan::{
    OutboundOrphanAction, OutboundOrphanCleanupPlan, OutboundOrphanCleanupPolicy,
    default_outbound_orphan_cleanup_policy, plan_outbound_orphan_cleanup,
};
pub use reconcile::{
    OutboundGroupReconciliationPlan, plan_outbound_group_entitlement_reconciliation,
};
pub use transport::{OutboundScimTransport, ReqwestOutboundScimTransport};

use qid_core::error::QidResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OutboundOperation {
    Create,
    Replace,
    Noop,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutboundDrift {
    pub path: String,
    pub desired: serde_json::Value,
    pub remote: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutboundProvisioningPlan {
    pub dry_run: bool,
    pub operation: OutboundOperation,
    pub path: String,
    pub desired: serde_json::Value,
    pub drift: Vec<OutboundDrift>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboundRetryPolicy {
    pub max_attempts: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub multiplier: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboundRetryDecision {
    pub attempt: u32,
    pub retry: bool,
    pub delay_ms: Option<u64>,
    pub next_attempt_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutboundScimClientConfig {
    pub base_url: String,
    pub bearer_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutboundScimHttpRequest {
    pub method: String,
    pub url: String,
    pub headers: std::collections::BTreeMap<String, String>,
    pub body: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutboundScimHttpResponse {
    pub status: u16,
    pub body: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutboundProvisioningResult {
    pub operation: OutboundOperation,
    pub dry_run: bool,
    pub sent: bool,
    pub request: Option<OutboundScimHttpRequest>,
    pub response: Option<OutboundScimHttpResponse>,
}

pub fn default_outbound_retry_policy() -> OutboundRetryPolicy {
    OutboundRetryPolicy {
        max_attempts: 5,
        initial_delay_ms: 1_000,
        max_delay_ms: 60_000,
        multiplier: 2,
    }
}

pub(crate) fn join_scim_url(base_url: &str, path: &str) -> QidResult<String> {
    let url = url::Url::parse(base_url).map_err(|_| remote::invalid("invalid base URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(remote::invalid(
            "base URL must be HTTP(S) without credentials, query or fragment",
        ));
    }
    Ok(format!("{}{path}", base_url.trim_end_matches('/')))
}

pub(crate) fn scim_success_status(operation: &OutboundOperation, status: u16) -> bool {
    match operation {
        OutboundOperation::Create => matches!(status, 200 | 201),
        OutboundOperation::Replace => matches!(status, 200 | 204),
        OutboundOperation::Noop => true,
    }
}

pub(crate) fn scim_operation_name(operation: &OutboundOperation) -> &'static str {
    match operation {
        OutboundOperation::Create => "create",
        OutboundOperation::Replace => "replace",
        OutboundOperation::Noop => "noop",
    }
}

pub(crate) fn collect_drift(
    path: &str,
    segments: &[&str],
    desired: &serde_json::Value,
    remote: &serde_json::Value,
    drift: &mut Vec<OutboundDrift>,
) {
    let Some(desired_value) = get_path(desired, segments) else {
        return;
    };
    let remote_value = get_path(remote, segments);
    if remote_value != Some(desired_value.clone()) {
        drift.push(OutboundDrift {
            path: path.to_string(),
            desired: desired_value,
            remote: remote_value,
        });
    }
}

pub(crate) fn get_path(value: &serde_json::Value, segments: &[&str]) -> Option<serde_json::Value> {
    let mut current = value;
    for segment in segments {
        current = if let Ok(index) = segment.parse::<usize>() {
            current.as_array()?.get(index)?
        } else {
            current.get(*segment)?
        };
    }
    Some(current.clone())
}

#[cfg(test)]
mod tests;
