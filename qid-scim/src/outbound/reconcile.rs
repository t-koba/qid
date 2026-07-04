use qid_core::{
    error::{QidError, QidResult},
    models::ScimGroup,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::{
    OutboundDrift, OutboundOperation, OutboundScimClientConfig, OutboundScimHttpRequest,
    collect_drift, join_scim_url,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutboundGroupReconciliationPlan {
    pub dry_run: bool,
    pub operation: OutboundOperation,
    pub display_name: String,
    pub path: String,
    pub desired: serde_json::Value,
    pub drift: Vec<OutboundDrift>,
    pub request: Option<OutboundScimHttpRequest>,
}

pub fn plan_outbound_group_entitlement_reconciliation(
    group: &ScimGroup,
    remote: Option<&serde_json::Value>,
    config: &OutboundScimClientConfig,
    dry_run: bool,
) -> QidResult<OutboundGroupReconciliationPlan> {
    let desired = render_outbound_group(group);
    let drift = remote
        .map(|remote| outbound_group_drift(&desired, remote))
        .unwrap_or_default();
    let operation = match remote {
        None => OutboundOperation::Create,
        Some(_) if drift.is_empty() => OutboundOperation::Noop,
        Some(_) => OutboundOperation::Replace,
    };
    let path = remote
        .and_then(|remote| remote.get("id").and_then(|value| value.as_str()))
        .map(|id| format!("/Groups/{id}"))
        .unwrap_or_else(|| format!("/Groups?filter=displayName eq \"{}\"", group.display_name));
    let request = if dry_run || operation == OutboundOperation::Noop {
        None
    } else {
        Some(build_outbound_group_reconciliation_request(
            &operation, &path, &desired, config,
        )?)
    };
    Ok(OutboundGroupReconciliationPlan {
        dry_run,
        operation,
        display_name: group.display_name.clone(),
        path,
        desired,
        drift,
        request,
    })
}

fn render_outbound_group(group: &ScimGroup) -> serde_json::Value {
    serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": group.display_name,
        "members": group.members_json
    })
}

fn outbound_group_drift(
    desired: &serde_json::Value,
    remote: &serde_json::Value,
) -> Vec<OutboundDrift> {
    let mut drift = Vec::new();
    collect_drift("displayName", &["displayName"], desired, remote, &mut drift);
    collect_drift("members", &["members"], desired, remote, &mut drift);
    drift
}

fn build_outbound_group_reconciliation_request(
    operation: &OutboundOperation,
    path: &str,
    desired: &serde_json::Value,
    config: &OutboundScimClientConfig,
) -> QidResult<OutboundScimHttpRequest> {
    let (method, path) = match operation {
        OutboundOperation::Create => ("POST", "/Groups"),
        OutboundOperation::Replace => ("PUT", path),
        OutboundOperation::Noop => {
            return Err(QidError::Internal {
                message: "unexpected Noop operation".to_string(),
            });
        }
    };
    let mut headers = BTreeMap::from([
        ("Accept".to_string(), "application/scim+json".to_string()),
        (
            "Content-Type".to_string(),
            "application/scim+json".to_string(),
        ),
    ]);
    if let Some(token) = &config.bearer_token {
        headers.insert("Authorization".to_string(), format!("Bearer {token}"));
    }
    Ok(OutboundScimHttpRequest {
        method: method.to_string(),
        url: join_scim_url(&config.base_url, path)?,
        headers,
        body: Some(desired.clone()),
    })
}
