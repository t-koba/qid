use qid_core::{
    error::{QidError, QidResult},
    models::ScimGroup,
};
use serde::{Deserialize, Serialize};

use super::{
    OutboundDrift, OutboundOperation, OutboundScimClientConfig, OutboundScimHttpRequest,
    collect_drift,
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
    member_ids(&desired)?;
    let drift = remote
        .map(|remote| outbound_group_drift(&desired, remote))
        .transpose()?
        .unwrap_or_default();
    let operation = match remote {
        None => OutboundOperation::Create,
        Some(_) if drift.is_empty() => OutboundOperation::Noop,
        Some(_) => OutboundOperation::Replace,
    };
    let path = if operation == OutboundOperation::Replace {
        super::remote::remote_path(
            "Groups",
            remote.ok_or_else(|| super::remote::invalid("missing remote"))?,
        )?
    } else {
        "/Groups".into()
    };
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
        "externalId": group.id,
        "displayName": group.display_name,
        "members": group.members_json
    })
}

fn outbound_group_drift(
    desired: &serde_json::Value,
    remote: &serde_json::Value,
) -> QidResult<Vec<OutboundDrift>> {
    let mut drift = Vec::new();
    collect_drift("externalId", &["externalId"], desired, remote, &mut drift);
    collect_drift("displayName", &["displayName"], desired, remote, &mut drift);
    if member_ids(desired)? != member_ids(remote)? {
        collect_drift("members", &["members"], desired, remote, &mut drift);
    }
    Ok(drift)
}

fn member_ids(resource: &serde_json::Value) -> QidResult<std::collections::BTreeSet<&str>> {
    let mut ids = std::collections::BTreeSet::new();
    // RFC 7643 §2.5: unassigned, null, and empty multi-valued attributes are equivalent.
    let Some(members) = resource.get("members").filter(|value| !value.is_null()) else {
        return Ok(ids);
    };
    for member in members
        .as_array()
        .ok_or_else(|| super::remote::invalid("invalid group members"))?
    {
        let id = member
            .get("value")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| super::remote::invalid("invalid group member"))?;
        if !ids.insert(id) {
            return Err(super::remote::invalid("duplicate group member"));
        }
    }
    Ok(ids)
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
    super::remote::request(config, method, path, Some(desired.clone()))
}
