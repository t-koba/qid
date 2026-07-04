use qid_core::{
    error::{QidError, QidResult},
    models::ScimUser,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::{OutboundScimClientConfig, OutboundScimHttpRequest, join_scim_url};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutboundOrphanAction {
    Deactivate,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboundOrphanCleanupPolicy {
    pub dry_run: bool,
    pub action: OutboundOrphanAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutboundOrphanCleanupPlan {
    pub dry_run: bool,
    pub action: OutboundOrphanAction,
    pub external_id: String,
    pub remote_id: String,
    pub path: String,
    pub request: Option<OutboundScimHttpRequest>,
}

pub fn default_outbound_orphan_cleanup_policy() -> OutboundOrphanCleanupPolicy {
    OutboundOrphanCleanupPolicy {
        dry_run: true,
        action: OutboundOrphanAction::Deactivate,
    }
}

pub fn plan_outbound_orphan_cleanup(
    local_users: &[ScimUser],
    remote_resources: &[serde_json::Value],
    config: &OutboundScimClientConfig,
    policy: &OutboundOrphanCleanupPolicy,
) -> QidResult<Vec<OutboundOrphanCleanupPlan>> {
    let local_external_ids: BTreeSet<&str> = local_users
        .iter()
        .filter_map(|user| user.external_id.as_deref())
        .collect();
    let mut plans = Vec::new();
    for remote in remote_resources {
        let Some(external_id) = remote.get("externalId").and_then(|value| value.as_str()) else {
            continue;
        };
        if local_external_ids.contains(external_id) {
            continue;
        }
        let remote_id = remote
            .get("id")
            .and_then(|value| value.as_str())
            .ok_or_else(|| QidError::BadRequest {
                message: "remote orphan SCIM user is missing id".to_string(),
            })?;
        let path = format!("/Users/{remote_id}");
        let request = if policy.dry_run {
            None
        } else {
            Some(build_outbound_orphan_cleanup_request(
                &path,
                config,
                &policy.action,
            )?)
        };
        plans.push(OutboundOrphanCleanupPlan {
            dry_run: policy.dry_run,
            action: policy.action.clone(),
            external_id: external_id.to_string(),
            remote_id: remote_id.to_string(),
            path,
            request,
        });
    }
    Ok(plans)
}

fn build_outbound_orphan_cleanup_request(
    path: &str,
    config: &OutboundScimClientConfig,
    action: &OutboundOrphanAction,
) -> QidResult<OutboundScimHttpRequest> {
    let (method, body) = match action {
        OutboundOrphanAction::Deactivate => (
            "PATCH",
            Some(serde_json::json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    { "op": "replace", "path": "active", "value": false }
                ]
            })),
        ),
        OutboundOrphanAction::Delete => ("DELETE", None),
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
        body,
    })
}
