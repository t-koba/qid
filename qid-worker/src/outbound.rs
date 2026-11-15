use qid_core::{
    error::{QidError, QidResult},
    models::{AuditEvent, ScimUser},
    tenant::RealmId,
};
use qid_scim::*;
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Realm SCIM registry is authoritative. Login users are never joined by email.
#[derive(Clone, Serialize, Deserialize)]
pub struct ScimOutboundSyncConfig {
    pub realm_id: String,
    pub actor: String,
    pub reason: String,
    pub now_epoch: u64,
    pub record_audit_event: bool,
    pub scim_base_url: String,
    pub scim_bearer_token: Option<String>,
    pub dry_run: bool,
}
impl std::fmt::Debug for ScimOutboundSyncConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScimOutboundSyncConfig")
            .field("realm_id", &self.realm_id)
            .field("dry_run", &self.dry_run)
            .finish_non_exhaustive()
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScimOutboundSyncOptions {
    pub inventory: OutboundInventoryLimits,
    /// None leaves remote-only resources untouched, including in apply mode.
    pub orphan_action: Option<OutboundOrphanAction>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimOutboundSyncReport {
    pub synced: u64,
    pub skipped: u64,
    pub planned: u64,
    pub failed: u64,
    pub errors: Vec<String>,
    pub dry_run: bool,
}
pub async fn run_scim_outbound_sync_job<R: Repository>(
    repo: &R,
    config: ScimOutboundSyncConfig,
) -> QidResult<ScimOutboundSyncReport> {
    run_scim_outbound_sync_job_with_options(repo, config, ScimOutboundSyncOptions::default()).await
}
pub async fn run_scim_outbound_sync_job_with_options<R: Repository>(
    repo: &R,
    config: ScimOutboundSyncConfig,
    options: ScimOutboundSyncOptions,
) -> QidResult<ScimOutboundSyncReport> {
    run_scim_outbound_sync_with_transport(
        repo,
        config,
        options,
        &ReqwestOutboundScimTransport::new()?,
    )
    .await
}
fn invalid(message: &str) -> QidError {
    QidError::BadRequest {
        message: format!("SCIM outbound: {message}"),
    }
}
fn external(user: &ScimUser) -> &str {
    user.external_id.as_deref().unwrap_or(&user.id)
}
fn remote_id(resource: &Value) -> QidResult<String> {
    resource
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| invalid("missing remote id"))
}
/// Transport injection uses exactly the same lookup, planning, execution and audit path.
pub async fn run_scim_outbound_sync_with_transport<R: Repository, T: OutboundScimTransport>(
    repo: &R,
    config: ScimOutboundSyncConfig,
    options: ScimOutboundSyncOptions,
    transport: &T,
) -> QidResult<ScimOutboundSyncReport> {
    let client = OutboundScimClientConfig {
        base_url: config.scim_base_url.clone(),
        bearer_token: config.scim_bearer_token.clone(),
    };
    let realm = RealmId(config.realm_id.clone());
    let users = repo.list_scim_users(&realm).await?;
    let groups = repo.list_scim_groups(&realm).await?;
    let local_users: BTreeMap<_, _> = users.iter().map(|u| (u.id.as_str(), u)).collect();
    let mut identities = BTreeSet::new();
    for user in &users {
        if user.realm_id != config.realm_id
            || external(user).is_empty()
            || !identities.insert(external(user))
        {
            return Err(invalid("invalid or duplicate source user identity"));
        }
    }
    identities.clear();
    for group in &groups {
        let external = group.id.as_str();
        if group.realm_id != config.realm_id || external.is_empty() || !identities.insert(external)
        {
            return Err(invalid("invalid or duplicate source group identity"));
        }
    }
    let mut report = ScimOutboundSyncReport {
        synced: 0,
        skipped: 0,
        planned: 0,
        failed: 0,
        errors: vec![],
        dry_run: config.dry_run,
    };
    let result: QidResult<()> = async {
        // Validate the entire inventory before any writes when cleanup was explicitly selected.
        let orphans = if let Some(action) = options.orphan_action {
            let inventory =
                list_outbound_resources(&client, transport, "Users", &options.inventory).await?;
            plan_outbound_orphan_cleanup(
                &users,
                &inventory,
                &client,
                &OutboundOrphanCleanupPolicy {
                    dry_run: config.dry_run,
                    action,
                },
            )?
        } else {
            vec![]
        };
        let mut user_ids = BTreeMap::new();
        let mut claimed = BTreeSet::new();
        for user in &users {
            let remote =
                lookup_outbound_resource(&client, transport, "Users", external(user)).await?;
            let plan = plan_outbound_user_provisioning(
                user,
                remote.as_ref(),
                &default_outbound_user_mapping(),
                config.dry_run,
            )?;
            if plan.operation != OutboundOperation::Noop {
                report.planned += 1;
            }
            let result = execute_outbound_user_provisioning(&plan, &client, transport).await?;
            let resolved = if let Some(remote) = remote {
                Some(remote)
            } else if result.sent {
                // A create response is not evidence of identity uniqueness: resolve again.
                lookup_outbound_resource(&client, transport, "Users", external(user)).await?
            } else {
                None
            };
            if let Some(remote) = resolved {
                let id = remote_id(&remote)?;
                if !claimed.insert(id.clone()) {
                    return Err(invalid("remote users share an id"));
                }
                user_ids.insert(user.id.clone(), id);
            } else if !config.dry_run {
                return Err(invalid("created user could not be resolved"));
            }
            if result.sent {
                report.synced += 1;
            } else {
                report.skipped += 1;
            }
        }
        for group in &groups {
            let external = group.id.as_str();
            let remote = lookup_outbound_resource(&client, transport, "Groups", external).await?;
            let mut desired = group.clone();
            let members = group
                .members_json
                .as_array()
                .ok_or_else(|| invalid("group members must be an array"))?;
            let mut values = BTreeSet::new();
            let mut translated = Vec::new();
            for member in members {
                let id = member
                    .get("value")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("group member missing value"))?;
                // Never forward a local id, foreign realm reference or unprovisioned member on apply.
                let local = local_users
                    .get(id)
                    .ok_or_else(|| invalid("group member is outside realm SCIM users"))?;
                if !local.active || local.deprovisioned_at.is_some() {
                    continue;
                }
                let remote_id = user_ids
                    .get(id)
                    .map(String::as_str)
                    .or_else(|| config.dry_run.then_some(id))
                    .ok_or_else(|| invalid("unresolved group member"))?;
                if !values.insert(remote_id) {
                    return Err(invalid("duplicate group member"));
                }
                translated.push(serde_json::json!({"value": remote_id}));
            }
            desired.members_json = Value::Array(translated);
            let plan = plan_outbound_group_entitlement_reconciliation(
                &desired,
                remote.as_ref(),
                &client,
                config.dry_run,
            )?;
            if plan.operation != OutboundOperation::Noop {
                report.planned += 1;
            }
            if let Some(request) = plan.request {
                let response = transport.send(request).await?;
                if !matches!(response.status, 200 | 201 | 204) {
                    return Err(invalid("group write failed"));
                }
                report.synced += 1;
            } else {
                report.skipped += 1;
            }
        }
        for orphan in orphans {
            report.planned += 1;
            if let Some(request) = orphan.request {
                let response = transport.send(request).await?;
                if !matches!(response.status, 200 | 204) {
                    return Err(invalid("orphan write failed"));
                }
                report.synced += 1;
            } else {
                report.skipped += 1;
            }
        }
        Ok(())
    }
    .await;
    if result.is_err() {
        report.failed += 1;
        // Injected transports may contain remote bodies or credentials in their errors too.
        report
            .errors
            .push("SCIM reconciliation failed; earlier writes may have occurred".into());
    }
    if config.record_audit_event {
        let event = AuditEvent {
            id: ulid::Ulid::new().to_string(),
            realm_id: Some(config.realm_id),
            actor: config.actor,
            action: "scim.outbound_sync".into(),
            target_type: "scim_sync".into(),
            target_id: "outbound".into(),
            reason: config.reason,
            metadata_json: serde_json::to_value(&report)
                .map_err(|_| invalid("report serialization failed"))?,
            created_at: config.now_epoch,
            previous_hash: None,
            event_hash: None,
        };
        if repo.append_audit_event(&event).await.is_err() {
            report.failed += 1;
            report.errors.push(
                "SCIM audit persistence failed; remote writes may already have occurred".into(),
            );
        }
    }
    Ok(report)
}
#[cfg(test)]
mod tests;

#[cfg(test)]
mod route_tests;
