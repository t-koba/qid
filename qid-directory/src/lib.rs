//! Directory lifecycle worker surface.
#![forbid(unsafe_code)]

use axum::{Json, Router, response::IntoResponse};
use qid_core::{
    error::{QidError, QidResult},
    models::{ScimGroup, ScimUser},
    state::SharedState,
    tenant::RealmId,
    util::now_seconds,
};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub const HR_SOURCE_SCHEMA: &str = "urn:qid:directory:hr";
pub const LIFECYCLE_SCHEMA: &str = "urn:qid:directory:lifecycle";
pub const LDAP_SOURCE_SCHEMA: &str = "urn:qid:directory:ldap";
pub const BREAK_GLASS_SCHEMA: &str = "urn:qid:directory:break_glass";

pub mod csv;
pub mod ldap_filter;

mod webhook;
pub(crate) use webhook::{HrEnvelope, import_hr_webhook};
mod routes;
pub use routes::directory_routes;

mod types;
pub use types::*;

pub mod connector;

pub async fn expand_nested_group_members<R: Repository>(
    state: &SharedState<R>,
    group_id: &str,
) -> QidResult<ExpandedGroupMembers> {
    let root = state
        .repo
        .get_scim_group(group_id)
        .await?
        .ok_or_else(|| QidError::NotFound {
            resource: format!("scim group {group_id}"),
        })?;
    let all_groups = state
        .repo
        .list_scim_groups(&RealmId::from(root.realm_id.clone()))
        .await?;
    let mut visited = BTreeSet::new();
    let mut users = BTreeSet::new();
    let mut nested_groups = BTreeSet::new();
    expand_group(
        &root,
        &all_groups,
        &mut visited,
        &mut nested_groups,
        &mut users,
    );
    nested_groups.remove(group_id);
    Ok(ExpandedGroupMembers {
        group_id: group_id.to_string(),
        user_ids: users.into_iter().collect(),
        nested_group_ids: nested_groups.into_iter().collect(),
    })
}

pub async fn sync_dynamic_group_members<R: Repository>(
    state: &SharedState<R>,
    group_id: &str,
    rule: &DynamicGroupRule,
) -> QidResult<DynamicGroupSyncResult> {
    let mut group =
        state
            .repo
            .get_scim_group(group_id)
            .await?
            .ok_or_else(|| QidError::NotFound {
                resource: format!("scim group {group_id}"),
            })?;
    let realm = RealmId::from(group.realm_id.clone());
    let users = state.repo.list_scim_users(&realm).await?;
    let groups = state.repo.list_scim_groups(&realm).await?;
    let group_ids = groups
        .iter()
        .map(|candidate| candidate.id.as_str())
        .collect::<BTreeSet<_>>();
    let previous_user_ids = group_user_member_ids(&group, &group_ids);
    let matched_user_ids = users
        .iter()
        .filter(|user| dynamic_group_rule_matches(rule, user))
        .map(|user| user.id.clone())
        .collect::<BTreeSet<_>>();
    let preserved_members = group
        .members_json
        .as_array()
        .into_iter()
        .flatten()
        .filter(|member| is_preserved_group_member(member, &group_ids))
        .cloned()
        .collect::<Vec<_>>();
    let mut next_members = preserved_members;
    for user_id in &matched_user_ids {
        next_members.push(serde_json::json!({
            "value": user_id,
            "type": "User"
        }));
    }
    group.members_json = serde_json::Value::Array(next_members);
    state.repo.update_scim_group(&group).await?;
    Ok(DynamicGroupSyncResult {
        group_id: group_id.to_string(),
        matched_user_ids: matched_user_ids.iter().cloned().collect(),
        added_user_ids: matched_user_ids
            .difference(&previous_user_ids)
            .cloned()
            .collect(),
        removed_user_ids: previous_user_ids
            .difference(&matched_user_ids)
            .cloned()
            .collect(),
    })
}

pub fn dynamic_group_rule_matches(rule: &DynamicGroupRule, user: &ScimUser) -> bool {
    match rule.match_mode {
        DynamicGroupMatchMode::All => rule
            .conditions
            .iter()
            .all(|condition| dynamic_group_condition_matches(condition, user)),
        DynamicGroupMatchMode::Any => {
            !rule.conditions.is_empty()
                && rule
                    .conditions
                    .iter()
                    .any(|condition| dynamic_group_condition_matches(condition, user))
        }
    }
}

/// Resolve the single realm user an SLA event refers to.
///
/// Matches only the server-owned `ScimUser.directory_provider_id` and raw
/// `external_id`; `enterprise_json` is never consulted. Returns `Ok(None)` when
/// nothing matches, and fails closed with `Conflict` when an `external_id`
/// (or a provider-scoped pair) matches more than one user, or with
/// `BadRequest` when `provider_id` is present but blank.
fn find_deprovision_user<'a>(
    users: &'a [ScimUser],
    event: &DeprovisionEvent,
) -> QidResult<Option<&'a ScimUser>> {
    let candidates: Vec<&'a ScimUser> = users
        .iter()
        .filter(|user| user.external_id.as_deref() == Some(event.external_id.as_str()))
        .collect();
    match event.provider_id.as_deref() {
        Some(provider_id) => {
            if provider_id.trim().is_empty() {
                return Err(QidError::BadRequest {
                    message: "deprovision event provider_id must not be blank".to_string(),
                });
            }
            let scoped: Vec<&'a ScimUser> = candidates
                .into_iter()
                .filter(|user| user.directory_provider_id.as_deref() == Some(provider_id))
                .collect();
            if scoped.len() > 1 {
                return Err(QidError::Conflict {
                    message: format!(
                        "multiple users share external_id '{}' for provider '{}'; data requires explicit migration",
                        event.external_id, provider_id
                    ),
                });
            }
            Ok(scoped.into_iter().next())
        }
        None => {
            if candidates.len() > 1 {
                return Err(QidError::Conflict {
                    message: format!(
                        "multiple users share external_id '{}'; provide provider_id to disambiguate",
                        event.external_id
                    ),
                });
            }
            Ok(candidates.into_iter().next())
        }
    }
}

/// Resolve the single realm user an HR record refers to.
///
/// HR records carry no provider identity, so a shared raw `external_id` is
/// ambiguous even when matches have different server-owned directory owners.
/// `enterprise_json` is never consulted. Returns `Ok(None)` when nothing
/// matches and fails closed with `Conflict` for multiple matches; repository
/// order never selects the target.
fn find_hr_user<'a>(users: &'a [ScimUser], external_id: &str) -> QidResult<Option<&'a ScimUser>> {
    let mut candidates = users
        .iter()
        .filter(|user| user.external_id.as_deref() == Some(external_id));
    let Some(user) = candidates.next() else {
        return Ok(None);
    };
    if candidates.next().is_some() {
        return Err(QidError::Conflict {
            message: format!(
                "multiple users share HR external_id '{external_id}'; import target is ambiguous"
            ),
        });
    }
    Ok(Some(user))
}

/// Audit leaver deprovisioning SLA without order-dependent user selection.
///
/// Provider-scoped LDAP sync permits identical raw DNs across providers, so
/// `DeprovisionEvent.provider_id`, when present, selects the single realm user
/// whose server-owned `ScimUser.directory_provider_id` plus `external_id`
/// both match. A blank `provider_id` is rejected. A legacy event without
/// `provider_id` is reported only when exactly one realm user carries the
/// `external_id`; multiple matches (including duplicates within one provider)
/// fail closed with `QidError::Conflict` telling the caller to provide
/// `provider_id`. Ownership is never inferred from `enterprise_json`.
pub async fn audit_deprovision_sla<R: Repository>(
    state: &SharedState<R>,
    realm_id: &str,
    leaver_events: &[DeprovisionEvent],
    sla_seconds: u64,
    now: u64,
) -> QidResult<Vec<DeprovisionSlaFinding>> {
    let users = state
        .repo
        .list_scim_users(&RealmId::from(realm_id.to_string()))
        .await?;
    let mut findings = Vec::with_capacity(leaver_events.len());
    for event in leaver_events {
        let due_at = event.occurred_at.saturating_add(sla_seconds);
        let user = find_deprovision_user(&users, event)?;
        let finding = match user {
            Some(user) => {
                let deprovisioned_at = user_deprovisioned_at(user);
                let status = if user.active && now <= due_at {
                    DeprovisionSlaStatus::Pending
                } else if user.active {
                    DeprovisionSlaStatus::Violated
                } else if deprovisioned_at.is_some_and(|ts| ts <= due_at) {
                    DeprovisionSlaStatus::Met
                } else {
                    DeprovisionSlaStatus::Violated
                };
                DeprovisionSlaFinding {
                    external_id: event.external_id.clone(),
                    user_id: Some(user.id.clone()),
                    due_at,
                    deprovisioned_at,
                    status,
                }
            }
            None => DeprovisionSlaFinding {
                external_id: event.external_id.clone(),
                user_id: None,
                due_at,
                deprovisioned_at: None,
                status: DeprovisionSlaStatus::MissingUser,
            },
        };
        findings.push(finding);
    }
    Ok(findings)
}

/// Reconcile one provider's LDAP snapshot into a realm.
///
/// `provider_id` is a stable, non-empty directory-provider identity stored in
/// the server-owned `ScimUser.directory_provider_id`. Ownership is never read
/// from `enterprise_json` (which SCIM clients can forge). Matching,
/// deactivation, and manager resolution use `(directory_provider_id,
/// external_id)` only, with `external_id` holding the raw DN. Rows without an
/// owner are never adopted, updated, or deactivated; a colliding unowned DN
/// fails the whole sync before any write, while unrelated ownerless rows do
/// not block it. Legacy rows need explicit internal migration, never inferred
/// ownership.
pub async fn sync_ldap_entries<R: Repository>(
    state: &SharedState<R>,
    realm_id: &str,
    provider_id: &str,
    entries: &[LdapDirectoryEntry],
    options: LdapSyncOptions,
) -> QidResult<LdapSyncResult> {
    if provider_id.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "LDAP provider_id is required".to_string(),
        });
    }
    let mut seen_dns = BTreeSet::new();
    for entry in entries {
        validate_ldap_entry(entry)?;
        if !seen_dns.insert(entry.dn.clone()) {
            return Err(QidError::BadRequest {
                message: format!("duplicate LDAP dn {}", entry.dn),
            });
        }
    }
    let realm = RealmId::from(realm_id.to_string());
    let existing = state.repo.list_scim_users(&realm).await?;
    preflight_directory_ownership(&existing)?;
    // Unowned rows (no `directory_provider_id`) never match: a colliding DN
    // fails closed before any write, unrelated ownerless rows are ignored.
    // Forged `enterprise_json.source`/`ldap_dn` markers are not consulted.
    let unowned_dns = existing
        .iter()
        .filter(|user| user.directory_provider_id.is_none())
        .filter_map(|user| user.external_id.as_deref())
        .collect::<BTreeSet<_>>();
    for entry in entries {
        if unowned_dns.contains(entry.dn.as_str()) {
            return Err(QidError::Conflict {
                message: format!(
                    "LDAP dn {} collides with an unowned user; explicit migration is required",
                    entry.dn
                ),
            });
        }
    }
    let mut owned_by_dn = existing
        .iter()
        .filter(|user| user.directory_provider_id.as_deref() == Some(provider_id))
        .filter_map(|user| {
            user.external_id
                .as_deref()
                .map(|dn| (dn.to_string(), user.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let mut result = LdapSyncResult {
        created_user_ids: Vec::new(),
        updated_user_ids: Vec::new(),
        unchanged_user_ids: Vec::new(),
        deactivated_user_ids: Vec::new(),
        break_glass_skipped_user_ids: Vec::new(),
    };
    for entry in entries {
        let previous = owned_by_dn.remove(entry.dn.as_str());
        match previous {
            Some(mut user) => {
                let before = user.clone();
                apply_ldap_entry(&mut user, provider_id, entry, options.synced_at);
                if scim_user_semantic_eq(&before, &user) {
                    result.unchanged_user_ids.push(user.id);
                } else {
                    state.repo.update_scim_user(&user).await?;
                    result.updated_user_ids.push(user.id);
                }
            }
            None => {
                let user =
                    scim_user_from_ldap_entry(realm_id, provider_id, entry, options.synced_at);
                state.repo.create_scim_user(&user).await?;
                result.created_user_ids.push(user.id);
            }
        }
    }
    if options.deactivate_missing {
        for mut user in owned_by_dn.into_values() {
            if user.active {
                if is_break_glass_user(&user) {
                    result.break_glass_skipped_user_ids.push(user.id);
                    continue;
                }
                user.active = false;
                mark_deprovisioned(&mut user, options.synced_at);
                state.repo.update_scim_user(&user).await?;
                result.deactivated_user_ids.push(user.id);
            }
        }
    }
    Ok(result)
}

/// Fail closed before any write when owned rows are ambiguous. Every row with
/// a trusted `directory_provider_id` must carry a non-blank owner and a
/// non-blank raw-DN `external_id`; duplicate `(provider_id, external_id)`
/// keys are rejected. `enterprise_json` is never consulted here. Rows without
/// an owner are skipped by this check and handled as unowned by the caller.
fn preflight_directory_ownership(existing: &[ScimUser]) -> QidResult<()> {
    let mut seen_keys = BTreeSet::new();
    for user in existing
        .iter()
        .filter(|user| user.directory_provider_id.is_some())
    {
        let owner = user.directory_provider_id.as_deref().unwrap_or_default();
        if owner.trim().is_empty() {
            return Err(QidError::Conflict {
                message: format!(
                    "LDAP user {} has blank provider ownership; explicit migration is required",
                    user.id
                ),
            });
        }
        let Some(dn) = user.external_id.as_deref() else {
            return Err(QidError::Conflict {
                message: format!(
                    "LDAP user {} owned by '{owner}' is missing raw-DN external_id",
                    user.id
                ),
            });
        };
        if dn.trim().is_empty() {
            return Err(QidError::Conflict {
                message: format!(
                    "LDAP user {} owned by '{owner}' has blank raw-DN external_id",
                    user.id
                ),
            });
        }
        if !seen_keys.insert((owner.to_string(), dn.to_string())) {
            return Err(QidError::Conflict {
                message: format!("duplicate LDAP ownership for provider '{owner}' dn {dn}"),
            });
        }
    }
    Ok(())
}

pub async fn resolve_manager_chain<R: Repository>(
    state: &SharedState<R>,
    user_id: &str,
) -> QidResult<ManagerChain> {
    let user = state
        .repo
        .get_scim_user(user_id)
        .await?
        .ok_or_else(|| QidError::NotFound {
            resource: format!("scim user {user_id}"),
        })?;
    let users = state
        .repo
        .list_scim_users(&RealmId::from(user.realm_id.clone()))
        .await?;
    // Manager scope follows the trusted owner only; forged enterprise markers
    // are never consulted. Ownerless users fall back to the full realm.
    let ldap_provider_id = match user.directory_provider_id.as_deref() {
        Some(provider_id) if !provider_id.trim().is_empty() => Some(provider_id.to_string()),
        Some(_) => {
            return Err(QidError::Conflict {
                message: format!(
                    "LDAP user {} has no provider ownership for manager resolution",
                    user.id
                ),
            });
        }
        None => None,
    };
    let by_external_id = users
        .iter()
        .filter(|candidate| match ldap_provider_id.as_deref() {
            Some(provider_id) => candidate.directory_provider_id.as_deref() == Some(provider_id),
            None => true,
        })
        .filter_map(|candidate| {
            candidate
                .external_id
                .as_ref()
                .map(|external_id| (external_id.as_str(), candidate))
        })
        .collect::<BTreeMap<_, _>>();
    let mut visited_user_ids = BTreeSet::from([user.id.clone()]);
    let mut manager_user_ids = Vec::new();
    let mut current = user;
    loop {
        let Some(manager_external_id) = manager_external_id(&current) else {
            return Ok(ManagerChain {
                user_id: user_id.to_string(),
                manager_user_ids,
                unresolved_manager_external_id: None,
                cycle_detected: false,
            });
        };
        let Some(manager) = by_external_id.get(manager_external_id.as_str()) else {
            return Ok(ManagerChain {
                user_id: user_id.to_string(),
                manager_user_ids,
                unresolved_manager_external_id: Some(manager_external_id),
                cycle_detected: false,
            });
        };
        if !visited_user_ids.insert(manager.id.clone()) {
            return Ok(ManagerChain {
                user_id: user_id.to_string(),
                manager_user_ids,
                unresolved_manager_external_id: Some(manager_external_id),
                cycle_detected: true,
            });
        }
        manager_user_ids.push(manager.id.clone());
        current = (*manager).clone();
    }
}

fn expand_group(
    group: &ScimGroup,
    all_groups: &[ScimGroup],
    visited: &mut BTreeSet<String>,
    nested_groups: &mut BTreeSet<String>,
    users: &mut BTreeSet<String>,
) {
    if !visited.insert(group.id.clone()) {
        return;
    }
    for member in group.members_json.as_array().into_iter().flatten() {
        let Some(value) = member.get("value").and_then(|v| v.as_str()) else {
            continue;
        };
        let is_group_member = member
            .get("type")
            .and_then(|v| v.as_str())
            .is_some_and(|kind| kind.eq_ignore_ascii_case("Group"));
        let member_group = all_groups.iter().find(|candidate| {
            candidate.id == value || is_group_member && candidate.display_name == value
        });
        if let Some(child_group) = member_group {
            nested_groups.insert(child_group.id.clone());
            expand_group(child_group, all_groups, visited, nested_groups, users);
        } else if !is_group_member {
            users.insert(value.to_string());
        }
    }
}

fn group_user_member_ids(group: &ScimGroup, group_ids: &BTreeSet<&str>) -> BTreeSet<String> {
    group
        .members_json
        .as_array()
        .into_iter()
        .flatten()
        .filter(|member| !is_preserved_group_member(member, group_ids))
        .filter_map(|member| member.get("value").and_then(|value| value.as_str()))
        .map(ToString::to_string)
        .collect()
}

fn is_preserved_group_member(member: &serde_json::Value, group_ids: &BTreeSet<&str>) -> bool {
    let Some(value) = member.get("value").and_then(|value| value.as_str()) else {
        return true;
    };
    member
        .get("type")
        .and_then(|kind| kind.as_str())
        .is_some_and(|kind| kind.eq_ignore_ascii_case("Group"))
        || group_ids.contains(value)
}

fn dynamic_group_condition_matches(condition: &DynamicGroupCondition, user: &ScimUser) -> bool {
    let actual = dynamic_group_field_value(&condition.field, user);
    match condition.operator {
        DynamicGroupOperator::Eq => actual.as_deref() == condition.value.as_deref(),
        DynamicGroupOperator::Contains => match (actual.as_deref(), condition.value.as_deref()) {
            (Some(actual), Some(expected)) => actual.contains(expected),
            _ => false,
        },
        DynamicGroupOperator::StartsWith => match (actual.as_deref(), condition.value.as_deref()) {
            (Some(actual), Some(expected)) => actual.starts_with(expected),
            _ => false,
        },
        DynamicGroupOperator::Exists => actual.is_some(),
    }
}

fn dynamic_group_field_value(field: &DynamicGroupField, user: &ScimUser) -> Option<String> {
    match field {
        DynamicGroupField::UserName => Some(user.user_name.clone()),
        DynamicGroupField::ExternalId => user.external_id.clone(),
        DynamicGroupField::Department => user
            .enterprise_json
            .get("department")
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        DynamicGroupField::ManagerExternalId => user
            .enterprise_json
            .get("manager")
            .and_then(|manager| manager.get("externalId"))
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        DynamicGroupField::EmploymentState => user_employment_state(user)
            .and_then(|state| serde_json::to_value(state).ok())
            .and_then(|value| value.as_str().map(ToString::to_string)),
        DynamicGroupField::Active => Some(user.active.to_string()),
    }
}

fn manager_external_id(user: &ScimUser) -> Option<String> {
    user.enterprise_json
        .get("manager")
        .and_then(|manager| manager.get("externalId"))
        .and_then(|value| value.as_str())
        .map(ToString::to_string)
}

fn user_deprovisioned_at(user: &ScimUser) -> Option<u64> {
    // Authority is the server-owned field only. Legacy or forged
    // `enterprise_json.deprovisioned_at` markers are never consulted and are
    // never backfilled; old rows read as `None` until a new lifecycle
    // transition stamps them.
    user.deprovisioned_at
}

pub fn user_employment_state(user: &ScimUser) -> Option<EmploymentState> {
    user.enterprise_json
        .get("employment_state")
        .and_then(|value| value.as_str())
        .and_then(|state| match state {
            "active" => Some(EmploymentState::Active),
            "inactive" => Some(EmploymentState::Inactive),
            "leave_pending" => Some(EmploymentState::LeavePending),
            _ => None,
        })
}

fn validate_ldap_entry(entry: &LdapDirectoryEntry) -> QidResult<()> {
    if entry.dn.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "LDAP dn is required".to_string(),
        });
    }
    if entry.uid.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: format!("LDAP uid is required for {}", entry.dn),
        });
    }
    Ok(())
}

fn scim_user_from_ldap_entry(
    realm_id: &str,
    provider_id: &str,
    entry: &LdapDirectoryEntry,
    synced_at: u64,
) -> ScimUser {
    let mut user = ScimUser {
        id: ulid::Ulid::new().to_string(),
        realm_id: realm_id.to_string(),
        external_id: Some(entry.dn.clone()),
        user_name: entry.uid.clone(),
        name_json: serde_json::json!({}),
        emails_json: serde_json::json!([]),
        enterprise_json: serde_json::json!({}),
        directory_provider_id: Some(provider_id.to_string()),
        deprovisioned_at: None,
        active: entry.enabled,
    };
    apply_ldap_entry(&mut user, provider_id, entry, synced_at);
    user
}

fn apply_ldap_entry(
    user: &mut ScimUser,
    provider_id: &str,
    entry: &LdapDirectoryEntry,
    synced_at: u64,
) {
    user.directory_provider_id = Some(provider_id.to_string());
    user.external_id = Some(entry.dn.clone());
    user.user_name = entry.uid.clone();
    user.active = entry.enabled;
    user.name_json = entry
        .display_name
        .as_ref()
        .map(|display_name| serde_json::json!({ "formatted": display_name }))
        .unwrap_or_else(|| serde_json::json!({}));
    user.emails_json = entry
        .mail
        .as_ref()
        .map(|mail| serde_json::json!([{ "value": mail, "primary": true }]))
        .unwrap_or_else(|| serde_json::json!([]));
    mark_ldap_source(user, entry, synced_at);
    if entry.enabled {
        // Reactivation clears the authoritative timestamp and any stale
        // enterprise marker so a later disable gets a fresh timestamp.
        clear_deprovisioned(user);
    } else {
        // Disabled snapshots stamp the first transition only and preserve it
        // across repeated disabled snapshots.
        ensure_deprovisioned(user, synced_at);
    }
}

fn mark_ldap_source(user: &mut ScimUser, entry: &LdapDirectoryEntry, synced_at: u64) {
    let mut enterprise = user
        .enterprise_json
        .as_object()
        .cloned()
        .unwrap_or_default();
    // Informational only: ownership lives in `directory_provider_id` and raw
    // `external_id`. SCIM clients can forge these enterprise keys, so the
    // reconciler never reads them as authority.
    enterprise.insert(
        "source".to_string(),
        serde_json::Value::String(LDAP_SOURCE_SCHEMA.to_string()),
    );
    enterprise.insert(
        "ldap_dn".to_string(),
        serde_json::Value::String(entry.dn.clone()),
    );
    enterprise.insert(
        "ldap_synced_at".to_string(),
        serde_json::Value::Number(synced_at.into()),
    );
    if let Some(department) = &entry.department {
        enterprise.insert(
            "department".to_string(),
            serde_json::Value::String(department.clone()),
        );
    } else {
        enterprise.remove("department");
    }
    if let Some(manager_dn) = &entry.manager_dn {
        enterprise.insert(
            "manager".to_string(),
            serde_json::json!({ "externalId": manager_dn }),
        );
    } else {
        enterprise.remove("manager");
    }
    set_employment_state_value(
        &mut enterprise,
        if entry.enabled {
            EmploymentState::Active
        } else {
            EmploymentState::Inactive
        },
    );
    user.enterprise_json = serde_json::Value::Object(enterprise);
}

// Ownership helpers deliberately read only the server-owned
// `directory_provider_id` and raw `external_id`. `enterprise_json` keys such
// as `source`, `ldap_dn`, or `ldap_provider_id` are informational and may be
// forged through SCIM, so they are never used as authority here.

fn scim_user_semantic_eq(left: &ScimUser, right: &ScimUser) -> bool {
    left.external_id == right.external_id
        && left.user_name == right.user_name
        && left.name_json == right.name_json
        && left.emails_json == right.emails_json
        && left.enterprise_json == right.enterprise_json
        && left.directory_provider_id == right.directory_provider_id
        && left.deprovisioned_at == right.deprovisioned_at
        && left.active == right.active
}

fn scim_user_from_hr_record(realm_id: &str, record: &HrRecord) -> ScimUser {
    let mut user = ScimUser {
        id: ulid::Ulid::new().to_string(),
        realm_id: realm_id.to_string(),
        external_id: Some(record.external_id.clone()),
        user_name: record.user_name.clone(),
        name_json: serde_json::json!({}),
        emails_json: serde_json::json!([]),
        enterprise_json: serde_json::json!({}),
        directory_provider_id: None,
        deprovisioned_at: None,
        active: true,
    };
    apply_hr_record(&mut user, record);
    user
}

fn apply_hr_record(user: &mut ScimUser, record: &HrRecord) {
    user.external_id = Some(record.external_id.clone());
    user.user_name = record.user_name.clone();
    user.active = true;
    // Any reactivation clears the authoritative timestamp and stale marker so
    // a later disable gets a fresh timestamp. Limited to lifecycle metadata;
    // department/manager clearing follows the mover-clear contract in
    // `mark_hr_source` (Mover `None` clears, other events preserve).
    clear_deprovisioned(user);
    user.name_json = record
        .display_name
        .as_ref()
        .map(|display_name| serde_json::json!({ "formatted": display_name }))
        .unwrap_or_else(|| serde_json::json!({}));
    user.emails_json = record
        .email
        .as_ref()
        .map(|email| serde_json::json!([{ "value": email, "primary": true }]))
        .unwrap_or_else(|| serde_json::json!([]));
    mark_hr_source(user, record);
}

/// Project HR organizational fields into stored enterprise attributes.
///
/// A `Mover` record with `department`/`manager_external_id` set to `None`
/// clears that previously stored enterprise field, so former organizational
/// attributes do not linger. `Joiner`/`Leaver` records with `None` preserve
/// the stored value. `Some` always sets. Unrelated enterprise attributes are
/// preserved.
fn mark_hr_source(user: &mut ScimUser, record: &HrRecord) {
    let mut enterprise = user
        .enterprise_json
        .as_object()
        .cloned()
        .unwrap_or_default();
    let clears_on_none = matches!(record.event, LifecycleEvent::Mover);
    match &record.department {
        Some(department) => {
            enterprise.insert(
                "department".to_string(),
                serde_json::Value::String(department.clone()),
            );
        }
        None if clears_on_none => {
            enterprise.remove("department");
        }
        None => {}
    }
    match &record.manager_external_id {
        Some(manager) => {
            enterprise.insert(
                "manager".to_string(),
                serde_json::json!({ "externalId": manager }),
            );
        }
        None if clears_on_none => {
            enterprise.remove("manager");
        }
        None => {}
    }
    enterprise.insert(
        "source".to_string(),
        serde_json::Value::String(HR_SOURCE_SCHEMA.to_string()),
    );
    set_employment_state_value(
        &mut enterprise,
        employment_state_for_lifecycle(&record.event),
    );
    user.enterprise_json = serde_json::Value::Object(enterprise);
}

fn employment_state_for_lifecycle(event: &LifecycleEvent) -> EmploymentState {
    match event {
        LifecycleEvent::Joiner | LifecycleEvent::Mover => EmploymentState::Active,
        LifecycleEvent::Leaver => EmploymentState::Inactive,
    }
}

fn set_employment_state_value(
    enterprise: &mut serde_json::Map<String, serde_json::Value>,
    state: EmploymentState,
) {
    let value = serde_json::to_value(state).expect("employment state serializes");
    enterprise.insert("employment_state".to_string(), value);
}

fn mark_deprovisioned(user: &mut ScimUser, deprovisioned_at: u64) {
    // Unconditional transition stamp (missing-user deactivation, HR leaver):
    // overwrites the authoritative timestamp and projects it.
    user.deprovisioned_at = Some(deprovisioned_at);
    let mut enterprise = user
        .enterprise_json
        .as_object()
        .cloned()
        .unwrap_or_default();
    enterprise.insert(
        "lifecycle_source".to_string(),
        serde_json::Value::String(LIFECYCLE_SCHEMA.to_string()),
    );
    enterprise.insert(
        "deprovisioned_at".to_string(),
        serde_json::Value::Number(deprovisioned_at.into()),
    );
    set_employment_state_value(&mut enterprise, EmploymentState::Inactive);
    user.enterprise_json = serde_json::Value::Object(enterprise);
}

/// Preserve-first disabled-snapshot stamp: set the authoritative timestamp
/// only when absent, then project the trusted value into `enterprise_json`
/// and mark employment inactive. Repeated disabled snapshots keep the first
/// timestamp.
fn ensure_deprovisioned(user: &mut ScimUser, synced_at: u64) {
    if user.deprovisioned_at.is_none() {
        user.deprovisioned_at = Some(synced_at);
    }
    let trusted = user.deprovisioned_at.expect("just ensured");
    let mut enterprise = user
        .enterprise_json
        .as_object()
        .cloned()
        .unwrap_or_default();
    enterprise.insert(
        "lifecycle_source".to_string(),
        serde_json::Value::String(LIFECYCLE_SCHEMA.to_string()),
    );
    enterprise.insert(
        "deprovisioned_at".to_string(),
        serde_json::Value::Number(trusted.into()),
    );
    set_employment_state_value(&mut enterprise, EmploymentState::Inactive);
    user.enterprise_json = serde_json::Value::Object(enterprise);
}

/// Reactivation: clear the authoritative timestamp and any stale or forged
/// enterprise marker. Only lifecycle metadata is touched.
fn clear_deprovisioned(user: &mut ScimUser) {
    user.deprovisioned_at = None;
    if let Some(object) = user.enterprise_json.as_object_mut() {
        object.remove("deprovisioned_at");
    } else {
        user.enterprise_json = serde_json::json!({});
    }
}

fn is_break_glass_user(user: &ScimUser) -> bool {
    user.enterprise_json
        .get("break_glass")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}

pub fn mark_break_glass(user: &mut ScimUser) {
    let mut enterprise = user
        .enterprise_json
        .as_object()
        .cloned()
        .unwrap_or_default();
    enterprise.insert(
        "break_glass_source".to_string(),
        serde_json::Value::String(BREAK_GLASS_SCHEMA.to_string()),
    );
    enterprise.insert("break_glass".to_string(), serde_json::Value::Bool(true));
    user.enterprise_json = serde_json::Value::Object(enterprise);
}

#[cfg(test)]
mod tests;
