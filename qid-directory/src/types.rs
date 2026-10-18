use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleEvent {
    Joiner,
    Mover,
    Leaver,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EmploymentState {
    Active,
    Inactive,
    LeavePending,
}

/// One HR-driven lifecycle input row.
///
/// `department` and `manager_external_id` follow mover-clear semantics: on a
/// [`LifecycleEvent::Mover`] record, `Some` sets the stored enterprise value
/// and `None` clears the previously stored value. On joiner/leaver records
/// `None` preserves the stored value. Unrelated enterprise attributes are
/// always preserved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HrRecord {
    pub external_id: String,
    pub user_name: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub department: Option<String>,
    pub manager_external_id: Option<String>,
    pub event: LifecycleEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HrImportAction {
    Created,
    Updated,
    Deprovisioned,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HrImportResult {
    pub external_id: String,
    pub user_id: String,
    pub action: HrImportAction,
}

/// Import HR joiner/mover/leaver records with whole-batch semantics.
///
/// The complete `records` input is preflighted before any write:
/// a repeated [`HrRecord::external_id`] anywhere in one batch fails with
/// [`QidError::Conflict`] (a batch is not an ordered event stream, so two
/// rows for one key never apply sequentially). All existing targets are also
/// resolved uniquely and missing leaver targets are validated before the
/// first write, so a later ambiguous or missing key cannot leave earlier
/// deterministic prefix mutations behind.
///
/// Target lookup never selects the first repository-order match: it matches
/// raw [`ScimUser::external_id`] and fails closed with [`QidError::Conflict`]
/// when more than one realm user shares it. HR records carry no provider
/// identity, so any shared `external_id` is ambiguous (including
/// provider-owned duplicates); unique targets keep the previous
/// create/update/deprovision behavior. Ownership is never inferred from
/// forgeable `enterprise_json`. Storage errors after
/// preflight may still leave prefix writes; no repository transaction is
/// claimed.
pub async fn import_hr_records<R: Repository>(
    state: &SharedState<R>,
    realm_id: &str,
    records: Vec<HrRecord>,
) -> QidResult<Vec<HrImportResult>> {
    let realm = RealmId::from(realm_id.to_string());
    let mut seen = BTreeSet::new();
    for record in &records {
        if !seen.insert(record.external_id.clone()) {
            return Err(QidError::Conflict {
                message: format!(
                    "duplicate HR external_id '{}' in batch; a batch carries at most one record per external_id",
                    record.external_id
                ),
            });
        }
    }
    let existing = state.repo.list_scim_users(&realm).await?;
    let mut planned: Vec<(HrRecord, Option<ScimUser>)> = Vec::with_capacity(records.len());
    for record in records {
        let current = find_hr_user(&existing, record.external_id.as_str())?.cloned();
        if matches!(record.event, LifecycleEvent::Leaver) && current.is_none() {
            return Err(QidError::NotFound {
                resource: format!("hr user {}", record.external_id),
            });
        }
        planned.push((record, current));
    }
    let mut results = Vec::with_capacity(planned.len());
    for (record, current) in planned {
        let result = match (record.event.clone(), current) {
            (LifecycleEvent::Joiner | LifecycleEvent::Mover, Some(mut user)) => {
                apply_hr_record(&mut user, &record);
                state.repo.update_scim_user(&user).await?;
                HrImportResult {
                    external_id: record.external_id,
                    user_id: user.id,
                    action: HrImportAction::Updated,
                }
            }
            (LifecycleEvent::Joiner | LifecycleEvent::Mover, None) => {
                let user = scim_user_from_hr_record(realm_id, &record);
                state.repo.create_scim_user(&user).await?;
                HrImportResult {
                    external_id: record.external_id,
                    user_id: user.id,
                    action: HrImportAction::Created,
                }
            }
            (LifecycleEvent::Leaver, Some(mut user)) => {
                user.active = false;
                mark_hr_source(&mut user, &record);
                mark_deprovisioned(&mut user, now_seconds());
                state.repo.update_scim_user(&user).await?;
                HrImportResult {
                    external_id: record.external_id,
                    user_id: user.id,
                    action: HrImportAction::Deprovisioned,
                }
            }
            (LifecycleEvent::Leaver, None) => {
                return Err(QidError::NotFound {
                    resource: format!("hr user {}", record.external_id),
                });
            }
        };
        results.push(result);
    }
    Ok(results)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExpandedGroupMembers {
    pub group_id: String,
    pub user_ids: Vec<String>,
    pub nested_group_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DynamicGroupMatchMode {
    All,
    Any,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DynamicGroupField {
    UserName,
    ExternalId,
    Department,
    ManagerExternalId,
    EmploymentState,
    Active,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DynamicGroupOperator {
    Eq,
    Contains,
    StartsWith,
    Exists,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DynamicGroupCondition {
    pub field: DynamicGroupField,
    pub operator: DynamicGroupOperator,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DynamicGroupRule {
    pub match_mode: DynamicGroupMatchMode,
    pub conditions: Vec<DynamicGroupCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DynamicGroupSyncResult {
    pub group_id: String,
    pub matched_user_ids: Vec<String>,
    pub added_user_ids: Vec<String>,
    pub removed_user_ids: Vec<String>,
}

/// A leaver event used to audit deprovisioning SLA.
///
/// `external_id` holds the raw DN (or HR external id). `provider_id` may
/// identify the server-owned directory provider that owns the user. When
/// present it is matched exactly against `ScimUser.directory_provider_id`; when
/// absent the event is legacy and only unambiguous single-match realms are
/// reported, otherwise auditing fails closed with a conflict asking the
/// caller to provide `provider_id`. Ownership is never inferred from
/// `enterprise_json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeprovisionEvent {
    pub external_id: String,
    pub occurred_at: u64,
    /// Optional directory provider that owns the user for this event.
    /// Old JSON without this field remains parseable and is treated as a
    /// legacy provider-less event.
    #[serde(default)]
    pub provider_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeprovisionSlaStatus {
    Met,
    Pending,
    Violated,
    MissingUser,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeprovisionSlaFinding {
    pub external_id: String,
    pub user_id: Option<String>,
    pub due_at: u64,
    pub deprovisioned_at: Option<u64>,
    pub status: DeprovisionSlaStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LdapDirectoryEntry {
    pub dn: String,
    pub uid: String,
    pub mail: Option<String>,
    pub display_name: Option<String>,
    pub department: Option<String>,
    pub manager_dn: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LdapSyncOptions {
    pub deactivate_missing: bool,
    pub synced_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LdapSyncResult {
    pub created_user_ids: Vec<String>,
    pub updated_user_ids: Vec<String>,
    pub unchanged_user_ids: Vec<String>,
    pub deactivated_user_ids: Vec<String>,
    pub break_glass_skipped_user_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagerChain {
    pub user_id: String,
    pub manager_user_ids: Vec<String>,
    pub unresolved_manager_external_id: Option<String>,
    pub cycle_detected: bool,
}
