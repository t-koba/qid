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

pub async fn import_hr_records<R: Repository>(
    state: &SharedState<R>,
    realm_id: &str,
    records: Vec<HrRecord>,
) -> QidResult<Vec<HrImportResult>> {
    let realm = RealmId::from(realm_id.to_string());
    let existing = state.repo.list_scim_users(&realm).await?;
    let mut results = Vec::with_capacity(records.len());
    for record in records {
        let current = existing
            .iter()
            .find(|user| user.external_id.as_deref() == Some(record.external_id.as_str()))
            .cloned();
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeprovisionEvent {
    pub external_id: String,
    pub occurred_at: u64,
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
