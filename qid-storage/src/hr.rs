//! Atomic ordered HR imports. Plans are revalidated while backend writers are serialized.
use qid_core::{
    error::{QidError, QidResult},
    models::ScimUser,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HrSummary {
    pub created: u32,
    pub updated: u32,
    pub deprovisioned: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HrReceipt {
    pub sequence: u64,
    pub digest: String,
    pub summary: HrSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HrBatchResult {
    #[serde(flatten)]
    pub summary: HrSummary,
    pub sequence: u64,
    pub replayed: bool,
}

#[derive(Debug, Clone)]
pub struct HrUserChange {
    pub expected: Option<ScimUser>,
    pub user: ScimUser,
}

#[derive(Debug, Clone)]
pub struct HrBatch {
    pub realm_id: String,
    pub provider_id: String,
    pub receipt: HrReceipt,
    /// None is a rejected preflight: it may replay a receipt, never advance it.
    pub changes: Option<Vec<HrUserChange>>,
}

pub(crate) fn conflict() -> QidError {
    QidError::Conflict { message: "HR sequence or target conflict; use the next contiguous sequence, or retry the latest identical body".into() }
}

/// Check ordering both before planning and at the atomic commit point.
pub fn hr_order(
    current: Option<&HrReceipt>,
    incoming: &HrReceipt,
) -> QidResult<Option<HrBatchResult>> {
    if incoming.sequence == 0 || incoming.sequence > i64::MAX as u64 {
        return Err(conflict());
    }
    if let Some(current) = current {
        if current.sequence == 0 || current.sequence > i64::MAX as u64 {
            return Err(QidError::Internal {
                message: "invalid persisted HR receipt sequence".into(),
            });
        }
        if current.sequence == incoming.sequence && current.digest == incoming.digest {
            return Ok(Some(HrBatchResult {
                summary: current.summary.clone(),
                sequence: current.sequence,
                replayed: true,
            }));
        }
        if current.sequence.checked_add(1) != Some(incoming.sequence) {
            return Err(conflict());
        }
    } else if incoming.sequence != 1 {
        return Err(conflict());
    }
    Ok(None)
}

pub(crate) fn validate_hr_changes(batch: &HrBatch, users: &[ScimUser]) -> QidResult<()> {
    use std::collections::{BTreeMap, BTreeSet};
    let changes = batch.changes.as_ref().ok_or_else(conflict)?;
    let by_id: BTreeMap<_, _> = users.iter().map(|u| (&u.id, u)).collect();
    let mut by_external = BTreeMap::<_, Vec<_>>::new();
    let mut names = BTreeMap::new();
    for u in users.iter().filter(|u| u.realm_id == batch.realm_id) {
        by_external.entry(&u.external_id).or_default().push(u);
        names.insert(&u.user_name, &u.id);
    }
    let mut external_ids = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for change in changes {
        let user = &change.user;
        if user.realm_id != batch.realm_id
            || !external_ids.insert(&user.external_id)
            || !ids.insert(&user.id)
        {
            return Err(conflict());
        }
        let targets = by_external
            .get(&user.external_id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let expected = change.expected.as_ref();
        if targets.len() != usize::from(expected.is_some())
            || targets.first().map(|u| serde_json::to_value(u).unwrap())
                != expected.map(|u| serde_json::to_value(u).unwrap())
            || expected.is_some_and(|u| {
                u.id != user.id || u.directory_provider_id != user.directory_provider_id
            })
            || (expected.is_none() && by_id.contains_key(&user.id))
            || names
                .insert(&user.user_name, &user.id)
                .is_some_and(|id| id != &user.id)
        {
            return Err(conflict());
        }
    }
    Ok(())
}
