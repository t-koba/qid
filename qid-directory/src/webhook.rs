//! Synchronous, ordered HR batches; periodic CSV/LDAP imports remain separate.
use super::*;
use qid_storage::{HrBatch, HrBatchResult, HrReceipt, HrSummary, HrUserChange, hr_order};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HrEnvelope {
    pub sequence: u64,
    pub records: Vec<HrRecord>,
}

pub async fn import_hr_webhook<R: Repository>(
    state: &SharedState<R>,
    realm_id: &str,
    provider_id: &str,
    envelope: HrEnvelope,
    digest: String,
) -> QidResult<HrBatchResult> {
    let receipt = HrReceipt {
        sequence: envelope.sequence,
        digest,
        summary: HrSummary::default(),
    };
    let current = state.repo.get_hr_receipt(realm_id, provider_id).await?;
    if hr_order(current.as_ref(), &receipt)?.is_some() {
        return state
            .repo
            .apply_hr_batch(&HrBatch {
                realm_id: realm_id.into(),
                provider_id: provider_id.into(),
                receipt,
                changes: None,
            })
            .await;
    }
    let existing = state
        .repo
        .list_scim_users(&RealmId::from(realm_id.to_owned()))
        .await?;
    let mut batch = HrBatch {
        realm_id: realm_id.into(),
        provider_id: provider_id.into(),
        receipt,
        changes: Some(Vec::with_capacity(envelope.records.len())),
    };
    let mut by_external = BTreeMap::<_, Vec<_>>::new();
    for user in &existing {
        if let Some(key) = &user.external_id {
            by_external.entry(key.as_str()).or_default().push(user);
        }
    }
    let mut seen = BTreeSet::new();
    for record in envelope.records {
        if !seen.insert(record.external_id.clone()) {
            batch.changes = None;
            break;
        }
        let targets = by_external
            .get(record.external_id.as_str())
            .map(Vec::as_slice)
            .unwrap_or_default();
        if targets.len() > 1 {
            batch.changes = None;
            break;
        }
        let expected = targets.first().map(|u| (*u).clone());
        let mut user = match (&record.event, &expected) {
            (LifecycleEvent::Leaver, None) => {
                batch.changes = None;
                break;
            }
            (_, Some(user)) => user.clone(),
            (_, None) => scim_user_from_hr_record(realm_id, &record),
        };
        match record.event {
            LifecycleEvent::Leaver => {
                user.active = false;
                mark_hr_source(&mut user, &record);
                mark_deprovisioned(&mut user, now_seconds());
                batch.receipt.summary.deprovisioned += 1;
            }
            _ => {
                apply_hr_record(&mut user, &record);
                if expected.is_some() {
                    batch.receipt.summary.updated += 1;
                } else {
                    batch.receipt.summary.created += 1;
                }
            }
        }
        batch
            .changes
            .as_mut()
            .unwrap()
            .push(HrUserChange { expected, user });
    }
    // A rejected preflight still checks the receipt at serialization. A
    // concurrent identical commit must replay even if its targets were deleted
    // or made ambiguous after the initial receipt read. None can never apply.
    state.repo.apply_hr_batch(&batch).await
}
