use super::*;
use crate::{
    HrBatch, HrBatchResult, HrReceipt,
    hr::{hr_order, validate_hr_changes},
};

impl FileRepository {
    pub(super) async fn read_hr_receipt(
        &self,
        realm: &str,
        provider: &str,
    ) -> QidResult<Option<HrReceipt>> {
        Ok(self
            .store
            .read()
            .await
            .hr_receipts
            .get(realm)
            .and_then(|r| r.get(provider))
            .cloned())
    }

    pub(super) async fn commit_hr_batch(&self, batch: &HrBatch) -> QidResult<HrBatchResult> {
        // Always durable, including interval-flush repositories. Cancellation cannot
        // abandon a renamed file before publishing the candidate in memory.
        let repo = self.clone();
        let batch = batch.clone();
        tokio::spawn(async move { repo.commit_hr_inner(&batch).await })
            .await
            .map_err(|_| QidError::Internal {
                message: "HR commit outcome uncertain; retry identical sequence and body".into(),
            })?
    }

    async fn commit_hr_inner(&self, batch: &HrBatch) -> QidResult<HrBatchResult> {
        let save = self.save_lock.lock().await;
        let mut store = self.store.write().await;
        let current = store
            .hr_receipts
            .get(&batch.realm_id)
            .and_then(|r| r.get(&batch.provider_id));
        if let Some(result) = hr_order(current, &batch.receipt)? {
            self.sync_hr_directory().await?;
            return Ok(result);
        }
        let changes = validate_hr_changes(
            batch,
            &store.scim_users.values().cloned().collect::<Vec<_>>(),
        )?;
        let mut candidate = store.clone();
        for change in changes {
            candidate
                .scim_users
                .insert(change.user.id.clone(), change.user.clone());
        }
        candidate
            .hr_receipts
            .entry(batch.realm_id.clone())
            .or_default()
            .insert(batch.provider_id.clone(), batch.receipt.clone());
        let content = serde_json::to_string(&candidate).map_err(|_| QidError::Internal {
            message: "HR store serialization failed".into(),
        })?;
        #[cfg(test)]
        self.before_flush().await?;
        self.write_store_content_locked(&save, &content).await?;
        *store = candidate;
        self.sync_hr_directory().await?;
        Ok(HrBatchResult {
            summary: batch.receipt.summary.clone(),
            sequence: batch.receipt.sequence,
            replayed: false,
        })
    }
    async fn sync_hr_directory(&self) -> QidResult<()> {
        // The candidate is already published if rename succeeded. A metadata
        // sync failure is uncertain, never a claimed rollback. Retrying the
        // same receipt repeats this durability barrier before acknowledging.
        #[cfg(unix)]
        if let Some(parent) = self.path.parent() {
            let result = async {
                tokio::fs::File::open(if parent.as_os_str().is_empty() {
                    std::path::Path::new(".")
                } else {
                    parent
                })
                .await?
                .sync_all()
                .await
            }
            .await;
            result.map_err(|_| QidError::Internal {
                message: "HR durability outcome uncertain; retry identical sequence and body"
                    .into(),
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "hr_tests.rs"]
mod tests;
