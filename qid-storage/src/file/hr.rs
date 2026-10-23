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
        validate_hr_changes(
            batch,
            &store.scim_users.values().cloned().collect::<Vec<_>>(),
        )?;
        let mut candidate = store.clone();
        for change in batch.changes.as_ref().unwrap() {
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
mod tests {
    use super::super::persistence_tests::{TestFile, assert_pending, complete, pause_next_write};
    use super::*;
    use crate::{HrSummary, HrUserChange};

    fn batch() -> HrBatch {
        HrBatch {
            realm_id: "corp".into(),
            provider_id: "hr".into(),
            receipt: HrReceipt {
                sequence: 1,
                digest: "body-digest".into(),
                summary: HrSummary {
                    created: 1,
                    ..Default::default()
                },
            },
            changes: Some(vec![HrUserChange {
                expected: None,
                user: ScimUser {
                    id: "created".into(),
                    realm_id: "corp".into(),
                    external_id: Some("external".into()),
                    user_name: "created".into(),
                    name_json: serde_json::json!({}),
                    emails_json: serde_json::json!([]),
                    enterprise_json: serde_json::json!({}),
                    directory_provider_id: None,
                    deprovisioned_at: None,
                    active: true,
                },
            }]),
        }
    }

    #[tokio::test]
    async fn failed_hr_persistence_never_publishes_candidate_and_identical_retry_works() {
        let (file, repo) = TestFile::new().await;
        repo.migrate().await.unwrap();
        let before = tokio::fs::read(&file.0).await.unwrap();
        let (reached, resume) = pause_next_write(&repo, true);
        let request = batch();
        let task = tokio::spawn({
            let repo = repo.clone();
            let request = request.clone();
            async move { repo.apply_hr_batch(&request).await }
        });
        complete(reached).await.unwrap();
        let mut reader = Box::pin(repo.get_scim_user("created"));
        assert_pending(reader.as_mut()).await;
        resume.send(()).unwrap();
        assert!(complete(task).await.unwrap().is_err());
        assert!(complete(reader).await.unwrap().is_none());
        assert!(repo.get_hr_receipt("corp", "hr").await.unwrap().is_none());
        assert_eq!(tokio::fs::read(&file.0).await.unwrap(), before);
        repo.apply_hr_batch(&request).await.unwrap();
        let after = tokio::fs::read(&file.0).await.unwrap();
        // A replay performs no store write (the failing write hook remains unused).
        let _unused = pause_next_write(&repo, true);
        assert!(repo.apply_hr_batch(&request).await.unwrap().replayed);
        assert_eq!(tokio::fs::read(&file.0).await.unwrap(), after);
        drop(repo);
        let reopened = file.reopen().await;
        assert!(reopened.get_scim_user("created").await.unwrap().is_some());
        assert_eq!(
            reopened
                .get_hr_receipt("corp", "hr")
                .await
                .unwrap()
                .unwrap(),
            request.receipt
        );
    }

    #[tokio::test]
    async fn cancelled_hr_commit_finishes_and_interval_mode_still_persists_receipt() {
        let (file, mut repo) = TestFile::new().await;
        repo.migrate().await.unwrap();
        repo.flush_mode = FileFlushMode::Interval(Duration::from_secs(3600));
        let (reached, resume) = pause_next_write(&repo, false);
        let request = batch();
        let task = tokio::spawn({
            let repo = repo.clone();
            let request = request.clone();
            async move { repo.apply_hr_batch(&request).await }
        });
        complete(reached).await.unwrap();
        task.abort();
        let _ = task.await;
        resume.send(()).unwrap();
        assert!(
            complete(repo.apply_hr_batch(&request))
                .await
                .unwrap()
                .replayed
        );
        drop(repo);
        let reopened = file.reopen().await;
        assert_eq!(
            reopened
                .get_hr_receipt("corp", "hr")
                .await
                .unwrap()
                .unwrap()
                .sequence,
            1
        );
        assert!(reopened.get_scim_user("created").await.unwrap().is_some());
    }
}
