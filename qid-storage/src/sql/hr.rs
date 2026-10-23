use super::*;
use crate::{
    HrBatch, HrBatchResult, HrReceipt,
    hr::{hr_order, validate_hr_changes},
};

#[derive(sqlx::FromRow)]
struct ReceiptRow {
    sequence: i64,
    digest: String,
    summary_json: String,
}
impl ReceiptRow {
    fn receipt(self) -> QidResult<HrReceipt> {
        Ok(HrReceipt {
            sequence: self.sequence as u64,
            digest: self.digest,
            summary: serde_json::from_str(&self.summary_json).map_err(|_| QidError::Internal {
                message: "invalid HR receipt".into(),
            })?,
        })
    }
}

impl SqlRepository {
    pub(super) async fn read_hr_receipt(
        &self,
        realm: &str,
        provider: &str,
    ) -> QidResult<Option<HrReceipt>> {
        sqlx::query_as::<_, ReceiptRow>("SELECT sequence, digest, summary_json FROM hr_receipts WHERE realm_id = $1 AND provider_id = $2")
            .bind(realm).bind(provider).fetch_optional(&self.pool).await.map_err(storage_to_qid_error)?.map(ReceiptRow::receipt).transpose()
    }

    pub(super) async fn commit_hr_batch(&self, batch: &HrBatch) -> QidResult<HrBatchResult> {
        let mut tx = self.pool.begin().await.map_err(storage_to_qid_error)?;
        // PostgreSQL: exclude all SCIM writers, including inserts of ambiguous
        // external IDs (row locks alone cannot protect that predicate).
        // SQLite: the receipt INSERT obtains the database writer lock before reads.
        if self.database_kind == SqlDatabaseKind::Postgres {
            sqlx::query("LOCK TABLE scim_users IN SHARE ROW EXCLUSIVE MODE")
                .execute(&mut *tx)
                .await
                .map_err(storage_to_qid_error)?;
        }
        sqlx::query("INSERT INTO hr_receipts (realm_id, provider_id, sequence, digest, summary_json) VALUES ($1, $2, 0, '', '{}') ON CONFLICT (realm_id, provider_id) DO NOTHING")
            .bind(&batch.realm_id).bind(&batch.provider_id).execute(&mut *tx).await.map_err(storage_to_qid_error)?;
        let current = sqlx::query_as::<_, ReceiptRow>("SELECT sequence, digest, summary_json FROM hr_receipts WHERE realm_id = $1 AND provider_id = $2")
            .bind(&batch.realm_id).bind(&batch.provider_id).fetch_one(&mut *tx).await.map_err(storage_to_qid_error)?;
        let previous = current.sequence;
        let current = if previous == 0 {
            if !current.digest.is_empty() || current.summary_json != "{}" {
                return Err(QidError::Internal {
                    message: "invalid initial HR receipt".into(),
                });
            }
            None
        } else {
            Some(current.receipt()?)
        };
        if let Some(result) = hr_order(current.as_ref(), &batch.receipt)? {
            tx.rollback().await.map_err(storage_to_qid_error)?;
            return Ok(result);
        }
        // Revalidate all realm targets under the writer lock. Global ID
        // collisions additionally fail closed in the atomic upsert below.
        let users =
            sqlx::query_as::<_, ScimUserRow>("SELECT * FROM scim_users WHERE realm_id = $1")
                .bind(&batch.realm_id)
                .fetch_all(&mut *tx)
                .await
                .map_err(storage_to_qid_error)?;
        let users: Vec<ScimUser> = users.into_iter().map(Into::into).collect();
        validate_hr_changes(batch, &users)?;
        for change in batch.changes.as_ref().unwrap() {
            let u = &change.user;
            let deprovisioned_at = u
                .deprovisioned_at
                .map(i64::try_from)
                .transpose()
                .map_err(|_| crate::hr::conflict())?;
            let written = sqlx::query("INSERT INTO scim_users (id, realm_id, external_id, user_name, name_json, emails_json, enterprise_json, directory_provider_id, deprovisioned_at, active) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (id) DO UPDATE SET external_id = excluded.external_id, user_name = excluded.user_name, name_json = excluded.name_json, emails_json = excluded.emails_json, enterprise_json = excluded.enterprise_json, deprovisioned_at = excluded.deprovisioned_at, active = excluded.active WHERE scim_users.realm_id = excluded.realm_id")
                .bind(&u.id).bind(&u.realm_id).bind(&u.external_id).bind(&u.user_name).bind(u.name_json.to_string()).bind(u.emails_json.to_string()).bind(u.enterprise_json.to_string()).bind(&u.directory_provider_id).bind(deprovisioned_at).bind(u.active as i64)
                .execute(&mut *tx).await.map_err(storage_to_qid_error)?;
            if written.rows_affected() != 1 {
                return Err(crate::hr::conflict());
            }
        }
        let advanced = sqlx::query("UPDATE hr_receipts SET sequence = $1, digest = $2, summary_json = $3 WHERE realm_id = $4 AND provider_id = $5 AND sequence = $6")
            .bind(batch.receipt.sequence as i64).bind(&batch.receipt.digest).bind(serde_json::to_string(&batch.receipt.summary).unwrap()).bind(&batch.realm_id).bind(&batch.provider_id).bind(previous)
            .execute(&mut *tx).await.map_err(storage_to_qid_error)?;
        if advanced.rows_affected() != 1 {
            return Err(crate::hr::conflict());
        }
        tx.commit().await.map_err(|_| QidError::Internal {
            message: "HR commit outcome uncertain; retry identical sequence and body".into(),
        })?;
        Ok(HrBatchResult {
            summary: batch.receipt.summary.clone(),
            sequence: batch.receipt.sequence,
            replayed: false,
        })
    }
}
