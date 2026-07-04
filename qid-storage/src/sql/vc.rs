use async_trait::async_trait;

use super::*;

#[async_trait]
impl VcRepository for SqlRepository {
    async fn store_vc_credential_status(&self, status: &VcCredentialStatusRecord) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO vc_credential_statuses (credential_id, realm_id, subject, issuer, status_list_uri, issued_at, expires_at, revoked, revocation_reason, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&status.credential_id)
        .bind(&status.realm_id)
        .bind(&status.subject)
        .bind(&status.issuer)
        .bind(&status.status_list_uri)
        .bind(status.issued_at as i64)
        .bind(status.expires_at as i64)
        .bind(status.revoked as i64)
        .bind(&status.revocation_reason)
        .bind(status.revoked_at.map(|value| value as i64))
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_vc_credential_status(
        &self,
        credential_id: &str,
    ) -> QidResult<Option<VcCredentialStatusRecord>> {
        let row: Option<VcCredentialStatusRow> =
            sqlx::query_as("SELECT * FROM vc_credential_statuses WHERE credential_id = ?")
                .bind(credential_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn revoke_vc_credential(
        &self,
        credential_id: &str,
        reason: &str,
        revoked_at: u64,
    ) -> QidResult<()> {
        let result = sqlx::query(
            "UPDATE vc_credential_statuses SET revoked = 1, revocation_reason = ?, revoked_at = ? WHERE credential_id = ?",
        )
        .bind(reason)
        .bind(revoked_at as i64)
        .bind(credential_id)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        if result.rows_affected() == 0 {
            return Err(QidError::NotFound {
                resource: "VC credential status".to_string(),
            });
        }
        Ok(())
    }
}
