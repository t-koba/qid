use async_trait::async_trait;

use super::*;

#[async_trait]
impl CredentialRepository for SqlRepository {
    async fn get_webauthn_credentials(&self, user_id: &str) -> QidResult<Vec<WebAuthnCredential>> {
        let rows: Vec<WebAuthnCredentialRow> =
            sqlx::query_as("SELECT * FROM credentials_webauthn WHERE user_id = ?")
                .bind(user_id)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        rows.into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| QidError::Storage { message: e })
    }

    async fn store_webauthn_credential(&self, cred: &WebAuthnCredential) -> QidResult<()> {
        let credential_id = base64::engine::general_purpose::STANDARD.encode(&cred.credential_id);
        let public_key = base64::engine::general_purpose::STANDARD.encode(&cred.public_key);
        let aaguid = base64::engine::general_purpose::STANDARD.encode(&cred.aaguid);
        sqlx::query(
            "INSERT INTO credentials_webauthn (id, user_id, credential_id, public_key, counter, aaguid, device_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&cred.id)
        .bind(&cred.user_id)
        .bind(&credential_id)
        .bind(&public_key)
        .bind(cred.counter as i64)
        .bind(&aaguid)
        .bind(&cred.device_name)
        .bind(cred.created_at as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn update_webauthn_credential_counter(&self, id: &str, counter: u64) -> QidResult<()> {
        sqlx::query("UPDATE credentials_webauthn SET counter = ? WHERE id = ?")
            .bind(counter as i64)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn store_totp_credential(&self, cred: &TotpCredential) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO credentials_totp (id, user_id, secret, algorithm, digits, period, enabled, last_used_step, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET secret = excluded.secret, algorithm = excluded.algorithm, digits = excluded.digits, period = excluded.period, enabled = excluded.enabled, last_used_step = excluded.last_used_step, created_at = excluded.created_at",
        )
        .bind(&cred.id)
        .bind(&cred.user_id)
        .bind(&cred.secret)
        .bind(&cred.algorithm)
        .bind(cred.digits as i64)
        .bind(cred.period as i64)
        .bind(cred.enabled as i64)
        .bind(cred.last_used_step.map(|step| step as i64))
        .bind(cred.created_at as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_totp_credential(&self, user_id: &str) -> QidResult<Option<TotpCredential>> {
        let row: Option<TotpCredentialRow> =
            sqlx::query_as("SELECT * FROM credentials_totp WHERE user_id = ?")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn consume_totp_step(&self, credential_id: &str, candidate_step: u64) -> QidResult<bool> {
        let affected =
            sqlx::query("UPDATE credentials_totp SET last_used_step = ? WHERE id = ? AND (last_used_step IS NULL OR last_used_step < ?)")
                .bind(candidate_step as i64)
                .bind(credential_id)
                .bind(candidate_step as i64)
                .execute(&self.pool)
                .await
                .map_err(storage_to_qid_error)?
                .rows_affected();
        Ok(affected == 1)
    }

    async fn delete_webauthn_credential(&self, id: &str) -> QidResult<()> {
        sqlx::query("DELETE FROM credentials_webauthn WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_webauthn_credentials(&self, user_id: &str) -> QidResult<Vec<WebAuthnCredential>> {
        let rows: Vec<WebAuthnCredentialRow> =
            sqlx::query_as("SELECT * FROM credentials_webauthn WHERE user_id = ?")
                .bind(user_id)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        rows.into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| QidError::Storage { message: e })
    }
}
