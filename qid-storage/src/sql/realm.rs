use async_trait::async_trait;

use super::*;

#[async_trait]
impl RealmRepository for SqlRepository {
    async fn create_realm(
        &self,
        tenant: &TenantId,
        realm_id: &RealmId,
        issuer: &str,
        display_name: Option<&str>,
    ) -> QidResult<()> {
        let result = sqlx::query(
            "INSERT INTO realms (id, tenant_id, issuer, display_name) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        )
        .bind(realm_id.as_str())
        .bind(tenant.as_str())
        .bind(issuer)
        .bind(display_name)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        crate::ownership::ensure_upsert_applied(result.rows_affected(), || {
            "realm ID or issuer already exists".to_string()
        })
    }

    async fn get_realm_issuer(&self, id: &RealmId) -> QidResult<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT issuer FROM realms WHERE id = $1")
            .bind(id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(row.map(|r| r.0))
    }

    async fn get_realm_tenant(&self, id: &RealmId) -> QidResult<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT tenant_id FROM realms WHERE id = $1")
            .bind(id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(row.map(|r| r.0))
    }

    async fn list_realms(&self) -> QidResult<Vec<(String, String)>> {
        let rows: Vec<(String, String)> = sqlx::query_as("SELECT id, issuer FROM realms")
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(rows)
    }

    async fn delete_realm(&self, id: &RealmId) -> QidResult<()> {
        let mut tx = self.pool.begin().await.map_err(storage_to_qid_error)?;
        sqlx::query("DELETE FROM hr_receipts WHERE realm_id = ?")
            .bind(id.as_str())
            .execute(&mut *tx)
            .await
            .map_err(storage_to_qid_error)?;
        // Walk session/family ownership before cascades remove the parents.
        // Token subjects have no user FK, intentionally: only subjects belonging
        // to removed users (or tokens in this realm/removed families) are deleted.
        sqlx::query("DELETE FROM authorization_codes WHERE realm_id = ? OR session_id IN (SELECT id FROM sessions WHERE realm_id = ? OR user_id IN (SELECT id FROM users WHERE realm_id = ?))")
            .bind(id.as_str()).bind(id.as_str()).bind(id.as_str())
            .execute(&mut *tx).await.map_err(storage_to_qid_error)?;
        sqlx::query("DELETE FROM access_tokens WHERE realm_id = ? OR user_id IN (SELECT id FROM users WHERE realm_id = ?) OR family_id IN (SELECT id FROM token_families WHERE realm_id = ? OR user_id IN (SELECT id FROM users WHERE realm_id = ?) OR session_id IN (SELECT id FROM sessions WHERE realm_id = ? OR user_id IN (SELECT id FROM users WHERE realm_id = ?)))")
            .bind(id.as_str()).bind(id.as_str()).bind(id.as_str())
            .bind(id.as_str()).bind(id.as_str()).bind(id.as_str())
            .execute(&mut *tx).await.map_err(storage_to_qid_error)?;
        sqlx::query("DELETE FROM token_families WHERE session_id IN (SELECT id FROM sessions WHERE realm_id = ? OR user_id IN (SELECT id FROM users WHERE realm_id = ?))")
            .bind(id.as_str()).bind(id.as_str())
            .execute(&mut *tx).await.map_err(storage_to_qid_error)?;
        // These tables lack a realm FK. Delete by the stored realm binding even
        // if the parent is already absent (legacy orphan cleanup/idempotence).
        // Keep the statements static and portable across supported SQL dialects.
        for statement in [
            "DELETE FROM service_accounts WHERE realm_id = ?",
            "DELETE FROM par_requests WHERE realm_id = ?",
            "DELETE FROM device_authorization_grants WHERE realm_id = ?",
            "DELETE FROM backchannel_authentication_grants WHERE realm_id = ?",
            "DELETE FROM vc_credential_statuses WHERE realm_id = ?",
            "DELETE FROM ciam_identity_links WHERE realm_id = ?",
            "DELETE FROM workload_certificates WHERE realm_id = ?",
            "DELETE FROM custom_domains WHERE realm_id = ?",
            "DELETE FROM ciam_brands WHERE realm_id = ?",
            "DELETE FROM app_catalog_entries WHERE realm_id = ?",
            "DELETE FROM scim_devices WHERE realm_id = ?",
            "DELETE FROM scim_event_subscriptions WHERE realm_id = ?",
            "DELETE FROM ssf_streams WHERE realm_id = ?",
            "DELETE FROM ssf_set_replay WHERE realm_id = ?",
        ] {
            sqlx::query(statement)
                .bind(id.as_str())
                .execute(&mut *tx)
                .await
                .map_err(storage_to_qid_error)?;
        }
        // Existing realm/user FKs cascade the remaining live records. Audit,
        // retention, SIEM delivery history and tenant/global state are independent.
        sqlx::query("DELETE FROM realms WHERE id = ?")
            .bind(id.as_str())
            .execute(&mut *tx)
            .await
            .map_err(storage_to_qid_error)?;
        tx.commit().await.map_err(storage_to_qid_error)?;
        Ok(())
    }
}
