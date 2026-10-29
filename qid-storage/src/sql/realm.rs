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
        let mut tx = self.pool.begin().await.map_err(storage_to_qid_error)?;
        let result = sqlx::query(
            "INSERT INTO realms (id, tenant_id, issuer, display_name) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        )
        .bind(realm_id.as_str())
        .bind(tenant.as_str())
        .bind(issuer)
        .bind(display_name)
        .execute(&mut *tx)
        .await
        .map_err(storage_to_qid_error)?;
        crate::ownership::ensure_upsert_applied(result.rows_affected(), || {
            "realm ID or issuer already exists".to_string()
        })?;
        remove_realm_children(&mut tx, realm_id).await?;
        tx.commit().await.map_err(storage_to_qid_error)
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

    async fn delete_realm(&self, id: &RealmId, expected_tenant: &TenantId) -> QidResult<()> {
        let mut tx = self.pool.begin().await.map_err(storage_to_qid_error)?;
        // Conditional no-op update rechecks ownership and locks the parent until commit.
        let matched = sqlx::query("UPDATE realms SET id = id WHERE id = $1 AND tenant_id = $2")
            .bind(id.as_str())
            .bind(expected_tenant.as_str())
            .execute(&mut *tx)
            .await
            .map_err(storage_to_qid_error)?;
        if matched.rows_affected() == 0 {
            tx.rollback().await.map_err(storage_to_qid_error)?;
            return Ok(());
        }
        remove_realm_children(&mut tx, id).await?;
        // Parent/user FKs cascade; audit/retention/SIEM history and tenant/global state survive.
        sqlx::query("DELETE FROM realms WHERE id = $1")
            .bind(id.as_str())
            .execute(&mut *tx)
            .await
            .map_err(storage_to_qid_error)?;
        tx.commit().await.map_err(storage_to_qid_error)?;
        Ok(())
    }
}

async fn remove_realm_children(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    id: &RealmId,
) -> QidResult<()> {
    sqlx::query("DELETE FROM hr_receipts WHERE realm_id = $1")
        .bind(id.as_str())
        .execute(&mut **tx)
        .await
        .map_err(storage_to_qid_error)?;
    // Delete session/family-linked credentials before cascades remove parents.
    // Token subjects omit a user FK, so restrict deletion to realm/linked ownership.
    sqlx::query("DELETE FROM authorization_codes WHERE realm_id = $1 OR session_id IN (SELECT id FROM sessions WHERE realm_id = $1 OR user_id IN (SELECT id FROM users WHERE realm_id = $1))")
            .bind(id.as_str())
            .execute(&mut **tx).await.map_err(storage_to_qid_error)?;
    sqlx::query("DELETE FROM access_tokens WHERE realm_id = $1 OR user_id IN (SELECT id FROM users WHERE realm_id = $1) OR family_id IN (SELECT id FROM token_families WHERE realm_id = $1 OR user_id IN (SELECT id FROM users WHERE realm_id = $1) OR session_id IN (SELECT id FROM sessions WHERE realm_id = $1 OR user_id IN (SELECT id FROM users WHERE realm_id = $1)))")
            .bind(id.as_str())
            .execute(&mut **tx).await.map_err(storage_to_qid_error)?;
    sqlx::query("DELETE FROM token_families WHERE session_id IN (SELECT id FROM sessions WHERE realm_id = $1 OR user_id IN (SELECT id FROM users WHERE realm_id = $1))")
            .bind(id.as_str())
            .execute(&mut **tx).await.map_err(storage_to_qid_error)?;
    // Static, portable non-FK deletes run only after claiming or locking the parent.
    for statement in [
        "DELETE FROM service_accounts WHERE realm_id = $1",
        "DELETE FROM par_requests WHERE realm_id = $1",
        "DELETE FROM device_authorization_grants WHERE realm_id = $1",
        "DELETE FROM backchannel_authentication_grants WHERE realm_id = $1",
        "DELETE FROM vc_credential_statuses WHERE realm_id = $1",
        "DELETE FROM ciam_identity_links WHERE realm_id = $1",
        "DELETE FROM workload_certificates WHERE realm_id = $1",
        "DELETE FROM custom_domains WHERE realm_id = $1",
        "DELETE FROM ciam_brands WHERE realm_id = $1",
        "DELETE FROM app_catalog_entries WHERE realm_id = $1",
        "DELETE FROM scim_devices WHERE realm_id = $1",
        "DELETE FROM scim_event_subscriptions WHERE realm_id = $1",
        "DELETE FROM ssf_streams WHERE realm_id = $1",
        "DELETE FROM ssf_set_replay WHERE realm_id = $1",
    ] {
        sqlx::query(statement)
            .bind(id.as_str())
            .execute(&mut **tx)
            .await
            .map_err(storage_to_qid_error)?;
    }
    Ok(())
}
