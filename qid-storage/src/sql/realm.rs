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
        sqlx::query("INSERT INTO realms (id, tenant_id, issuer, display_name) VALUES (?, ?, ?, ?)")
            .bind(realm_id.as_str())
            .bind(tenant.as_str())
            .bind(issuer)
            .bind(display_name)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_realm_issuer(&self, id: &RealmId) -> QidResult<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT issuer FROM realms WHERE id = ?")
            .bind(id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(row.map(|r| r.0))
    }

    async fn get_realm_tenant(&self, id: &RealmId) -> QidResult<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT tenant_id FROM realms WHERE id = ?")
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
        sqlx::query("DELETE FROM realms WHERE id = ?")
            .bind(id.as_str())
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }
}
