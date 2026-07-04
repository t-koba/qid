use async_trait::async_trait;

use super::*;

#[async_trait]
impl ServiceAccountRepository for SqlRepository {
    async fn create_service_account(&self, sa: &ServiceAccount) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO service_accounts (id, client_id, realm_id, description, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&sa.id)
        .bind(&sa.client_id)
        .bind(&sa.realm_id)
        .bind(&sa.description)
        .bind(sa.created_at as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_service_account_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> QidResult<Option<ServiceAccount>> {
        let row: Option<ServiceAccountRow> =
            sqlx::query_as("SELECT * FROM service_accounts WHERE realm_id = ? AND client_id = ?")
                .bind(realm_id)
                .bind(client_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn list_service_accounts(&self, realm_id: &str) -> QidResult<Vec<ServiceAccount>> {
        let rows: Vec<ServiceAccountRow> =
            sqlx::query_as("SELECT * FROM service_accounts WHERE realm_id = ?")
                .bind(realm_id)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn delete_service_account(&self, id: &str) -> QidResult<()> {
        sqlx::query("DELETE FROM service_accounts WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }
}
