use async_trait::async_trait;

use super::*;

#[async_trait]
impl FedCmRepository for SqlRepository {
    async fn store_fedcm_identity(&self, identity: &FedCmIdentity) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO fedcm_identities (id, realm_id, account_id, email, name, given_name, picture_url, approved_clients) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&identity.id)
        .bind(&identity.realm_id)
        .bind(&identity.account_id)
        .bind(&identity.email)
        .bind(&identity.name)
        .bind(&identity.given_name)
        .bind(&identity.picture_url)
        .bind(serde_json::to_string(&identity.approved_clients).unwrap_or_default())
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_fedcm_identities(
        &self,
        realm_id: &RealmId,
        account_id: &str,
    ) -> QidResult<Vec<FedCmIdentity>> {
        let rows: Vec<FedCmIdentityRow> =
            sqlx::query_as("SELECT * FROM fedcm_identities WHERE realm_id = ? AND account_id = ?")
                .bind(realm_id.as_str())
                .bind(account_id)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn delete_fedcm_identity(&self, id: &str) -> QidResult<()> {
        sqlx::query("DELETE FROM fedcm_identities WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }
}
