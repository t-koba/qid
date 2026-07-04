use async_trait::async_trait;

use super::*;

#[async_trait]
impl PolicyRepository for SqlRepository {
    async fn create_policy_bundle(&self, bundle: &PolicyBundle) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO policy_bundles (id, realm_id, name, source_hash, compiled_json, version, active) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&bundle.id)
        .bind(&bundle.realm_id)
        .bind(&bundle.name)
        .bind(&bundle.source_hash)
        .bind(bundle.compiled_json.to_string())
        .bind(bundle.version as i64)
        .bind(bundle.active as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_active_policy_bundle(
        &self,
        realm_id: &RealmId,
    ) -> QidResult<Option<PolicyBundle>> {
        let row: Option<PolicyBundleRow> =
            sqlx::query_as("SELECT * FROM policy_bundles WHERE realm_id = ? AND active = 1")
                .bind(realm_id.as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn list_policy_bundles(&self, realm_id: &RealmId) -> QidResult<Vec<PolicyBundle>> {
        let rows: Vec<PolicyBundleRow> =
            sqlx::query_as("SELECT * FROM policy_bundles WHERE realm_id = ?")
                .bind(realm_id.as_str())
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn delete_policy_bundle(&self, id: &str) -> QidResult<()> {
        sqlx::query("DELETE FROM policy_bundles WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }
}
