use async_trait::async_trait;

use super::*;

#[async_trait]
impl AdminRepository for SqlRepository {
    async fn get_admin(&self, tenant_id: &str, subject: &str) -> QidResult<Option<Admin>> {
        let row: Option<AdminRow> =
            sqlx::query_as("SELECT * FROM admins WHERE tenant_id = ? AND subject = ?")
                .bind(tenant_id)
                .bind(subject)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn get_admin_by_id(&self, id: &str) -> QidResult<Option<Admin>> {
        let row: Option<AdminRow> = sqlx::query_as("SELECT * FROM admins WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn upsert_admin(&self, admin: &Admin) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO admins (id, tenant_id, subject, roles_json, created_at) VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(tenant_id, subject) DO UPDATE SET roles_json = excluded.roles_json",
        )
        .bind(&admin.id)
        .bind(&admin.tenant_id)
        .bind(&admin.subject)
        .bind(serde_json::to_string(&admin.roles).unwrap_or_default())
        .bind(admin.created_at as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_admin_elevation(&self, id: &str) -> QidResult<Option<AdminElevation>> {
        let row: Option<AdminElevationRow> =
            sqlx::query_as("SELECT * FROM admin_elevations WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn store_admin_elevation(&self, elevation: &AdminElevation) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO admin_elevations (id, tenant_id, admin_id, acr, amr_json, elevation_expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&elevation.id)
        .bind(&elevation.tenant_id)
        .bind(&elevation.admin_id)
        .bind(&elevation.acr)
        .bind(serde_json::to_string(&elevation.amr).unwrap_or_default())
        .bind(elevation.elevation_expires_at as i64)
        .bind(elevation.created_at as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_admin_approval(&self, id: &str) -> QidResult<Option<AdminApproval>> {
        let row: Option<AdminApprovalRow> =
            sqlx::query_as("SELECT * FROM admin_approvals WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn store_admin_approval(&self, approval: &AdminApproval) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO admin_approvals (id, tenant_id, approver_admin_id, target_admin_id, reason, approved_at, expires_at, consumed) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&approval.id)
        .bind(&approval.tenant_id)
        .bind(&approval.approver_admin_id)
        .bind(&approval.target_admin_id)
        .bind(&approval.reason)
        .bind(approval.approved_at as i64)
        .bind(approval.expires_at as i64)
        .bind(approval.consumed as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn consume_admin_approval_if_unconsumed(&self, id: &str) -> QidResult<bool> {
        let result =
            sqlx::query("UPDATE admin_approvals SET consumed = 1 WHERE id = ? AND consumed = 0")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(result.rows_affected() == 1)
    }
}
