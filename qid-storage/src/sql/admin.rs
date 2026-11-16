use async_trait::async_trait;

use super::*;
use crate::oidc_continuation as state;

macro_rules! admin_repository {
    ([$($method:ident($($arg:ident),+): $row:ty => $model:ty = $sql:literal;)+] $($write:item)*) => {
        #[async_trait]
        impl AdminRepository for SqlRepository {
            $(async fn $method(&self, $($arg: &str),+) -> QidResult<Option<$model>> {
                sqlx::query_as::<_, $row>($sql)
                    $(.bind($arg))+
                    .fetch_optional(&self.pool)
                    .await
                    .map(|row| row.map(Into::into))
                    .map_err(storage_to_qid_error)
            })+
            $($write)*
        }
    };
}

const EXPIRED_LOW: &str = "SELECT id FROM admin_elevations WHERE elevation_expires_at >= 0 AND elevation_expires_at <= $1 ORDER BY elevation_expires_at LIMIT $2";
const DELETE_EXPIRED: &str = "DELETE FROM admin_elevations WHERE id = $1";

admin_repository! {
    [
    get_admin(tenant_id, subject): AdminRow => Admin = "SELECT * FROM admins WHERE tenant_id = ? AND subject = ?";
    get_admin_by_id(id): AdminRow => Admin = "SELECT * FROM admins WHERE id = ?";
    get_admin_elevation(id): AdminElevationRow => AdminElevation = "SELECT * FROM admin_elevations WHERE id = ?";
    get_admin_approval(id): AdminApprovalRow => AdminApproval = "SELECT * FROM admin_approvals WHERE id = ?";
    ]
    async fn upsert_admin(&self, admin: &Admin) -> QidResult<()> {
        let conflict = || format!("Admin ID {} belongs to another identity", admin.id);
        let result = sqlx::query(
            "INSERT INTO admins (id, tenant_id, subject, roles_json, created_at) VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(tenant_id, subject) DO UPDATE SET roles_json = excluded.roles_json \
             WHERE NOT EXISTS (SELECT 1 FROM admins WHERE id = excluded.id \
             AND (tenant_id <> excluded.tenant_id OR subject <> excluded.subject))",
        )
        .bind(&admin.id)
        .bind(&admin.tenant_id)
        .bind(&admin.subject)
        .bind(serde_json::to_string(&admin.roles).unwrap_or_default())
        .bind(admin.created_at as i64)
        .execute(&self.pool)
        .await
        .map_err(|err| unique_violation_to_qid_error(err, || QidError::Conflict {
            message: conflict(),
        }))?;
        crate::ownership::ensure_upsert_applied(result.rows_affected(), conflict)
    }

    async fn store_admin_elevation(&self, elevation: &AdminElevation) -> QidResult<()> {
        let result = sqlx::query(
            "INSERT INTO admin_elevations (id, tenant_id, admin_id, source_session_id, acr, amr_json, elevation_expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING",
        )
        .bind(&elevation.id)
        .bind(&elevation.tenant_id)
        .bind(&elevation.admin_id)
        .bind(&elevation.source_session_id)
        .bind(&elevation.acr)
        .bind(serde_json::to_string(&elevation.amr).unwrap_or_default())
        .bind(elevation.elevation_expires_at as i64)
        .bind(elevation.created_at as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        crate::ownership::ensure_upsert_applied(result.rows_affected(), || {
            format!("Admin elevation ID {} already exists", elevation.id)
        })
    }

    async fn cleanup_expired_admin_elevations(&self, now: u64, limit: u32) -> QidResult<u64> {
        state::validate_cleanup(now, limit)?;
        let mut tx = self.begin_write("BEGIN ISOLATION LEVEL READ COMMITTED").await?;
        let ids: Vec<String> = sqlx::query_scalar(EXPIRED_LOW)
            .bind(now as i64).bind(i64::from(limit))
            .fetch_all(&mut *tx).await.map_err(storage_to_qid_error)?;
        let mut deleted = 0u64;
        for id in &ids {
            deleted += sqlx::query(DELETE_EXPIRED).bind(id).execute(&mut *tx).await.map_err(storage_to_qid_error)?.rows_affected();
        }
        tx.commit().await.map_err(storage_to_qid_error)?;
        Ok(deleted)
    }

    async fn store_admin_approval(&self, approval: &AdminApproval) -> QidResult<()> {
        let result = sqlx::query(
            "INSERT INTO admin_approvals (id, tenant_id, approver_admin_id, target_admin_id, reason, approved_at, expires_at, consumed) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING",
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
        crate::ownership::ensure_upsert_applied(result.rows_affected(), || {
            format!("Admin approval ID {} already exists", approval.id)
        })
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
#[cfg(test)]
mod tests;
