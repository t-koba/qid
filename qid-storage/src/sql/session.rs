use async_trait::async_trait;

use super::*;

#[async_trait]
impl SessionRepository for SqlRepository {
    async fn create_session(&self, session: &Session) -> QidResult<()> {
        // Check for duplicate id before inserting
        let dup: Option<String> = sqlx::query_scalar("SELECT id FROM sessions WHERE id = ?")
            .bind(&session.id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        if let Some(ref id) = dup {
            return Err(QidError::BadRequest {
                message: format!("session {id} already exists"),
            });
        }
        let cnf_json = session
            .cnf
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default());
        sqlx::query(
            "INSERT INTO sessions (id, realm_id, user_id, auth_time, acr, amr, idle_expires_at, absolute_expires_at, revoked, created_at, cnf) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&session.id)
        .bind(&session.realm_id)
        .bind(&session.user_id)
        .bind(session.auth_time as i64)
        .bind(&session.acr)
        .bind(serde_json::to_string(&session.amr).unwrap_or_default())
        .bind(session.idle_expires_at as i64)
        .bind(session.absolute_expires_at as i64)
        .bind(session.revoked as i64)
        .bind(session.created_at as i64)
        .bind(&cnf_json)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_session(&self, id: &str) -> QidResult<Option<Session>> {
        let row: Option<SessionRow> = sqlx::query_as("SELECT * FROM sessions WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn update_session_idle_expiry(&self, id: &str, idle_expires_at: u64) -> QidResult<()> {
        sqlx::query("UPDATE sessions SET idle_expires_at = ? WHERE id = ?")
            .bind(idle_expires_at as i64)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn revoke_session(&self, id: &str) -> QidResult<()> {
        sqlx::query("UPDATE sessions SET revoked = 1 WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_sessions(
        &self,
        realm_id: &str,
        user_id: Option<&str>,
    ) -> QidResult<Vec<Session>> {
        let rows: Vec<SessionRow> = if let Some(uid) = user_id {
            sqlx::query_as(
                "SELECT * FROM sessions WHERE realm_id = ? AND user_id = ? ORDER BY created_at DESC",
            )
            .bind(realm_id)
            .bind(uid)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?
        } else {
            sqlx::query_as("SELECT * FROM sessions WHERE realm_id = ? ORDER BY created_at DESC")
                .bind(realm_id)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?
        };
        Ok(rows.into_iter().map(Into::into).collect())
    }
}
