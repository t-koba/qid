use async_trait::async_trait;

use super::*;

#[async_trait]
impl UserRepository for SqlRepository {
    async fn create_user(&self, user: &User) -> QidResult<()> {
        // The primary key and the UNIQUE(realm_id, email) index hold the
        // identity of a user, so the insert itself refuses a second user
        // that carries a taken record ID or a taken email in the realm.
        // The read names the reason of the refusal.
        let result = sqlx::query(
            "INSERT INTO users (id, realm_id, email, email_verified, display_name, failed_login_attempts, locked_until, org) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING",
        )
        .bind(&user.id)
        .bind(&user.realm_id)
        .bind(&user.email)
        .bind(user.email_verified as i64)
        .bind(&user.display_name)
        .bind(user.failed_login_attempts as i64)
        .bind(user.locked_until.map(|v| v as i64))
        .bind(&user.org)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        if result.rows_affected() == 0 {
            if self.get_user_by_id(&user.id).await?.is_some() {
                return Err(QidError::Conflict {
                    message: format!("user record ID {} already exists", user.id),
                });
            }
            return Err(crate::ownership::user_email_conflict(
                user.email.as_deref().unwrap_or_default(),
                &user.realm_id,
            ));
        }
        Ok(())
    }

    async fn get_user_by_id(&self, id: &str) -> QidResult<Option<User>> {
        let row: Option<UserRow> = sqlx::query_as("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn get_user_by_id_in_realm(
        &self,
        realm_id: &RealmId,
        id: &str,
    ) -> QidResult<Option<User>> {
        let row: Option<UserRow> =
            sqlx::query_as("SELECT * FROM users WHERE realm_id = $1 AND id = $2")
                .bind(realm_id.as_str())
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn get_user_by_email(&self, realm_id: &RealmId, email: &str) -> QidResult<Option<User>> {
        let row: Option<UserRow> =
            sqlx::query_as("SELECT * FROM users WHERE realm_id = $1 AND email = $2")
                .bind(realm_id.as_str())
                .bind(email)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn store_password_credential(&self, cred: &PasswordCredential) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO credentials_password (user_id, hash, algorithm) VALUES (?, ?, ?) \
             ON CONFLICT(user_id) DO UPDATE SET hash = excluded.hash, algorithm = excluded.algorithm",
        )
            .bind(&cred.user_id)
            .bind(&cred.hash)
            .bind(&cred.algorithm)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_password_credential(
        &self,
        user_id: &str,
    ) -> QidResult<Option<PasswordCredential>> {
        let row: Option<(String, String, String)> = sqlx::query_as(
            "SELECT user_id, hash, algorithm FROM credentials_password WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(row.map(|(user_id, hash, algorithm)| PasswordCredential {
            user_id,
            hash,
            algorithm,
        }))
    }

    async fn list_users_page(
        &self,
        realm_id: &RealmId,
        offset: usize,
        limit: usize,
    ) -> QidResult<Vec<User>> {
        let rows: Vec<UserRow> = sqlx::query_as(
            "SELECT * FROM users WHERE realm_id = ? ORDER BY id ASC LIMIT ? OFFSET ?",
        )
        .bind(realm_id.as_str())
        .bind(page_bound(limit))
        .bind(page_bound(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn delete_user(&self, id: &str) -> QidResult<()> {
        let mut tx = self.pool.begin().await.map_err(storage_to_qid_error)?;
        // Session links need not have the same direct owner. Remove their children
        // before the user cascade removes the sessions, in the same transaction.
        sqlx::query("DELETE FROM authorization_codes WHERE user_id = ? OR session_id IN (SELECT id FROM sessions WHERE user_id = ?)")
            .bind(id)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(storage_to_qid_error)?;
        // Access-token subjects deliberately have no user FK: service/workload
        // subjects survive, unless their token belongs to a removed refresh family.
        sqlx::query("DELETE FROM access_tokens WHERE user_id = ? OR family_id IN (SELECT id FROM token_families WHERE user_id = ? OR session_id IN (SELECT id FROM sessions WHERE user_id = ?))")
            .bind(id)
            .bind(id)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(storage_to_qid_error)?;
        sqlx::query("DELETE FROM token_families WHERE user_id = ? OR session_id IN (SELECT id FROM sessions WHERE user_id = ?)")
            .bind(id)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(storage_to_qid_error)?;
        sqlx::query("DELETE FROM device_authorization_grants WHERE user_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(storage_to_qid_error)?;
        sqlx::query("DELETE FROM backchannel_authentication_grants WHERE user_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(storage_to_qid_error)?;
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(storage_to_qid_error)?;
        tx.commit().await.map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn update_user(&self, user: &User) -> QidResult<()> {
        sqlx::query("UPDATE users SET email = ?, email_verified = ?, display_name = ?, failed_login_attempts = ?, locked_until = ?, org = ?, updated_at = strftime('%s', 'now') WHERE id = ?")
            .bind(&user.email)
            .bind(user.email_verified as i64)
            .bind(&user.display_name)
            .bind(user.failed_login_attempts as i64)
            .bind(user.locked_until.map(|v| v as i64))
            .bind(&user.org)
            .bind(&user.id)
            .execute(&self.pool)
            .await
            .map_err(|error| match &error {
                sqlx::Error::Database(database_error) if database_error.is_unique_violation() => {
                    crate::ownership::user_email_conflict(
                        user.email.as_deref().unwrap_or_default(),
                        &user.realm_id,
                    )
                }
                _ => storage_to_qid_error(error),
            })?;
        Ok(())
    }
}
