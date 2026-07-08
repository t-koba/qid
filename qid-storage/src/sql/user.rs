use async_trait::async_trait;

use super::*;

#[async_trait]
impl UserRepository for SqlRepository {
    async fn create_user(&self, user: &User) -> QidResult<()> {
        // Email uniqueness is enforced at the application layer (qid-admin, qid-session).
        sqlx::query(
            "INSERT INTO users (id, realm_id, email, email_verified, display_name, failed_login_attempts, locked_until, org) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
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
        Ok(())
    }

    async fn get_user_by_id(&self, id: &str) -> QidResult<Option<User>> {
        let row: Option<UserRow> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn get_user_by_email(&self, realm_id: &RealmId, email: &str) -> QidResult<Option<User>> {
        let row: Option<UserRow> =
            sqlx::query_as("SELECT * FROM users WHERE realm_id = ? AND email = ?")
                .bind(realm_id.as_str())
                .bind(email)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn store_password_credential(&self, cred: &PasswordCredential) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO credentials_password (user_id, hash, algorithm, pepper_ref) VALUES (?, ?, ?, ?) \
             ON CONFLICT(user_id) DO UPDATE SET hash = excluded.hash, algorithm = excluded.algorithm, pepper_ref = excluded.pepper_ref",
        )
            .bind(&cred.user_id)
            .bind(&cred.hash)
            .bind(&cred.algorithm)
            .bind(&cred.pepper_ref)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_password_credential(
        &self,
        user_id: &str,
    ) -> QidResult<Option<PasswordCredential>> {
        let row: Option<(String, String, String, Option<String>)> = sqlx::query_as(
            "SELECT user_id, hash, algorithm, pepper_ref FROM credentials_password WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(row.map(
            |(user_id, hash, algorithm, pepper_ref)| PasswordCredential {
                user_id,
                hash,
                algorithm,
                pepper_ref,
            },
        ))
    }

    async fn list_users(&self, realm_id: &RealmId) -> QidResult<Vec<User>> {
        self.list_users_page(realm_id, 0, usize::MAX).await
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
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
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
            .map_err(storage_to_qid_error)?;
        Ok(())
    }
}
