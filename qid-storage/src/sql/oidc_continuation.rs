use super::*;
use crate::{OidcContinuationRepository, oidc_continuation as state};
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[async_trait]
impl OidcContinuationRepository for SqlRepository {
    async fn create_oidc_continuation(
        &self,
        record: &OidcAuthorizationContinuation,
        now: u64,
    ) -> QidResult<()> {
        state::validate_creation(record, now)?;
        let inserted = sqlx::query("INSERT INTO oidc_authorization_continuations (id, realm_id, user_id, client_id, context_json, browser_binding_sha256, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (id) DO NOTHING")
            .bind(&record.id).bind(&record.realm_id).bind(&record.user_id).bind(&record.client_id)
            .bind(&record.context_json).bind(URL_SAFE_NO_PAD.encode(record.browser_binding_sha256))
            .bind(record.created_at as i64).bind(record.expires_at as i64)
            .execute(&self.pool).await.map_err(storage_to_qid_error)?.rows_affected();
        if inserted == 0 {
            return Err(QidError::Conflict {
                message: "OIDC continuation ID already exists".into(),
            });
        }
        Ok(())
    }

    async fn consume_oidc_continuation(
        &self,
        realm: &RealmId,
        user: &str,
        client: &str,
        id: &str,
        browser_binding_sha256: &[u8; 32],
        now: u64,
    ) -> QidResult<Option<OidcAuthorizationContinuation>> {
        if now > i64::MAX as u64 {
            return Err(state::invalid());
        }
        let mut tx = self.pool.begin().await.map_err(storage_to_qid_error)?;
        let row: Option<(String, i64, i64)> = sqlx::query_as("UPDATE oidc_authorization_continuations SET consumed_at = $6 WHERE id = $1 AND realm_id = $2 AND user_id = $3 AND client_id = $4 AND browser_binding_sha256 = $5 AND consumed_at IS NULL AND created_at <= $6 AND expires_at > $6 RETURNING context_json, created_at, expires_at")
            .bind(id).bind(&realm.0).bind(user).bind(client).bind(URL_SAFE_NO_PAD.encode(browser_binding_sha256)).bind(now as i64)
            .fetch_optional(&mut *tx).await.map_err(storage_to_qid_error)?;
        let result = row
            .map(|(context_json, created, expires)| {
                let c = OidcAuthorizationContinuation {
                    id: id.into(),
                    realm_id: realm.0.clone(),
                    user_id: user.into(),
                    client_id: client.into(),
                    context_json,
                    browser_binding_sha256: *browser_binding_sha256,
                    created_at: created as u64,
                    expires_at: expires as u64,
                };
                state::validate(&c)?;
                Ok::<_, QidError>(c)
            })
            .transpose()?;
        tx.commit().await.map_err(storage_to_qid_error)?;
        Ok(result)
    }

    async fn cleanup_expired_oidc_continuations(&self, now: u64, limit: u32) -> QidResult<u64> {
        state::validate_cleanup(now, limit)?;
        let deleted = sqlx::query("DELETE FROM oidc_authorization_continuations WHERE id IN (SELECT id FROM oidc_authorization_continuations WHERE expires_at <= $1 ORDER BY expires_at, id LIMIT $2)")
            .bind(now as i64)
            .bind(i64::from(limit))
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?
            .rows_affected();
        Ok(deleted)
    }
}
