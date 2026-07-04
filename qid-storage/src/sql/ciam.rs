use async_trait::async_trait;

use super::*;

#[async_trait]
impl CiamRepository for SqlRepository {
    async fn store_ciam_consent_grant(&self, grant: &CiamConsentGrant) -> QidResult<()> {
        grant.validate()?;
        crate::domain::validate_ciam_consent_grant_state(grant)?;
        sqlx::query(
            "INSERT INTO ciam_consent_grants (id, realm_id, user_id, client_id, granted_claims_json, terms_version, granted_at_epoch_seconds, revoked) VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET granted_claims_json = excluded.granted_claims_json, terms_version = excluded.terms_version, revoked = excluded.revoked",
        )
        .bind(&grant.id)
        .bind(&grant.realm_id)
        .bind(&grant.user_id)
        .bind(&grant.client_id)
        .bind(serde_json::to_string(&grant.granted_claims).unwrap_or_default())
        .bind(&grant.terms_version)
        .bind(grant.granted_at_epoch_seconds as i64)
        .bind(grant.revoked as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_ciam_consent_grants(
        &self,
        realm_id: &RealmId,
        user_id: &str,
        client_id: Option<&str>,
    ) -> QidResult<Vec<CiamConsentGrant>> {
        let rows: Vec<CiamConsentGrantRow> = if let Some(client_id) = client_id {
            sqlx::query_as(
                "SELECT * FROM ciam_consent_grants WHERE realm_id = ? AND user_id = ? AND client_id = ? ORDER BY granted_at_epoch_seconds DESC, id ASC",
            )
            .bind(realm_id.as_str())
            .bind(user_id)
            .bind(client_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?
        } else {
            sqlx::query_as(
                "SELECT * FROM ciam_consent_grants WHERE realm_id = ? AND user_id = ? ORDER BY granted_at_epoch_seconds DESC, id ASC",
            )
            .bind(realm_id.as_str())
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?
        };
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn revoke_ciam_consent_grant(&self, id: &str, _revoked_at: u64) -> QidResult<()> {
        sqlx::query("UPDATE ciam_consent_grants SET revoked = 1 WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn store_ciam_verification_challenge(
        &self,
        challenge: &CiamVerificationChallengeRecord,
    ) -> QidResult<()> {
        challenge.validate()?;
        sqlx::query(
            "INSERT INTO ciam_verification_challenges (id, realm_id, user_id, channel, address, purpose, code_hash, expires_at_epoch_seconds, consumed_at_epoch_seconds, created_at_epoch_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&challenge.id)
        .bind(&challenge.realm_id)
        .bind(&challenge.user_id)
        .bind(&challenge.channel)
        .bind(&challenge.address)
        .bind(&challenge.purpose)
        .bind(&challenge.code_hash)
        .bind(challenge.expires_at_epoch_seconds as i64)
        .bind(challenge.consumed_at_epoch_seconds.map(|value| value as i64))
        .bind(challenge.created_at_epoch_seconds as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_ciam_verification_challenge(
        &self,
        id: &str,
    ) -> QidResult<Option<CiamVerificationChallengeRecord>> {
        let row: Option<CiamVerificationChallengeRow> =
            sqlx::query_as("SELECT * FROM ciam_verification_challenges WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn consume_ciam_verification_challenge(
        &self,
        id: &str,
        consumed_at: u64,
    ) -> QidResult<()> {
        let result = sqlx::query(
            "UPDATE ciam_verification_challenges SET consumed_at_epoch_seconds = ? WHERE id = ? AND consumed_at_epoch_seconds IS NULL",
        )
        .bind(consumed_at as i64)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        if result.rows_affected() == 0 {
            return Err(QidError::Conflict {
                message: "CIAM verification challenge already consumed".to_string(),
            });
        }
        Ok(())
    }

    async fn store_ciam_identity_link(&self, link: &CiamIdentityLink) -> QidResult<()> {
        link.validate()?;
        let existing = self
            .get_ciam_identity_link(&RealmId(link.realm_id.clone()), &link.id)
            .await?;
        crate::domain::validate_ciam_identity_link_state(link, existing.as_ref())?;
        let user_realm: Option<String> =
            sqlx::query_scalar("SELECT realm_id FROM users WHERE id = ?")
                .bind(&link.user_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        let Some(user_realm) = user_realm else {
            return Err(QidError::BadRequest {
                message: "CIAM identity link user does not exist".to_string(),
            });
        };
        if user_realm != link.realm_id {
            return Err(QidError::BadRequest {
                message: "CIAM identity link user belongs to another realm".to_string(),
            });
        }
        if let Some(existing_id) = sqlx::query_scalar::<_, String>(
            "SELECT id FROM ciam_identity_links WHERE realm_id = ? AND provider = ? AND external_subject = ?",
        )
        .bind(&link.realm_id)
        .bind(&link.provider)
        .bind(&link.external_subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_to_qid_error)?
            && existing_id != link.id
        {
            return Err(QidError::BadRequest {
                message: "CIAM identity link external subject is already linked".to_string(),
            });
        }
        sqlx::query(
            "INSERT INTO ciam_identity_links (id, realm_id, user_id, provider, external_subject, external_email, profile_json, linked_at_epoch_seconds, verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET user_id = excluded.user_id, provider = excluded.provider, external_subject = excluded.external_subject, external_email = excluded.external_email, profile_json = excluded.profile_json, linked_at_epoch_seconds = excluded.linked_at_epoch_seconds, verified = excluded.verified",
        )
        .bind(&link.id)
        .bind(&link.realm_id)
        .bind(&link.user_id)
        .bind(&link.provider)
        .bind(&link.external_subject)
        .bind(&link.external_email)
        .bind(link.profile_json.to_string())
        .bind(link.linked_at_epoch_seconds as i64)
        .bind(link.verified as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_ciam_identity_links(
        &self,
        realm_id: &RealmId,
        user_id: &str,
    ) -> QidResult<Vec<CiamIdentityLink>> {
        let rows: Vec<CiamIdentityLinkRow> = sqlx::query_as(
            "SELECT * FROM ciam_identity_links WHERE realm_id = ? AND user_id = ? ORDER BY linked_at_epoch_seconds DESC, id ASC",
        )
        .bind(realm_id.as_str())
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn get_ciam_identity_link(
        &self,
        realm_id: &RealmId,
        id: &str,
    ) -> QidResult<Option<CiamIdentityLink>> {
        let row: Option<CiamIdentityLinkRow> =
            sqlx::query_as("SELECT * FROM ciam_identity_links WHERE realm_id = ? AND id = ?")
                .bind(realm_id.as_str())
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn get_ciam_identity_link_by_external_subject(
        &self,
        realm_id: &RealmId,
        provider: &str,
        external_subject: &str,
    ) -> QidResult<Option<CiamIdentityLink>> {
        let row: Option<CiamIdentityLinkRow> = sqlx::query_as(
            "SELECT * FROM ciam_identity_links WHERE realm_id = ? AND provider = ? AND external_subject = ?",
        )
        .bind(realm_id.as_str())
        .bind(provider)
        .bind(external_subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn delete_ciam_identity_link(&self, realm_id: &RealmId, id: &str) -> QidResult<()> {
        sqlx::query("DELETE FROM ciam_identity_links WHERE realm_id = ? AND id = ?")
            .bind(realm_id.as_str())
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn store_password_reset_token(&self, token: &PasswordResetToken) -> QidResult<()> {
        token.validate()?;
        sqlx::query(
            "INSERT INTO password_reset_tokens (id, realm_id, user_id, token_hash, device_id, risk_json, expires_at_epoch_seconds, consumed_at_epoch_seconds, created_at_epoch_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&token.id)
        .bind(&token.realm_id)
        .bind(&token.user_id)
        .bind(&token.token_hash)
        .bind(&token.device_id)
        .bind(token.risk_json.to_string())
        .bind(token.expires_at_epoch_seconds as i64)
        .bind(token.consumed_at_epoch_seconds.map(|value| value as i64))
        .bind(token.created_at_epoch_seconds as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn get_password_reset_token(&self, id: &str) -> QidResult<Option<PasswordResetToken>> {
        let row: Option<PasswordResetTokenRow> =
            sqlx::query_as("SELECT * FROM password_reset_tokens WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn consume_password_reset_token(&self, id: &str, consumed_at: u64) -> QidResult<()> {
        let result = sqlx::query(
            "UPDATE password_reset_tokens SET consumed_at_epoch_seconds = ? WHERE id = ? AND consumed_at_epoch_seconds IS NULL",
        )
        .bind(consumed_at as i64)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        if result.rows_affected() == 0 {
            return Err(QidError::Conflict {
                message: "password reset token already consumed".to_string(),
            });
        }
        Ok(())
    }

    async fn get_ciam_progressive_profile(
        &self,
        realm_id: &RealmId,
        user_id: &str,
    ) -> QidResult<Option<CiamProgressiveProfile>> {
        let row: Option<CiamProgressiveProfileRow> =
            sqlx::query_as("SELECT * FROM ciam_profiles WHERE realm_id = ? AND user_id = ?")
                .bind(realm_id.as_str())
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn store_ciam_progressive_profile(
        &self,
        profile: &CiamProgressiveProfile,
    ) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO ciam_profiles (id, realm_id, user_id, profile_json, passwordless_migrated_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET profile_json = excluded.profile_json, passwordless_migrated_at = COALESCE(excluded.passwordless_migrated_at, ciam_profiles.passwordless_migrated_at), updated_at = excluded.updated_at",
        )
        .bind(&profile.id)
        .bind(&profile.realm_id)
        .bind(&profile.user_id)
        .bind(serde_json::to_string(&profile.profile_json).unwrap_or_default())
        .bind(profile.passwordless_migrated_at.map(|v| v as i64))
        .bind(profile.created_at as i64)
        .bind(profile.updated_at as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn delete_ciam_progressive_profile(
        &self,
        realm_id: &RealmId,
        user_id: &str,
    ) -> QidResult<()> {
        sqlx::query("DELETE FROM ciam_profiles WHERE realm_id = ? AND user_id = ?")
            .bind(realm_id.as_str())
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_ciam_passwordless_migrations(
        &self,
        realm_id: &RealmId,
    ) -> QidResult<Vec<CiamProgressiveProfile>> {
        let rows: Vec<CiamProgressiveProfileRow> = sqlx::query_as(
            "SELECT * FROM ciam_profiles WHERE realm_id = ? AND passwordless_migrated_at IS NOT NULL ORDER BY updated_at DESC, id ASC",
        )
        .bind(realm_id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
}
