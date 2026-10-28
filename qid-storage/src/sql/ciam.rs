use async_trait::async_trait;

use super::*;

#[async_trait]
impl CiamRepository for SqlRepository {
    async fn store_ciam_consent_grant(&self, grant: &CiamConsentGrant) -> QidResult<()> {
        grant.validate()?;
        crate::domain::validate_ciam_consent_grant_state(grant)?;
        let result = sqlx::query(
            "INSERT INTO ciam_consent_grants (id, realm_id, user_id, client_id, granted_claims_json, terms_version, granted_at_epoch_seconds, revoked) VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET granted_claims_json = excluded.granted_claims_json, terms_version = excluded.terms_version, revoked = excluded.revoked \
             WHERE ciam_consent_grants.realm_id = excluded.realm_id AND ciam_consent_grants.user_id = excluded.user_id AND ciam_consent_grants.client_id = excluded.client_id",
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
        crate::ownership::ensure_upsert_applied(result.rows_affected(), || {
            format!("CIAM consent grant {} belongs to another owner", grant.id)
        })
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
        let result = sqlx::query(
            "INSERT INTO ciam_verification_challenges (id, realm_id, user_id, channel, address, purpose, code_hash, attempt_count, expires_at_epoch_seconds, consumed_at_epoch_seconds, created_at_epoch_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING",
        )
        .bind(&challenge.id)
        .bind(&challenge.realm_id)
        .bind(&challenge.user_id)
        .bind(&challenge.channel)
        .bind(&challenge.address)
        .bind(&challenge.purpose)
        .bind(&challenge.code_hash)
        .bind(challenge.attempt_count as i64)
        .bind(challenge.expires_at_epoch_seconds as i64)
        .bind(challenge.consumed_at_epoch_seconds.map(|value| value as i64))
        .bind(challenge.created_at_epoch_seconds as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        crate::ownership::ensure_upsert_applied(result.rows_affected(), || {
            format!(
                "CIAM verification challenge ID {} already exists",
                challenge.id
            )
        })
    }

    async fn get_ciam_verification_challenge(
        &self,
        realm_id: &RealmId,
        id: &str,
    ) -> QidResult<Option<CiamVerificationChallengeRecord>> {
        let row: Option<CiamVerificationChallengeRow> = sqlx::query_as(
            "SELECT * FROM ciam_verification_challenges WHERE realm_id = ? AND id = ?",
        )
        .bind(realm_id.as_str())
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(row.map(Into::into))
    }

    async fn attempt_ciam_verification_challenge(
        &self,
        realm_id: &RealmId,
        id: &str,
        expected_code_hash: &str,
        verified: bool,
        attempted_at: u64,
        max_attempts: u32,
    ) -> QidResult<()> {
        let result = sqlx::query(
            "UPDATE ciam_verification_challenges SET attempt_count = attempt_count + 1, consumed_at_epoch_seconds = CASE WHEN ? != 0 THEN ? ELSE consumed_at_epoch_seconds END WHERE realm_id = ? AND id = ? AND code_hash = ? AND consumed_at_epoch_seconds IS NULL AND expires_at_epoch_seconds >= ? AND attempt_count < ?",
        )
        .bind(verified as i64)
        .bind(attempted_at as i64)
        .bind(realm_id.as_str())
        .bind(id)
        .bind(expected_code_hash)
        .bind(attempted_at as i64)
        .bind(max_attempts as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        if result.rows_affected() == 0 {
            let owner: Option<String> = sqlx::query_scalar(
                "SELECT realm_id FROM ciam_verification_challenges WHERE id = ?",
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
            if owner.as_deref() != Some(realm_id.as_str()) {
                return Err(QidError::NotFound {
                    resource: format!("CIAM verification challenge {id}"),
                });
            }
            return Err(QidError::Conflict {
                message: "CIAM verification challenge unavailable".to_string(),
            });
        }
        Ok(())
    }

    async fn confirm_ciam_email_verification(
        &self,
        realm_id: &RealmId,
        id: &str,
        user_id: &str,
        candidate_hash: &str,
        attempted_at: u64,
        max_attempts: u32,
    ) -> QidResult<bool> {
        let Ok(attempted_at_i64) = i64::try_from(attempted_at) else {
            return Ok(false);
        };
        let mut tx = self.pool.begin().await.map_err(storage_to_qid_error)?;
        // The first statement obtains the challenge write lock; no pre-read
        // authorization or optimistic consume can race a competing confirmation.
        let row: Option<CiamVerificationChallengeRow> = sqlx::query_as(
            "UPDATE ciam_verification_challenges SET attempt_count = attempt_count + 1 WHERE realm_id = ? AND id = ? AND user_id = ? AND channel = 'email' AND purpose = 'email_verification' AND consumed_at_epoch_seconds IS NULL AND expires_at_epoch_seconds >= ? AND attempt_count < ? AND EXISTS (SELECT 1 FROM users WHERE users.id = ciam_verification_challenges.user_id AND users.realm_id = ciam_verification_challenges.realm_id AND users.email = ciam_verification_challenges.address) RETURNING *"
        ).bind(realm_id.as_str()).bind(id).bind(user_id).bind(attempted_at_i64).bind(i64::from(max_attempts))
            .fetch_optional(&mut *tx).await.map_err(storage_to_qid_error)?;
        let Some(row) = row else {
            return Ok(false);
        };
        let challenge: CiamVerificationChallengeRecord = row.into();
        let verified = qid_core::util::constant_time_eq(
            challenge.code_hash.as_bytes(),
            candidate_hash.as_bytes(),
        );
        if verified {
            // Conditional write locks the user too. If its contact changed since
            // the first statement, rollback the attempt as well as consumption.
            let result = sqlx::query(
                "UPDATE users SET email_verified = 1 WHERE id = ? AND realm_id = ? AND email = ?",
            )
            .bind(user_id)
            .bind(realm_id.as_str())
            .bind(&challenge.address)
            .execute(&mut *tx)
            .await
            .map_err(storage_to_qid_error)?;
            if result.rows_affected() != 1 {
                tx.rollback().await.map_err(storage_to_qid_error)?;
                return Ok(false);
            }
            sqlx::query("UPDATE ciam_verification_challenges SET consumed_at_epoch_seconds = ? WHERE realm_id = ? AND id = ?")
                .bind(attempted_at_i64).bind(realm_id.as_str()).bind(id)
                .execute(&mut *tx).await.map_err(storage_to_qid_error)?;
        }
        tx.commit().await.map_err(storage_to_qid_error)?;
        Ok(verified)
    }

    async fn try_issue_email_challenge(
        &self,
        challenge: &CiamVerificationChallengeRecord,
        max_issuances: u32,
        window_seconds: u64,
    ) -> QidResult<bool> {
        let start =
            crate::domain::email_challenge_window_start(challenge, max_issuances, window_seconds)?;
        // Serialize admission before checking the budget, as for password resets.
        let mut tx = self
            .pool
            .begin_with(match self.database_kind {
                SqlDatabaseKind::Sqlite => "BEGIN IMMEDIATE",
                SqlDatabaseKind::Postgres => "BEGIN",
            })
            .await
            .map_err(storage_to_qid_error)?;
        if self.database_kind == SqlDatabaseKind::Postgres {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(
                    serde_json::json!([challenge.realm_id, challenge.user_id, challenge.purpose])
                        .to_string(),
                )
                .execute(&mut *tx)
                .await
                .map_err(storage_to_qid_error)?;
        }
        let duplicate: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM ciam_verification_challenges WHERE id = $1")
                .bind(&challenge.id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage_to_qid_error)?;
        if duplicate.is_some() {
            tx.rollback().await.map_err(storage_to_qid_error)?;
            return Err(QidError::Conflict {
                message: "CIAM verification challenge ID already exists".into(),
            });
        }
        let current_owner: Option<String> = sqlx::query_scalar(match self.database_kind {
            SqlDatabaseKind::Sqlite => {
                "SELECT id FROM users WHERE id = $1 AND realm_id = $2 AND email = $3 AND email_verified = $4"
            }
            SqlDatabaseKind::Postgres => {
                "SELECT id FROM users WHERE id = $1 AND realm_id = $2 AND email = $3 AND email_verified = $4 FOR UPDATE"
            }
        })
        .bind(&challenge.user_id)
        .bind(&challenge.realm_id)
        .bind(&challenge.address)
        .bind(i64::from(challenge.purpose == "email_magic_link"))
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage_to_qid_error)?;
        if current_owner.is_none() {
            tx.rollback().await.map_err(storage_to_qid_error)?;
            return Ok(false);
        }
        // No upsert can overwrite identity or reset attempts/consumption.
        // All lifecycle states count, including consumed and expired records.
        let result = sqlx::query(
            "INSERT INTO ciam_verification_challenges (id, realm_id, user_id, channel, address, purpose, code_hash, attempt_count, expires_at_epoch_seconds, consumed_at_epoch_seconds, created_at_epoch_seconds) SELECT $1, $2, $3, $4, $5, $6, $7, 0, $8, NULL, $9 WHERE EXISTS (SELECT 1 FROM ciam_verification_challenges WHERE id = $1) OR (SELECT COUNT(*) FROM ciam_verification_challenges WHERE realm_id = $2 AND user_id = $3 AND purpose = $6 AND created_at_epoch_seconds >= $10) < $11"
        )
        .bind(&challenge.id).bind(&challenge.realm_id).bind(&challenge.user_id)
        .bind(&challenge.channel).bind(&challenge.address).bind(&challenge.purpose)
        .bind(&challenge.code_hash).bind(challenge.expires_at_epoch_seconds as i64)
        .bind(challenge.created_at_epoch_seconds as i64).bind(start as i64)
        .bind(i64::from(max_issuances))
        .execute(&mut *tx).await.map_err(|err| {
            if err.as_database_error().is_some_and(|db| db.is_unique_violation()) {
                QidError::Conflict { message: "CIAM verification challenge ID already exists".into() }
            } else {
                storage_to_qid_error(err)
            }
        })?;
        tx.commit().await.map_err(storage_to_qid_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn redeem_email_magic_link_challenge(
        &self,
        realm_id: &RealmId,
        id: &str,
        candidate_hash: &str,
        attempted_at: u64,
        max_attempts: u32,
    ) -> QidResult<Option<User>> {
        let Ok(attempted_at) = i64::try_from(attempted_at) else {
            return Ok(None);
        };
        let mut tx = self.pool.begin().await.map_err(storage_to_qid_error)?;
        // Write-lock without spending an attempt. Compare binding under this lock
        // before atomically counting a token failure or consuming a success.
        let row: Option<CiamVerificationChallengeRow> = sqlx::query_as(
            "UPDATE ciam_verification_challenges SET attempt_count = attempt_count WHERE realm_id = $1 AND id = $2 AND channel = 'email' AND purpose = 'email_magic_link' AND consumed_at_epoch_seconds IS NULL AND created_at_epoch_seconds <= $3 AND expires_at_epoch_seconds >= $3 AND attempt_count < $4 AND EXISTS (SELECT 1 FROM users WHERE users.id = ciam_verification_challenges.user_id AND users.realm_id = ciam_verification_challenges.realm_id AND users.email = ciam_verification_challenges.address AND users.email_verified = 1) RETURNING *"
        ).bind(realm_id.as_str()).bind(id).bind(attempted_at).bind(i64::from(max_attempts))
            .fetch_optional(&mut *tx).await.map_err(storage_to_qid_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let challenge: CiamVerificationChallengeRecord = row.into();
        // Lock the current owner through commit, not merely the snapshot in the
        // EXISTS above. SQLite's first write already locks competing writers.
        let user: Option<UserRow> = sqlx::query_as(match self.database_kind {
            SqlDatabaseKind::Sqlite => "SELECT * FROM users WHERE id = $1 AND realm_id = $2",
            SqlDatabaseKind::Postgres => {
                "SELECT * FROM users WHERE id = $1 AND realm_id = $2 FOR UPDATE"
            }
        })
        .bind(&challenge.user_id)
        .bind(realm_id.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage_to_qid_error)?;
        let user: Option<User> = user.map(Into::into);
        let Some(user) = user
            .filter(|u| u.email_verified && u.email.as_deref() == Some(challenge.address.as_str()))
        else {
            tx.rollback().await.map_err(storage_to_qid_error)?;
            return Ok(None);
        };
        let Some(verified) =
            crate::domain::email_magic_link_token_matches(&challenge.code_hash, candidate_hash)
        else {
            tx.rollback().await.map_err(storage_to_qid_error)?;
            return Ok(None);
        };
        sqlx::query("UPDATE ciam_verification_challenges SET attempt_count = attempt_count + 1 WHERE realm_id = $1 AND id = $2")
            .bind(realm_id.as_str()).bind(id)
            .execute(&mut *tx).await.map_err(storage_to_qid_error)?;
        if verified {
            let result = sqlx::query("UPDATE ciam_verification_challenges SET consumed_at_epoch_seconds = $1 WHERE realm_id = $2 AND id = $3 AND consumed_at_epoch_seconds IS NULL")
                .bind(attempted_at).bind(realm_id.as_str()).bind(id)
                .execute(&mut *tx).await.map_err(storage_to_qid_error)?;
            crate::ownership::ensure_upsert_applied(result.rows_affected(), || {
                "magic-link challenge could not be consumed".into()
            })?;
        }
        tx.commit().await.map_err(storage_to_qid_error)?;
        Ok(verified.then_some(user))
    }

    async fn store_ciam_identity_link(&self, link: &CiamIdentityLink) -> QidResult<()> {
        link.validate()?;
        let existing: Option<CiamIdentityLinkRow> =
            sqlx::query_as("SELECT * FROM ciam_identity_links WHERE id = ?")
                .bind(&link.id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_to_qid_error)?;
        let existing = existing.map(Into::into);
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
        if link.verified
            && let Some(existing_id) = sqlx::query_scalar::<_, String>(
            "SELECT id FROM ciam_identity_links WHERE realm_id = ? AND provider = ? AND external_subject = ? AND verified = 1",
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
        let result = sqlx::query(
            "INSERT INTO ciam_identity_links (id, realm_id, user_id, provider, external_subject, external_email, profile_json, linked_at_epoch_seconds, verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET external_email = excluded.external_email, profile_json = excluded.profile_json, linked_at_epoch_seconds = excluded.linked_at_epoch_seconds, verified = excluded.verified \
             WHERE ciam_identity_links.realm_id = excluded.realm_id AND ciam_identity_links.user_id = excluded.user_id AND ciam_identity_links.provider = excluded.provider AND ciam_identity_links.external_subject = excluded.external_subject \
             AND (ciam_identity_links.verified = 0 OR excluded.verified = 1)",
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
        crate::ownership::ensure_upsert_applied(result.rows_affected(), || {
            format!("CIAM identity link {} changed concurrently", link.id)
        })
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
            "SELECT * FROM ciam_identity_links WHERE realm_id = ? AND provider = ? AND external_subject = ? AND verified = 1",
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
        let result = sqlx::query(
            "INSERT INTO password_reset_tokens (id, realm_id, user_id, token_hash, device_id, risk_json, expires_at_epoch_seconds, consumed_at_epoch_seconds, created_at_epoch_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING",
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
        crate::ownership::ensure_upsert_applied(result.rows_affected(), || {
            format!("Password reset token ID {} already exists", token.id)
        })
    }

    async fn try_issue_password_reset_token(
        &self,
        token: &PasswordResetToken,
        max_issuances: u32,
        window_seconds: u64,
    ) -> QidResult<bool> {
        let start =
            crate::domain::password_reset_window_start(token, max_issuances, window_seconds)?;
        let mut tx = self
            .pool
            .begin_with(match self.database_kind {
                SqlDatabaseKind::Sqlite => "BEGIN IMMEDIATE",
                SqlDatabaseKind::Postgres => "BEGIN",
            })
            .await
            .map_err(storage_to_qid_error)?;
        if self.database_kind == SqlDatabaseKind::Postgres {
            // Transaction-scoped per-account serialization across connections/processes.
            // Hash collisions only serialize unrelated accounts; they cannot bypass a budget.
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(serde_json::json!([token.realm_id, token.user_id]).to_string())
                .execute(&mut *tx)
                .await
                .map_err(storage_to_qid_error)?;
        }
        // Shared validation above proves every u64 timestamp fits i64. Deliberately
        // attempt duplicate IDs even over budget, so collisions remain storage errors.
        let result = sqlx::query(
            "INSERT INTO password_reset_tokens (id, realm_id, user_id, token_hash, device_id, risk_json, expires_at_epoch_seconds, consumed_at_epoch_seconds, created_at_epoch_seconds) SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9 WHERE EXISTS (SELECT 1 FROM password_reset_tokens WHERE id = $1) OR (SELECT COUNT(*) FROM password_reset_tokens WHERE realm_id = $2 AND user_id = $3 AND created_at_epoch_seconds >= $10) < $11",
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
        .bind(start as i64)
        .bind(i64::from(max_issuances))
        .execute(&mut *tx).await.map_err(storage_to_qid_error)?;
        tx.commit().await.map_err(storage_to_qid_error)?;
        Ok(result.rows_affected() == 1)
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
            let exists: Option<String> =
                sqlx::query_scalar("SELECT id FROM password_reset_tokens WHERE id = ?")
                    .bind(id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(storage_to_qid_error)?;
            if exists.is_none() {
                return Err(QidError::NotFound {
                    resource: format!("password reset token {id}"),
                });
            }
            return Err(QidError::Conflict {
                message: "password reset token already consumed".to_string(),
            });
        }
        Ok(())
    }

    async fn replace_password_with_reset_token(
        &self,
        id: &str,
        realm_id: &RealmId,
        token_hash: &str,
        device_id: Option<&str>,
        credential: &PasswordCredential,
        consumed_at: u64,
    ) -> QidResult<()> {
        let mut tx = self.pool.begin().await.map_err(storage_to_qid_error)?;
        // Claim before reading: a conditional write serializes competing resets
        // without a SQLite read-to-write transaction upgrade race.
        let result = sqlx::query(
            "UPDATE password_reset_tokens SET consumed_at_epoch_seconds = ? WHERE id = ? AND realm_id = ? AND user_id = ? AND token_hash = ? AND (device_id = ? OR (device_id IS NULL AND ? IS NULL)) AND expires_at_epoch_seconds >= ? AND consumed_at_epoch_seconds IS NULL",
        )
        .bind(consumed_at as i64)
        .bind(id)
        .bind(realm_id.as_str())
        .bind(&credential.user_id)
        .bind(token_hash)
        .bind(device_id)
        .bind(device_id)
        .bind(consumed_at as i64)
        .execute(&mut *tx)
        .await
        .map_err(storage_to_qid_error)?;
        if result.rows_affected() == 0 {
            let row: Option<PasswordResetTokenRow> =
                sqlx::query_as("SELECT * FROM password_reset_tokens WHERE id = ?")
                    .bind(id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(storage_to_qid_error)?;
            let token = row
                .map(PasswordResetToken::from)
                .ok_or_else(|| QidError::NotFound {
                    resource: "password reset token".into(),
                })?;
            crate::domain::validate_password_reset(
                &token,
                realm_id,
                token_hash,
                device_id,
                credential,
                consumed_at,
            )?;
            return Err(QidError::Conflict {
                message: "password reset token already consumed".into(),
            });
        }
        sqlx::query(
            "INSERT INTO credentials_password (user_id, hash, algorithm) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET hash = excluded.hash, algorithm = excluded.algorithm",
        )
        .bind(&credential.user_id)
        .bind(&credential.hash)
        .bind(&credential.algorithm)
        .execute(&mut *tx)
        .await
        .map_err(storage_to_qid_error)?;
        tx.commit().await.map_err(storage_to_qid_error)
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
        let result = sqlx::query(
            "INSERT INTO ciam_profiles (id, realm_id, user_id, profile_json, passwordless_migrated_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET profile_json = excluded.profile_json, passwordless_migrated_at = COALESCE(excluded.passwordless_migrated_at, ciam_profiles.passwordless_migrated_at), updated_at = excluded.updated_at \
             WHERE ciam_profiles.realm_id = excluded.realm_id AND ciam_profiles.user_id = excluded.user_id",
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
        .map_err(|err| match err {
            sqlx::Error::Database(database_error) if database_error.is_unique_violation() => {
                QidError::Conflict {
                    message: "CIAM progressive profile identity cannot change".to_string(),
                }
            }
            other => storage_to_qid_error(other),
        })?;
        crate::ownership::ensure_upsert_applied(result.rows_affected(), || {
            format!(
                "CIAM progressive profile {} belongs to another owner",
                profile.id
            )
        })
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
