use super::*;
use crate::{PushRepository, push as state};
use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};

fn json<T: Serialize>(record: &T) -> QidResult<String> {
    serde_json::to_string(record).map_err(|_| invalid_record())
}
fn invalid_record() -> QidError {
    QidError::Internal {
        message: "invalid push storage record".into(),
    }
}
fn decode_record<T: DeserializeOwned>(value: String) -> QidResult<T> {
    serde_json::from_str(&value).map_err(|_| invalid_record())
}
type AuthenticatorRow = (String, String, String, String, i64, Option<i64>, String);
type LoginRow = (String, String, String, String, String, i64, i64, String);

fn pending_expiry(row: &PushAuthenticatorRecord) -> Option<i64> {
    match row {
        PushAuthenticatorRecord::Pending(c) => Some(c.expires_at as i64),
        PushAuthenticatorRecord::Enrolled(_) => None,
    }
}
fn decode_authenticator_row(
    row: Option<AuthenticatorRow>,
) -> QidResult<Option<PushAuthenticatorRecord>> {
    let Some((id, realm, user, purpose, issued_at, pending_expires_at, json)) = row else {
        return Ok(None);
    };
    let record: PushAuthenticatorRecord = decode_record(json)?;
    let issued = u64::try_from(issued_at).map_err(|_| invalid_record())?;
    if purpose != state::PUSH_REGISTRATION_PURPOSE || pending_expires_at != pending_expiry(&record)
    {
        return Err(invalid_record());
    }
    state::authenticator_record(&record, &id)?;
    match &record {
        // Admission time must lie within the JSON lifecycle; activation preserves it.
        PushAuthenticatorRecord::Pending(c) => {
            if issued < c.authenticator.created_at || issued >= c.expires_at {
                return Err(invalid_record());
            }
        }
        PushAuthenticatorRecord::Enrolled(a) => {
            if issued == 0 || issued > a.created_at {
                return Err(invalid_record());
            }
        }
    }
    let a = record.authenticator();
    if a.realm_id != realm || a.user_id != user {
        return Err(invalid_record());
    }
    Ok(Some(record))
}
fn into_enrolled(row: PushAuthenticatorRecord) -> Option<PushAuthenticator> {
    match row {
        PushAuthenticatorRecord::Enrolled(a) => Some(a),
        PushAuthenticatorRecord::Pending(_) => None,
    }
}
fn decode_login_row(row: Option<LoginRow>) -> QidResult<Option<PushLoginChallenge>> {
    let Some((id, realm, user, authenticator, purpose, issued_at, expires_at, json)) = row else {
        return Ok(None);
    };
    let record: PushLoginChallenge = decode_record(json)?;
    let issued = u64::try_from(issued_at).map_err(|_| invalid_record())?;
    state::validate_login_record(&record)?;
    state::validate_login_issued(&record, issued)?;
    if record.id != id
        || record.realm_id != realm
        || record.user_id != user
        || record.authenticator_id != authenticator
        || state::login_purpose_str(record.purpose) != purpose
        || issued < record.created_at
        || issued >= record.expires_at
        || i64::try_from(record.expires_at).ok() != Some(expires_at)
    {
        return Err(invalid_record());
    }
    Ok(Some(record))
}

// UPDATE obtains a write lock before reading, on both SQLite and PostgreSQL.
// Every login mutation locks authenticator THEN challenge; revocation uses the
// same authenticator lock, so its check cannot race a decision or redemption.
async fn lock_authenticator(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    realm: &str,
    user: &str,
    id: &str,
) -> QidResult<Option<(PushAuthenticatorRecord, u64)>> {
    let row: Option<AuthenticatorRow> = sqlx::query_as("UPDATE push_authenticators SET record_json = record_json WHERE id = $1 AND realm_id = $2 AND user_id = $3 RETURNING id, realm_id, user_id, purpose, issued_at, pending_expires_at, record_json")
        .bind(id).bind(realm).bind(user).fetch_optional(&mut **tx).await.map_err(storage_to_qid_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let issued_at = u64::try_from(row.4).map_err(|_| invalid_record())?;
    Ok(decode_authenticator_row(Some(row))?.map(|record| (record, issued_at)))
}
async fn lock_auth(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    realm: &str,
    user: &str,
    id: &str,
) -> QidResult<Option<PushAuthenticator>> {
    Ok(lock_authenticator(tx, realm, user, id)
        .await?
        .and_then(|(record, _)| into_enrolled(record)))
}
async fn save_authenticator(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    row: &PushAuthenticatorRecord,
) -> QidResult<()> {
    let a = row.authenticator();
    sqlx::query("UPDATE push_authenticators SET record_json = $1, pending_expires_at = $5 WHERE id = $2 AND realm_id = $3 AND user_id = $4")
        .bind(json(row)?).bind(&a.id).bind(&a.realm_id).bind(&a.user_id).bind(pending_expiry(row))
        .execute(&mut **tx).await.map_err(storage_to_qid_error)?;
    Ok(())
}
async fn lock_login(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    expected: &PushLoginChallenge,
) -> QidResult<Option<PushLoginChallenge>> {
    decode_login_row(
        sqlx::query_as("UPDATE push_login_challenges SET record_json = record_json WHERE id = $1 AND realm_id = $2 AND user_id = $3 AND authenticator_id = $4 RETURNING id, realm_id, user_id, authenticator_id, purpose, issued_at, expires_at, record_json")
            .bind(&expected.id).bind(&expected.realm_id).bind(&expected.user_id).bind(&expected.authenticator_id)
            .fetch_optional(&mut **tx).await.map_err(storage_to_qid_error)?,
    )
}

async fn save_login(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    c: &PushLoginChallenge,
) -> QidResult<()> {
    sqlx::query("UPDATE push_login_challenges SET record_json = $1 WHERE id = $2 AND realm_id = $3 AND user_id = $4 AND authenticator_id = $5")
        .bind(json(c)?).bind(&c.id).bind(&c.realm_id).bind(&c.user_id).bind(&c.authenticator_id)
        .execute(&mut **tx).await.map_err(storage_to_qid_error)?;
    Ok(())
}

// Caller holds the owner/purpose admission lock. Rows issued before the window
// can still contain a resend: select on immutable expiry, not original issuance.
async fn login_send_count(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    c: &PushLoginChallenge,
    start: u64,
) -> QidResult<u64> {
    let rows: Vec<LoginRow> = sqlx::query_as("SELECT id, realm_id, user_id, authenticator_id, purpose, issued_at, expires_at, record_json FROM push_login_challenges WHERE realm_id = $1 AND user_id = $2 AND purpose = $3 AND (issued_at >= $4 OR expires_at > $4)")
        .bind(&c.realm_id).bind(&c.user_id).bind(state::login_purpose_str(c.purpose)).bind(start as i64)
        .fetch_all(&mut **tx).await.map_err(storage_to_qid_error)?;
    let mut count = 0;
    for row in rows {
        let issued = u64::try_from(row.5).map_err(|_| invalid_record())?;
        let c = decode_login_row(Some(row))?.ok_or_else(invalid_record)?;
        count += state::send_count(&c, issued, start)?;
    }
    Ok(count)
}

#[async_trait]
impl PushRepository for SqlRepository {
    async fn get_push_registration(
        &self,
        realm: &RealmId,
        user: &str,
        id: &str,
    ) -> QidResult<Option<PushRegistrationChallenge>> {
        Ok(match decode_authenticator_row(
            sqlx::query_as("SELECT id, realm_id, user_id, purpose, issued_at, pending_expires_at, record_json FROM push_authenticators WHERE id = $1 AND realm_id = $2 AND user_id = $3")
                .bind(id).bind(&realm.0).bind(user).fetch_optional(&self.pool).await.map_err(storage_to_qid_error)?,
        )? {
            Some(PushAuthenticatorRecord::Pending(c)) => Some(c),
            _ => None,
        })
    }
    async fn attempt_push_registration(
        &self,
        expected: &PushRegistrationChallenge,
        verified: bool,
        now: u64,
    ) -> QidResult<bool> {
        let a = &expected.authenticator;
        let mut tx = self.pool.begin().await.map_err(storage_to_qid_error)?;
        state::validate_registration_record(expected)?;
        let Some((mut row, issued_at)) =
            lock_authenticator(&mut tx, &a.realm_id, &a.user_id, &a.id).await?
        else {
            return Ok(false);
        };
        if now < issued_at || !state::registration_attempt(&mut row, expected, verified, now) {
            return Ok(false);
        }
        state::authenticator_record(&row, &a.id)?;
        save_authenticator(&mut tx, &row).await?;
        tx.commit().await.map_err(storage_to_qid_error)?;
        Ok(true)
    }
    async fn get_push_authenticator(
        &self,
        realm: &RealmId,
        user: &str,
        id: &str,
    ) -> QidResult<Option<PushAuthenticator>> {
        Ok(decode_authenticator_row(
            sqlx::query_as("SELECT id, realm_id, user_id, purpose, issued_at, pending_expires_at, record_json FROM push_authenticators WHERE id = $1 AND realm_id = $2 AND user_id = $3")
                .bind(id).bind(&realm.0).bind(user).fetch_optional(&self.pool).await.map_err(storage_to_qid_error)?,
        )?.and_then(into_enrolled))
    }
    async fn list_push_authenticators(
        &self,
        realm: &RealmId,
        user: &str,
    ) -> QidResult<Vec<PushAuthenticator>> {
        let rows: Vec<AuthenticatorRow> = sqlx::query_as("SELECT id, realm_id, user_id, purpose, issued_at, pending_expires_at, record_json FROM push_authenticators WHERE realm_id = $1 AND user_id = $2 ORDER BY id")
            .bind(&realm.0).bind(user).fetch_all(&self.pool).await.map_err(storage_to_qid_error)?;
        let mut enrolled = Vec::new();
        for row in rows {
            if let Some(a) = decode_authenticator_row(Some(row))?.and_then(into_enrolled) {
                enrolled.push(a);
            }
        }
        Ok(enrolled)
    }
    async fn revoke_push_authenticator(
        &self,
        realm: &RealmId,
        user: &str,
        id: &str,
        now: u64,
    ) -> QidResult<bool> {
        let mut tx = self.pool.begin().await.map_err(storage_to_qid_error)?;
        let Some(mut a) = lock_auth(&mut tx, &realm.0, user, id).await? else {
            return Ok(false);
        };
        if a.revoked_at.is_some() || now < a.created_at {
            return Ok(false);
        }
        a.revoked_at = Some(now);
        save_authenticator(&mut tx, &PushAuthenticatorRecord::Enrolled(a)).await?;
        tx.commit().await.map_err(storage_to_qid_error)?;
        Ok(true)
    }
    async fn get_push_login(
        &self,
        realm: &RealmId,
        user: &str,
        id: &str,
    ) -> QidResult<Option<PushLoginChallenge>> {
        decode_login_row(
            sqlx::query_as("SELECT id, realm_id, user_id, authenticator_id, purpose, issued_at, expires_at, record_json FROM push_login_challenges WHERE id = $1 AND realm_id = $2 AND user_id = $3")
                .bind(id).bind(&realm.0).bind(user).fetch_optional(&self.pool).await.map_err(storage_to_qid_error)?,
        )
    }
    async fn attempt_push_login(
        &self,
        expected: &PushLoginChallenge,
        decision: Option<PushDecision>,
        now: u64,
    ) -> QidResult<bool> {
        state::validate_login_record(expected)?;
        let mut tx = self.pool.begin().await.map_err(storage_to_qid_error)?;
        if !lock_auth(
            &mut tx,
            &expected.realm_id,
            &expected.user_id,
            &expected.authenticator_id,
        )
        .await?
        .is_some_and(|a| state::current(&a, expected))
        {
            return Ok(false);
        }
        let Some(mut c) = lock_login(&mut tx, expected).await? else {
            return Ok(false);
        };
        if !state::login_attempt(&mut c, expected, decision, now) {
            return Ok(false);
        }
        state::validate_login_record(&c)?;
        save_login(&mut tx, &c).await?;
        tx.commit().await.map_err(storage_to_qid_error)?;
        Ok(true)
    }
    async fn redeem_push_login(
        &self,
        expected: &PushLoginChallenge,
        binding_verifier: &str,
        now: u64,
    ) -> QidResult<bool> {
        state::validate_login_record(expected)?;
        let mut tx = self.pool.begin().await.map_err(storage_to_qid_error)?;
        if !lock_auth(
            &mut tx,
            &expected.realm_id,
            &expected.user_id,
            &expected.authenticator_id,
        )
        .await?
        .is_some_and(|a| state::current(&a, expected))
        {
            return Ok(false);
        }
        let Some(mut c) = lock_login(&mut tx, expected).await? else {
            return Ok(false);
        };
        if !state::redeem(&mut c, expected, binding_verifier, now) {
            return Ok(false);
        }
        state::validate_login_record(&c)?;
        save_login(&mut tx, &c).await?;
        tx.commit().await.map_err(storage_to_qid_error)?;
        Ok(true)
    }
    // Quota admission and expiry cleanup. Counts and inserts share one write
    // transaction (SQLite BEGIN IMMEDIATE, PostgreSQL READ COMMITTED with an
    // advisory xact lock). Explicit isolation ensures counts see prior admissions
    // after waiting for the lock, regardless of the session/server default.
    async fn try_issue_push_registration(
        &self,
        challenge: &PushRegistrationChallenge,
        max_issuances: u32,
        window_seconds: u64,
    ) -> QidResult<bool> {
        self.issue_push_registration(
            challenge,
            max_issuances,
            window_seconds,
            state::AdmissionClock::default(),
        )
        .await
    }
    async fn try_issue_push_login(
        &self,
        challenge: &PushLoginChallenge,
        max_issuances: u32,
        window_seconds: u64,
    ) -> QidResult<bool> {
        self.issue_push_login(
            challenge,
            max_issuances,
            window_seconds,
            state::AdmissionClock::default(),
        )
        .await
    }
    async fn try_resend_push_login(
        &self,
        expected: &PushLoginChallenge,
        binding_verifier: &str,
        nonce_verifier: &str,
        max_issuances: u32,
        window_seconds: u64,
        cooldown_seconds: u64,
    ) -> QidResult<Option<PushLoginChallenge>> {
        self.resend_push_login(
            expected,
            binding_verifier,
            nonce_verifier,
            max_issuances,
            window_seconds,
            cooldown_seconds,
            state::AdmissionClock::default(),
        )
        .await
    }
    async fn cleanup_expired_push_records(&self, now: u64, limit: u32) -> QidResult<u64> {
        let cutoff = state::cleanup_cutoff(now, limit)?;
        let mut tx = self
            .pool
            .begin_with(match self.database_kind {
                SqlDatabaseKind::Sqlite => "BEGIN IMMEDIATE",
                SqlDatabaseKind::Postgres => "BEGIN ISOLATION LEVEL READ COMMITTED",
            })
            .await
            .map_err(storage_to_qid_error)?;
        if self.database_kind == SqlDatabaseKind::Postgres {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind("push-cleanup".to_string())
                .execute(&mut *tx)
                .await
                .map_err(storage_to_qid_error)?;
        }
        // Indexed expiry/state prefilters and LIMIT bound materialization, not
        // just deletion. Enrolled/revoked rows have NULL pending_expires_at.
        let regs: Vec<AuthenticatorRow> =
            sqlx::query_as("SELECT id, realm_id, user_id, purpose, issued_at, pending_expires_at, record_json FROM push_authenticators WHERE pending_expires_at <= $1 AND issued_at < $2 ORDER BY pending_expires_at, issued_at, id LIMIT $3")
                .bind(now as i64).bind(cutoff as i64).bind(i64::from(limit))
                .fetch_all(&mut *tx).await.map_err(storage_to_qid_error)?;
        let mut deleted = 0u64;
        for row in regs {
            let id = row.0.clone();
            let snapshot = row.6.clone();
            let admission_key = serde_json::json!([row.1, row.2, row.3]).to_string();
            decode_authenticator_row(Some(row))?;
            // Serialize deletion with quota clock sampling/counting for this
            // owner and purpose, not merely with other cleanup calls.
            if self.database_kind == SqlDatabaseKind::Postgres {
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                    .bind(admission_key)
                    .execute(&mut *tx)
                    .await
                    .map_err(storage_to_qid_error)?;
            }
            // On PostgreSQL READ COMMITTED a concurrent activation may happen
            // after SELECT: DELETE locks/rechecks the current row predicate.
            // Activation atomically clears pending expiry; the JSON equality
            // also guards against any intervening replacement. SQLite holds
            // BEGIN IMMEDIATE throughout selection and deletion.
            deleted += sqlx::query("DELETE FROM push_authenticators WHERE id = $1 AND pending_expires_at <= $2 AND issued_at < $3 AND record_json = $4")
                .bind(&id).bind(now as i64).bind(cutoff as i64).bind(snapshot)
                .execute(&mut *tx).await.map_err(storage_to_qid_error)?.rows_affected();
        }
        let remaining = u64::from(limit) - deleted;
        let logins: Vec<LoginRow> =
            sqlx::query_as("SELECT id, realm_id, user_id, authenticator_id, purpose, issued_at, expires_at, record_json FROM push_login_challenges WHERE expires_at <= $1 AND expires_at < $2 ORDER BY expires_at, issued_at, id LIMIT $3")
                .bind(now as i64).bind(cutoff as i64).bind(remaining as i64)
                .fetch_all(&mut *tx).await.map_err(storage_to_qid_error)?;
        for row in logins {
            let id = row.0.clone();
            let snapshot = row.7.clone();
            let admission_key = serde_json::json!([row.1, row.2, row.4]).to_string();
            decode_login_row(Some(row))?;
            // Serialize deletion with quota clock sampling/counting for this
            // owner and purpose, not merely with other cleanup calls.
            if self.database_kind == SqlDatabaseKind::Postgres {
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                    .bind(admission_key)
                    .execute(&mut *tx)
                    .await
                    .map_err(storage_to_qid_error)?;
            }
            deleted += sqlx::query("DELETE FROM push_login_challenges WHERE id = $1 AND expires_at <= $2 AND expires_at < $3 AND record_json = $4")
                .bind(&id).bind(now as i64).bind(cutoff as i64).bind(snapshot)
                .execute(&mut *tx).await.map_err(storage_to_qid_error)?.rows_affected();
        }
        tx.commit().await.map_err(storage_to_qid_error)?;
        Ok(deleted)
    }
}

impl SqlRepository {
    pub(crate) async fn issue_push_registration(
        &self,
        challenge: &PushRegistrationChallenge,
        max_issuances: u32,
        window_seconds: u64,
        clock: state::AdmissionClock,
    ) -> QidResult<bool> {
        state::validate_registration(challenge)?;
        let a = &challenge.authenticator;
        let mut tx = self
            .pool
            .begin_with(match self.database_kind {
                SqlDatabaseKind::Sqlite => "BEGIN IMMEDIATE",
                SqlDatabaseKind::Postgres => "BEGIN ISOLATION LEVEL READ COMMITTED",
            })
            .await
            .map_err(storage_to_qid_error)?;
        if self.database_kind == SqlDatabaseKind::Postgres {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(
                    serde_json::json!([a.realm_id, a.user_id, state::PUSH_REGISTRATION_PURPOSE])
                        .to_string(),
                )
                .execute(&mut *tx)
                .await
                .map_err(storage_to_qid_error)?;
        }
        let duplicate: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM push_authenticators WHERE id = $1")
                .bind(&a.id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage_to_qid_error)?;
        if duplicate.is_some() {
            tx.rollback().await.map_err(storage_to_qid_error)?;
            return Err(state::conflict());
        }
        let owner: Option<String> =
            sqlx::query_scalar("SELECT id FROM users WHERE id = $1 AND realm_id = $2")
                .bind(&a.user_id)
                .bind(&a.realm_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage_to_qid_error)?;
        if owner.is_none() {
            tx.rollback().await.map_err(storage_to_qid_error)?;
            return Err(state::conflict());
        }
        let issued = clock.sample();
        let start = state::quota_window_start(
            challenge.authenticator.created_at,
            challenge.expires_at,
            issued,
            max_issuances,
            window_seconds,
        )?;
        let written = sqlx::query("INSERT INTO push_authenticators (id, realm_id, user_id, purpose, issued_at, pending_expires_at, record_json) SELECT $1, $2, $3, $4, $5, $9, $6 WHERE (SELECT COUNT(*) FROM push_authenticators WHERE realm_id = $2 AND user_id = $3 AND purpose = $4 AND issued_at >= $7) < $8")
            .bind(&a.id).bind(&a.realm_id).bind(&a.user_id).bind(state::PUSH_REGISTRATION_PURPOSE)
            .bind(issued as i64).bind(json(&PushAuthenticatorRecord::Pending(challenge.clone()))?)
            .bind(start as i64).bind(i64::from(max_issuances)).bind(challenge.expires_at as i64)
            .execute(&mut *tx).await.map_err(|err| {
                if err.as_database_error().is_some_and(|db| db.is_unique_violation()) {
                    state::conflict()
                } else {
                    storage_to_qid_error(err)
                }
            })?;
        tx.commit().await.map_err(storage_to_qid_error)?;
        Ok(written.rows_affected() == 1)
    }
    #[allow(clippy::too_many_arguments)] // Atomic admission inputs plus a test-only clock.
    pub(crate) async fn resend_push_login(
        &self,
        expected: &PushLoginChallenge,
        binding_verifier: &str,
        nonce_verifier: &str,
        max_issuances: u32,
        window_seconds: u64,
        cooldown: u64,
        clock: state::AdmissionClock,
    ) -> QidResult<Option<PushLoginChallenge>> {
        state::validate_login_record(expected)?;
        let mut tx = self
            .pool
            .begin_with(match self.database_kind {
                SqlDatabaseKind::Sqlite => "BEGIN IMMEDIATE",
                SqlDatabaseKind::Postgres => "BEGIN ISOLATION LEVEL READ COMMITTED",
            })
            .await
            .map_err(storage_to_qid_error)?;
        if self.database_kind == SqlDatabaseKind::Postgres {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(
                    serde_json::json!([
                        expected.realm_id,
                        expected.user_id,
                        state::login_purpose_str(expected.purpose)
                    ])
                    .to_string(),
                )
                .execute(&mut *tx)
                .await
                .map_err(storage_to_qid_error)?;
        }
        let Some(a) = lock_auth(
            &mut tx,
            &expected.realm_id,
            &expected.user_id,
            &expected.authenticator_id,
        )
        .await?
        else {
            return Ok(None);
        };
        if !state::current(&a, expected) {
            return Ok(None);
        }
        let Some(mut c) = lock_login(&mut tx, expected).await? else {
            return Ok(None);
        };
        let now = clock.sample();
        if now < c.created_at || now >= c.expires_at {
            return Ok(None);
        }
        let start = state::quota_window_start(
            c.created_at,
            c.expires_at,
            now,
            max_issuances,
            window_seconds,
        )?;
        if login_send_count(&mut tx, &c, start).await? >= u64::from(max_issuances) {
            return Ok(None);
        }
        let issued: i64 =
            sqlx::query_scalar("SELECT issued_at FROM push_login_challenges WHERE id = $1")
                .bind(&c.id)
                .fetch_one(&mut *tx)
                .await
                .map_err(storage_to_qid_error)?;
        if !state::resend(
            &mut c,
            expected,
            binding_verifier,
            nonce_verifier,
            issued as u64,
            cooldown,
            now,
        ) {
            return Ok(None);
        }
        state::validate_login_record(&c)?;
        save_login(&mut tx, &c).await?;
        tx.commit().await.map_err(storage_to_qid_error)?;
        Ok(Some(c))
    }
    pub(crate) async fn issue_push_login(
        &self,
        challenge: &PushLoginChallenge,
        max_issuances: u32,
        window_seconds: u64,
        clock: state::AdmissionClock,
    ) -> QidResult<bool> {
        state::validate_login(challenge)?;
        let purpose = state::login_purpose_str(challenge.purpose);
        let mut tx = self
            .pool
            .begin_with(match self.database_kind {
                SqlDatabaseKind::Sqlite => "BEGIN IMMEDIATE",
                SqlDatabaseKind::Postgres => "BEGIN ISOLATION LEVEL READ COMMITTED",
            })
            .await
            .map_err(storage_to_qid_error)?;
        if self.database_kind == SqlDatabaseKind::Postgres {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(
                    serde_json::json!([challenge.realm_id, challenge.user_id, purpose]).to_string(),
                )
                .execute(&mut *tx)
                .await
                .map_err(storage_to_qid_error)?;
        }
        let duplicate: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM push_login_challenges WHERE id = $1")
                .bind(&challenge.id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage_to_qid_error)?;
        if duplicate.is_some() {
            tx.rollback().await.map_err(storage_to_qid_error)?;
            return Err(state::conflict());
        }
        let current = lock_auth(
            &mut tx,
            &challenge.realm_id,
            &challenge.user_id,
            &challenge.authenticator_id,
        )
        .await?;
        if !current.is_some_and(|a| state::current(&a, challenge)) {
            tx.rollback().await.map_err(storage_to_qid_error)?;
            return Err(state::conflict());
        }
        let issued = clock.sample();
        let start = state::quota_window_start(
            challenge.created_at,
            challenge.expires_at,
            issued,
            max_issuances,
            window_seconds,
        )?;
        if login_send_count(&mut tx, challenge, start).await? >= u64::from(max_issuances) {
            return Ok(false);
        }
        let written = sqlx::query("INSERT INTO push_login_challenges (id, realm_id, user_id, authenticator_id, purpose, issued_at, expires_at, record_json) VALUES ($1, $2, $3, $4, $5, $6, $8, $7)")
            .bind(&challenge.id).bind(&challenge.realm_id).bind(&challenge.user_id).bind(&challenge.authenticator_id)
            .bind(purpose).bind(issued as i64).bind(json(challenge)?).bind(challenge.expires_at as i64)
            .execute(&mut *tx).await.map_err(|err| {
                if err.as_database_error().is_some_and(|db| db.is_unique_violation()) {
                    state::conflict()
                } else {
                    storage_to_qid_error(err)
                }
            })?;
        tx.commit().await.map_err(storage_to_qid_error)?;
        Ok(written.rows_affected() == 1)
    }
}
