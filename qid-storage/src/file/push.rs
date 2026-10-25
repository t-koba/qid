use super::*;
use crate::{PushRepository, push as state};
use async_trait::async_trait;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(super) struct PushStore {
    pub authenticators: HashMap<String, PushAuthenticatorRecord>,
    pub logins: HashMap<String, PushLoginChallenge>,
    /// Original registration issuance per authenticator ID, kept when proof
    /// replaces the pending row so quotas still count the first issuance.
    /// `try_issue_push_registration` writes it; activation and revocation preserve it; user/realm
    /// deletion and expiry cleanup remove it with its row.
    #[serde(default)]
    pub registration_issued_at: HashMap<String, u64>,
    #[serde(default)]
    pub login_issued_at: HashMap<String, u64>,
}

/// Issuance is sampled under the admission lock, not taken from challenge creation.
fn registration_issued(store: &Store, id: &str, row: &PushAuthenticatorRecord) -> QidResult<u64> {
    let issued = store
        .push
        .registration_issued_at
        .get(id)
        .copied()
        .ok_or_else(state::corrupt)?;
    let valid = match row {
        PushAuthenticatorRecord::Pending(c) => {
            c.authenticator.created_at <= issued && issued < c.expires_at
        }
        PushAuthenticatorRecord::Enrolled(a) => issued != 0 && issued <= a.created_at,
    };
    if !valid {
        return Err(state::corrupt());
    }
    Ok(issued)
}
fn login_issued(store: &Store, id: &str, c: &PushLoginChallenge) -> QidResult<u64> {
    let issued = store
        .push
        .login_issued_at
        .get(id)
        .copied()
        .ok_or_else(state::corrupt)?;
    state::validate_login_issued(c, issued)?;
    Ok(issued)
}

/// Keep only the smallest `limit` keys. O(N log limit) time, O(limit) memory;
/// references avoid even cloning IDs for the unselected backlog.
fn select_oldest<'a>(
    candidates: impl Iterator<Item = (u64, &'a str)>,
    limit: usize,
) -> Vec<String> {
    let mut selected = std::collections::BinaryHeap::with_capacity(limit);
    for key in candidates {
        if selected.len() < limit {
            selected.push(key);
        } else if selected.peek().is_some_and(|largest| key < *largest) {
            selected.pop();
            selected.push(key);
        }
    }
    selected
        .into_sorted_vec()
        .into_iter()
        .map(|(_, id)| id.to_owned())
        .collect()
}

impl FileRepository {
    // Push transitions are written synchronously even in interval-flush mode.
    // The shared writer fsyncs the temp file and atomically renames it; directory
    // entry power-loss durability remains best-effort on supported platforms.
    // Keep the write lock through persistence/rollback; spawning shields cancellation.
    async fn mutate_push<F>(&self, f: F) -> QidResult<bool>
    where
        F: FnOnce(&mut Store) -> QidResult<bool> + Send + 'static,
    {
        self.mutate_push_value(move |s| f(s).map(|changed| (changed, changed)))
            .await
    }
    async fn mutate_push_value<F, T>(&self, f: F) -> QidResult<T>
    where
        F: FnOnce(&mut Store) -> QidResult<(bool, T)> + Send + 'static,
        T: Send + 'static,
    {
        let repo = self.clone();
        tokio::spawn(async move {
            let save_guard = repo.save_lock.lock().await;
            let mut store = repo.store.write().await;
            let before = store.push.clone();
            let (changed, value) = match f(&mut store) {
                Ok(changed) => changed,
                Err(error) => {
                    store.push = before;
                    return Err(error);
                }
            };
            if !changed {
                return Ok(value);
            }
            let result = async {
                let content = serde_json::to_string(&*store).map_err(|_| QidError::Internal {
                    message: "push store serialization failed".into(),
                })?;
                repo.write_store_content_locked(&save_guard, &content).await
            }
            .await;
            if let Err(e) = result {
                store.push = before;
                return Err(e);
            }
            Ok(value)
        })
        .await
        .map_err(|_| QidError::Internal {
            message: "push storage task failed".into(),
        })?
    }
}

#[async_trait]
impl PushRepository for FileRepository {
    async fn get_push_registration(
        &self,
        realm: &RealmId,
        user: &str,
        id: &str,
    ) -> QidResult<Option<PushRegistrationChallenge>> {
        let store = self.store.read().await;
        let Some(c) = store.push.authenticators.get(id) else {
            return Ok(None);
        };
        let a = state::authenticator_record(c, id)?;
        if a.realm_id != realm.0 || a.user_id != user {
            return Ok(None);
        }
        Ok(match c {
            PushAuthenticatorRecord::Pending(c) => Some(c.clone()),
            PushAuthenticatorRecord::Enrolled(_) => None,
        })
    }
    async fn attempt_push_registration(
        &self,
        expected: &PushRegistrationChallenge,
        verified: bool,
        now: u64,
    ) -> QidResult<bool> {
        let expected = expected.clone();
        self.mutate_push(move |s| {
            let a = &expected.authenticator;
            if s.users
                .get(&a.user_id)
                .is_none_or(|u| u.realm_id != a.realm_id)
            {
                return Ok(false);
            }
            state::validate_registration_record(&expected)?;
            let Some(c) = s.push.authenticators.get(&a.id) else {
                return Ok(false);
            };
            state::authenticator_record(c, &a.id)?;
            if now < registration_issued(s, &a.id, c)? {
                return Ok(false);
            }
            let c = s
                .push
                .authenticators
                .get_mut(&a.id)
                .ok_or_else(state::corrupt)?;
            if !state::registration_attempt(c, &expected, verified, now) {
                return Ok(false);
            }
            state::authenticator_record(c, &a.id)?;
            Ok(true)
        })
        .await
    }
    async fn get_push_authenticator(
        &self,
        realm: &RealmId,
        user: &str,
        id: &str,
    ) -> QidResult<Option<PushAuthenticator>> {
        let store = self.store.read().await;
        let Some(a) = store.push.authenticators.get(id) else {
            return Ok(None);
        };
        let Some(a) = state::enrolled(a, id)? else {
            return Ok(None);
        };
        if a.realm_id != realm.0 || a.user_id != user {
            return Ok(None);
        }
        Ok(Some(a.clone()))
    }
    async fn list_push_authenticators(
        &self,
        realm: &RealmId,
        user: &str,
    ) -> QidResult<Vec<PushAuthenticator>> {
        let store = self.store.read().await;
        let mut rows = Vec::new();
        for (id, a) in &store.push.authenticators {
            let Some(a) = state::enrolled(a, id)? else {
                continue;
            };
            if a.realm_id == realm.0 && a.user_id == user {
                rows.push(a.clone());
            }
        }
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(rows)
    }
    async fn revoke_push_authenticator(
        &self,
        realm: &RealmId,
        user: &str,
        id: &str,
        now: u64,
    ) -> QidResult<bool> {
        let (realm, user, id) = (realm.clone(), user.to_owned(), id.to_owned());
        self.mutate_push(move |s| {
            let Some(a) = s.push.authenticators.get_mut(&id) else {
                return Ok(false);
            };
            state::authenticator_record(a, &id)?;
            let PushAuthenticatorRecord::Enrolled(a) = a else {
                return Ok(false);
            };
            if a.realm_id != realm.0
                || a.user_id != user
                || a.revoked_at.is_some()
                || now < a.created_at
            {
                return Ok(false);
            }
            a.revoked_at = Some(now);
            state::validate_authenticator_record(a)?;
            Ok(true)
        })
        .await
    }
    async fn get_push_login(
        &self,
        realm: &RealmId,
        user: &str,
        id: &str,
    ) -> QidResult<Option<PushLoginChallenge>> {
        let store = self.store.read().await;
        let Some(c) = store.push.logins.get(id) else {
            return Ok(None);
        };
        state::validate_login_record(c)?;
        if c.id != id {
            return Err(state::corrupt());
        }
        login_issued(&store, id, c)?;
        if c.realm_id != realm.0 || c.user_id != user {
            return Ok(None);
        }
        Ok(Some(c.clone()))
    }
    async fn attempt_push_login(
        &self,
        expected: &PushLoginChallenge,
        decision: Option<PushDecision>,
        now: u64,
    ) -> QidResult<bool> {
        let expected = expected.clone();
        self.mutate_push(move |s| {
            state::validate_login_record(&expected)?;
            let Some(a) = s.push.authenticators.get(&expected.authenticator_id) else {
                return Ok(false);
            };
            let Some(a) = state::enrolled(a, &expected.authenticator_id)? else {
                return Ok(false);
            };
            if !state::current(a, &expected) {
                return Ok(false);
            }
            let Some(row) = s.push.logins.get(&expected.id) else {
                return Ok(false);
            };
            login_issued(s, &expected.id, row)?;
            let Some(c) = s.push.logins.get_mut(&expected.id) else {
                return Ok(false);
            };
            state::validate_login_record(c)?;
            if c.id != expected.id {
                return Err(state::corrupt());
            }
            let accepted = state::login_attempt(c, &expected, decision, now);
            if accepted {
                state::validate_login_record(c)?;
            }
            Ok(accepted)
        })
        .await
    }
    async fn redeem_push_login(
        &self,
        expected: &PushLoginChallenge,
        binding_verifier: &str,
        now: u64,
    ) -> QidResult<bool> {
        let (expected, binding) = (expected.clone(), binding_verifier.to_owned());
        self.mutate_push(move |s| {
            state::validate_login_record(&expected)?;
            if binding.len() != 64
                || !binding
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Ok(false);
            }
            let Some(a) = s.push.authenticators.get(&expected.authenticator_id) else {
                return Ok(false);
            };
            let Some(a) = state::enrolled(a, &expected.authenticator_id)? else {
                return Ok(false);
            };
            if !state::current(a, &expected) {
                return Ok(false);
            }
            let Some(row) = s.push.logins.get(&expected.id) else {
                return Ok(false);
            };
            login_issued(s, &expected.id, row)?;
            let Some(c) = s.push.logins.get_mut(&expected.id) else {
                return Ok(false);
            };
            state::validate_login_record(c)?;
            if c.id != expected.id {
                return Err(state::corrupt());
            }
            let accepted = state::redeem(c, &expected, &binding, now);
            if accepted {
                state::validate_login_record(c)?;
            }
            Ok(accepted)
        })
        .await
    }
    // Quota admission and expiry cleanup. Counts and deletes hold the same exclusive
    // store lock as the lifecycle transitions, so admission and cleanup serialize
    // with activation, decisions, redemption and revocation.
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
        let repo = self.clone();
        tokio::spawn(async move {
            let save_guard = repo.save_lock.lock().await;
            let mut store = repo.store.write().await;
            // Validate before deleting anything; rollback then needs only the
            // removed rows, never a clone of the full backlog.
            for (id, row) in &store.push.authenticators {
                state::authenticator_record(row, id)?;
                registration_issued(&store, id, row)?;
            }
            for (id, c) in &store.push.logins {
                state::validate_login_record(c)?;
                if c.id != *id {
                    return Err(state::corrupt());
                }
                login_issued(&store, id, c)?;
            }
            let regs = select_oldest(
                store.push.authenticators.iter().filter_map(|(id, row)| {
                    if let PushAuthenticatorRecord::Pending(c) = row {
                        let issued = store.push.registration_issued_at[id];
                        if c.expires_at <= now && issued < cutoff {
                            return Some((issued, id.as_str()));
                        }
                    }
                    None
                }),
                limit as usize,
            );
            let remaining = limit as usize - regs.len();
            let logins = if remaining == 0 {
                Vec::new()
            } else {
                select_oldest(
                    store.push.logins.iter().filter_map(|(id, c)| {
                        let issued = store.push.login_issued_at[id];
                        (c.expires_at < cutoff).then_some((issued, id.as_str()))
                    }),
                    remaining,
                )
            };
            let deleted = (regs.len() + logins.len()) as u64;
            if deleted == 0 {
                return Ok(0);
            }
            let mut removed_regs = Vec::with_capacity(regs.len());
            let mut removed_logins = Vec::with_capacity(logins.len());
            for id in regs {
                let row = store.push.authenticators.remove(&id).expect("selected row");
                let issued = store
                    .push
                    .registration_issued_at
                    .remove(&id)
                    .expect("validated metadata");
                removed_regs.push((id, row, issued));
            }
            for id in logins {
                let row = store.push.logins.remove(&id).expect("selected row");
                let issued = store
                    .push
                    .login_issued_at
                    .remove(&id)
                    .expect("validated metadata");
                removed_logins.push((id, row, issued));
            }
            let result = async {
                let content = serde_json::to_string(&*store).map_err(|_| QidError::Internal {
                    message: "push store serialization failed".into(),
                })?;
                repo.write_store_content_locked(&save_guard, &content).await
            }
            .await;
            if let Err(e) = result {
                for (id, row, issued) in removed_regs {
                    store.push.registration_issued_at.insert(id.clone(), issued);
                    store.push.authenticators.insert(id, row);
                }
                for (id, row, issued) in removed_logins {
                    store.push.login_issued_at.insert(id.clone(), issued);
                    store.push.logins.insert(id, row);
                }
                return Err(e);
            }
            Ok(deleted)
        })
        .await
        .map_err(|_| QidError::Internal {
            message: "push storage task failed".into(),
        })?
    }
}

impl FileRepository {
    pub(crate) async fn issue_push_registration(
        &self,
        challenge: &PushRegistrationChallenge,
        max_issuances: u32,
        window_seconds: u64,
        clock: state::AdmissionClock,
    ) -> QidResult<bool> {
        state::validate_registration(challenge)?;
        let c = challenge.clone();
        self.mutate_push(move |s| {
            let issued = clock.sample();
            let start = state::quota_window_start(
                c.authenticator.created_at,
                c.expires_at,
                issued,
                max_issuances,
                window_seconds,
            )?;
            let a = &c.authenticator;
            if s.users
                .get(&a.user_id)
                .is_none_or(|u| u.realm_id != a.realm_id)
            {
                return Err(state::conflict());
            }
            if s.push.authenticators.contains_key(&a.id) {
                return Err(state::conflict());
            }
            let mut count = 0u128;
            for (id, row) in &s.push.authenticators {
                state::authenticator_record(row, id)?;
                let r = row.authenticator();
                if r.realm_id == a.realm_id
                    && r.user_id == a.user_id
                    && registration_issued(s, id, row)? >= start
                {
                    count += 1;
                }
            }
            if count >= u128::from(max_issuances) {
                return Ok(false);
            }
            let id = a.id.clone();
            s.push
                .authenticators
                .insert(id.clone(), PushAuthenticatorRecord::Pending(c));
            s.push.registration_issued_at.insert(id, issued);
            Ok(true)
        })
        .await
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
        let expected = expected.clone();
        let nonce = nonce_verifier.to_string();
        let binding = binding_verifier.to_string();
        self.mutate_push_value(move |s| {
            let now = clock.sample();
            // Expired/refused resends are not malformed initial issuances.
            if now < expected.created_at || now >= expected.expires_at {
                return Ok((false, None));
            }
            let start = state::quota_window_start(
                expected.created_at,
                expected.expires_at,
                now,
                max_issuances,
                window_seconds,
            )?;
            let Some(a) = s.push.authenticators.get(&expected.authenticator_id) else {
                return Ok((false, None));
            };
            let Some(a) = state::enrolled(a, &expected.authenticator_id)? else {
                return Ok((false, None));
            };
            if !state::current(a, &expected) {
                return Ok((false, None));
            }
            let mut count = 0u64;
            for (id, row) in &s.push.logins {
                state::validate_login_record(row)?;
                if row.id != *id {
                    return Err(state::corrupt());
                }
                if row.realm_id == expected.realm_id
                    && row.user_id == expected.user_id
                    && row.purpose == expected.purpose
                {
                    count += state::send_count(row, login_issued(s, id, row)?, start)?;
                }
            }
            if count >= u64::from(max_issuances) {
                return Ok((false, None));
            }
            let Some(c) = s.push.logins.get(&expected.id) else {
                return Ok((false, None));
            };
            let issued = login_issued(s, &expected.id, c)?;
            let c = s.push.logins.get_mut(&expected.id).expect("checked row");
            if !state::resend(c, &expected, &binding, &nonce, issued, cooldown, now) {
                return Ok((false, None));
            }
            state::validate_login_record(c)?;
            Ok((true, Some(c.clone())))
        })
        .await
    }
    pub(crate) async fn issue_push_login(
        &self,
        challenge: &PushLoginChallenge,
        max_issuances: u32,
        window_seconds: u64,
        clock: state::AdmissionClock,
    ) -> QidResult<bool> {
        state::validate_login(challenge)?;
        let c = challenge.clone();
        self.mutate_push(move |s| {
            let issued = clock.sample();
            let start = state::quota_window_start(
                c.created_at,
                c.expires_at,
                issued,
                max_issuances,
                window_seconds,
            )?;
            if s.push.logins.contains_key(&c.id) {
                return Err(state::conflict());
            }
            let Some(a) = s.push.authenticators.get(&c.authenticator_id) else {
                return Err(state::conflict());
            };
            let Some(a) = state::enrolled(a, &c.authenticator_id)? else {
                return Err(state::conflict());
            };
            if !state::current(a, &c) {
                return Err(state::conflict());
            }
            let purpose = state::login_purpose_str(c.purpose);
            let mut count = 0u128;
            for (id, row) in &s.push.logins {
                state::validate_login_record(row)?;
                if row.id != *id {
                    return Err(state::corrupt());
                }
                if row.realm_id == c.realm_id
                    && row.user_id == c.user_id
                    && state::login_purpose_str(row.purpose) == purpose
                {
                    count += u128::from(state::send_count(row, login_issued(s, id, row)?, start)?);
                }
            }
            if count >= u128::from(max_issuances) {
                return Ok(false);
            }
            s.push.login_issued_at.insert(c.id.clone(), issued);
            s.push.logins.insert(c.id.clone(), c);
            Ok(true)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::select_oldest;

    #[test]
    fn cleanup_selection_is_bounded_and_deterministic() {
        let candidates = [(3, "c"), (1, "b"), (1, "a"), (2, "d")];
        for limit in 1..=4 {
            let expected: Vec<_> = ["a", "b", "d", "c"][..limit].to_vec();
            assert_eq!(select_oldest(candidates.into_iter(), limit), expected);
            assert_eq!(select_oldest(candidates.into_iter().rev(), limit), expected);
        }
    }
}
