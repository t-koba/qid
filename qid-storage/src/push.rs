//! Push state transitions shared by the file and SQL implementations.
use qid_core::{
    error::{QidError, QidResult},
    models::*,
    util::constant_time_eq,
};

pub(super) fn conflict() -> QidError {
    QidError::Conflict {
        message: "push record unavailable or ID already used".into(),
    }
}
fn bad() -> QidError {
    QidError::BadRequest {
        message: "invalid initial push record".into(),
    }
}
pub(super) fn corrupt() -> QidError {
    QidError::Internal {
        message: "corrupt push storage record".into(),
    }
}
fn nonempty(s: &str) -> bool {
    !s.trim().is_empty()
}
fn verifier(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn key_valid(k: &PushPublicJwk) -> bool {
    match k {
        PushPublicJwk::EC { crv, x, y } => [crv, x, y].into_iter().all(|s| nonempty(s)),
        PushPublicJwk::OKP { crv, x } => [crv, x].into_iter().all(|s| nonempty(s)),
        PushPublicJwk::RSA { n, e } => [n, e].into_iter().all(|s| nonempty(s)),
    }
}
fn authenticator_fields_valid(a: &PushAuthenticator) -> bool {
    [&a.id, &a.realm_id, &a.user_id, &a.destination]
        .into_iter()
        .all(|s| nonempty(s))
        && valid_push_device_metadata(&a.device_name)
        && valid_push_device_metadata(&a.device_platform)
        && key_valid(&a.public_jwk)
        && a.created_at != 0
        && i64::try_from(a.created_at).is_ok()
}
fn registration_fields_valid(c: &PushRegistrationChallenge) -> bool {
    authenticator_fields_valid(&c.authenticator)
        && c.authenticator.revoked_at.is_none()
        && verifier(&c.nonce_verifier)
        && c.expires_at > c.authenticator.created_at
        && i64::try_from(c.expires_at).is_ok()
        && c.max_attempts != 0
}
fn login_fields_valid(c: &PushLoginChallenge) -> bool {
    [&c.id, &c.realm_id, &c.user_id, &c.authenticator_id]
        .into_iter()
        .all(|s| nonempty(s))
        && verifier(&c.nonce_verifier)
        && verifier(&c.browser_binding_verifier)
        && c.created_at != 0
        && i64::try_from(c.created_at).is_ok()
        && c.expires_at > c.created_at
        && c.expires_at - c.created_at <= 600
        && c.resend_admitted_at.len() <= 600
        && c.resend_admitted_at
            .iter()
            .all(|&at| at >= c.created_at && at < c.expires_at && i64::try_from(at).is_ok())
        && c.resend_admitted_at
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        && c.decided_at
            .is_none_or(|at| c.resend_admitted_at.last().is_none_or(|last| *last <= at))
        && i64::try_from(c.expires_at).is_ok()
        && c.max_attempts != 0
}
pub(super) fn validate_registration(c: &PushRegistrationChallenge) -> QidResult<()> {
    if !registration_fields_valid(c) || c.attempt_count != 0 {
        return Err(bad());
    }
    Ok(())
}
pub(super) fn validate_login(c: &PushLoginChallenge) -> QidResult<()> {
    if !login_fields_valid(c)
        || c.attempt_count != 0
        || !c.resend_admitted_at.is_empty()
        || c.decision.is_some()
        || c.decided_at.is_some()
        || c.consumed_at.is_some()
    {
        return Err(bad());
    }
    Ok(())
}

/// Validate a persisted authenticator independently of how it was created.
pub(super) fn validate_authenticator_record(a: &PushAuthenticator) -> QidResult<()> {
    if !authenticator_fields_valid(a) || a.revoked_at.is_some_and(|at| at < a.created_at) {
        return Err(corrupt());
    }
    Ok(())
}

/// Validate the bounded attempt state of a pending registration row.
pub(super) fn validate_registration_record(c: &PushRegistrationChallenge) -> QidResult<()> {
    if !registration_fields_valid(c) || c.attempt_count > c.max_attempts {
        return Err(corrupt());
    }
    Ok(())
}

/// Validate persisted state before it can be read or used to authorize a login.
pub(super) fn validate_login_record(c: &PushLoginChallenge) -> QidResult<()> {
    if !login_fields_valid(c)
        || c.attempt_count > c.max_attempts
        || match (c.decision, c.decided_at, c.consumed_at) {
            (None, None, None) => false,
            (Some(_), Some(decided_at), consumed_at) => {
                decided_at < c.created_at
                    || decided_at >= c.expires_at
                    || c.attempt_count == 0
                    || consumed_at.is_some_and(|consumed_at| {
                        c.decision != Some(PushDecision::Approve)
                            || consumed_at < decided_at
                            || consumed_at >= c.expires_at
                    })
            }
            _ => true,
        }
    {
        return Err(corrupt());
    }
    Ok(())
}

pub(super) fn current(a: &PushAuthenticator, c: &PushLoginChallenge) -> bool {
    a.id == c.authenticator_id
        && a.realm_id == c.realm_id
        && a.user_id == c.user_id
        && c.created_at >= a.created_at
        && a.revoked_at.is_none()
}
fn live(created: u64, expires: u64, now: u64) -> bool {
    now >= created && now < expires
}
/// Validate both lifecycle variants, including map/SQL identity, before projection.
pub(super) fn authenticator_record<'a>(
    row: &'a PushAuthenticatorRecord,
    id: &str,
) -> QidResult<&'a PushAuthenticator> {
    match row {
        PushAuthenticatorRecord::Pending(c) => validate_registration_record(c)?,
        PushAuthenticatorRecord::Enrolled(a) => validate_authenticator_record(a)?,
    }
    let a = row.authenticator();
    if a.id != id {
        return Err(corrupt());
    }
    Ok(a)
}
pub(super) fn enrolled<'a>(
    row: &'a PushAuthenticatorRecord,
    id: &str,
) -> QidResult<Option<&'a PushAuthenticator>> {
    authenticator_record(row, id)?;
    Ok(match row {
        PushAuthenticatorRecord::Enrolled(a) => Some(a),
        PushAuthenticatorRecord::Pending(_) => None,
    })
}
pub(super) fn registration_attempt(
    row: &mut PushAuthenticatorRecord,
    expected: &PushRegistrationChallenge,
    verified: bool,
    now: u64,
) -> bool {
    let PushAuthenticatorRecord::Pending(c) = row else {
        return false;
    };
    // Ignore only the mutable state: concurrent bad signatures must each count.
    if c.authenticator != expected.authenticator
        || c.nonce_verifier != expected.nonce_verifier
        || c.expires_at != expected.expires_at
        || c.max_attempts != expected.max_attempts
        || !live(c.authenticator.created_at, c.expires_at, now)
        || c.attempt_count >= c.max_attempts
    {
        return false;
    }
    c.attempt_count += 1;
    if verified {
        let mut active = c.authenticator.clone();
        active.created_at = now;
        *row = PushAuthenticatorRecord::Enrolled(active);
    }
    true
}
fn same_login(c: &PushLoginChallenge, expected: &PushLoginChallenge) -> bool {
    let mut binding = c.clone();
    binding.attempt_count = expected.attempt_count;
    binding.decision = expected.decision;
    binding.decided_at = expected.decided_at;
    binding.consumed_at = expected.consumed_at;
    binding == *expected
}
pub(super) fn login_attempt(
    c: &mut PushLoginChallenge,
    expected: &PushLoginChallenge,
    decision: Option<PushDecision>,
    now: u64,
) -> bool {
    if !same_login(c, expected)
        || !live(c.created_at, c.expires_at, now)
        || c.decision.is_some()
        || c.consumed_at.is_some()
        || c.attempt_count >= c.max_attempts
    {
        return false;
    }
    c.attempt_count += 1;
    if let Some(d) = decision {
        c.decision = Some(d);
        c.decided_at = Some(now);
    }
    true
}
pub(super) fn redeem(
    c: &mut PushLoginChallenge,
    expected: &PushLoginChallenge,
    binding_verifier: &str,
    now: u64,
) -> bool {
    if !verifier(binding_verifier)
        || !same_login(c, expected)
        || !live(c.created_at, c.expires_at, now)
        || c.decision != Some(PushDecision::Approve)
        || c.consumed_at.is_some()
        || c.decided_at.is_none_or(|at| at > now)
        || !constant_time_eq(
            c.browser_binding_verifier.as_bytes(),
            binding_verifier.as_bytes(),
        )
    {
        return false;
    }
    c.consumed_at = Some(now);
    true
}

/// Maximum rolling-window and retention horizon for push issuance, in seconds.
/// Quota windows must lie within this bound, and expiry cleanup only deletes
/// records strictly older than it, so cleanup can never remove a row that any
/// admissible quota window still counts.
pub(super) const MAX_PUSH_WINDOW_SECONDS: u64 = 86_400;

/// Quota purpose stored for registration/authenticator rows. Logins store the
/// [`PushPurpose`] string instead, so the two issuance budgets never share a key.
pub(super) const PUSH_REGISTRATION_PURPOSE: &str = "registration";

pub(super) fn login_purpose_str(purpose: PushPurpose) -> &'static str {
    match purpose {
        PushPurpose::PasswordLogin => "password_login",
    }
}

/// Shared bounds for quota admission: `max_issuances` must be positive,
/// `window_seconds` must fit the retention horizon, and the challenge's
/// lifecycle must be current at trusted admission time; all timestamps must fit
/// signed storage (fail closed). Returns the inclusive window start based only
/// on admission time, never challenge creation.
pub(super) fn quota_window_start(
    created_at: u64,
    expires_at: u64,
    admitted_at: u64,
    max_issuances: u32,
    window_seconds: u64,
) -> QidResult<u64> {
    if max_issuances == 0
        || !(1..=MAX_PUSH_WINDOW_SECONDS).contains(&window_seconds)
        || !live(created_at, expires_at, admitted_at)
        || i64::try_from(admitted_at).is_err()
        || i64::try_from(created_at).is_err()
        || i64::try_from(expires_at).is_err()
    {
        return Err(QidError::BadRequest {
            message: "invalid push issuance budget or timestamp".into(),
        });
    }
    Ok(admitted_at.saturating_sub(window_seconds - 1))
}

/// Shared bounds for expiry cleanup: `now` must fit signed storage and `limit`
/// must lie in 1..=1000 (the hard per-call deletion bound). Returns the retention cutoff:
/// registrations require original issuance before it; logins require immutable
/// expiry strictly before it to retain all possible resend evidence.
pub(super) fn cleanup_cutoff(now: u64, limit: u32) -> QidResult<u64> {
    if !(1..=1000).contains(&limit) || i64::try_from(now).is_err() {
        return Err(QidError::BadRequest {
            message: "invalid push cleanup bound".into(),
        });
    }
    Ok(now.saturating_sub(MAX_PUSH_WINDOW_SECONDS))
}

/// Production has no clock override. Unit fixtures can choose a per-call instant;
/// there is no shared mutable clock and sampling happens inside the admission lock.
#[derive(Default)]
pub(crate) struct AdmissionClock {
    #[cfg(test)]
    at: Option<u64>,
}
impl AdmissionClock {
    pub(crate) fn sample(self) -> u64 {
        #[cfg(test)]
        if let Some(at) = self.at {
            return at;
        }
        qid_core::util::now_seconds()
    }
    #[cfg(test)]
    pub(crate) fn at(at: u64) -> Self {
        Self { at: Some(at) }
    }
}

/// Validate immutable admission metadata against the durable resend history.
pub(super) fn validate_login_issued(c: &PushLoginChallenge, issued: u64) -> QidResult<()> {
    if issued < c.created_at
        || issued >= c.expires_at
        || c.resend_admitted_at.first().is_some_and(|at| *at <= issued)
    {
        return Err(corrupt());
    }
    Ok(())
}
pub(super) fn send_count(c: &PushLoginChallenge, issued: u64, start: u64) -> QidResult<u64> {
    validate_login_record(c)?;
    validate_login_issued(c, issued)?;
    Ok(u64::from(issued >= start)
        + c.resend_admitted_at
            .iter()
            .filter(|&&at| at >= start)
            .count() as u64)
}
/// Ignore mutable attempt state in the CAS, but never overwrite it.
pub(super) fn resend(
    c: &mut PushLoginChallenge,
    expected: &PushLoginChallenge,
    binding_verifier: &str,
    nonce_verifier: &str,
    issued: u64,
    cooldown: u64,
    now: u64,
) -> bool {
    if cooldown == 0
        || !verifier(binding_verifier)
        || !constant_time_eq(
            c.browser_binding_verifier.as_bytes(),
            binding_verifier.as_bytes(),
        )
        || !verifier(nonce_verifier)
        || nonce_verifier == c.nonce_verifier
        || !same_login(c, expected)
        || !live(c.created_at, c.expires_at, now)
        || c.decision.is_some()
        || c.consumed_at.is_some()
        || c.attempt_count >= c.max_attempts
        || now.saturating_sub(*c.resend_admitted_at.last().unwrap_or(&issued)) < cooldown
    {
        return false;
    }
    c.nonce_verifier = nonce_verifier.into();
    c.resend_admitted_at.push(now);
    true
}
