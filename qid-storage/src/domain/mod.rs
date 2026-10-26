use qid_core::{
    QidError, QidResult,
    models::{AuthorizationCode, CiamConsentGrant, CiamIdentityLink, Session, TokenFamily},
};

/// Validate that a session can be revoked (not already revoked).
pub fn validate_session_revocation(session: &Session) -> QidResult<()> {
    if session.revoked {
        return Err(QidError::BadRequest {
            message: format!("session {} is already revoked", session.id),
        });
    }
    Ok(())
}

/// Validate that a session can be created (no duplicate id).
pub fn validate_session_creation(existing: Option<&Session>) -> QidResult<()> {
    if let Some(s) = existing {
        return Err(QidError::BadRequest {
            message: format!("session {} already exists", s.id),
        });
    }
    Ok(())
}

/// Validate an atomic token family rotation:
/// - Family must not be revoked
/// - Presented expected hash must still match current (single consumption)
/// - New hash must differ from current (reuse/replay detection)
pub fn validate_token_family_rotation(
    family: &TokenFamily,
    expected_refresh_hash: &str,
    new_refresh_hash: &str,
) -> QidResult<()> {
    if family.revoked {
        return Err(QidError::Conflict {
            message: format!("token family {} is revoked", family.id),
        });
    }
    if family.current_refresh_hash != expected_refresh_hash {
        return Err(QidError::Conflict {
            message: format!("token family {} refresh token already consumed", family.id),
        });
    }
    if new_refresh_hash == expected_refresh_hash || family.current_refresh_hash == new_refresh_hash
    {
        return Err(QidError::Conflict {
            message: format!("token family {} refresh hash reuse detected", family.id),
        });
    }
    Ok(())
}

/// Validate that an authorization code has not already been used (reuse detection).
pub fn validate_authz_code_reuse(code: &AuthorizationCode) -> QidResult<()> {
    if code.used {
        return Err(QidError::BadRequest {
            message: format!("authorization code {} already used", code.code_hash),
        });
    }
    Ok(())
}

/// Validate consent grant state validity (must not be revoked when storing).
pub fn validate_ciam_consent_grant_state(grant: &CiamConsentGrant) -> QidResult<()> {
    if grant.revoked {
        return Err(QidError::BadRequest {
            message: format!("consent grant {} is already revoked", grant.id),
        });
    }
    Ok(())
}

/// Validate identity link state transitions.
///
/// Existing IDs retain their owner and identity key, and cannot revert to unverified.
pub fn validate_ciam_identity_link_state(
    link: &CiamIdentityLink,
    existing: Option<&CiamIdentityLink>,
) -> QidResult<()> {
    if let Some(ex) = existing
        && (ex.realm_id != link.realm_id
            || ex.user_id != link.user_id
            || ex.provider != link.provider
            || ex.external_subject != link.external_subject)
    {
        return Err(QidError::Conflict {
            message: format!(
                "CIAM identity link {} has another owner or identity key",
                link.id
            ),
        });
    }
    if let Some(ex) = existing
        && ex.verified
        && !link.verified
    {
        return Err(QidError::BadRequest {
            message: format!(
                "identity link {} cannot be reverted from verified to unverified",
                link.id
            ),
        });
    }
    Ok(())
}

/// Storage-side reset validation; no caller's earlier token read is authoritative.
pub(crate) fn validate_password_reset(
    token: &qid_core::models::PasswordResetToken,
    realm_id: &qid_core::tenant::RealmId,
    token_hash: &str,
    device_id: Option<&str>,
    credential: &qid_core::models::PasswordCredential,
    now: u64,
) -> QidResult<()> {
    if token.realm_id != realm_id.as_str() || token.user_id != credential.user_id {
        return Err(QidError::BadRequest {
            message: "owner_mismatch".into(),
        });
    }
    if token.consumed_at_epoch_seconds.is_some() {
        return Err(QidError::Conflict {
            message: "password reset token already consumed".into(),
        });
    }
    let message = if now > token.expires_at_epoch_seconds {
        Some("expired")
    } else if token.device_id.as_deref() != device_id {
        Some("device_mismatch")
    } else if !qid_core::util::constant_time_eq(token_hash, &token.token_hash) {
        Some("token_mismatch")
    } else {
        None
    };
    match message {
        Some(message) => Err(QidError::BadRequest {
            message: message.into(),
        }),
        None => Ok(()),
    }
}

/// Shared bounds keep file and SQL accounting identical, without integer wrapping.
pub(crate) fn password_reset_window_start(
    token: &qid_core::models::PasswordResetToken,
    max_issuances: u32,
    window_seconds: u64,
) -> QidResult<u64> {
    token.validate()?;
    if max_issuances == 0
        || !(1..=86400).contains(&window_seconds)
        || [
            Some(token.created_at_epoch_seconds),
            Some(token.expires_at_epoch_seconds),
            token.consumed_at_epoch_seconds,
        ]
        .into_iter()
        .flatten()
        .any(|value| i64::try_from(value).is_err())
    {
        return Err(QidError::BadRequest {
            message: "invalid password reset issuance budget or timestamp".into(),
        });
    }
    Ok(token
        .created_at_epoch_seconds
        .saturating_sub(window_seconds - 1))
}

/// Shared rolling-window admission for both email challenge kinds (same bounds
/// as password resets); only `email_magic_link` carries the digest-pair proof.
pub(crate) fn email_challenge_window_start(
    challenge: &qid_core::models::CiamVerificationChallengeRecord,
    max_issuances: u32,
    window_seconds: u64,
) -> QidResult<u64> {
    challenge.validate()?;
    let magic_link = challenge.purpose == "email_magic_link";
    if challenge.channel != "email"
        || (!magic_link && challenge.purpose != "email_verification")
        || (magic_link != email_magic_link_proof(&challenge.code_hash).is_some())
        || challenge.attempt_count != 0
        || challenge.consumed_at_epoch_seconds.is_some()
        || max_issuances == 0
        || !(1..=86400).contains(&window_seconds)
        || i64::try_from(challenge.created_at_epoch_seconds).is_err()
        || i64::try_from(challenge.expires_at_epoch_seconds).is_err()
    {
        return Err(QidError::BadRequest {
            message: "invalid email challenge, issuance budget or timestamp".into(),
        });
    }
    Ok(challenge
        .created_at_epoch_seconds
        .saturating_sub(window_seconds - 1))
}

/// Strict versioned magic-link proof encoding, held in the existing code_hash column.
/// Old combined digests and malformed proofs fail closed without spending attempts.
fn email_magic_link_proof(value: &str) -> Option<(&str, &str)> {
    let (binding, token) = value.strip_prefix("ml2:")?.split_once(':')?;
    let digest = |v: &str| {
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    (digest(binding) && digest(token)).then_some((binding, token))
}

/// None means no binding authority (no attempt); Some is the token comparison.
pub(crate) fn email_magic_link_token_matches(stored: &str, candidate: &str) -> Option<bool> {
    let (binding, token) = email_magic_link_proof(stored)?;
    let (candidate_binding, candidate_token) = email_magic_link_proof(candidate)?;
    if !qid_core::util::constant_time_eq(binding.as_bytes(), candidate_binding.as_bytes()) {
        return None;
    }
    Some(qid_core::util::constant_time_eq(
        token.as_bytes(),
        candidate_token.as_bytes(),
    ))
}
