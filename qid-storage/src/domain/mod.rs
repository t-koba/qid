use qid_core::{
    QidError, QidResult,
    models::{
        AuthorizationCode, CiamConsentGrant, CiamIdentityLink, Client, Session, TokenFamily, User,
    },
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

/// Validate a token family rotation:
/// - Family must not be revoked
/// - New hash must differ from current (reuse/replay detection)
pub fn validate_token_family_rotation(
    family: &TokenFamily,
    new_refresh_hash: &str,
) -> QidResult<()> {
    if family.revoked {
        return Err(QidError::BadRequest {
            message: format!("token family {} is revoked", family.id),
        });
    }
    if family.current_refresh_hash == new_refresh_hash {
        return Err(QidError::BadRequest {
            message: format!("token family {} refresh hash reuse detected", family.id),
        });
    }
    Ok(())
}

/// Validate that a token family can be revoked (not already revoked).
pub fn validate_token_family_revocation(family: &TokenFamily) -> QidResult<()> {
    if family.revoked {
        return Err(QidError::BadRequest {
            message: format!("token family {} is already revoked", family.id),
        });
    }
    Ok(())
}

/// Validate that a user's email is unique within a realm.
#[allow(dead_code)]
pub fn validate_user_email_uniqueness(
    existing: Option<&User>,
    realm_id: &str,
    email: &str,
) -> QidResult<()> {
    if let Some(_user) = existing {
        return Err(QidError::BadRequest {
            message: format!(
                "user with email {} already exists in realm {}",
                email, realm_id
            ),
        });
    }
    Ok(())
}

/// Validate that a client_id is unique within a realm.
#[allow(dead_code)]
pub fn validate_client_id_uniqueness(existing: Option<&Client>) -> QidResult<()> {
    if let Some(client) = existing {
        return Err(QidError::BadRequest {
            message: format!(
                "client with client_id {} already exists in realm {}",
                client.client_id, client.realm_id
            ),
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
/// For existing links, prevent reverting from verified to unverified.
pub fn validate_ciam_identity_link_state(
    link: &CiamIdentityLink,
    existing: Option<&CiamIdentityLink>,
) -> QidResult<()> {
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
