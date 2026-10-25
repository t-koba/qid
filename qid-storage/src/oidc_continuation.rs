use qid_core::{
    error::{QidError, QidResult},
    models::{OIDC_CONTINUATION_CONTEXT_MAX_BYTES, OidcAuthorizationContinuation},
};

pub(super) fn invalid() -> QidError {
    QidError::BadRequest {
        message: "invalid OIDC authorization continuation".into(),
    }
}

pub(super) fn validate(c: &OidcAuthorizationContinuation) -> QidResult<()> {
    let identifier = |s: &str| {
        !s.is_empty() && s.len() <= 256 && !s.chars().any(|c| c.is_control() || c.is_whitespace())
    };
    if ![&c.id, &c.realm_id, &c.user_id, &c.client_id]
        .into_iter()
        .all(|s| identifier(s))
        || c.created_at >= c.expires_at
        || c.expires_at > i64::MAX as u64
        || c.context_json.len() > OIDC_CONTINUATION_CONTEXT_MAX_BYTES
    {
        return Err(invalid());
    }
    match serde_json::from_str::<serde_json::Value>(&c.context_json) {
        Ok(serde_json::Value::Object(object)) if !object.is_empty() => Ok(()),
        _ => Err(invalid()),
    }
}

pub(super) fn validate_creation(c: &OidcAuthorizationContinuation, now: u64) -> QidResult<()> {
    validate(c)?;
    if c.created_at != now {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn validate_cleanup(now: u64, limit: u32) -> QidResult<()> {
    if !(1..=1000).contains(&limit) || i64::try_from(now).is_err() {
        return Err(QidError::BadRequest {
            message: "invalid OIDC continuation cleanup bound".into(),
        });
    }
    Ok(())
}
