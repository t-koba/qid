use axum::http::HeaderMap;
use qid_core::error::QidError;
use qid_core::state::SharedState;
use qid_storage::prelude::*;

/// Require an active browser session matching the expected `user_id`.
/// Returns the authenticated `user_id` on success.
pub(crate) async fn require_session<R: Repository>(
    headers: &HeaderMap,
    state: &SharedState<R>,
    realm_id: &str,
    expected_user_id: &str,
) -> Result<String, axum::response::Response> {
    let session = load_active_session(headers, state, realm_id).await?;
    if !expected_user_id.is_empty() && session.user_id != expected_user_id {
        return Err(qid_http::error_response(QidError::Unauthorized {
            message: "session user does not match expected user".to_string(),
        }));
    }
    Ok(session.user_id)
}

/// Require any active session (no user_id check).
/// Returns the authenticated `user_id`.
pub(crate) async fn require_any_session<R: Repository>(
    headers: &HeaderMap,
    state: &SharedState<R>,
    realm_id: &str,
) -> Result<String, axum::response::Response> {
    let session = load_active_session(headers, state, realm_id).await?;
    Ok(session.user_id)
}

async fn load_active_session<R: Repository>(
    headers: &HeaderMap,
    state: &SharedState<R>,
    realm_id: &str,
) -> Result<qid_core::models::Session, axum::response::Response> {
    let realm_cfg = state.plan.realm(realm_id).ok_or_else(|| {
        qid_http::error_response(QidError::Config {
            message: format!("realm {realm_id} not found"),
        })
    })?;
    let cookie_name = &realm_cfg.browser_session.cookie_name;
    let session_id = extract_cookie(headers, cookie_name).ok_or_else(|| {
        qid_http::error_response(QidError::Unauthorized {
            message: "authentication required: missing session cookie".to_string(),
        })
    })?;
    let session = state
        .repo
        .get_session(session_id)
        .await
        .map_err(qid_http::error_response)?
        .ok_or_else(|| {
            qid_http::error_response(QidError::Unauthorized {
                message: "invalid or expired session".to_string(),
            })
        })?;
    if session.revoked
        || session.absolute_expires_at < qid_core::util::now_seconds()
        || session.idle_expires_at < qid_core::util::now_seconds()
    {
        return Err(qid_http::error_response(QidError::Unauthorized {
            message: "session is no longer active".to_string(),
        }));
    }
    if session.realm_id != realm_id {
        return Err(qid_http::error_response(QidError::Unauthorized {
            message: "session realm does not match request realm".to_string(),
        }));
    }
    Ok(session)
}

fn extract_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let cookie = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for pair in cookie.split(';') {
        let mut parts = pair.splitn(2, '=');
        if parts.next()?.trim() == name {
            return Some(parts.next()?.trim());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{StatusCode, header::COOKIE};
    use qid_core::{
        models::{Session, User},
        test_helpers,
    };
    use qid_crypto::LocalSigner;
    use qid_storage::{FileRepository, SqlRepository};
    use std::sync::Arc;

    async fn deleted_user_cannot_authenticate(repo: &Arc<impl Repository>) {
        repo.create_realm(
            &"tenant".into(),
            &"test".into(),
            "https://id.example.com",
            None,
        )
        .await
        .unwrap();
        let now = qid_core::util::now_seconds();
        for id in ["target", "survivor"] {
            repo.create_user(&User {
                id: id.into(),
                realm_id: "test".into(),
                email: None,
                email_verified: false,
                display_name: None,
                failed_login_attempts: 0,
                locked_until: None,
                org: None,
            })
            .await
            .unwrap();
            repo.create_session(&Session {
                id: id.into(),
                realm_id: "test".into(),
                user_id: id.into(),
                auth_time: now,
                acr: None,
                amr: vec!["pwd".into()],
                idle_expires_at: now + 600,
                absolute_expires_at: now + 600,
                revoked: false,
                created_at: now,
                cnf: None,
            })
            .await
            .unwrap();
        }
        let state = SharedState::new(
            test_helpers::test_config(),
            Arc::clone(repo),
            Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests")),
            serde_json::json!({}),
        )
        .unwrap();
        let cookie_name = &state
            .plan
            .realm("test")
            .unwrap()
            .browser_session
            .cookie_name;
        let mut target = HeaderMap::new();
        target.insert(COOKIE, format!("{cookie_name}=target").parse().unwrap());
        let mut survivor = HeaderMap::new();
        survivor.insert(COOKIE, format!("{cookie_name}=survivor").parse().unwrap());
        assert_eq!(
            require_any_session(&target, &state, "test").await.unwrap(),
            "target"
        );
        repo.delete_user("target").await.unwrap();
        assert_eq!(
            require_any_session(&target, &state, "test")
                .await
                .unwrap_err()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            require_session(&target, &state, "test", "target")
                .await
                .unwrap_err()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            require_session(&survivor, &state, "test", "survivor")
                .await
                .unwrap(),
            "survivor"
        );
    }

    #[tokio::test]
    async fn deleted_file_user_session_is_rejected() {
        let path =
            std::env::temp_dir().join(format!("qid-session-deletion-{}.json", ulid::Ulid::new()));
        let repo = Arc::new(FileRepository::new(path.to_str().unwrap()).await.unwrap());
        deleted_user_cannot_authenticate(&repo).await;
        drop(repo);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn deleted_sql_user_session_is_rejected() {
        let path =
            std::env::temp_dir().join(format!("qid-session-deletion-{}.db", ulid::Ulid::new()));
        let repo = Arc::new(
            SqlRepository::connect(&format!("sqlite:{}", path.display()))
                .await
                .unwrap(),
        );
        repo.migrate().await.unwrap();
        deleted_user_cannot_authenticate(&repo).await;
        repo.close().await;
        drop(repo);
        std::fs::remove_file(path).unwrap();
    }
}
