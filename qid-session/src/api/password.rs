//! Password authentication handler.

use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use qid_core::web::JsonObject;
use qid_core::{error::QidError, state::SharedState, tenant::RealmId};
use qid_storage::prelude::*;
use std::sync::Arc;

use super::{Authenticator, PasswordAuthRequest, PasswordAuthResponse, UserResponse};
use crate::auth::PasswordPolicy;
use crate::browser::SessionManager;

pub async fn password_auth<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    JsonObject(req): JsonObject<PasswordAuthRequest>,
) -> Response {
    let realm_config = match state.require_realm(&realm) {
        Ok(config) => config,
        Err(error) => return qid_http::error_response(error),
    };

    if !realm_config.accepts_password_authentication() {
        return qid_http::error_response(QidError::Unauthorized {
            message: "password authentication is disabled for this realm".to_string(),
        });
    }

    // The realm's password policy is the only attempt limit a password
    // login has. The authenticator locks the account after the realm's
    // `max_failed_attempts` failures and refuses even the correct
    // password until the lockout expires, and the OIDC authorization
    // endpoint enforces the same numbers, so this route adds no second
    // limit of its own.
    let authenticator = Authenticator::new(
        state.repo.clone(),
        PasswordPolicy::from_config(&realm_config.password),
        state.failure_budget.clone(),
    );
    metrics::counter!("qid_authn_attempts_total", "method" => "password").increment(1);
    let auth_result = match authenticator
        .authenticate_password(&RealmId(realm.clone()), &req.email, &req.password)
        .await
    {
        Ok(r) => {
            metrics::counter!("qid_authn_success_total", "method" => "password").increment(1);
            r
        }
        Err(e) => {
            metrics::counter!("qid_authn_failures_total", "method" => "password").increment(1);
            metrics::counter!(
                "qid_login_failures_total",
                "realm" => realm.clone(),
                "reason" => e.error_code().as_str()
            )
            .increment(1);
            return qid_http::error_response(e);
        }
    };

    let session_config = &realm_config.browser_session;
    let old_session_id = super::extract_cookie(&headers, &session_config.cookie_name);

    let manager = SessionManager::from_browser_session_config(state.repo.clone(), session_config);

    let session = match manager
        .create_with_regeneration(
            &realm,
            &auth_result.user.id,
            &auth_result.acr,
            &auth_result.amr,
            old_session_id.as_deref(),
        )
        .await
    {
        Ok(s) => s,
        Err(e) => return qid_http::error_response(e),
    };

    let mut headers = HeaderMap::new();
    if let Err(error) = super::set_session_cookie(
        &mut headers,
        session_config,
        &session.id,
        "failed to build session cookie header",
    ) {
        return qid_http::error_response(error);
    }

    let body = Json(PasswordAuthResponse {
        session: session.id,
        user: UserResponse {
            id: auth_result.user.id,
            email: auth_result.user.email.unwrap_or_default(),
        },
    });

    (headers, body).into_response()
}
