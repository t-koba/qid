//! Password authentication handler.

use axum::{
    Extension, Json,
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
use crate::password_limit::PasswordAttemptLimiter;

pub async fn password_auth<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Extension(limiter): Extension<Arc<PasswordAttemptLimiter>>,
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

    // The realm policy sets the account's lockout numbers, which the
    // OIDC authorization endpoint enforces as well. The shared admission
    // limiter below separately bounds requests that reach credential work.
    let policy = PasswordPolicy::from_config(&realm_config.password);
    // A login is admitted before the credential lookup and before any
    // Argon2id work. The account's admission count and the realm's own
    // count are the counts of the limiter the session routes and the
    // OIDC authorization endpoint share, so both paths refuse the same
    // logins and a refused login costs no Argon2id work.
    if !limiter.admit(&realm, &req.email, &policy) {
        metrics::counter!("qid_authn_rate_limited_total", "method" => "password").increment(1);
        return qid_http::error_response(QidError::TooManyRequests {
            message: "too many login attempts, please wait and try again".to_string(),
        });
    }
    let credentials = match qid_crypto::realm_password_context(&state, &realm) {
        Ok(credentials) => credentials,
        Err(error) => return qid_http::error_response(error),
    };
    let authenticator =
        Authenticator::new(state.repo.clone(), policy, state.failure_budget.clone())
            .with_credentials(credentials);
    metrics::counter!("qid_authn_attempts_total", "method" => "password").increment(1);
    let auth_result = match authenticator
        .authenticate_password(&RealmId(realm.clone()), &req.email, &req.password)
        .await
    {
        Ok(r) => {
            metrics::counter!("qid_authn_success_total", "method" => "password").increment(1);
            // A successful login clears the account's admission count and
            // gives the realm back the admission it spent.
            limiter.succeeded(&realm, &req.email);
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
