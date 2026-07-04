use super::*;
#[derive(Debug, Deserialize)]
pub(crate) struct SessionListQuery {
    user_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct SessionView {
    id: String,
    user_id: String,
    auth_time: u64,
    acr: Option<String>,
    amr: Vec<String>,
    idle_expires_at: u64,
    absolute_expires_at: u64,
    revoked: bool,
    created_at: u64,
}

pub(crate) async fn list_sessions_handler<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Query(query): Query<SessionListQuery>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin(
        &state,
        &headers,
        AdminPermission::SecurityAdmin,
        &state.config.admin.security,
        Some(&realm),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    qid_http::list_handler!(
        state.repo.list_sessions(&realm, query.user_id.as_deref()),
        |s| SessionView {
            id: s.id,
            user_id: s.user_id,
            auth_time: s.auth_time,
            acr: s.acr,
            amr: s.amr,
            idle_expires_at: s.idle_expires_at,
            absolute_expires_at: s.absolute_expires_at,
            revoked: s.revoked,
            created_at: s.created_at,
        }
    )
}

#[derive(Debug, Deserialize)]
pub(crate) struct TokenFamilyListQuery {
    user_id: Option<String>,
    client_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenFamilyView {
    id: String,
    user_id: String,
    client_id: String,
    issued_at: u64,
    revoked: bool,
}

pub(crate) async fn list_token_families_handler<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Query(query): Query<TokenFamilyListQuery>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin(
        &state,
        &headers,
        AdminPermission::SecurityAdmin,
        &state.config.admin.security,
        Some(&realm),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    qid_http::list_handler!(
        state.repo.list_token_families(
            &realm,
            query.user_id.as_deref(),
            query.client_id.as_deref()
        ),
        |f| TokenFamilyView {
            id: f.id,
            user_id: f.user_id,
            client_id: f.client_id,
            issued_at: f.issued_at,
            revoked: f.revoked,
        }
    )
}

#[derive(Debug, Deserialize)]
pub(crate) struct PepDecisionQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Serialize)]
struct PepDecisionView {
    decision_id: String,
    realm: String,
    decision: String,
    policy_id: Option<String>,
    policy_tags: Vec<String>,
    request_id: Option<String>,
    created_at: u64,
}

pub(crate) async fn list_pep_decisions_handler<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Query(query): Query<PepDecisionQuery>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin(
        &state,
        &headers,
        AdminPermission::AuditRead,
        &state.config.admin.security,
        Some(&realm),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    let decisions = match PEP_DECISIONS.lock() {
        Ok(decisions) => decisions,
        Err(_) => {
            return qid_http::error_response(QidError::Internal {
                message: "PEP decision store lock poisoned".to_string(),
            });
        }
    };
    let limit = query.limit.unwrap_or(50).min(200);
    let offset = query.offset.unwrap_or(0);
    let views: Vec<PepDecisionView> = decisions
        .iter()
        .filter(|d| d.realm == realm)
        .skip(offset)
        .take(limit)
        .map(|d| PepDecisionView {
            decision_id: d.decision_id.clone(),
            realm: d.realm.clone(),
            decision: d.decision.clone(),
            policy_id: d.policy_id.clone(),
            policy_tags: d.policy_tags.clone(),
            request_id: d.request_id.clone(),
            created_at: d.created_at,
        })
        .collect();
    (StatusCode::OK, Json(views)).into_response()
}

#[derive(Debug, Deserialize)]
pub(crate) struct RiskEventQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

pub(crate) async fn list_risk_events_handler<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Query(query): Query<RiskEventQuery>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin(
        &state,
        &headers,
        AdminPermission::AuditRead,
        &state.config.admin.security,
        Some(&realm),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    let events = qid_risk::risk_events();
    let limit = query.limit.unwrap_or(50).min(200);
    let offset = query.offset.unwrap_or(0);
    let views: Vec<serde_json::Value> = events
        .iter()
        .skip(offset)
        .take(limit)
        .map(|e| {
            serde_json::json!({
                "eval_id": e.eval_id,
                "score": e.score,
                "labels": e.labels,
                "outcome": e.outcome,
                "subject": e.subject,
                "created_at": e.created_at,
            })
        })
        .collect();
    (StatusCode::OK, Json(views)).into_response()
}

pub(crate) async fn revoke_session_handler<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path((realm, session_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation(
        &state,
        &headers,
        AdminPermission::SecurityAdmin,
        &state.config.admin.security,
        Some(&realm),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    let session = match state.repo.get_session(&session_id).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("session {session_id}"),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };
    if session.realm_id != realm {
        return qid_http::error_response(QidError::NotFound {
            resource: format!("session {session_id}"),
        });
    }
    match state.repo.revoke_session(&session_id).await {
        Ok(_) => {
            let _ = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                Some(realm),
                "admin.session_revoke",
                "session",
                &session_id,
                serde_json::json!({"forced": true}),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn revoke_token_family_handler<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path((realm, family_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation(
        &state,
        &headers,
        AdminPermission::SecurityAdmin,
        &state.config.admin.security,
        Some(&realm),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    let family = match state.repo.get_token_family(&family_id).await {
        Ok(Some(family)) => family,
        Ok(None) => {
            return qid_http::error_response(QidError::NotFound {
                resource: format!("token family {family_id}"),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };
    if family.realm_id != realm {
        return qid_http::error_response(QidError::NotFound {
            resource: format!("token family {family_id}"),
        });
    }
    match state.repo.revoke_token_family(&family_id).await {
        Ok(_) => {
            let _ = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                Some(realm),
                "admin.token_family_revoke",
                "token_family",
                &family_id,
                serde_json::json!({"forced": true}),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

// --- Service Account Admin ---

#[derive(Debug, Deserialize)]
pub(crate) struct CreateServiceAccountRequest {
    client_id: String,
    description: Option<String>,
}

#[derive(Debug, Serialize)]
struct ServiceAccountView {
    id: String,
    client_id: String,
    description: Option<String>,
    created_at: u64,
}

pub(crate) async fn list_service_accounts_handler<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin(
        &state,
        &headers,
        AdminPermission::AppAdmin,
        &state.config.admin.security,
        Some(&realm),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    qid_http::list_handler!(state.repo.list_service_accounts(&realm), |sa| {
        ServiceAccountView {
            id: sa.id,
            client_id: sa.client_id,
            description: sa.description,
            created_at: sa.created_at,
        }
    })
}

pub(crate) async fn create_service_account_handler<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Json(req): Json<CreateServiceAccountRequest>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation(
        &state,
        &headers,
        AdminPermission::AppAdmin,
        &state.config.admin.security,
        Some(&realm),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    let sa = qid_core::models::ServiceAccount {
        id: Ulid::new().to_string(),
        client_id: req.client_id,
        realm_id: realm.clone(),
        description: req.description,
        created_at: qid_core::util::now_seconds(),
    };
    match state.repo.create_service_account(&sa).await {
        Ok(_) => {
            let _ = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                Some(realm),
                "admin.service_account_create",
                "service_account",
                &sa.id,
                serde_json::json!({"client_id": &sa.client_id}),
            )
            .await;
            (StatusCode::CREATED, Json(sa)).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn delete_service_account_handler<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path((realm, sa_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation(
        &state,
        &headers,
        AdminPermission::AppAdmin,
        &state.config.admin.security,
        Some(&realm),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    let belongs_to_realm = match state.repo.list_service_accounts(&realm).await {
        Ok(accounts) => accounts.iter().any(|account| account.id == sa_id),
        Err(e) => return qid_http::error_response(e),
    };
    if !belongs_to_realm {
        return qid_http::error_response(QidError::NotFound {
            resource: format!("service account {sa_id}"),
        });
    }
    match state.repo.delete_service_account(&sa_id).await {
        Ok(_) => {
            let _ = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                Some(realm),
                "admin.service_account_delete",
                "service_account",
                &sa_id,
                serde_json::json!({}),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}
