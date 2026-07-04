use super::*;

/// Core audit function.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn append_admin_audit<R: Repository>(
    state: &SharedState<R>,
    headers: &HeaderMap,
    admin: &Admin,
    elevation: &AdminElevation,
    realm_id: Option<String>,
    action: &str,
    target_type: &str,
    target_id: &str,
    metadata_json: serde_json::Value,
) -> QidResult<()> {
    let event = AuditEvent {
        id: Ulid::new().to_string(),
        realm_id,
        actor: admin.subject.clone(),
        action: action.to_string(),
        target_type: target_type.to_string(),
        target_id: target_id.to_string(),
        reason: if state.config.admin.security.require_reason {
            admin_reason(headers)?
        } else {
            admin_reason(headers).unwrap_or_else(|_| "not-required".to_string())
        },
        metadata_json: serde_json::json!({
            "admin_session": admin_session_metadata(admin, elevation),
            "operation": metadata_json,
        }),
        created_at: qid_core::util::now_seconds(),
        previous_hash: None,
        event_hash: None,
    };
    state.repo.append_audit_event(&event).await
}

pub(crate) fn audit_limit(requested: Option<usize>) -> usize {
    requested.unwrap_or(100).clamp(1, 500)
}

pub(crate) fn audit_export_options(query: &AuditQuery) -> AuditExportOptions {
    AuditExportOptions {
        include_metadata: query.include_metadata.unwrap_or(true),
        traceparent: query.traceparent.clone(),
        audit_correlation_id: query.audit_correlation_id.clone(),
    }
}

fn audit_event_json(event: AuditEvent, include_metadata: bool) -> serde_json::Value {
    serde_json::json!({
        "id": event.id,
        "realm_id": event.realm_id,
        "actor": event.actor,
        "action": event.action,
        "target_type": event.target_type,
        "target_id": event.target_id,
        "reason": event.reason,
        "metadata": if include_metadata { event.metadata_json } else { serde_json::Value::Object(Default::default()) },
        "created_at": event.created_at,
    })
}

#[derive(Deserialize)]
pub(crate) struct AuditQuery {
    pub(crate) limit: Option<usize>,
    pub(crate) traceparent: Option<String>,
    pub(crate) audit_correlation_id: Option<String>,
    pub(crate) include_metadata: Option<bool>,
}

#[derive(Deserialize)]
pub(crate) struct AuditRetentionRequest {
    retention_days: u64,
    legal_hold: bool,
}

pub(crate) async fn list_global_audit<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin(
        &state,
        &headers,
        AdminPermission::PlatformAuditRead,
        &state.config.admin.security,
        None,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state
        .repo
        .list_audit_events(None, audit_limit(query.limit))
        .await
    {
        Ok(events) => {
            let include_meta = query.include_metadata.unwrap_or(true);
            let items: Vec<serde_json::Value> = events
                .into_iter()
                .map(|e| audit_event_json(e, include_meta))
                .collect();
            (StatusCode::OK, Json(serde_json::json!(items))).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn list_realm_audit<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
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
    match state
        .repo
        .list_audit_events(Some(&RealmId(realm)), audit_limit(query.limit))
        .await
    {
        Ok(events) => {
            let include_meta = query.include_metadata.unwrap_or(true);
            let items: Vec<serde_json::Value> = events
                .into_iter()
                .map(|e| audit_event_json(e, include_meta))
                .collect();
            (StatusCode::OK, Json(serde_json::json!(items))).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn export_global_audit<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin(
        &state,
        &headers,
        AdminPermission::PlatformAuditRead,
        &state.config.admin.security,
        None,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state
        .repo
        .list_audit_events(None, audit_limit(query.limit))
        .await
    {
        Ok(events) => match export_jsonl(&events, &audit_export_options(&query)) {
            Ok(body) => (
                StatusCode::OK,
                [(CONTENT_TYPE, "application/x-ndjson")],
                body,
            )
                .into_response(),
            Err(e) => qid_http::error_response(QidError::Internal {
                message: e.to_string(),
            }),
        },
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn export_realm_audit<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
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
    match state
        .repo
        .list_audit_events(Some(&RealmId(realm)), audit_limit(query.limit))
        .await
    {
        Ok(events) => match export_jsonl(&events, &audit_export_options(&query)) {
            Ok(body) => (
                StatusCode::OK,
                [(CONTENT_TYPE, "application/x-ndjson")],
                body,
            )
                .into_response(),
            Err(e) => qid_http::error_response(QidError::Internal {
                message: e.to_string(),
            }),
        },
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn verify_global_audit<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin(
        &state,
        &headers,
        AdminPermission::PlatformAuditRead,
        &state.config.admin.security,
        None,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state.repo.verify_audit_chain(None).await {
        Ok(verification) => (StatusCode::OK, Json(verification)).into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn verify_realm_audit<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
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
    match state.repo.verify_audit_chain(Some(&RealmId(realm))).await {
        Ok(verification) => (StatusCode::OK, Json(verification)).into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn get_global_audit_retention<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin(
        &state,
        &headers,
        AdminPermission::PlatformSecurityAdmin,
        &state.config.admin.security,
        None,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state.repo.get_audit_retention_config(None).await {
        Ok(Some(config)) => (StatusCode::OK, Json(config)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "audit retention config not found" })),
        )
            .into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn get_realm_audit_retention<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
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
    match state
        .repo
        .get_audit_retention_config(Some(&RealmId(realm)))
        .await
    {
        Ok(Some(config)) => (StatusCode::OK, Json(config)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "audit retention config not found" })),
        )
            .into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn put_global_audit_retention<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<AuditRetentionRequest>,
) -> impl IntoResponse {
    put_audit_retention(state, headers, None, req).await
}

pub(crate) async fn put_realm_audit_retention<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Json(req): Json<AuditRetentionRequest>,
) -> impl IntoResponse {
    put_audit_retention(state, headers, Some(realm), req).await
}

pub(crate) async fn plan_global_audit_retention<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin(
        &state,
        &headers,
        AdminPermission::PlatformSecurityAdmin,
        &state.config.admin.security,
        None,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state
        .repo
        .plan_audit_retention(None, qid_core::util::now_seconds())
        .await
    {
        Ok(Some(plan)) => (StatusCode::OK, Json(plan)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "audit retention config not found" })),
        )
            .into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

pub(crate) async fn plan_realm_audit_retention<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
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
    match state
        .repo
        .plan_audit_retention(Some(&RealmId(realm)), qid_core::util::now_seconds())
        .await
    {
        Ok(Some(plan)) => (StatusCode::OK, Json(plan)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "audit retention config not found" })),
        )
            .into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

async fn put_audit_retention<R: Repository>(
    state: Arc<SharedState<R>>,
    headers: HeaderMap,
    realm_id: Option<String>,
    req: AuditRetentionRequest,
) -> impl IntoResponse {
    let permission = if realm_id.is_some() {
        AdminPermission::SecurityAdmin
    } else {
        AdminPermission::PlatformSecurityAdmin
    };
    let (admin, elevation) = match authorize_admin_mutation(
        &state,
        &headers,
        permission,
        &state.config.admin.security,
        realm_id.as_deref(),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    if req.retention_days > 36_500 {
        return qid_http::error_response(QidError::BadRequest {
            message: "retention_days must be at most 36500".to_string(),
        });
    }
    let reason = admin_reason(&headers).unwrap_or_else(|_| "not-required".to_string());
    let config = AuditRetentionConfig {
        realm_id: realm_id.clone(),
        retention_days: req.retention_days,
        legal_hold: req.legal_hold,
        updated_by: admin.subject.clone(),
        reason,
        updated_at: qid_core::util::now_seconds(),
    };

    match state.repo.set_audit_retention_config(&config).await {
        Ok(()) => {
            let target_id = realm_id.clone().unwrap_or_else(|| "__global__".to_string());
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &admin,
                &elevation,
                realm_id,
                "audit_retention.update",
                "audit_retention",
                &target_id,
                serde_json::json!({
                    "retention_days": config.retention_days,
                    "legal_hold": config.legal_hold,
                }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (StatusCode::OK, Json(config)).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}
