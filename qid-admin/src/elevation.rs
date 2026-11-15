use super::*;

pub(crate) async fn exchange<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> axum::response::Response {
    let mut response = match issue(&state, &realm, &headers).await {
        Ok(elevation) => Json(serde_json::json!({
            "admin_session_id": elevation.id,
            "expires_at": elevation.elevation_expires_at,
        }))
        .into_response(),
        Err(error) => qid_http::error_response(error),
    };
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

async fn issue<R: Repository>(
    state: &SharedState<R>,
    realm: &str,
    headers: &HeaderMap,
) -> QidResult<AdminElevation> {
    let runtime = state.require_realm(realm)?;
    let invalid = || QidError::Unauthorized {
        message: "invalid admin browser session or membership".into(),
    };
    let session_id = qid_http::extract_cookie(headers, &runtime.browser_session.cookie_name)
        .ok_or_else(invalid)?;
    let session = state
        .repo
        .get_session(&session_id)
        .await?
        .ok_or_else(invalid)?;
    if session.id != session_id || session.realm_id != realm {
        return Err(invalid());
    }
    let user = state
        .repo
        .get_user_by_id(&session.user_id)
        .await?
        .ok_or_else(invalid)?;
    // Issuance requires the stored binding; configuration alone is not proof.
    let tenant = state
        .repo
        .get_realm_tenant(&RealmId(realm.into()))
        .await?
        .ok_or_else(invalid)?;
    let admin = state
        .repo
        .get_admin(&tenant, &session.user_id)
        .await?
        .ok_or_else(invalid)?;
    let security = &state.config.admin.security;
    enforce_admin_assurance(session.acr.as_deref(), &session.amr, security)?;
    let now = qid_core::util::now_seconds();
    let elevation = AdminElevation {
        id: Ulid::new().to_string(),
        tenant_id: tenant.clone(),
        admin_id: admin.id.clone(),
        source_session_id: Some(session_id),
        acr: session.acr.clone(),
        amr: session.amr.clone(),
        elevation_expires_at: now
            .saturating_add(security.max_elevation_seconds)
            .min(session.idle_expires_at)
            .min(session.absolute_expires_at),
        created_at: now,
    };
    if elevation.elevation_expires_at <= now
        || !elevation.source_session_is_valid(&admin, &session, &user, Some(&tenant), now)
    {
        return Err(invalid());
    }
    if security.require_reason {
        // Audit fail-open mode suppresses append errors, so validate policy before auditing.
        admin_reason(headers)?;
    }
    record_admin_audit_or_warn(
        state,
        headers,
        &admin,
        &elevation,
        Some(realm.into()),
        "admin.elevation.issue.intent",
        "admin",
        &admin.id,
        serde_json::json!({"auth_time": session.auth_time}),
    )
    .await?;
    state.repo.store_admin_elevation(&elevation).await?;
    Ok(elevation)
}
