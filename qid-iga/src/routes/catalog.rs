use super::*;

pub(super) async fn entitlements<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(None, &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    match catalog_for_tenant(&state, &tenant_id).await {
        Ok(catalog) => Json(serde_json::json!({
            "tenant_id": tenant_id,
            "entitlements": catalog
        }))
        .into_response(),
        Err(error) => storage_error_response("list_iga_entitlements", error),
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct EntitlementRequest {
    #[serde(default)]
    tenant_id: Option<String>,
    id: String,
    display_name: String,
    owner: String,
    risk_level: EntitlementRiskLevel,
    #[serde(default)]
    conflicting_entitlements: Vec<String>,
    #[serde(default)]
    max_duration_seconds: Option<u64>,
    #[serde(default = "default_true")]
    active: bool,
}

pub(super) async fn upsert_entitlement<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<EntitlementRequest>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(req.tenant_id.as_deref(), &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    let owner = match state.repo.list_iga_entitlements(&tenant_id).await {
        Ok(existing) => existing
            .into_iter()
            .find(|entitlement| entitlement.id == req.id)
            .map(|entitlement| entitlement.owner)
            .unwrap_or_else(|| admin.subject.clone()),
        Err(error) => return storage_error_response("list_iga_entitlements", error),
    };
    let _ = &req.owner;
    let record = IgaEntitlementRecord {
        id: req.id,
        tenant_id: tenant_id.clone(),
        display_name: req.display_name,
        owner,
        risk_level: risk_level_as_str(&req.risk_level).to_string(),
        conflicting_entitlements: req.conflicting_entitlements,
        max_duration_seconds: req.max_duration_seconds,
        active: req.active,
    };
    if let Err(error) = state.repo.store_iga_entitlement(&record).await {
        return storage_error_response("store_iga_entitlement", error);
    }
    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "entitlement": entitlement_from_record(record)
    }))
    .into_response()
}

pub(super) async fn delete_entitlement<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(None, &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    if let Err(error) = state.repo.delete_iga_entitlement(&tenant_id, &id).await {
        return storage_error_response("delete_iga_entitlement", error);
    }
    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "id": id,
        "deleted": true
    }))
    .into_response()
}

pub(super) async fn access_packages<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(None, &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    let packages = match state.repo.list_iga_access_packages(&tenant_id).await {
        Ok(packages) => packages,
        Err(error) => return storage_error_response("list_iga_access_packages", error),
    };
    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "access_packages": packages
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct AccessPackageRequest {
    #[serde(default)]
    tenant_id: Option<String>,
    id: String,
    display_name: String,
    owner: String,
    entitlement_ids: Vec<String>,
    #[serde(default = "default_access_package_approval_policy")]
    approval_policy_json: serde_json::Value,
    #[serde(default)]
    max_duration_seconds: Option<u64>,
    #[serde(default = "default_true")]
    active: bool,
}

pub(super) async fn upsert_access_package<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<AccessPackageRequest>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(req.tenant_id.as_deref(), &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    let known_entitlements = match catalog_for_tenant(&state, &tenant_id).await {
        Ok(catalog) => catalog
            .into_iter()
            .map(|entitlement| entitlement.id)
            .collect::<HashSet<_>>(),
        Err(error) => return storage_error_response("list_iga_entitlements", error),
    };
    for entitlement_id in &req.entitlement_ids {
        if !known_entitlements.contains(entitlement_id) {
            return bad_request_response("access_package_unknown_entitlement");
        }
    }
    let record = IgaAccessPackageRecord {
        id: req.id,
        tenant_id: tenant_id.clone(),
        display_name: req.display_name,
        owner: req.owner,
        entitlement_ids: req.entitlement_ids,
        approval_policy_json: req.approval_policy_json,
        max_duration_seconds: req.max_duration_seconds,
        active: req.active,
    };
    if let Err(error) = state.repo.store_iga_access_package(&record).await {
        return storage_error_response("store_iga_access_package", error);
    }
    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "access_package": record
    }))
    .into_response()
}

pub(super) async fn delete_access_package<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(None, &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    if let Err(error) = state.repo.delete_iga_access_package(&tenant_id, &id).await {
        return storage_error_response("delete_iga_access_package", error);
    }
    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "id": id,
        "deleted": true
    }))
    .into_response()
}
