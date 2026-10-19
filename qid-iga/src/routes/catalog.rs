use super::*;

pub(super) async fn entitlements<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (_, tenant_id) = match require_admin_tenant_context(&headers, &state, None).await {
        Ok(context) => context,
        Err(response) => return response,
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
    let (admin, tenant_id) =
        match require_admin_tenant_context(&headers, &state, req.tenant_id.as_deref()).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    let _ = &req.owner;
    let mut record = IgaEntitlementRecord {
        id: req.id,
        tenant_id: tenant_id.clone(),
        display_name: req.display_name,
        owner: admin.subject.clone(),
        risk_level: risk_level_as_str(&req.risk_level).to_string(),
        conflicting_entitlements: req.conflicting_entitlements,
        max_duration_seconds: req.max_duration_seconds,
        active: req.active,
    };
    if let Err(error) = record.validate() {
        return match error {
            qid_core::error::QidError::BadRequest { .. } => {
                bad_request_response("iga_entitlement_invalid")
            }
            error => storage_error_response("validate_iga_entitlement", error),
        };
    }
    match state.repo.list_iga_entitlements(&tenant_id).await {
        Ok(existing) => {
            if let Some(existing) = existing
                .into_iter()
                .find(|entitlement| entitlement.id == record.id)
            {
                record.owner = existing.owner;
            }
        }
        Err(error) => return storage_error_response("list_iga_entitlements", error),
    }
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
    let (_, tenant_id) = match require_admin_tenant_context(&headers, &state, None).await {
        Ok(context) => context,
        Err(response) => return response,
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
    let (_, tenant_id) = match require_admin_tenant_context(&headers, &state, None).await {
        Ok(context) => context,
        Err(response) => return response,
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
    let (_, tenant_id) =
        match require_admin_tenant_context(&headers, &state, req.tenant_id.as_deref()).await {
            Ok(context) => context,
            Err(response) => return response,
        };
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
    if let Err(error) = record.validate() {
        return match error {
            qid_core::error::QidError::BadRequest { .. } => {
                bad_request_response("iga_access_package_invalid")
            }
            error => storage_error_response("validate_iga_access_package", error),
        };
    }
    let known_entitlements = match catalog_for_tenant(&state, &tenant_id).await {
        Ok(catalog) => catalog
            .into_iter()
            .map(|entitlement| entitlement.id)
            .collect::<HashSet<_>>(),
        Err(error) => return storage_error_response("list_iga_entitlements", error),
    };
    for entitlement_id in &record.entitlement_ids {
        if !known_entitlements.contains(entitlement_id) {
            return bad_request_response("access_package_unknown_entitlement");
        }
    }
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
    let (_, tenant_id) = match require_admin_tenant_context(&headers, &state, None).await {
        Ok(context) => context,
        Err(response) => return response,
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
