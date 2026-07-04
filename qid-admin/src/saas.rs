use super::*;

#[derive(Deserialize)]
pub(super) struct UsageBillingQuery {
    limit: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct CustomDomainActivationRequest {
    dns_challenge_value: String,
    certificate_ref: String,
    certificate_expires_at: u64,
    certificate_renew_after: u64,
    verified_at: u64,
}

#[derive(Deserialize)]
pub(super) struct CustomDomainCertificateRenewalRequest {
    certificate_ref: String,
    certificate_expires_at: u64,
    certificate_renew_after: u64,
}

pub(super) fn validate_tenant_path(path_tenant: &str, body_tenant: &str) -> QidResult<()> {
    if path_tenant != body_tenant {
        return Err(QidError::BadRequest {
            message: "tenant_id must match tenant path parameter".to_string(),
        });
    }
    Ok(())
}

pub(super) async fn load_custom_domain<R: Repository>(
    state: &SharedState<R>,
    tenant: &str,
    domain_id: &str,
) -> QidResult<CustomDomain> {
    state
        .repo
        .list_custom_domains(tenant)
        .await?
        .into_iter()
        .find(|domain| domain.id == domain_id)
        .ok_or_else(|| QidError::NotFound {
            resource: format!("custom domain {domain_id}"),
        })
}

pub(super) async fn list_custom_domains<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(tenant): Path<String>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_for_tenant(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state.repo.list_custom_domains(&tenant).await {
        Ok(domains) => (StatusCode::OK, Json(domains)).into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

pub(super) async fn create_custom_domain<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    Json(domain): Json<CustomDomain>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation_for_tenant(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    if let Err(e) = validate_tenant_path(&tenant, &domain.tenant_id).and_then(|_| domain.validate())
    {
        return qid_http::error_response(e);
    }
    match state.repo.store_custom_domain(&domain).await {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                Some(domain.realm_id.clone()),
                "custom_domain.create",
                "custom_domain",
                &domain.id,
                serde_json::json!({
                    "tenant_id": domain.tenant_id,
                    "hostname": domain.hostname,
                    "certificate_ref": domain.certificate_ref,
                    "verified": domain.verified,
                    "verification_status": domain.verification_status,
                    "dns_challenge_name": domain.dns_challenge_name,
                    "certificate_expires_at": domain.certificate_expires_at,
                    "certificate_renew_after": domain.certificate_renew_after,
                    "last_verified_at": domain.last_verified_at,
                }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (StatusCode::CREATED, Json(domain)).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(super) async fn activate_custom_domain<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path((tenant, domain_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(req): Json<CustomDomainActivationRequest>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation_for_tenant(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    let mut domain = match load_custom_domain(&state, &tenant, &domain_id).await {
        Ok(domain) => domain,
        Err(e) => return qid_http::error_response(e),
    };
    if domain.dns_challenge_value.as_deref() != Some(req.dns_challenge_value.as_str()) {
        return qid_http::error_response(QidError::BadRequest {
            message: "custom domain DNS challenge value does not match".to_string(),
        });
    }
    domain.certificate_ref = req.certificate_ref;
    domain.certificate_expires_at = Some(req.certificate_expires_at);
    domain.certificate_renew_after = Some(req.certificate_renew_after);
    domain.last_verified_at = Some(req.verified_at);
    domain.verified = true;
    domain.verification_status = "active".to_string();
    if let Err(e) = domain.validate_activation() {
        return qid_http::error_response(e);
    }
    match state.repo.store_custom_domain(&domain).await {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                Some(domain.realm_id.clone()),
                "custom_domain.activate",
                "custom_domain",
                &domain.id,
                serde_json::json!({
                    "tenant_id": domain.tenant_id,
                    "hostname": domain.hostname,
                    "certificate_ref": domain.certificate_ref,
                    "certificate_expires_at": domain.certificate_expires_at,
                    "certificate_renew_after": domain.certificate_renew_after,
                    "last_verified_at": domain.last_verified_at,
                }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (StatusCode::OK, Json(domain)).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(super) async fn renew_custom_domain_certificate<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path((tenant, domain_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(req): Json<CustomDomainCertificateRenewalRequest>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation_for_tenant(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    let mut domain = match load_custom_domain(&state, &tenant, &domain_id).await {
        Ok(domain) => domain,
        Err(e) => return qid_http::error_response(e),
    };
    if !domain.verified || domain.verification_status != "active" {
        return qid_http::error_response(QidError::BadRequest {
            message: "custom domain certificate renewal requires an active domain".to_string(),
        });
    }
    domain.certificate_ref = req.certificate_ref;
    domain.certificate_expires_at = Some(req.certificate_expires_at);
    domain.certificate_renew_after = Some(req.certificate_renew_after);
    if let Err(e) = domain.validate_activation() {
        return qid_http::error_response(e);
    }
    match state.repo.store_custom_domain(&domain).await {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                Some(domain.realm_id.clone()),
                "custom_domain.certificate_renew",
                "custom_domain",
                &domain.id,
                serde_json::json!({
                    "tenant_id": domain.tenant_id,
                    "hostname": domain.hostname,
                    "certificate_ref": domain.certificate_ref,
                    "certificate_expires_at": domain.certificate_expires_at,
                    "certificate_renew_after": domain.certificate_renew_after,
                }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (StatusCode::OK, Json(domain)).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(super) async fn delete_custom_domain<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path((tenant, domain_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation_for_tenant(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state.repo.delete_custom_domain(&tenant, &domain_id).await {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                None,
                "custom_domain.delete",
                "custom_domain",
                &domain_id,
                serde_json::json!({ "tenant_id": tenant }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (StatusCode::NO_CONTENT, Json(serde_json::json!({}))).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(super) async fn list_app_catalog_entries<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(tenant): Path<String>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_for_tenant(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state.repo.list_app_catalog_entries(&tenant).await {
        Ok(entries) => (StatusCode::OK, Json(entries)).into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

pub(super) async fn create_app_catalog_entry<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    Json(entry): Json<AppCatalogEntry>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation_for_tenant(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    if let Err(e) = validate_tenant_path(&tenant, &entry.tenant_id)
        .and_then(|_| entry.validate())
        .and_then(|_| validate_app_catalog_saml_reference(&state.config, &entry))
    {
        return qid_http::error_response(e);
    }
    match state.repo.store_app_catalog_entry(&entry).await {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                None,
                "app_catalog_entry.create",
                "app_catalog_entry",
                &entry.id,
                serde_json::json!({
                    "tenant_id": entry.tenant_id,
                    "realm_id": entry.realm_id,
                    "display_name": entry.display_name,
                    "category": entry.category,
                    "oidc_client_id": entry.oidc_client_id,
                    "saml_entity_id": entry.saml_entity_id,
                    "scim_enabled": entry.scim_enabled,
                    "marketplace_connector_id": entry.marketplace_connector_id,
                }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (StatusCode::CREATED, Json(entry)).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(super) fn validate_app_catalog_saml_reference(
    config: &qid_core::config::QidConfig,
    entry: &AppCatalogEntry,
) -> QidResult<()> {
    let Some(saml_entity_id) = entry.saml_entity_id.as_deref() else {
        return Ok(());
    };
    let Some(realm) = config
        .realms
        .iter()
        .find(|realm| realm.id == entry.realm_id)
    else {
        return Err(QidError::BadRequest {
            message: "app catalog SAML realm is not configured".to_string(),
        });
    };
    if !realm.protocols.saml.enabled {
        return Err(QidError::BadRequest {
            message: "app catalog SAML realm is disabled".to_string(),
        });
    }
    if !realm
        .protocols
        .saml
        .service_providers
        .iter()
        .any(|sp| sp.entity_id == saml_entity_id)
    {
        return Err(QidError::BadRequest {
            message: "app catalog SAML entity is not configured for this realm".to_string(),
        });
    }
    Ok(())
}

pub(super) async fn delete_app_catalog_entry<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path((tenant, entry_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation_for_tenant(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state
        .repo
        .delete_app_catalog_entry(&tenant, &entry_id)
        .await
    {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                None,
                "app_catalog_entry.delete",
                "app_catalog_entry",
                &entry_id,
                serde_json::json!({ "tenant_id": tenant }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (StatusCode::NO_CONTENT, Json(serde_json::json!({}))).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(super) async fn list_ciam_brands<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(tenant): Path<String>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_for_tenant(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state.repo.list_ciam_brands(&tenant).await {
        Ok(brands) => (StatusCode::OK, Json(brands)).into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

pub(super) async fn create_ciam_brand<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    Json(brand): Json<CiamBrand>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation_for_tenant(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    if let Err(e) = validate_tenant_path(&tenant, &brand.tenant_id).and_then(|_| brand.validate()) {
        return qid_http::error_response(e);
    }
    match state.repo.store_ciam_brand(&brand).await {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                None,
                "ciam_brand.create",
                "ciam_brand",
                &brand.id,
                serde_json::json!({
                    "tenant_id": brand.tenant_id,
                    "realm_id": brand.realm_id,
                    "display_name": brand.display_name,
                    "active": brand.active,
                    "terms_version": brand.terms_version,
                }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (StatusCode::CREATED, Json(brand)).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(super) async fn delete_ciam_brand<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path((tenant, brand_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation_for_tenant(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state.repo.delete_ciam_brand(&tenant, &brand_id).await {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                None,
                "ciam_brand.delete",
                "ciam_brand",
                &brand_id,
                serde_json::json!({ "tenant_id": tenant }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (StatusCode::NO_CONTENT, Json(serde_json::json!({}))).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(super) async fn list_marketplace_connectors<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(tenant): Path<String>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_for_tenant(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state.repo.list_marketplace_connectors(&tenant).await {
        Ok(connectors) => (StatusCode::OK, Json(connectors)).into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

pub(super) async fn create_marketplace_connector<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    Json(connector): Json<MarketplaceConnector>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation_for_tenant(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    if let Err(e) =
        validate_tenant_path(&tenant, &connector.tenant_id).and_then(|_| connector.validate())
    {
        return qid_http::error_response(e);
    }
    match state.repo.store_marketplace_connector(&connector).await {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                None,
                "marketplace_connector.create",
                "marketplace_connector",
                &connector.id,
                serde_json::json!({
                    "tenant_id": connector.tenant_id,
                    "provider": connector.provider,
                    "connector_type": connector.connector_type,
                    "enabled": connector.enabled,
                }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (StatusCode::CREATED, Json(connector)).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(super) async fn delete_marketplace_connector<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path((tenant, connector_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation_for_tenant(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state
        .repo
        .delete_marketplace_connector(&tenant, &connector_id)
        .await
    {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                None,
                "marketplace_connector.delete",
                "marketplace_connector",
                &connector_id,
                serde_json::json!({ "tenant_id": tenant }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (StatusCode::NO_CONTENT, Json(serde_json::json!({}))).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(super) async fn list_usage_billing_events<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(tenant): Path<String>,
    Query(query): Query<UsageBillingQuery>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_for_tenant(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state
        .repo
        .list_usage_billing_events(&tenant, audit_limit(query.limit))
        .await
    {
        Ok(events) => (StatusCode::OK, Json(events)).into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

pub(super) async fn create_usage_billing_event<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    Json(event): Json<UsageBillingEvent>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation_for_tenant(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    if let Err(e) = validate_tenant_path(&tenant, &event.tenant_id).and_then(|_| event.validate()) {
        return qid_http::error_response(e);
    }
    match state.repo.store_usage_billing_event(&event).await {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                None,
                "usage_billing_event.create",
                "usage_billing_event",
                &event.id,
                serde_json::json!({
                    "tenant_id": event.tenant_id,
                    "meter": event.meter,
                    "quantity": event.quantity,
                    "occurred_at": event.occurred_at,
                    "idempotency_key": event.idempotency_key,
                }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (StatusCode::CREATED, Json(event)).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(super) async fn list_compliance_evidence_packs<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(tenant): Path<String>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_for_tenant(
        &state,
        &headers,
        AdminPermission::AuditRead,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state.repo.list_compliance_evidence_packs(&tenant).await {
        Ok(packs) => (StatusCode::OK, Json(packs)).into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

pub(super) async fn create_compliance_evidence_pack<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    Json(pack): Json<ComplianceEvidencePack>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation_for_tenant(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    if let Err(e) = validate_tenant_path(&tenant, &pack.tenant_id).and_then(|_| pack.validate()) {
        return qid_http::error_response(e);
    }
    match state.repo.store_compliance_evidence_pack(&pack).await {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                None,
                "compliance_evidence_pack.create",
                "compliance_evidence_pack",
                &pack.id,
                serde_json::json!({
                    "tenant_id": pack.tenant_id,
                    "period_start": pack.period_start,
                    "period_end": pack.period_end,
                    "controls": pack.controls,
                    "object_uri": pack.object_uri,
                    "sha256_hex": pack.sha256_hex,
                    "generated_at": pack.generated_at,
                }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (StatusCode::CREATED, Json(pack)).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(super) async fn list_delegated_tenant_admins<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(tenant): Path<String>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_for_tenant(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state.repo.list_delegated_tenant_admins(&tenant).await {
        Ok(admins) => (StatusCode::OK, Json(admins)).into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

pub(super) async fn create_delegated_tenant_admin<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    Json(admin): Json<DelegatedTenantAdmin>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation_for_tenant(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    if let Err(e) = validate_tenant_path(&tenant, &admin.tenant_id).and_then(|_| admin.validate()) {
        return qid_http::error_response(e);
    }
    match state.repo.store_delegated_tenant_admin(&admin).await {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                None,
                "delegated_tenant_admin.create",
                "delegated_tenant_admin",
                &admin.id,
                serde_json::json!({
                    "tenant_id": admin.tenant_id,
                    "subject": admin.subject,
                    "roles": admin.roles,
                    "allowed_realm_ids": admin.allowed_realm_ids,
                    "granted_by": admin.granted_by,
                    "granted_at": admin.granted_at,
                    "expires_at": admin.expires_at,
                    "revoked": admin.revoked,
                }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            (StatusCode::CREATED, Json(admin)).into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

pub(super) async fn revoke_delegated_tenant_admin<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path((tenant, admin_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation_for_tenant(
        &state,
        &headers,
        AdminPermission::TenantAdmin,
        &state.config.admin.security,
        &tenant,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    match state
        .repo
        .revoke_delegated_tenant_admin(&tenant, &admin_id)
        .await
    {
        Ok(()) => {
            if let Err(e) = append_admin_audit(
                &state,
                &headers,
                &_admin,
                &_elevation,
                None,
                "delegated_tenant_admin.revoke",
                "delegated_tenant_admin",
                &admin_id,
                serde_json::json!({
                    "tenant_id": tenant,
                    "revoked": true,
                }),
            )
            .await
            {
                return qid_http::error_response(e);
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}
