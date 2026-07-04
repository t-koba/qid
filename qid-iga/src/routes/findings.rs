use super::*;

#[derive(Debug, Deserialize)]
pub(super) struct FindingQuery {
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    finding_type: Option<String>,
}

pub(super) async fn list_findings<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Query(query): Query<FindingQuery>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(query.tenant_id.as_deref(), &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    let finding_type = query
        .finding_type
        .as_deref()
        .filter(|value| !value.trim().is_empty());
    let findings = match state.repo.list_iga_findings(&tenant_id, finding_type).await {
        Ok(findings) => findings,
        Err(error) => return storage_error_response("list_iga_findings", error),
    };
    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "finding_type": finding_type,
        "findings": findings,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct FindingDetectionRequest {
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default = "default_dormant_threshold_seconds")]
    dormant_threshold_seconds: u64,
}

pub(super) async fn detect_findings<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<FindingDetectionRequest>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(req.tenant_id.as_deref(), &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    if req.dormant_threshold_seconds == 0 {
        return bad_request_response("dormant_threshold_required");
    }
    let now = now_seconds();
    let mut findings = Vec::new();
    let catalog = match catalog_for_tenant(&state, &tenant_id).await {
        Ok(catalog) => catalog,
        Err(error) => return storage_error_response("list_iga_entitlements", error),
    };
    let catalog_index: HashMap<&str, &[String]> = catalog
        .iter()
        .map(|entitlement| {
            (
                entitlement.id.as_str(),
                entitlement.conflicting_entitlements.as_ref(),
            )
        })
        .collect();
    let grants = match state.repo.list_iga_access_grants(&tenant_id, None).await {
        Ok(grants) => grants,
        Err(error) => return storage_error_response("list_iga_access_grants", error),
    };
    let mut subject_entitlements: HashMap<String, Vec<String>> = HashMap::new();
    for grant in grants {
        if grant.revoked
            || grant
                .expires_at_epoch_seconds
                .is_some_and(|expires_at| expires_at <= now)
        {
            continue;
        }
        subject_entitlements
            .entry(grant.subject)
            .or_default()
            .push(grant.entitlement);
    }
    for (subject, entitlements) in &mut subject_entitlements {
        entitlements.sort();
        entitlements.dedup();
        let assigned: HashSet<&str> = entitlements.iter().map(String::as_str).collect();
        for entitlement_id in entitlements.iter() {
            if let Some(conflicts) = catalog_index.get(entitlement_id.as_str()) {
                for conflict in *conflicts {
                    if assigned.contains(conflict.as_str()) {
                        let conflict_key = format!("{}+{}", entitlement_id, conflict);
                        findings.push(IgaFindingRecord {
                            id: ulid::Ulid::new().to_string(),
                            tenant_id: tenant_id.clone(),
                            finding_type: "sod_conflict".to_string(),
                            subject: subject.clone(),
                            severity: "high".to_string(),
                            evidence_json: serde_json::json!({
                                "source": "iga_access_grants",
                                "conflict": conflict_key,
                                "entitlements": entitlements,
                            }),
                            detected_at_epoch_seconds: now,
                            resolved: false,
                        });
                    }
                }
            }
        }
    }
    for finding in &findings {
        if let Err(error) = state.repo.store_iga_finding(finding).await {
            return storage_error_response("store_iga_finding", error);
        }
    }
    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "findings": findings,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct ResolveFindingRequest {
    #[serde(default)]
    tenant_id: Option<String>,
}

pub(super) async fn resolve_finding<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(req): Json<ResolveFindingRequest>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(req.tenant_id.as_deref(), &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    let existing = match state.repo.list_iga_findings(&tenant_id, None).await {
        Ok(findings) => findings.into_iter().find(|finding| finding.id == id),
        Err(error) => return storage_error_response("list_iga_findings", error),
    };
    let Some(existing) = existing else {
        return not_found_response("IGA finding not found");
    };
    if let Err(error) = state.repo.resolve_iga_finding(&id).await {
        return storage_error_response("resolve_iga_finding", error);
    }
    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "id": id,
        "finding_type": existing.finding_type,
        "subject": existing.subject,
        "resolved": true,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct EvidenceQuery {
    #[serde(default)]
    tenant_id: Option<String>,
}

pub(super) async fn export_iga_evidence<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Query(query): Query<EvidenceQuery>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(query.tenant_id.as_deref(), &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    let campaigns = match state
        .repo
        .list_iga_access_review_campaigns(&tenant_id)
        .await
    {
        Ok(campaigns) => campaigns,
        Err(error) => return storage_error_response("list_iga_access_review_campaigns", error),
    };
    let certifications = match state.repo.list_iga_certifications(&tenant_id, None).await {
        Ok(certifications) => certifications,
        Err(error) => return storage_error_response("list_iga_certifications", error),
    };
    let grants = match state.repo.list_iga_access_grants(&tenant_id, None).await {
        Ok(grants) => grants,
        Err(error) => return storage_error_response("list_iga_access_grants", error),
    };
    let jit_privileges = match state
        .repo
        .list_iga_jit_privilege_grants(&tenant_id, None)
        .await
    {
        Ok(grants) => grants,
        Err(error) => return storage_error_response("list_iga_jit_privilege_grants", error),
    };
    let findings = match state.repo.list_iga_findings(&tenant_id, None).await {
        Ok(findings) => findings,
        Err(error) => return storage_error_response("list_iga_findings", error),
    };
    Json(serde_json::json!({
        "schema_version": "qid.iga.evidence.v1",
        "tenant_id": tenant_id,
        "generated_at_epoch_seconds": now_seconds(),
        "access_review_campaigns": campaigns,
        "certifications": certifications,
        "findings": findings,
        "access_grants": grants,
        "jit_privileges": jit_privileges,
    }))
    .into_response()
}
