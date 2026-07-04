use super::*;

#[derive(Debug, Deserialize)]
pub(super) struct AccessReviewRequest {
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    assignments: HashMap<String, Vec<String>>,
    #[serde(default)]
    dormant_subjects: Vec<String>,
    #[serde(default)]
    orphan_subjects: Vec<String>,
    #[serde(default)]
    due_in_seconds: Option<u64>,
}

pub(super) async fn create_access_review<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<AccessReviewRequest>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(req.tenant_id.as_deref(), &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    let now = now_seconds();
    let assignments = match active_assignments_for_review(&state, &tenant_id, now).await {
        Ok(assignments) => assignments,
        Err(error) => return storage_error_response("list_iga_access_grants", error),
    };
    let (dormant_subjects, orphan_subjects) =
        match finding_subjects_for_review(&state, &tenant_id).await {
            Ok(subjects) => subjects,
            Err(error) => return storage_error_response("list_iga_findings", error),
        };
    let _ = (
        &req.assignments,
        &req.dormant_subjects,
        &req.orphan_subjects,
    );
    let campaign = build_access_review_campaign(
        ulid::Ulid::new().to_string(),
        admin.subject.clone(),
        &assignments,
        &match catalog_for_tenant(&state, &tenant_id).await {
            Ok(catalog) => catalog,
            Err(error) => return storage_error_response("list_iga_entitlements", error),
        },
        &dormant_subjects,
        &orphan_subjects,
    );
    let record = IgaAccessReviewCampaignRecord {
        id: campaign.id.clone(),
        tenant_id: tenant_id.clone(),
        reviewer: campaign.reviewer.clone(),
        subjects_json: serde_json::to_value(&campaign.subjects)
            .unwrap_or_else(|_| serde_json::json!([])),
        status: "open".to_string(),
        created_at_epoch_seconds: now,
        due_at_epoch_seconds: req.due_in_seconds.map(|seconds| now + seconds),
    };
    if let Err(error) = state.repo.store_iga_access_review_campaign(&record).await {
        return storage_error_response("store_iga_access_review_campaign", error);
    }
    Json(serde_json::json!({
        "id": campaign.id,
        "tenant_id": tenant_id,
        "reviewer": campaign.reviewer,
        "subjects": campaign.subjects,
        "status": "open",
        "created_at_epoch_seconds": now,
        "due_at_epoch_seconds": record.due_at_epoch_seconds,
    }))
    .into_response()
}

pub(super) async fn list_access_reviews<R: Repository>(
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
    let campaigns = match state
        .repo
        .list_iga_access_review_campaigns(&tenant_id)
        .await
    {
        Ok(campaigns) => campaigns,
        Err(error) => return storage_error_response("list_iga_access_review_campaigns", error),
    };
    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "campaigns": campaigns,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct CloseAccessReviewRequest {
    #[serde(default)]
    tenant_id: Option<String>,
}

pub(super) async fn close_access_review<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(req): Json<CloseAccessReviewRequest>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(req.tenant_id.as_deref(), &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    if let Err(error) = state
        .repo
        .close_iga_access_review_campaign(&tenant_id, &id)
        .await
    {
        return storage_error_response("close_iga_access_review_campaign", error);
    }
    Json(serde_json::json!({
        "id": id,
        "status": "closed",
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct AccessReviewDecisionRequest {
    #[serde(default)]
    tenant_id: Option<String>,
    subject: String,
    decision: AccessReviewDecision,
    #[serde(default)]
    reason: Option<String>,
}

pub(super) async fn create_access_review_decision<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    axum::extract::Path(campaign_id): axum::extract::Path<String>,
    Json(req): Json<AccessReviewDecisionRequest>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(req.tenant_id.as_deref(), &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    let campaign = match state
        .repo
        .get_iga_access_review_campaign(&tenant_id, &campaign_id)
        .await
    {
        Ok(Some(campaign)) => campaign,
        Ok(_) => return not_found_response("IGA access review campaign not found"),
        Err(error) => return storage_error_response("get_iga_access_review_campaign", error),
    };
    if campaign.status != "open" {
        return bad_request_response("access_review_campaign_closed");
    }
    if campaign.reviewer != admin.subject {
        return unauthorized_response("admin is not the reviewer for this access review campaign");
    }
    let campaign_subjects = match access_review_subjects_from_record(&campaign) {
        Ok(subjects) => subjects,
        Err(response) => return *response,
    };
    let Some(review_subject) = campaign_subjects
        .iter()
        .find(|subject| subject.subject == req.subject)
    else {
        return bad_request_response("access_review_subject_not_in_campaign");
    };
    let record = IgaAccessReviewDecisionRecord {
        id: ulid::Ulid::new().to_string(),
        tenant_id: tenant_id.clone(),
        campaign_id: campaign_id.clone(),
        subject: req.subject,
        reviewer: admin.subject.clone(),
        decision: access_review_decision_as_str(&req.decision).to_string(),
        reason: req.reason,
        decided_at_epoch_seconds: now_seconds(),
    };
    if let Err(error) = state.repo.store_iga_access_review_decision(&record).await {
        return storage_error_response("store_iga_access_review_decision", error);
    }
    let revoked_grants = if matches!(req.decision, AccessReviewDecision::Revoke) {
        match revoke_active_grants_for_subject_entitlements(
            &state,
            &tenant_id,
            &record.subject,
            &review_subject.entitlements,
        )
        .await
        {
            Ok(grants) => grants,
            Err(error) => return storage_error_response("revoke_iga_access_grant", error),
        }
    } else {
        Vec::new()
    };
    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "decision": record,
        "revoked_grants": revoked_grants,
    }))
    .into_response()
}

pub(super) async fn list_access_review_decisions<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    axum::extract::Path(campaign_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(None, &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    let decisions = match state
        .repo
        .list_iga_access_review_decisions(&tenant_id, &campaign_id)
        .await
    {
        Ok(decisions) => decisions,
        Err(error) => return storage_error_response("list_iga_access_review_decisions", error),
    };
    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "campaign_id": campaign_id,
        "decisions": decisions,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct CertificationQuery {
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    certification_type: Option<CertificationType>,
}

#[derive(Debug, Deserialize)]
pub(super) struct CertificationRequest {
    #[serde(default)]
    tenant_id: Option<String>,
    certification_type: CertificationType,
    #[serde(default)]
    campaign_id: Option<String>,
    subject: String,
    entitlement: String,
    decision: AccessReviewDecision,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default = "default_certification_evidence")]
    evidence_json: serde_json::Value,
}

pub(super) async fn list_certifications<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Query(query): Query<CertificationQuery>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(query.tenant_id.as_deref(), &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    let certification_type = query
        .certification_type
        .as_ref()
        .map(certification_type_as_str);
    let certifications = match state
        .repo
        .list_iga_certifications(&tenant_id, certification_type)
        .await
    {
        Ok(certifications) => certifications,
        Err(error) => return storage_error_response("list_iga_certifications", error),
    };
    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "certification_type": certification_type,
        "certifications": certifications,
    }))
    .into_response()
}

pub(super) async fn create_certification<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<CertificationRequest>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(req.tenant_id.as_deref(), &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    let catalog = match catalog_for_tenant(&state, &tenant_id).await {
        Ok(catalog) => catalog,
        Err(error) => return storage_error_response("list_iga_entitlements", error),
    };
    let Some(entitlement) = catalog.iter().find(|item| item.id == req.entitlement) else {
        return bad_request_response("certification_unknown_entitlement");
    };
    if matches!(req.certification_type, CertificationType::ApplicationOwner)
        && admin.subject != entitlement.owner
    {
        return bad_request_response("certification_requires_application_owner");
    }
    if matches!(req.certification_type, CertificationType::PrivilegedRole)
        && !matches!(
            entitlement.risk_level,
            EntitlementRiskLevel::High | EntitlementRiskLevel::Critical
        )
    {
        return bad_request_response("privileged_role_attestation_requires_high_risk_entitlement");
    }
    let record = IgaCertificationRecord {
        id: ulid::Ulid::new().to_string(),
        tenant_id: tenant_id.clone(),
        certification_type: certification_type_as_str(&req.certification_type).to_string(),
        campaign_id: req.campaign_id,
        subject: req.subject,
        entitlement: req.entitlement,
        certifier: admin.subject.clone(),
        decision: access_review_decision_as_str(&req.decision).to_string(),
        reason: req.reason,
        evidence_json: req.evidence_json,
        decided_at_epoch_seconds: now_seconds(),
    };
    if let Err(error) = state.repo.store_iga_certification(&record).await {
        return storage_error_response("store_iga_certification", error);
    }
    let revoked_grants = if matches!(req.decision, AccessReviewDecision::Revoke) {
        match revoke_active_grants_for_subject_entitlements(
            &state,
            &tenant_id,
            &record.subject,
            std::slice::from_ref(&record.entitlement),
        )
        .await
        {
            Ok(grants) => grants,
            Err(error) => return storage_error_response("revoke_iga_access_grant", error),
        }
    } else {
        Vec::new()
    };
    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "certification": record,
        "revoked_grants": revoked_grants,
    }))
    .into_response()
}

async fn active_assignments_for_review<R: Repository>(
    state: &SharedState<R>,
    tenant_id: &str,
    now: u64,
) -> qid_core::error::QidResult<HashMap<String, Vec<String>>> {
    let grants = state.repo.list_iga_access_grants(tenant_id, None).await?;
    let mut assignments: HashMap<String, Vec<String>> = HashMap::new();
    for grant in grants {
        if grant.revoked
            || grant
                .expires_at_epoch_seconds
                .is_some_and(|expires_at| expires_at <= now)
        {
            continue;
        }
        assignments
            .entry(grant.subject)
            .or_default()
            .push(grant.entitlement);
    }
    for entitlements in assignments.values_mut() {
        entitlements.sort();
        entitlements.dedup();
    }
    Ok(assignments)
}

async fn finding_subjects_for_review<R: Repository>(
    state: &SharedState<R>,
    tenant_id: &str,
) -> qid_core::error::QidResult<(Vec<String>, Vec<String>)> {
    let findings = state.repo.list_iga_findings(tenant_id, None).await?;
    let mut dormant_subjects = Vec::new();
    let mut orphan_subjects = Vec::new();
    for finding in findings.into_iter().filter(|finding| !finding.resolved) {
        match finding.finding_type.as_str() {
            "dormant_account" | "dormant_access" | "dormant_subject" => {
                dormant_subjects.push(finding.subject)
            }
            "orphaned_service_account" | "orphan_subject" | "orphan_account" => {
                orphan_subjects.push(finding.subject)
            }
            _ => {}
        }
    }
    dormant_subjects.sort();
    dormant_subjects.dedup();
    orphan_subjects.sort();
    orphan_subjects.dedup();
    Ok((dormant_subjects, orphan_subjects))
}

fn access_review_subjects_from_record(
    campaign: &IgaAccessReviewCampaignRecord,
) -> Result<Vec<AccessReviewSubject>, Box<axum::response::Response>> {
    serde_json::from_value(campaign.subjects_json.clone()).map_err(|_| {
        Box::new(bad_request_response(
            "access_review_campaign_subjects_invalid",
        ))
    })
}
