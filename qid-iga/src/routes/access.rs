use super::*;

#[derive(Debug, Deserialize)]
pub(super) struct AccessRequest {
    #[serde(default)]
    tenant_id: Option<String>,
    subject: String,
    #[serde(default)]
    entitlement: Option<String>,
    #[serde(default)]
    access_package_id: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    requested_duration_seconds: Option<u64>,
}

pub(super) async fn access_request<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<AccessRequest>,
) -> impl IntoResponse {
    let bearer_token = qid_oauth::endpoints::extract_bearer_token(&headers)
        .ok()
        .map(str::to_string);
    let tenant_id = match resolve_tenant_id(req.tenant_id.as_deref(), &state) {
        Ok(tenant_id) => tenant_id,
        Err(()) => return tenant_scope_unavailable_response(),
    };
    if let Some(token) = bearer_token {
        let decoded = match qid_oauth::endpoints::decode_access_token(&state, &token).await {
            Ok(decoded) => decoded,
            Err(_) => return unauthorized_response("invalid access request bearer token"),
        };
        let htu = format!(
            "{}/iga/v1/access-requests",
            state.plan.public_base_url.trim_end_matches('/')
        );
        if let Err(error) = qid_oauth::endpoints::enforce_sender_constrained_access_token(
            &state,
            &headers,
            &axum::http::Method::POST,
            &htu,
            &token,
            &decoded,
        ) {
            return unauthorized_response(&error.to_string());
        }
        if decoded.user_id != req.subject {
            return unauthorized_response("access request subject must match authenticated user");
        }
        let token_tenant = match state
            .repo
            .get_realm_tenant(&qid_core::tenant::RealmId(decoded.realm_id.clone()))
            .await
        {
            Ok(Some(tenant_id)) => tenant_id,
            Ok(None) => {
                return unauthorized_response("access request token realm is not registered");
            }
            Err(error) => return storage_error_response("get_realm_tenant", error),
        };
        if tenant_id != token_tenant {
            return unauthorized_response(
                "access request tenant does not match authenticated user",
            );
        }
    } else {
        let admin = match require_admin_session(&headers, &state).await {
            Ok(admin) => admin,
            Err(response) => return response,
        };
        if let Err(response) = resolve_admin_tenant_id(Some(&tenant_id), &state, &admin) {
            return *response;
        }
    }
    if let Some(access_package_id) = req
        .access_package_id
        .clone()
        .filter(|value| !value.trim().is_empty())
    {
        return access_package_request(&state, &tenant_id, req, &access_package_id).await;
    }
    let Some(entitlement) = req
        .entitlement
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    else {
        return bad_request_response("entitlement_required");
    };
    let now = now_seconds();
    let current_entitlements =
        match current_entitlements_for_subject(&state, &tenant_id, &req.subject, now).await {
            Ok(entitlements) => entitlements,
            Err(response) => return *response,
        };
    let evaluation = evaluate_access_request(
        &req.subject,
        entitlement,
        &current_entitlements,
        req.requested_duration_seconds,
        &match catalog_for_tenant(&state, &tenant_id).await {
            Ok(catalog) => catalog,
            Err(error) => return storage_error_response("list_iga_entitlements", error),
        },
    );
    let record = IgaAccessRequestRecord {
        id: evaluation.request_id.clone(),
        tenant_id: tenant_id.clone(),
        subject: evaluation.subject.clone(),
        entitlement: evaluation.entitlement.clone(),
        reason: req.reason.clone(),
        status: access_request_status_as_str(&evaluation.status).to_string(),
        approval_steps_json: serde_json::to_value(&evaluation.approval_steps)
            .unwrap_or_else(|_| serde_json::json!([])),
        violations_json: serde_json::to_value(&evaluation.violations)
            .unwrap_or_else(|_| serde_json::json!([])),
        expires_at_epoch_seconds: evaluation.expires_at_epoch_seconds,
        created_at_epoch_seconds: now,
    };
    if let Err(error) = state.repo.store_iga_access_request(&record).await {
        return storage_error_response("store_iga_access_request", error);
    }
    Json(serde_json::json!({
        "id": evaluation.request_id,
        "tenant_id": tenant_id,
        "subject": evaluation.subject,
        "entitlement": evaluation.entitlement,
        "reason": req.reason,
        "status": evaluation.status,
        "approval_steps": evaluation.approval_steps,
        "violations": evaluation.violations,
        "expires_at_epoch_seconds": evaluation.expires_at_epoch_seconds,
    }))
    .into_response()
}

pub(super) async fn access_package_request<R: Repository>(
    state: &SharedState<R>,
    tenant_id: &str,
    req: AccessRequest,
    access_package_id: &str,
) -> axum::response::Response {
    let packages = match state.repo.list_iga_access_packages(tenant_id).await {
        Ok(packages) => packages,
        Err(error) => return storage_error_response("list_iga_access_packages", error),
    };
    let Some(package) = packages
        .into_iter()
        .find(|package| package.id == access_package_id && package.active)
    else {
        return bad_request_response("access_package_unknown");
    };
    let catalog = match catalog_for_tenant(state, tenant_id).await {
        Ok(catalog) => catalog,
        Err(error) => return storage_error_response("list_iga_entitlements", error),
    };
    let requested_duration = match (req.requested_duration_seconds, package.max_duration_seconds) {
        (Some(requested), Some(max)) => Some(requested.min(max)),
        (Some(requested), None) => Some(requested),
        (None, max) => max,
    };
    let now = now_seconds();
    let current_entitlements =
        match current_entitlements_for_subject(state, tenant_id, &req.subject, now).await {
            Ok(entitlements) => entitlements,
            Err(response) => return *response,
        };
    let request_id = ulid::Ulid::new().to_string();
    let mut evaluations = Vec::new();
    for entitlement_id in &package.entitlement_ids {
        let mut evaluation = evaluate_access_request(
            &req.subject,
            entitlement_id,
            &current_entitlements,
            requested_duration,
            &catalog,
        );
        evaluation.request_id = request_id.clone();
        evaluations.push(evaluation);
    }
    let package_evaluation =
        build_access_package_evaluation(request_id.clone(), &req.subject, &package.id, evaluations);
    let record = IgaAccessRequestRecord {
        id: request_id.clone(),
        tenant_id: tenant_id.to_string(),
        subject: package_evaluation.subject.clone(),
        entitlement: format!("access_package:{}", package.id),
        reason: req.reason.clone(),
        status: access_request_status_as_str(&package_evaluation.status).to_string(),
        approval_steps_json: serde_json::to_value(&package_evaluation.approval_steps)
            .unwrap_or_else(|_| serde_json::json!([])),
        violations_json: serde_json::to_value(&package_evaluation.violations)
            .unwrap_or_else(|_| serde_json::json!([])),
        expires_at_epoch_seconds: package_evaluation.expires_at_epoch_seconds,
        created_at_epoch_seconds: now,
    };
    if let Err(error) = state.repo.store_iga_access_request(&record).await {
        return storage_error_response("store_iga_access_request", error);
    }
    Json(serde_json::json!({
        "id": request_id,
        "tenant_id": tenant_id,
        "subject": package_evaluation.subject,
        "access_package_id": package_evaluation.access_package_id,
        "entitlement": record.entitlement,
        "reason": req.reason,
        "status": package_evaluation.status,
        "approval_steps": package_evaluation.approval_steps,
        "violations": package_evaluation.violations,
        "expires_at_epoch_seconds": package_evaluation.expires_at_epoch_seconds,
        "package_evaluation": package_evaluation,
    }))
    .into_response()
}

async fn current_entitlements_for_subject<R: Repository>(
    state: &SharedState<R>,
    tenant_id: &str,
    subject: &str,
    now_epoch_seconds: u64,
) -> Result<Vec<String>, Box<axum::response::Response>> {
    let grants = state
        .repo
        .list_iga_access_grants(tenant_id, Some(subject))
        .await
        .map_err(|error| Box::new(storage_error_response("list_iga_access_grants", error)))?;
    let mut entitlements = grants
        .into_iter()
        .filter(|grant| !grant.revoked)
        .filter(|grant| {
            grant
                .expires_at_epoch_seconds
                .is_none_or(|expires_at| expires_at > now_epoch_seconds)
        })
        .map(|grant| grant.entitlement)
        .collect::<Vec<_>>();
    entitlements.sort();
    entitlements.dedup();
    Ok(entitlements)
}

#[derive(Debug, Deserialize)]
pub(super) struct ApprovalValidationRequest {
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    approvals: Vec<AccessApprovalRecord>,
    #[serde(default)]
    decision: Option<AccessApprovalDecision>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    expires_at_epoch_seconds: Option<u64>,
    #[serde(default)]
    issue_grant: bool,
}

pub(super) async fn validate_approvals<R: Repository>(
    headers: HeaderMap,
    State(state): State<Arc<SharedState<R>>>,
    Json(req): Json<ApprovalValidationRequest>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(response) => return response,
    };
    let tenant_id = match resolve_admin_tenant_id(req.tenant_id.as_deref(), &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    let request_id = req
        .request_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            req.approvals
                .first()
                .map(|approval| approval.request_id.clone())
        });
    let Some(request_id) = request_id else {
        return bad_request_response("request_id_required");
    };

    let stored = match state
        .repo
        .get_iga_access_request(&tenant_id, &request_id)
        .await
    {
        Ok(Some(stored)) => stored,
        Ok(None) => return not_found_response("access_request_not_found"),
        Err(error) => return storage_error_response("get_iga_access_request", error),
    };

    if stored.status != "approval_required" && stored.status != "approved" {
        return bad_request_response(&format!(
            "request_status_not_approval_required:{}",
            stored.status
        ));
    }

    let approval_steps: Vec<ApprovalStep> =
        serde_json::from_value(stored.approval_steps_json.clone()).unwrap_or_default();

    let now = now_seconds();
    if let Some(expires_at) = req.expires_at_epoch_seconds
        && expires_at <= now
    {
        return bad_request_response("approval_expired");
    }
    let evaluation = AccessRequestEvaluation {
        request_id: stored.id.clone(),
        subject: stored.subject.clone(),
        entitlement: stored.entitlement.clone(),
        status: AccessRequestStatus::ApprovalRequired,
        approval_steps: approval_steps.clone(),
        violations: serde_json::from_value(stored.violations_json.clone()).unwrap_or_default(),
        expires_at_epoch_seconds: stored.expires_at_epoch_seconds,
    };

    let mut current_approvals: Vec<AccessApprovalRecord> = if stored.status == "approval_required" {
        req.approvals
            .iter()
            .filter(|approval| approval.approver == admin.subject)
            .map(|approval| AccessApprovalRecord {
                id: ulid::Ulid::new().to_string(),
                request_id: request_id.clone(),
                approver: admin.subject.clone(),
                decision: approval.decision.clone(),
                approved_at_epoch_seconds: now,
                expires_at_epoch_seconds: approval
                    .expires_at_epoch_seconds
                    .or(req.expires_at_epoch_seconds),
                reason: approval.reason.clone().or_else(|| req.reason.clone()),
            })
            .collect()
    } else {
        Vec::new()
    };
    if stored.status == "approval_required"
        && current_approvals.is_empty()
        && let Some(decision) = req.decision
    {
        current_approvals.push(AccessApprovalRecord {
            id: ulid::Ulid::new().to_string(),
            request_id: request_id.clone(),
            approver: admin.subject.clone(),
            decision,
            approved_at_epoch_seconds: now,
            expires_at_epoch_seconds: req.expires_at_epoch_seconds,
            reason: req.reason,
        });
    }
    if !current_approvals.is_empty()
        && !approval_steps
            .iter()
            .any(|step| step.approver == admin.subject)
    {
        return unauthorized_response("admin is not an approver for this access request");
    }
    let stored_approvals = match state.repo.list_iga_approvals(&tenant_id, &request_id).await {
        Ok(approvals) => approvals,
        Err(error) => return storage_error_response("list_iga_approvals", error),
    };
    let mut approvals = Vec::new();
    for approval in stored_approvals {
        match access_approval_from_stored(approval) {
            Ok(approval) => approvals.push(approval),
            Err(response) => return *response,
        }
    }
    approvals.extend(current_approvals.clone());

    let validation = validate_access_request_approvals(&evaluation, &approvals, now);

    let existing_grants = match state.repo.list_iga_access_grants(&tenant_id, None).await {
        Ok(grants) => grants,
        Err(error) => return storage_error_response("list_iga_access_grants", error),
    };
    let has_existing_grant = existing_grants.iter().any(|g| g.request_id == request_id);
    let grants = if req.issue_grant && validation.valid && !has_existing_grant {
        issue_grants_for_evaluation(&evaluation, &approvals, now)
    } else {
        Vec::new()
    };

    for approval in &approvals {
        if !current_approvals
            .iter()
            .any(|current| current.id == approval.id)
        {
            continue;
        }
        let record = IgaApprovalRecord {
            id: approval.id.clone(),
            tenant_id: tenant_id.clone(),
            request_id: approval.request_id.clone(),
            approver: approval.approver.clone(),
            decision: approval_decision_as_str(&approval.decision).to_string(),
            approved_at_epoch_seconds: approval.approved_at_epoch_seconds,
            expires_at_epoch_seconds: approval.expires_at_epoch_seconds,
            reason: approval.reason.clone(),
        };
        if let Err(error) = state.repo.store_iga_approval(&record).await {
            return storage_error_response("store_iga_approval", error);
        }
    }
    let next_status = if validation.valid {
        Some("approved")
    } else if !validation.rejected_approvers.is_empty() {
        Some("rejected")
    } else {
        None
    };
    if stored.status == "approval_required"
        && let Some(status) = next_status
        && let Err(error) = state
            .repo
            .update_iga_access_request_status(&tenant_id, &request_id, status)
            .await
    {
        return storage_error_response("update_iga_access_request_status", error);
    }
    for grant in &grants {
        let record = IgaAccessGrantRecord {
            id: grant.id.clone(),
            tenant_id: tenant_id.clone(),
            request_id: grant.request_id.clone(),
            subject: grant.subject.clone(),
            entitlement: grant.entitlement.clone(),
            granted_at_epoch_seconds: grant.granted_at_epoch_seconds,
            expires_at_epoch_seconds: grant.expires_at_epoch_seconds,
            approval_ids: grant.approvals.clone(),
            revoked: false,
        };
        if let Err(error) = state.repo.store_iga_access_grant(&record).await {
            return storage_error_response("store_iga_access_grant", error);
        }
    }
    Json(serde_json::json!({
        "validation": validation,
        "grant": grants.first(),
        "grants": grants,
    }))
    .into_response()
}

fn access_approval_from_stored(
    record: IgaApprovalRecord,
) -> Result<AccessApprovalRecord, Box<axum::response::Response>> {
    let decision = match record.decision.as_str() {
        "approved" => AccessApprovalDecision::Approved,
        "rejected" => AccessApprovalDecision::Rejected,
        _ => {
            return Err(Box::new(bad_request_response(
                "stored_approval_decision_invalid",
            )));
        }
    };
    Ok(AccessApprovalRecord {
        id: record.id,
        request_id: record.request_id,
        approver: record.approver,
        decision,
        approved_at_epoch_seconds: record.approved_at_epoch_seconds,
        expires_at_epoch_seconds: record.expires_at_epoch_seconds,
        reason: record.reason,
    })
}

#[derive(Debug, Deserialize)]
pub(super) struct AccessGrantQuery {
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    subject: Option<String>,
}

pub(super) async fn list_access_grants<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Query(query): Query<AccessGrantQuery>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(query.tenant_id.as_deref(), &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    let subject = query
        .subject
        .as_deref()
        .filter(|value| !value.trim().is_empty());
    let grants = match state.repo.list_iga_access_grants(&tenant_id, subject).await {
        Ok(grants) => grants,
        Err(error) => return storage_error_response("list_iga_access_grants", error),
    };
    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "subject": subject,
        "grants": grants,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct AccessGrantRevokeRequest {
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

pub(super) async fn revoke_access_grant<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(req): Json<AccessGrantRevokeRequest>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(req.tenant_id.as_deref(), &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    let existing = match state.repo.list_iga_access_grants(&tenant_id, None).await {
        Ok(grants) => grants.into_iter().find(|grant| grant.id == id),
        Err(error) => return storage_error_response("list_iga_access_grants", error),
    };
    let Some(existing) = existing else {
        return not_found_response("IGA access grant not found");
    };
    if let Err(error) = state.repo.revoke_iga_access_grant(&tenant_id, &id).await {
        return storage_error_response("revoke_iga_access_grant", error);
    }
    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "id": id,
        "subject": existing.subject,
        "entitlement": existing.entitlement,
        "revoked": true,
        "reason": req.reason,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct JitPrivilegeQuery {
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    subject: Option<String>,
}

pub(super) async fn list_jit_privileges<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Query(query): Query<JitPrivilegeQuery>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(query.tenant_id.as_deref(), &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    let subject = query
        .subject
        .as_deref()
        .filter(|value| !value.trim().is_empty());
    let grants = match state
        .repo
        .list_iga_jit_privilege_grants(&tenant_id, subject)
        .await
    {
        Ok(grants) => grants,
        Err(error) => return storage_error_response("list_iga_jit_privilege_grants", error),
    };
    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "subject": subject,
        "jit_privileges": grants,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct JitPrivilegeRequest {
    #[serde(default)]
    tenant_id: Option<String>,
    request_id: String,
    subject: String,
    entitlement: String,
    reason: String,
    duration_seconds: u64,
    #[serde(default = "default_jit_constraints")]
    constraints_json: serde_json::Value,
}

pub(super) async fn issue_jit_privilege<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<JitPrivilegeRequest>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(req.tenant_id.as_deref(), &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    let stored_request = match state
        .repo
        .get_iga_access_request(&tenant_id, &req.request_id)
        .await
    {
        Ok(Some(record)) => record,
        Ok(None) => return not_found_response("jit_privilege_access_request_not_found"),
        Err(error) => return storage_error_response("get_iga_access_request", error),
    };
    if stored_request.status != "approved" {
        return bad_request_response("jit_privilege_access_request_not_approved");
    }
    if stored_request.subject != req.subject || stored_request.entitlement != req.entitlement {
        return bad_request_response("jit_privilege_request_scope_mismatch");
    }
    let approvals = match state
        .repo
        .list_iga_approvals(&tenant_id, &req.request_id)
        .await
    {
        Ok(approvals) => approvals,
        Err(error) => return storage_error_response("list_iga_approvals", error),
    };
    if approvals.is_empty() {
        return bad_request_response("jit_privilege_approval_evidence_required");
    }
    let approval_steps: Vec<ApprovalStep> =
        serde_json::from_value(stored_request.approval_steps_json.clone()).unwrap_or_default();
    let evaluation = AccessRequestEvaluation {
        request_id: stored_request.id.clone(),
        subject: stored_request.subject.clone(),
        entitlement: stored_request.entitlement.clone(),
        status: AccessRequestStatus::ApprovalRequired,
        approval_steps,
        violations: serde_json::from_value(stored_request.violations_json.clone())
            .unwrap_or_default(),
        expires_at_epoch_seconds: stored_request.expires_at_epoch_seconds,
    };
    let mut approval_records = Vec::new();
    for approval in approvals {
        match access_approval_from_stored(approval) {
            Ok(approval) => approval_records.push(approval),
            Err(response) => return *response,
        }
    }
    let validation =
        validate_access_request_approvals(&evaluation, &approval_records, now_seconds());
    if !validation.valid {
        return bad_request_response("jit_privilege_approval_evidence_invalid");
    }
    let catalog = match catalog_for_tenant(&state, &tenant_id).await {
        Ok(catalog) => catalog,
        Err(error) => return storage_error_response("list_iga_entitlements", error),
    };
    let Some(entitlement) = catalog
        .iter()
        .find(|entitlement| entitlement.id == req.entitlement)
    else {
        return bad_request_response("jit_privilege_unknown_entitlement");
    };
    if req.duration_seconds == 0 {
        return bad_request_response("jit_privilege_duration_required");
    }
    let max_duration = entitlement.max_duration_seconds.unwrap_or(900).min(3600);
    if req.duration_seconds > max_duration {
        return bad_request_response("jit_privilege_duration_exceeds_max");
    }
    let approved_by = if matches!(
        entitlement.risk_level,
        EntitlementRiskLevel::High | EntitlementRiskLevel::Critical
    ) {
        Some(admin.subject.clone())
    } else {
        None
    };
    let now = now_seconds();
    let record = IgaJitPrivilegeGrantRecord {
        id: ulid::Ulid::new().to_string(),
        tenant_id: tenant_id.clone(),
        subject: req.subject,
        entitlement: req.entitlement,
        requested_by: admin.subject,
        approved_by,
        reason: req.reason,
        issued_at_epoch_seconds: now,
        expires_at_epoch_seconds: now + req.duration_seconds,
        revoked: false,
        constraints_json: req.constraints_json,
    };
    if let Err(error) = state.repo.store_iga_jit_privilege_grant(&record).await {
        return storage_error_response("store_iga_jit_privilege_grant", error);
    }
    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "jit_privilege": record,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct JitPrivilegeRevokeRequest {
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

pub(super) async fn revoke_jit_privilege<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(req): Json<JitPrivilegeRevokeRequest>,
) -> impl IntoResponse {
    let admin = match require_admin_session(&headers, &state).await {
        Ok(admin) => admin,
        Err(e) => return e,
    };
    let tenant_id = match resolve_admin_tenant_id(req.tenant_id.as_deref(), &state, &admin) {
        Ok(tenant_id) => tenant_id,
        Err(e) => return *e,
    };
    let existing = match state
        .repo
        .list_iga_jit_privilege_grants(&tenant_id, None)
        .await
    {
        Ok(grants) => grants.into_iter().find(|grant| grant.id == id),
        Err(error) => return storage_error_response("list_iga_jit_privilege_grants", error),
    };
    let Some(existing) = existing else {
        return not_found_response("IGA JIT privilege grant not found");
    };
    if let Err(error) = state
        .repo
        .revoke_iga_jit_privilege_grant(&tenant_id, &id)
        .await
    {
        return storage_error_response("revoke_iga_jit_privilege_grant", error);
    }
    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "id": id,
        "subject": existing.subject,
        "entitlement": existing.entitlement,
        "revoked": true,
        "reason": req.reason,
    }))
    .into_response()
}
