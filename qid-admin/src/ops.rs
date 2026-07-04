use super::*;
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct BreakglassSessionRevokeRequest {
    incident_id: String,
    justification: String,
}

pub(crate) async fn breakglass_revoke_session<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Json(req): Json<BreakglassSessionRevokeRequest>,
) -> impl IntoResponse {
    let (admin, elevation) =
        match authorize_breakglass_mutation(&state, &headers, &state.config.admin.security, None)
            .await
        {
            Ok(a) => a,
            Err(e) => return qid_http::error_response(e),
        };
    if req.incident_id.trim().is_empty() || req.justification.trim().is_empty() {
        return qid_http::error_response(QidError::BadRequest {
            message: "break-glass incident_id and justification are required".to_string(),
        });
    }
    let session = match state.repo.get_session(&session_id).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "session not found" })),
            )
                .into_response();
        }
        Err(e) => return qid_http::error_response(e),
    };
    let session_tenant = match state
        .repo
        .get_realm_tenant(&RealmId(session.realm_id.clone()))
        .await
    {
        Ok(Some(tenant)) => tenant,
        Ok(None) => {
            return qid_http::error_response(QidError::Unauthorized {
                message: "session realm tenant binding was not found".to_string(),
            });
        }
        Err(e) => return qid_http::error_response(e),
    };
    if session_tenant != admin.tenant_id {
        return qid_http::error_response(QidError::Unauthorized {
            message: "admin tenant does not match session realm tenant".to_string(),
        });
    }
    if let Err(e) = state.repo.revoke_session(&session_id).await {
        return qid_http::error_response(e);
    }
    if let Err(e) = append_admin_audit(
        &state,
        &headers,
        &admin,
        &elevation,
        Some(session.realm_id.clone()),
        "breakglass.session_revoke",
        "session",
        &session_id,
        serde_json::json!({
            "breakglass": true,
            "incident_id": req.incident_id.trim(),
            "justification": req.justification.trim(),
            "target_user_id": session.user_id.clone(),
            "target_realm_id": session.realm_id.clone(),
            "emergency_read_only": state.config.ops.emergency.read_only,
        }),
    )
    .await
    {
        return qid_http::error_response(e);
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "session_id": session_id,
            "revoked": true,
            "incident_id": req.incident_id.trim(),
            "realm_id": session.realm_id,
            "user_id": session.user_id,
        })),
    )
        .into_response()
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct KeyRotationPlanRequest {
    inventory: Vec<KeyringInventoryRecord>,
    requirements: Vec<KeyRotationRequirement>,
    now_epoch: Option<u64>,
}

pub(crate) async fn plan_key_rotation_admin<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<KeyRotationPlanRequest>,
) -> impl IntoResponse {
    let (_admin, _elevation) = match authorize_admin_mutation(
        &state,
        &headers,
        AdminPermission::SecurityAdmin,
        &state.config.admin.security,
        None,
    )
    .await
    {
        Ok(a) => a,
        Err(e) => return qid_http::error_response(e),
    };
    if req.requirements.is_empty() {
        return qid_http::error_response(QidError::BadRequest {
            message: "key rotation plan requires at least one requirement".to_string(),
        });
    }
    let now_epoch = req.now_epoch.unwrap_or_else(qid_core::util::now_seconds);
    let plans = plan_key_rotation(&req.inventory, &req.requirements, now_epoch);
    let rejected_count = plans
        .iter()
        .filter(|plan| matches!(plan.status, qid_ops::KeyRotationPlanStatus::Rejected))
        .count();
    let action_required_count = plans
        .iter()
        .filter(|plan| matches!(plan.status, qid_ops::KeyRotationPlanStatus::ActionRequired))
        .count();
    let ready_count = plans.len() - rejected_count - action_required_count;
    let status = if rejected_count > 0 {
        "rejected"
    } else if action_required_count > 0 {
        "action_required"
    } else {
        "ready"
    };
    let realm_id = common_key_rotation_realm(&req.requirements);
    if let Err(e) = append_admin_audit(
        &state,
        &headers,
        &_admin,
        &_elevation,
        realm_id,
        "key_rotation.plan",
        "key_rotation",
        "key_rotation_plan",
        serde_json::json!({
            "status": status,
            "ready_count": ready_count,
            "action_required_count": action_required_count,
            "rejected_count": rejected_count,
            "plan_count": plans.len(),
            "now_epoch": now_epoch,
        }),
    )
    .await
    {
        return qid_http::error_response(e);
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": status,
            "ready_count": ready_count,
            "action_required_count": action_required_count,
            "rejected_count": rejected_count,
            "plans": plans,
        })),
    )
        .into_response()
}

fn common_key_rotation_realm(requirements: &[KeyRotationRequirement]) -> Option<String> {
    let first = requirements.first()?.realm_id.as_str();
    requirements
        .iter()
        .all(|requirement| requirement.realm_id == first)
        .then(|| first.to_string())
}
