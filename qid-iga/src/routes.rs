use axum::{
    Json, Router,
    extract::{Query, State},
    http::HeaderMap,
    response::IntoResponse,
    routing::{get, post},
};
use qid_core::{
    config::AdminSecurityConfig,
    models::{
        Admin, AdminElevation, IgaAccessGrantRecord, IgaAccessPackageRecord,
        IgaAccessRequestRecord, IgaAccessReviewCampaignRecord, IgaAccessReviewDecisionRecord,
        IgaApprovalRecord, IgaCertificationRecord, IgaEntitlementRecord, IgaFindingRecord,
        IgaJitPrivilegeGrantRecord,
    },
    state::SharedState,
    util::now_seconds,
};
use qid_storage::prelude::*;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::engine::*;

const ADMIN_SESSION_ID_HEADER: &str = "x-qid-admin-session-id";

fn header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(crate) async fn require_admin_session<R: Repository>(
    headers: &HeaderMap,
    state: &Arc<SharedState<R>>,
) -> Result<Admin, axum::response::Response> {
    let session_id = header_string(headers, ADMIN_SESSION_ID_HEADER)
        .ok_or_else(|| unauthorized_response("admin session required"))?;
    let elevation = state
        .repo
        .get_admin_elevation(&session_id)
        .await
        .map_err(|e| storage_error_response("get_admin_elevation", e))?
        .ok_or_else(|| unauthorized_response("admin elevation session not found"))?;
    let admin = state
        .repo
        .get_admin_by_id(&elevation.admin_id)
        .await
        .map_err(|e| storage_error_response("get_admin_by_id", e))?
        .ok_or_else(|| unauthorized_response("admin record not found"))?;
    enforce_iga_admin_authorization(&admin, &elevation, &state.config.admin.security)
        .map_err(|response| *response)?;
    Ok(admin)
}

pub(crate) fn resolve_admin_tenant_id<R>(
    explicit: Option<&str>,
    state: &SharedState<R>,
    admin: &Admin,
) -> Result<String, Box<axum::response::Response>> {
    let tenant_id = resolve_tenant_id(explicit, state)
        .map_err(|()| Box::new(tenant_scope_unavailable_response()))?;
    if tenant_id != admin.tenant_id {
        return Err(Box::new(unauthorized_response(
            "admin tenant does not match requested tenant",
        )));
    }
    Ok(tenant_id)
}

fn enforce_iga_admin_authorization(
    admin: &Admin,
    elevation: &AdminElevation,
    security: &AdminSecurityConfig,
) -> Result<(), Box<axum::response::Response>> {
    if admin.tenant_id != elevation.tenant_id {
        return Err(Box::new(unauthorized_response(
            "admin elevation belongs to a different tenant",
        )));
    }

    let now = now_seconds();
    if elevation.elevation_expires_at <= now {
        return Err(Box::new(unauthorized_response(
            "admin elevation has expired",
        )));
    }
    if elevation.elevation_expires_at.saturating_sub(now) > security.max_elevation_seconds {
        return Err(Box::new(unauthorized_response(
            "admin elevation lifetime exceeds configured maximum",
        )));
    }

    if security.require_step_up {
        let acr_ok = elevation.acr.as_deref() == Some(security.required_acr.as_str());
        let amr_ok = elevation
            .amr
            .iter()
            .any(|method| security.required_amr.contains(method));
        if !acr_ok || !amr_ok {
            return Err(Box::new(unauthorized_response("admin step-up is required")));
        }
    }

    if !admin.roles.iter().any(|role| iga_role_allows(role)) {
        return Err(Box::new(unauthorized_response(
            "admin role is not allowed for IGA operations",
        )));
    }

    Ok(())
}

fn iga_role_allows(role: &str) -> bool {
    matches!(
        role,
        "tenant.owner" | "realm.admin" | "directory.admin" | "security.admin"
    )
}

mod access;
mod catalog;
mod findings;
mod rebac;
mod review;

use access::*;
use catalog::*;
use findings::*;
use rebac::rebac_routes;
use review::*;

pub fn iga_routes<R: Repository>() -> Router<Arc<SharedState<R>>> {
    Router::new()
        .route(
            "/iga/v1/entitlements",
            get(entitlements::<R>).post(upsert_entitlement::<R>),
        )
        .route(
            "/iga/v1/entitlements/:id",
            axum::routing::delete(delete_entitlement::<R>),
        )
        .route(
            "/iga/v1/access-packages",
            get(access_packages::<R>).post(upsert_access_package::<R>),
        )
        .route(
            "/iga/v1/access-packages/:id",
            axum::routing::delete(delete_access_package::<R>),
        )
        .route("/iga/v1/access-requests", post(access_request::<R>))
        .route(
            "/iga/v1/access-requests/approvals/validate",
            post(validate_approvals::<R>),
        )
        .route("/iga/v1/access-grants", get(list_access_grants::<R>))
        .route(
            "/iga/v1/access-grants/:id/revoke",
            post(revoke_access_grant::<R>),
        )
        .route(
            "/iga/v1/jit-privileges",
            get(list_jit_privileges::<R>).post(issue_jit_privilege::<R>),
        )
        .route(
            "/iga/v1/jit-privileges/:id/revoke",
            post(revoke_jit_privilege::<R>),
        )
        .route(
            "/iga/v1/access-reviews",
            get(list_access_reviews::<R>).post(create_access_review::<R>),
        )
        .route(
            "/iga/v1/access-reviews/:id/close",
            post(close_access_review::<R>),
        )
        .route(
            "/iga/v1/access-reviews/:id/decisions",
            get(list_access_review_decisions::<R>).post(create_access_review_decision::<R>),
        )
        .route(
            "/iga/v1/certifications",
            get(list_certifications::<R>).post(create_certification::<R>),
        )
        .route("/iga/v1/findings", get(list_findings::<R>))
        .route("/iga/v1/findings/detect", post(detect_findings::<R>))
        .route("/iga/v1/findings/:id/resolve", post(resolve_finding::<R>))
        .route("/iga/v1/evidence", get(export_iga_evidence::<R>))
        .merge(rebac_routes::<R>())
}
