use super::*;
use crate::{identity::*, ops::*, policy::*};
use qid_core::models::{Admin, AdminApproval, AdminElevation};
use qid_core::tenant::RealmId;

pub(crate) const ADMIN_REASON_HEADER: &str = "x-qid-admin-reason";
pub(crate) const ADMIN_SESSION_ID_HEADER: &str = "x-qid-admin-session-id";
pub(crate) const ADMIN_APPROVAL_ID_HEADER: &str = "x-qid-admin-approval-id";
// Test-only header constants.
#[cfg(test)]
pub(crate) const ADMIN_ROLES_HEADER: &str = "x-qid-admin-roles";
#[cfg(test)]
pub(crate) const ADMIN_ACR_HEADER: &str = "x-qid-admin-acr";
#[cfg(test)]
pub(crate) const ADMIN_AMR_HEADER: &str = "x-qid-admin-amr";
#[cfg(test)]
pub(crate) const ADMIN_ELEVATION_EXPIRES_AT_HEADER: &str = "x-qid-admin-elevation-expires-at";

pub fn admin_routes<R>(_paths: &ServerPaths) -> Router<Arc<SharedState<R>>>
where
    R: Repository,
{
    Router::new()
        .route("/admin/ui", get(admin_ui))
        .route("/admin/api/v1/ui/dashboard", get(admin_dashboard::<R>))
        .route(
            "/admin/api/v1/breakglass/sessions/:session_id/revoke",
            post(breakglass_revoke_session::<R>),
        )
        .route(
            "/admin/api/v1/key-rotation/plan",
            post(plan_key_rotation_admin::<R>),
        )
        .route(
            "/admin/api/v1/:realm/policy/simulate",
            post(simulate_policy::<R>),
        )
        .route("/admin/api/v1/realms", get(list_realms::<R>))
        .route("/admin/api/v1/realms", post(create_realm::<R>))
        .route("/admin/api/v1/realms/:realm", get(get_realm::<R>))
        .route("/admin/api/v1/realms/:realm", delete(delete_realm::<R>))
        .route("/admin/api/v1/:realm/users", get(list_users::<R>))
        .route("/admin/api/v1/:realm/users", post(create_user::<R>))
        .route("/admin/api/v1/:realm/users/:user_id", get(get_user::<R>))
        .route("/admin/api/v1/:realm/users/:user_id", put(update_user::<R>))
        .route(
            "/admin/api/v1/:realm/users/:user_id",
            delete(delete_user::<R>),
        )
        .route(
            "/admin/api/v1/:realm/sessions",
            get(list_sessions_handler::<R>),
        )
        .route(
            "/admin/api/v1/:realm/sessions/:session_id/revoke",
            post(revoke_session_handler::<R>),
        )
        .route(
            "/admin/api/v1/:realm/token-families",
            get(list_token_families_handler::<R>),
        )
        .route(
            "/admin/api/v1/:realm/token-families/:family_id/revoke",
            post(revoke_token_family_handler::<R>),
        )
        .route(
            "/admin/api/v1/:realm/pep-decisions",
            get(list_pep_decisions_handler::<R>),
        )
        .route(
            "/admin/api/v1/:realm/risk-events",
            get(list_risk_events_handler::<R>),
        )
        .route("/admin/api/v1/:realm/clients", get(list_clients::<R>))
        .route("/admin/api/v1/:realm/clients", post(create_client::<R>))
        .route(
            "/admin/api/v1/:realm/clients/:client_id",
            delete(delete_client::<R>),
        )
        .route(
            "/admin/api/v1/:realm/service-accounts",
            get(list_service_accounts_handler::<R>),
        )
        .route(
            "/admin/api/v1/:realm/service-accounts",
            post(create_service_account_handler::<R>),
        )
        .route(
            "/admin/api/v1/:realm/service-accounts/:sa_id",
            delete(delete_service_account_handler::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/custom-domains",
            get(list_custom_domains::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/custom-domains",
            post(create_custom_domain::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/custom-domains/:domain_id",
            delete(delete_custom_domain::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/custom-domains/:domain_id/activate",
            post(activate_custom_domain::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/custom-domains/:domain_id/renew-certificate",
            post(renew_custom_domain_certificate::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/app-catalog",
            get(list_app_catalog_entries::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/app-catalog",
            post(create_app_catalog_entry::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/app-catalog/:entry_id",
            delete(delete_app_catalog_entry::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/ciam-brands",
            get(list_ciam_brands::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/ciam-brands",
            post(create_ciam_brand::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/ciam-brands/:brand_id",
            delete(delete_ciam_brand::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/marketplace-connectors",
            get(list_marketplace_connectors::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/marketplace-connectors",
            post(create_marketplace_connector::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/marketplace-connectors/:connector_id",
            delete(delete_marketplace_connector::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/usage-billing-events",
            get(list_usage_billing_events::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/usage-billing-events",
            post(create_usage_billing_event::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/compliance-evidence-packs",
            get(list_compliance_evidence_packs::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/compliance-evidence-packs",
            post(create_compliance_evidence_pack::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/delegated-admins",
            get(list_delegated_tenant_admins::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/delegated-admins",
            post(create_delegated_tenant_admin::<R>),
        )
        .route(
            "/admin/api/v1/tenants/:tenant/delegated-admins/:admin_id/revoke",
            post(revoke_delegated_tenant_admin::<R>),
        )
        .route("/admin/api/v1/audit/export", get(export_global_audit::<R>))
        .route(
            "/admin/api/v1/:realm/audit/export",
            get(export_realm_audit::<R>),
        )
        .route("/admin/api/v1/audit/verify", get(verify_global_audit::<R>))
        .route(
            "/admin/api/v1/:realm/audit/verify",
            get(verify_realm_audit::<R>),
        )
        .route(
            "/admin/api/v1/audit/retention",
            get(get_global_audit_retention::<R>),
        )
        .route(
            "/admin/api/v1/audit/retention",
            put(put_global_audit_retention::<R>),
        )
        .route(
            "/admin/api/v1/audit/retention/plan",
            get(plan_global_audit_retention::<R>),
        )
        .route(
            "/admin/api/v1/:realm/audit/retention",
            get(get_realm_audit_retention::<R>),
        )
        .route(
            "/admin/api/v1/:realm/audit/retention",
            put(put_realm_audit_retention::<R>),
        )
        .route(
            "/admin/api/v1/:realm/audit/retention/plan",
            get(plan_realm_audit_retention::<R>),
        )
        .route("/admin/api/v1/audit", get(list_global_audit::<R>))
        .route("/admin/api/v1/:realm/audit", get(list_realm_audit::<R>))
}

pub(crate) fn admin_reason(headers: &HeaderMap) -> QidResult<String> {
    let reason = headers
        .get(ADMIN_REASON_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| QidError::BadRequest {
            message: format!("{ADMIN_REASON_HEADER} header is required for admin mutation"),
        })?;
    Ok(reason.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdminPermission {
    RealmAdmin,
    AppAdmin,
    DirectoryAdmin,
    SecurityAdmin,
    AuditRead,
    TenantAdmin,
    PlatformAdmin,
    PlatformSecurityAdmin,
    PlatformAuditRead,
    BreakGlass,
}

#[cfg(test)]
fn comma_header_values(headers: &HeaderMap, name: &str) -> Vec<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
fn admin_roles(headers: &HeaderMap) -> Vec<String> {
    comma_header_values(headers, ADMIN_ROLES_HEADER)
}

#[cfg(test)]
fn admin_amr(headers: &HeaderMap) -> Vec<String> {
    comma_header_values(headers, ADMIN_AMR_HEADER)
}

#[cfg(test)]
pub(crate) fn admin_has_step_up(headers: &HeaderMap, security: &AdminSecurityConfig) -> bool {
    if !security.require_step_up {
        return true;
    }
    let acr = headers
        .get(ADMIN_ACR_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim);
    let amr = admin_amr(headers);
    acr == Some(security.required_acr.as_str())
        && amr.iter().any(|method| {
            security
                .required_amr
                .iter()
                .any(|required| required == method)
        })
}

pub(crate) fn role_allows(
    permission: AdminPermission,
    role: &str,
    security: &AdminSecurityConfig,
) -> bool {
    if role == "tenant.owner" {
        return permission == AdminPermission::TenantAdmin;
    }
    if security.breakglass_enabled && role == "breakglass" {
        return true;
    }
    match permission {
        AdminPermission::RealmAdmin => role == "realm.admin",
        AdminPermission::AppAdmin => role == "app.admin",
        AdminPermission::DirectoryAdmin => role == "directory.admin",
        AdminPermission::SecurityAdmin => role == "security.admin",
        AdminPermission::AuditRead => role == "auditor" || role == "security.admin",
        AdminPermission::TenantAdmin => role == "app.admin" || role == "realm.admin",
        AdminPermission::PlatformAdmin => role == "platform.admin",
        AdminPermission::PlatformSecurityAdmin => {
            role == "platform.admin" || role == "platform.security.admin"
        }
        AdminPermission::PlatformAuditRead => {
            role == "platform.admin"
                || role == "platform.security.admin"
                || role == "platform.auditor"
        }
        AdminPermission::BreakGlass => false,
    }
}

#[cfg(test)]
pub(crate) fn admin_elevation_expires_at(headers: &HeaderMap) -> QidResult<u64> {
    let value = headers
        .get(ADMIN_ELEVATION_EXPIRES_AT_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| QidError::Unauthorized {
            message: format!("{ADMIN_ELEVATION_EXPIRES_AT_HEADER} header is required"),
        })?;
    value.parse::<u64>().map_err(|_| QidError::BadRequest {
        message: format!("{ADMIN_ELEVATION_EXPIRES_AT_HEADER} must be a unix timestamp"),
    })
}

pub(crate) fn header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

async fn resolve_admin_approval<R: Repository>(
    state: &Arc<SharedState<R>>,
    headers: &HeaderMap,
) -> QidResult<Option<AdminApproval>> {
    let approval_id = header_string(headers, ADMIN_APPROVAL_ID_HEADER);
    match approval_id {
        Some(id) => state.repo.get_admin_approval(&id).await,
        None => Ok(None),
    }
}

/// Header-only authorization for unit tests.
#[cfg(test)]
pub(crate) fn authorize_admin_headers(
    headers: &HeaderMap,
    permission: AdminPermission,
    security: &AdminSecurityConfig,
) -> QidResult<()> {
    if !admin_has_step_up(headers, security) {
        return Err(QidError::Unauthorized {
            message: format!(
                "admin step-up is required: {ADMIN_ACR_HEADER} must be {} and {ADMIN_AMR_HEADER} must include one of {:?}",
                security.required_acr, security.required_amr
            ),
        });
    }
    let now = qid_core::util::now_seconds();
    let expires_at = admin_elevation_expires_at(headers)?;
    if expires_at <= now {
        return Err(QidError::Unauthorized {
            message: "admin elevation has expired".to_string(),
        });
    }
    if expires_at.saturating_sub(now) > security.max_elevation_seconds {
        return Err(QidError::Unauthorized {
            message: "admin elevation lifetime exceeds configured maximum".to_string(),
        });
    }
    let roles = admin_roles(headers);
    if roles
        .iter()
        .any(|role| role_allows(permission, role, security))
    {
        return Ok(());
    }
    Err(QidError::Unauthorized {
        message: "admin role is not allowed for this operation".to_string(),
    })
}

/// Resolve the authenticated admin from the session elevation, without requiring any
/// specific permission. Returns (Admin, AdminElevation) or an Unauthorized error.
pub(crate) async fn resolve_authenticated_admin<R: Repository>(
    state: &Arc<SharedState<R>>,
    headers: &HeaderMap,
) -> QidResult<(Admin, AdminElevation)> {
    let session_id =
        header_string(headers, ADMIN_SESSION_ID_HEADER).ok_or_else(|| QidError::Unauthorized {
            message: format!("{ADMIN_SESSION_ID_HEADER} header is required"),
        })?;
    let elevation = state
        .repo
        .get_admin_elevation(&session_id)
        .await?
        .ok_or_else(|| QidError::Unauthorized {
            message: "admin elevation session not found".to_string(),
        })?;
    let admin = state
        .repo
        .get_admin_by_id(&elevation.admin_id)
        .await?
        .ok_or_else(|| QidError::Unauthorized {
            message: "admin record for elevation not found".to_string(),
        })?;
    Ok((admin, elevation))
}

/// Returns (Admin, AdminElevation) so callers can use both for audit logging.
#[allow(unused_variables)]
pub(crate) async fn authorize_admin<R: Repository>(
    state: &Arc<SharedState<R>>,
    headers: &HeaderMap,
    permission: AdminPermission,
    security: &AdminSecurityConfig,
    realm: Option<&str>,
) -> QidResult<(Admin, AdminElevation)> {
    let (admin, elevation) = resolve_authenticated_admin(state, headers).await?;
    enforce_admin_tenant_binding(state, realm, &admin, &elevation, None).await?;

    if security.require_step_up {
        let acr_ok = elevation.acr.as_deref() == Some(security.required_acr.as_str());
        let amr_ok = elevation
            .amr
            .iter()
            .any(|method| security.required_amr.contains(method));
        if !acr_ok || !amr_ok {
            return Err(QidError::Unauthorized {
                message: format!(
                    "admin step-up is required: ACR must be {} and AMR must include one of {:?}",
                    security.required_acr, security.required_amr
                ),
            });
        }
    }
    let now = qid_core::util::now_seconds();
    if elevation.elevation_expires_at <= now {
        return Err(QidError::Unauthorized {
            message: "admin elevation has expired".to_string(),
        });
    }
    if elevation.elevation_expires_at.saturating_sub(now) > security.max_elevation_seconds {
        return Err(QidError::Unauthorized {
            message: "admin elevation lifetime exceeds configured maximum".to_string(),
        });
    }

    if admin
        .roles
        .iter()
        .any(|role| role_allows(permission, role, security))
    {
        return Ok((admin, elevation));
    }
    Err(QidError::Unauthorized {
        message: "admin role is not allowed for this operation".to_string(),
    })
}

pub(crate) async fn authorize_admin_for_tenant<R: Repository>(
    state: &Arc<SharedState<R>>,
    headers: &HeaderMap,
    permission: AdminPermission,
    security: &AdminSecurityConfig,
    tenant_id: &str,
) -> QidResult<(Admin, AdminElevation)> {
    let (admin, elevation) = authorize_admin(state, headers, permission, security, None).await?;
    enforce_admin_path_tenant_binding(&admin, tenant_id)?;
    Ok((admin, elevation))
}

/// Returns (Admin, AdminElevation) so callers can use both for audit logging.
pub(crate) async fn authorize_admin_mutation<R: Repository>(
    state: &Arc<SharedState<R>>,
    headers: &HeaderMap,
    permission: AdminPermission,
    security: &AdminSecurityConfig,
    realm: Option<&str>,
) -> QidResult<(Admin, AdminElevation)> {
    if security.require_reason {
        admin_reason(headers)?;
    }
    let stored_approval = resolve_admin_approval(state, headers).await?;
    match stored_approval {
        Some(ref a) => {
            if a.consumed {
                return Err(QidError::Unauthorized {
                    message: "admin approval has already been consumed".to_string(),
                });
            }
            if a.expires_at <= qid_core::util::now_seconds() {
                return Err(QidError::Unauthorized {
                    message: "admin approval has expired".to_string(),
                });
            }
        }
        None => {
            if security.require_approval {
                return Err(QidError::Unauthorized {
                    message: "admin approval is required but no approval record was found"
                        .to_string(),
                });
            }
        }
    }
    let (admin, elevation) = authorize_admin(state, headers, permission, security, realm).await?;

    if let Some(ref a) = stored_approval {
        enforce_admin_tenant_binding(state, realm, &admin, &elevation, Some(a)).await?;
        if a.target_admin_id != admin.id {
            return Err(QidError::Unauthorized {
                message: "admin approval targets a different admin".to_string(),
            });
        }
        if !state
            .repo
            .consume_admin_approval_if_unconsumed(&a.id)
            .await?
        {
            return Err(QidError::Unauthorized {
                message: "admin approval has already been consumed".to_string(),
            });
        }
    }
    Ok((admin, elevation))
}

pub(crate) async fn authorize_admin_mutation_for_tenant<R: Repository>(
    state: &Arc<SharedState<R>>,
    headers: &HeaderMap,
    permission: AdminPermission,
    security: &AdminSecurityConfig,
    tenant_id: &str,
) -> QidResult<(Admin, AdminElevation)> {
    let (admin, elevation) =
        authorize_admin_mutation(state, headers, permission, security, None).await?;
    enforce_admin_path_tenant_binding(&admin, tenant_id)?;
    Ok((admin, elevation))
}

/// Returns (Admin, AdminElevation) so callers can use both for audit logging.
pub(crate) async fn authorize_breakglass_mutation<R: Repository>(
    state: &Arc<SharedState<R>>,
    headers: &HeaderMap,
    security: &AdminSecurityConfig,
    realm: Option<&str>,
) -> QidResult<(Admin, AdminElevation)> {
    if !security.breakglass_enabled {
        return Err(QidError::Unauthorized {
            message: "break-glass operations are disabled".to_string(),
        });
    }
    if security.require_reason {
        admin_reason(headers)?;
    }
    let stored_approval = resolve_admin_approval(state, headers).await?;
    match stored_approval {
        Some(ref a) => {
            if a.consumed {
                return Err(QidError::Unauthorized {
                    message: "admin approval has already been consumed".to_string(),
                });
            }
            if a.expires_at <= qid_core::util::now_seconds() {
                return Err(QidError::Unauthorized {
                    message: "admin approval has expired".to_string(),
                });
            }
        }
        None => {
            if security.require_approval {
                return Err(QidError::Unauthorized {
                    message: "admin approval is required but no approval record was found"
                        .to_string(),
                });
            }
        }
    }
    let (admin, elevation) =
        authorize_admin(state, headers, AdminPermission::BreakGlass, security, realm).await?;

    // Verify approval targets this admin.
    if let Some(ref a) = stored_approval {
        enforce_admin_tenant_binding(state, realm, &admin, &elevation, Some(a)).await?;
        if a.target_admin_id != admin.id {
            return Err(QidError::Unauthorized {
                message: "admin approval targets a different admin".to_string(),
            });
        }
        if !state
            .repo
            .consume_admin_approval_if_unconsumed(&a.id)
            .await?
        {
            return Err(QidError::Unauthorized {
                message: "admin approval has already been consumed".to_string(),
            });
        }
    }
    Ok((admin, elevation))
}

async fn enforce_admin_tenant_binding<R: Repository>(
    state: &Arc<SharedState<R>>,
    realm: Option<&str>,
    admin: &Admin,
    elevation: &AdminElevation,
    approval: Option<&AdminApproval>,
) -> QidResult<()> {
    if admin.tenant_id != elevation.tenant_id {
        return Err(QidError::Unauthorized {
            message: "admin elevation belongs to a different tenant".to_string(),
        });
    }
    if let Some(approval) = approval
        && approval.tenant_id != admin.tenant_id
    {
        return Err(QidError::Unauthorized {
            message: "admin approval belongs to a different tenant".to_string(),
        });
    }
    let Some(realm) = realm else {
        return Ok(());
    };
    let tenant_id = state
        .repo
        .get_realm_tenant(&RealmId(realm.to_string()))
        .await?
        .ok_or_else(|| QidError::Unauthorized {
            message: "admin realm tenant binding was not found".to_string(),
        })?;
    if tenant_id != admin.tenant_id {
        return Err(QidError::Unauthorized {
            message: "admin tenant does not match realm tenant".to_string(),
        });
    }
    Ok(())
}

fn enforce_admin_path_tenant_binding(admin: &Admin, tenant_id: &str) -> QidResult<()> {
    if admin.tenant_id != tenant_id {
        return Err(QidError::Unauthorized {
            message: "admin tenant does not match tenant path".to_string(),
        });
    }
    Ok(())
}

pub(crate) fn admin_session_metadata(
    admin: &Admin,
    elevation: &AdminElevation,
) -> serde_json::Value {
    serde_json::json!({
        "admin_id": admin.id,
        "subject": admin.subject,
        "tenant_id": admin.tenant_id,
        "roles": admin.roles,
        "admin_session_id": elevation.id,
        "acr": elevation.acr,
        "amr": elevation.amr,
        "elevation_expires_at": elevation.elevation_expires_at,
    })
}

// --- PEP decision storage ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PepDecisionRecord {
    pub decision_id: String,
    pub realm: String,
    pub decision: String,
    pub policy_id: Option<String>,
    pub policy_tags: Vec<String>,
    pub request_id: Option<String>,
    pub created_at: u64,
}

pub(crate) static PEP_DECISIONS: std::sync::LazyLock<std::sync::Mutex<Vec<PepDecisionRecord>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

/// Record a PEP decision for later viewing. Called by pep_decision.
pub fn record_pep_decision(record: PepDecisionRecord) {
    let Ok(mut decisions) = PEP_DECISIONS.lock() else {
        return;
    };
    // Keep only the last 1000 decisions
    if decisions.len() >= 1000 {
        decisions.remove(0);
    }
    decisions.push(record);
}
