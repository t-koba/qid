#![forbid(unsafe_code)]
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{Html, IntoResponse},
    routing::{delete, get, post, put},
};
use qid_core::{
    config::{AdminSecurityConfig, ServerPaths},
    error::{QidError, QidResult},
    models::{
        Admin, AdminElevation, AppCatalogEntry, AuditEvent, AuditRetentionConfig, CiamBrand,
        Client, ClientType, ComplianceEvidencePack, CustomDomain, DelegatedTenantAdmin,
        MarketplaceConnector, UsageBillingEvent, User,
    },
    state::SharedState,
    tenant::{RealmId, TenantId},
};

use qid_observability::audit::{AuditExportOptions, export_jsonl};
use qid_ops::{KeyRotationRequirement, KeyringInventoryRecord, plan_key_rotation};
use qid_policy::{DecisionDetails, NativePolicyEngine, PolicyContext, PolicyEngine};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use ulid::Ulid;

macro_rules! authorize_admin_or_return {
    ($authorization:expr) => {
        match ($authorization).await {
            Ok(context) => context,
            Err(error) => return qid_http::error_response(error),
        }
    };
}
pub(crate) use authorize_admin_or_return;

/// Authorizes the admin request in scope and yields the admin context.
/// `$authorize` names the authorization variant; the required permission and
/// the realm scope stay visible at the call site.
macro_rules! admin_context {
    ($state:expr, $headers:expr, $authorize:ident, $permission:expr, $scope:expr) => {
        crate::authorize_admin_or_return!($authorize(
            (&$state),
            $headers,
            $permission,
            &$state.config.admin.security,
            $scope,
        ))
    };
}

/// Read-only admin authorization, optionally scoped to a realm.
macro_rules! admin_read {
    ($state:expr, $headers:expr, $permission:expr, $scope:expr) => {
        admin_context!($state, $headers, authorize_admin, $permission, $scope)
    };
}

/// Mutating admin authorization, optionally scoped to a realm.
macro_rules! admin_mutation {
    ($state:expr, $headers:expr, $permission:expr, $scope:expr) => {
        admin_context!(
            $state,
            $headers,
            authorize_admin_mutation,
            $permission,
            $scope
        )
    };
}

/// Read-only admin authorization bound to the tenant in the path.
macro_rules! admin_tenant_read {
    ($state:expr, $headers:expr, $permission:expr, $tenant:expr) => {
        admin_context!(
            $state,
            $headers,
            authorize_admin_for_tenant,
            $permission,
            $tenant
        )
    };
}

/// Mutating admin authorization bound to the tenant in the path.
macro_rules! admin_tenant_mutation {
    ($state:expr, $headers:expr, $permission:expr, $tenant:expr) => {
        admin_context!(
            $state,
            $headers,
            authorize_admin_mutation_for_tenant,
            $permission,
            $tenant
        )
    };
}

mod identity;
mod ops;
mod policy;
mod saas;

use saas::*;

mod authz;

use authz::*;
pub use authz::{PepDecisionRecord, admin_routes, record_pep_decision};

mod audit;

use audit::*;

// ── Realm handlers ────────────────────────────────────────────────────────────

mod directory;

use directory::*;

// ── SaaS tenant handlers ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
