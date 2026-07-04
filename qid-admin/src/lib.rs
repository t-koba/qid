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
