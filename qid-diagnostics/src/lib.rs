use qid_core::config::QidConfig;
use qid_core::models::{AppCatalogEntry, MarketplaceConnector, MarketplaceConnectorType};
use qid_core::tenant::RealmId;
use qid_storage::{AnyRepository, prelude::*};
use serde::Serialize;
use std::path::Path;

mod config;
mod network;
mod ops_checks;
mod profile;
mod storage;

use config::*;
use network::*;
use ops_checks::*;
use profile::*;
pub use storage::{check_storage_saas, check_storage_saas_with_repo};

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct CheckReport {
    pub status: String,
    pub summary: CheckSummary,
    pub checks: Vec<CheckItem>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct CheckSummary {
    pub realms: usize,
    pub pep_registrations: usize,
    pub pep_registrations_count: usize,
    pub keyrings: usize,
    pub errors: usize,
    pub warnings: usize,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct CheckItem {
    pub name: String,
    pub status: CheckStatus,
    pub message: String,
}

impl CheckReport {
    pub fn extend_checks(&mut self, checks: Vec<CheckItem>) {
        self.checks.extend(checks);
        self.summary.errors = self
            .checks
            .iter()
            .filter(|check| check.status == CheckStatus::Error)
            .count();
        self.summary.warnings = self
            .checks
            .iter()
            .filter(|check| check.status == CheckStatus::Warning)
            .count();
        self.status = if self.summary.errors > 0 {
            "error"
        } else if self.summary.warnings > 0 {
            "warning"
        } else {
            "ok"
        }
        .to_string();
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Ok,
    Warning,
    Error,
    NotApplicable,
}

pub fn build_check_report(
    config: &QidConfig,
    plan: &qid_core::plan::RuntimePlan,
    config_path: &Path,
) -> CheckReport {
    let mut checks = Vec::new();
    checks.push(check_listen(config));
    checks.push(check_public_base_url(config));
    checks.push(check_deployment_profile(config, plan));
    checks.extend(check_profile_obligations(config));
    checks.extend(check_issuer_alignment(config, plan));
    checks.extend(check_weak_flows(config));
    checks.extend(check_policy_bundles(config, config_path));
    checks.extend(check_pep_registrations(config));
    checks.extend(check_resource_servers(config));
    checks.push(check_metrics_listen(config));
    checks.extend(check_keyrings(config));
    checks.push(check_redirect_uri_surface(config));
    checks.extend(check_saml_metadata(config));
    checks.extend(check_scim_schemas(config));
    checks.extend(check_ops_cache(config));
    checks.extend(check_ops_cluster(config));
    checks.extend(check_ops_backup(config));

    let errors = checks
        .iter()
        .filter(|check| check.status == CheckStatus::Error)
        .count();
    let warnings = checks
        .iter()
        .filter(|check| check.status == CheckStatus::Warning)
        .count();
    let pep_registrations = config
        .realms
        .iter()
        .map(|realm| realm.pep_registrations.registrations.len())
        .sum();
    let status = if errors > 0 {
        "error"
    } else if warnings > 0 {
        "warning"
    } else {
        "ok"
    }
    .to_string();

    CheckReport {
        status,
        summary: CheckSummary {
            realms: config.realms.len(),
            pep_registrations,
            pep_registrations_count: pep_registrations,
            keyrings: config.crypto.keyrings.len(),
            errors,
            warnings,
        },
        checks,
    }
}

pub(crate) fn check_ok(name: impl Into<String>, message: impl Into<String>) -> CheckItem {
    CheckItem {
        name: name.into(),
        status: CheckStatus::Ok,
        message: message.into(),
    }
}

pub(crate) fn check_warning(name: impl Into<String>, message: impl Into<String>) -> CheckItem {
    CheckItem {
        name: name.into(),
        status: CheckStatus::Warning,
        message: message.into(),
    }
}

pub(crate) fn check_error(name: impl Into<String>, message: impl Into<String>) -> CheckItem {
    CheckItem {
        name: name.into(),
        status: CheckStatus::Error,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests;
