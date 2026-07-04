//! Adaptive risk scoring.
#![forbid(unsafe_code)]

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    routing::post,
};
use qid_core::{
    error::{QidError, QidResult},
    models::AuditEvent,
    state::SharedState,
};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

pub fn risk_routes<R: Repository>() -> Router<Arc<SharedState<R>>> {
    Router::new().route("/risk/v1/evaluate", post(evaluate))
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskOutcome {
    Allow,
    StepUp,
    Deny,
    Quarantine,
    ForceInspect,
    ForceTunnel,
    RateLimit,
    AuditHigh,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceTrustState {
    Managed,
    Registered,
    Unknown,
    Unmanaged,
    Compromised,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DestinationReputation {
    KnownGood,
    Unknown,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GeoPoint {
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoginSignal {
    pub epoch_seconds: u64,
    #[serde(default)]
    pub location: Option<GeoPoint>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub asn: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PepSignal {
    #[serde(default)]
    pub edge_name: Option<String>,
    #[serde(default)]
    pub route: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub destination_category: Option<String>,
    #[serde(default)]
    pub destination_reputation: Option<DestinationReputation>,
    #[serde(default)]
    pub application: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DevicePostureSignal {
    #[serde(default)]
    pub managed: bool,
    #[serde(default)]
    pub encrypted: bool,
    #[serde(default)]
    pub edr: bool,
    #[serde(default)]
    pub os_outdated: bool,
    #[serde(default)]
    pub jailbreak_or_root: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TenantPolicySignal {
    #[serde(default)]
    pub current_country: Option<String>,
    #[serde(default)]
    pub allowed_countries: Vec<String>,
    #[serde(default)]
    pub network_allowed: Option<bool>,
    #[serde(default)]
    pub working_hours_allowed: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TokenSignal {
    #[serde(default)]
    pub sender_constrained: bool,
    #[serde(default)]
    pub token_age_seconds: Option<u64>,
    #[serde(default)]
    pub auth_time_age_seconds: Option<u64>,
    #[serde(default)]
    pub acr: Option<String>,
    #[serde(default)]
    pub amr: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RiskInput {
    #[serde(default)]
    pub realm_id: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub previous_login: Option<LoginSignal>,
    #[serde(default)]
    pub current_login: Option<LoginSignal>,
    #[serde(default = "default_device_trust_state")]
    pub device_trust: DeviceTrustState,
    #[serde(default)]
    pub high_risk_asn: bool,
    #[serde(default)]
    pub anonymous_network: bool,
    #[serde(default = "default_destination_reputation")]
    pub destination_reputation: DestinationReputation,
    #[serde(default)]
    pub phishing_resistant_mfa_satisfied: bool,
    #[serde(default)]
    pub step_up_succeeded: bool,
    #[serde(default)]
    pub new_device: bool,
    #[serde(default)]
    pub impossible_travel: bool,
    #[serde(default)]
    pub unmanaged_device: bool,
    #[serde(default)]
    pub malicious_destination: bool,
    #[serde(default)]
    pub pep: Option<PepSignal>,
    #[serde(default)]
    pub device_posture: Option<DevicePostureSignal>,
    #[serde(default)]
    pub tenant_policy: Option<TenantPolicySignal>,
    #[serde(default)]
    pub token: Option<TokenSignal>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct RiskEvaluation {
    pub score: u64,
    pub labels: Vec<String>,
    pub outcome: RiskOutcome,
    pub required_acr: Option<String>,
    pub required_amr: Vec<String>,
    pub pep_force_inspect: bool,
    pub pep_force_tunnel: bool,
    pub rate_limit_profile: Option<String>,
    pub audit_level: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskEventRecord {
    pub eval_id: String,
    pub score: u64,
    pub labels: Vec<String>,
    pub outcome: RiskOutcome,
    pub subject: Option<String>,
    pub created_at: u64,
}

static RISK_EVENTS: std::sync::LazyLock<Mutex<Vec<RiskEventRecord>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

/// Record a risk evaluation for later viewing.
pub fn record_risk_event(record: RiskEventRecord) {
    let Ok(mut events) = RISK_EVENTS.lock() else {
        return;
    };
    if events.len() >= 1000 {
        events.remove(0);
    }
    events.push(record);
}

/// Get recorded risk events (for admin API).
pub fn risk_events() -> Vec<RiskEventRecord> {
    RISK_EVENTS
        .lock()
        .map(|events| events.clone())
        .unwrap_or_default()
}

async fn evaluate<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(input): Json<RiskInput>,
) -> impl IntoResponse {
    let adapter = match authenticate_risk_adapter(&headers, &state) {
        Ok(adapter) => adapter,
        Err(error) => return unauthorized_response(error),
    };
    let audit_realm_id = match input.realm_id.as_deref() {
        Some(realm_id) if realm_id != adapter.realm_id => {
            return unauthorized_response(QidError::Unauthorized {
                message: "risk evaluation realm does not match adapter realm".to_string(),
            });
        }
        Some(realm_id) => realm_id.to_string(),
        None => adapter.realm_id,
    };
    let evaluation = evaluate_risk(&input);
    let eval_id = ulid::Ulid::new().to_string();
    let now = qid_core::util::now_seconds();
    let record = RiskEventRecord {
        eval_id: eval_id.clone(),
        score: evaluation.score,
        labels: evaluation.labels.clone(),
        outcome: evaluation.outcome.clone(),
        subject: input.subject.clone(),
        created_at: now,
    };
    record_risk_event(record);
    // Persist risk event as an audit event for durability.
    if let Err(err) = state
        .repo
        .append_audit_event(&AuditEvent {
            id: format!("risk_{eval_id}"),
            realm_id: Some(audit_realm_id),
            actor: input.subject.clone().unwrap_or_default(),
            action: "risk.evaluate".to_string(),
            target_type: "risk_event".to_string(),
            target_id: eval_id.clone(),
            reason: format!(
                "score={},outcome={:?}",
                evaluation.score, evaluation.outcome
            ),
            metadata_json: serde_json::json!({
                "score": evaluation.score,
                "labels": evaluation.labels,
                "outcome": format!("{:?}", evaluation.outcome),
                "subject": input.subject,
            }),
            created_at: now,
            previous_hash: None,
            event_hash: None,
        })
        .await
    {
        tracing::warn!("failed to persist risk evaluation audit event: {err}");
    }
    Json(evaluation).into_response()
}

struct RiskAdapterAuthentication {
    realm_id: String,
}

fn authenticate_risk_adapter<R: Repository>(
    headers: &HeaderMap,
    state: &SharedState<R>,
) -> QidResult<RiskAdapterAuthentication> {
    let token = bearer_token(headers).ok_or_else(|| QidError::Unauthorized {
        message: "risk evaluation adapter token is required".to_string(),
    })?;
    let mut last_error = None;
    for realm in &state.config.realms {
        for adapter in &realm.pep_registrations.registrations {
            let Some(audience) = adapter.audience.as_deref() else {
                continue;
            };
            match state.signer.decode_with_aud(token, audience) {
                Ok(decoded) if decoded.claims.sub.as_deref() == Some(adapter.name.as_str()) => {
                    return Ok(RiskAdapterAuthentication {
                        realm_id: realm.id.clone(),
                    });
                }
                Ok(_) => {
                    last_error = Some("risk evaluation adapter token subject mismatch".to_string());
                }
                Err(_) => {
                    last_error = Some("invalid risk evaluation adapter token".to_string());
                }
            }
        }
    }
    Err(QidError::Unauthorized {
        message: last_error.unwrap_or_else(|| "unknown risk evaluation adapter".to_string()),
    })
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty() && !token.contains(' ')).then_some(token)
}

fn unauthorized_response(error: QidError) -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": error.message() })),
    )
        .into_response()
}

pub fn evaluate_risk(input: &RiskInput) -> RiskEvaluation {
    let mut score = 10_u64;
    let mut labels = vec!["baseline".to_string()];

    if input.new_device {
        score += 20;
        labels.push("new-device".to_string());
    }
    if input.impossible_travel || detects_impossible_travel(input) {
        score += 40;
        labels.push("impossible-travel".to_string());
    }

    match input.device_trust {
        DeviceTrustState::Managed => {
            labels.push("managed-device".to_string());
        }
        DeviceTrustState::Registered => {
            score += 5;
            labels.push("registered-device".to_string());
        }
        DeviceTrustState::Unknown => {
            score += 15;
            labels.push("unknown-device".to_string());
        }
        DeviceTrustState::Unmanaged => {
            score += 25;
            labels.push("unmanaged-device".to_string());
        }
        DeviceTrustState::Compromised => {
            score += 90;
            labels.push("compromised-device".to_string());
        }
    }

    if input.unmanaged_device {
        score += 25;
        labels.push("unmanaged-device".to_string());
    }

    if input.high_risk_asn {
        score += 25;
        labels.push("high-risk-asn".to_string());
    }
    if input.anonymous_network {
        score += 30;
        labels.push("anonymous-network".to_string());
    }

    match input.destination_reputation {
        DestinationReputation::KnownGood => {
            labels.push("known-good-destination".to_string());
        }
        DestinationReputation::Unknown => {
            score += 10;
            labels.push("unknown-destination".to_string());
        }
        DestinationReputation::Suspicious => {
            score += 35;
            labels.push("suspicious-destination".to_string());
        }
        DestinationReputation::Malicious => {
            score += 80;
            labels.push("malicious-destination".to_string());
        }
    }

    let pep_destination_reputation = input
        .pep
        .as_ref()
        .and_then(|pep| pep.destination_reputation.as_ref())
        .unwrap_or(&input.destination_reputation);
    if let Some(pep) = &input.pep {
        if let Some(edge_name) = &pep.edge_name {
            labels.push(format!("pep-edge:{edge_name}"));
        }
        if let Some(route) = &pep.route {
            labels.push(format!("pep-route:{route}"));
        }
        if let Some(category) = &pep.destination_category {
            labels.push(format!("pep-destination-category:{category}"));
            match category.as_str() {
                "malware" | "phishing" | "command-and-control" => {
                    score += 90;
                    labels.push("pep-malicious-category".to_string());
                }
                "privacy" | "health" | "banking" => {
                    score += 5;
                    labels.push("pep-sensitive-category".to_string());
                }
                "newly-registered-domain" | "unknown" => {
                    score += 20;
                    labels.push("pep-unknown-category".to_string());
                }
                _ => {}
            }
        }
        match pep_destination_reputation {
            DestinationReputation::KnownGood => {}
            DestinationReputation::Unknown => {
                score += 10;
                labels.push("pep-unknown-destination".to_string());
            }
            DestinationReputation::Suspicious => {
                score += 35;
                labels.push("pep-suspicious-destination".to_string());
            }
            DestinationReputation::Malicious => {
                score += 80;
                labels.push("pep-malicious-destination".to_string());
            }
        }
    }

    if input.malicious_destination {
        score += 80;
        labels.push("malicious-destination".to_string());
    };

    if let Some(posture) = &input.device_posture {
        if posture.managed {
            labels.push("posture-managed".to_string());
        }
        if !posture.encrypted {
            score += 15;
            labels.push("posture-unencrypted".to_string());
        }
        if !posture.edr {
            score += 10;
            labels.push("posture-no-edr".to_string());
        }
        if posture.os_outdated {
            score += 15;
            labels.push("posture-outdated-os".to_string());
        }
        if posture.jailbreak_or_root {
            score += 90;
            labels.push("posture-jailbreak-or-root".to_string());
        }
    }

    if let Some(policy) = &input.tenant_policy {
        if let (Some(country), false) = (
            policy.current_country.as_ref(),
            policy.allowed_countries.is_empty(),
        ) {
            labels.push(format!("country:{country}"));
        }
        if let Some(country) = &policy.current_country
            && !policy.allowed_countries.is_empty()
            && !policy.allowed_countries.contains(country)
        {
            score += 40;
            labels.push("country-not-allowed".to_string());
        }
        if policy.network_allowed == Some(false) {
            score += 45;
            labels.push("network-not-allowed".to_string());
        }
        if policy.working_hours_allowed == Some(false) {
            score += 15;
            labels.push("outside-working-hours".to_string());
        }
    }

    if let Some(token) = &input.token {
        if token.sender_constrained {
            score = score.saturating_sub(10);
            labels.push("sender-constrained-token".to_string());
        } else {
            score += 15;
            labels.push("bearer-token".to_string());
        }
        if token.token_age_seconds.is_some_and(|age| age > 3600) {
            score += 10;
            labels.push("old-token".to_string());
        }
        if token.auth_time_age_seconds.is_some_and(|age| age > 900) {
            score += 15;
            labels.push("stale-auth-time".to_string());
        }
        if token
            .acr
            .as_deref()
            .is_some_and(|acr| acr.contains("phishing-resistant"))
            || token
                .amr
                .iter()
                .any(|amr| amr == "webauthn" || amr == "hwk")
        {
            score = score.saturating_sub(10);
            labels.push("strong-token-auth".to_string());
        }
    }

    if input.phishing_resistant_mfa_satisfied {
        score = score.saturating_sub(20);
        labels.push("phishing-resistant-mfa".to_string());
    } else if input.step_up_succeeded {
        score = score.saturating_sub(10);
        labels.push("step-up-succeeded".to_string());
    };

    score = score.min(100);
    let pep_privacy_category = input
        .pep
        .as_ref()
        .and_then(|pep| pep.destination_category.as_deref())
        .is_some_and(|category| matches!(category, "privacy" | "health" | "banking"));
    let pep_suspicious = input.pep.as_ref().is_some_and(|pep| {
        pep.destination_reputation == Some(DestinationReputation::Suspicious)
            || pep
                .destination_category
                .as_deref()
                .is_some_and(|category| matches!(category, "newly-registered-domain" | "unknown"))
    });
    let deny_required = score >= 80
        || input.device_trust == DeviceTrustState::Compromised
        || input
            .device_posture
            .as_ref()
            .is_some_and(|posture| posture.jailbreak_or_root);
    let outcome = if deny_required {
        RiskOutcome::Deny
    } else if input.impossible_travel && input.anonymous_network {
        RiskOutcome::Quarantine
    } else if pep_privacy_category {
        RiskOutcome::ForceTunnel
    } else if pep_suspicious {
        RiskOutcome::ForceInspect
    } else if input.anonymous_network
        && matches!(
            pep_destination_reputation,
            DestinationReputation::Unknown | DestinationReputation::Suspicious
        )
    {
        RiskOutcome::RateLimit
    } else if score >= 50 {
        RiskOutcome::StepUp
    } else if score >= 45 {
        RiskOutcome::AuditHigh
    } else {
        RiskOutcome::Allow
    };

    let (required_acr, required_amr) = match outcome {
        RiskOutcome::Allow
        | RiskOutcome::ForceInspect
        | RiskOutcome::ForceTunnel
        | RiskOutcome::RateLimit
        | RiskOutcome::AuditHigh => (None, Vec::new()),
        RiskOutcome::StepUp | RiskOutcome::Quarantine => (
            Some("urn:qid:acr:phishing-resistant".to_string()),
            vec!["webauthn".to_string()],
        ),
        RiskOutcome::Deny => (
            Some("urn:qid:acr:admin-review".to_string()),
            vec!["webauthn".to_string(), "admin_review".to_string()],
        ),
    };

    RiskEvaluation {
        score,
        labels: dedupe_labels(labels),
        pep_force_inspect: outcome == RiskOutcome::ForceInspect,
        pep_force_tunnel: outcome == RiskOutcome::ForceTunnel,
        rate_limit_profile: (outcome == RiskOutcome::RateLimit).then(|| "pep-standard".to_string()),
        audit_level: matches!(
            outcome,
            RiskOutcome::AuditHigh
                | RiskOutcome::ForceInspect
                | RiskOutcome::ForceTunnel
                | RiskOutcome::RateLimit
                | RiskOutcome::Quarantine
                | RiskOutcome::Deny
        )
        .then(|| "high".to_string()),
        outcome,
        required_acr,
        required_amr,
    }
}

pub fn detects_impossible_travel(input: &RiskInput) -> bool {
    let Some(previous) = &input.previous_login else {
        return false;
    };
    let Some(current) = &input.current_login else {
        return false;
    };
    let Some(previous_location) = &previous.location else {
        return false;
    };
    let Some(current_location) = &current.location else {
        return false;
    };
    if current.epoch_seconds <= previous.epoch_seconds {
        return false;
    }

    let elapsed_hours = (current.epoch_seconds - previous.epoch_seconds) as f64 / 3600.0;
    if elapsed_hours <= 0.0 {
        return false;
    }

    let distance_km = haversine_km(previous_location, current_location);
    distance_km / elapsed_hours > 900.0
}

fn haversine_km(a: &GeoPoint, b: &GeoPoint) -> f64 {
    let radius_km = 6371.0_f64;
    let lat1 = a.latitude.to_radians();
    let lat2 = b.latitude.to_radians();
    let delta_lat = (b.latitude - a.latitude).to_radians();
    let delta_lon = (b.longitude - a.longitude).to_radians();

    let h =
        (delta_lat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (delta_lon / 2.0).sin().powi(2);
    2.0 * radius_km * h.sqrt().asin()
}

fn dedupe_labels(labels: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for label in labels {
        if !unique.contains(&label) {
            unique.push(label);
        }
    }
    unique
}

fn default_device_trust_state() -> DeviceTrustState {
    DeviceTrustState::Unknown
}

fn default_destination_reputation() -> DestinationReputation {
    DestinationReputation::Unknown
}

impl Default for RiskInput {
    fn default() -> Self {
        Self {
            realm_id: None,
            subject: None,
            previous_login: None,
            current_login: None,
            device_trust: default_device_trust_state(),
            high_risk_asn: false,
            anonymous_network: false,
            destination_reputation: default_destination_reputation(),
            phishing_resistant_mfa_satisfied: false,
            step_up_succeeded: false,
            new_device: false,
            impossible_travel: false,
            unmanaged_device: false,
            malicious_destination: false,
            pep: None,
            device_posture: None,
            tenant_policy: None,
            token: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn location(latitude: f64, longitude: f64) -> GeoPoint {
        GeoPoint {
            latitude,
            longitude,
        }
    }

    #[test]
    fn impossible_travel_is_derived_from_login_locations() {
        let input = RiskInput {
            realm_id: None,
            previous_login: Some(LoginSignal {
                epoch_seconds: 100,
                location: Some(location(35.6762, 139.6503)),
                ip: Some("192.0.2.1".to_string()),
                asn: Some(64500),
            }),
            current_login: Some(LoginSignal {
                epoch_seconds: 3700,
                location: Some(location(40.7128, -74.0060)),
                ip: Some("198.51.100.1".to_string()),
                asn: Some(64501),
            }),
            device_trust: DeviceTrustState::Managed,
            destination_reputation: DestinationReputation::KnownGood,
            phishing_resistant_mfa_satisfied: false,
            step_up_succeeded: false,
            subject: Some("user-1".to_string()),
            high_risk_asn: false,
            anonymous_network: false,
            new_device: false,
            impossible_travel: false,
            unmanaged_device: false,
            malicious_destination: false,
            ..RiskInput::default()
        };

        let evaluation = evaluate_risk(&input);

        assert_eq!(evaluation.outcome, RiskOutcome::StepUp);
        assert!(evaluation.labels.contains(&"impossible-travel".to_string()));
        assert_eq!(
            evaluation.required_acr,
            Some("urn:qid:acr:phishing-resistant".to_string())
        );
    }

    #[test]
    fn malicious_destination_and_compromised_device_deny() {
        let input = RiskInput {
            realm_id: None,
            subject: Some("user-1".to_string()),
            previous_login: None,
            current_login: None,
            device_trust: DeviceTrustState::Compromised,
            high_risk_asn: true,
            anonymous_network: true,
            destination_reputation: DestinationReputation::Malicious,
            phishing_resistant_mfa_satisfied: false,
            step_up_succeeded: false,
            new_device: false,
            impossible_travel: false,
            unmanaged_device: false,
            malicious_destination: false,
            ..RiskInput::default()
        };

        let evaluation = evaluate_risk(&input);

        assert_eq!(evaluation.score, 100);
        assert_eq!(evaluation.outcome, RiskOutcome::Deny);
        assert!(
            evaluation
                .required_amr
                .contains(&"admin_review".to_string())
        );
    }

    #[test]
    fn phishing_resistant_mfa_reduces_step_up_risk() {
        let input = RiskInput {
            realm_id: None,
            subject: None,
            previous_login: None,
            current_login: None,
            device_trust: DeviceTrustState::Unknown,
            high_risk_asn: false,
            anonymous_network: false,
            destination_reputation: DestinationReputation::Suspicious,
            phishing_resistant_mfa_satisfied: true,
            step_up_succeeded: false,
            new_device: false,
            impossible_travel: false,
            unmanaged_device: false,
            malicious_destination: false,
            ..RiskInput::default()
        };

        let evaluation = evaluate_risk(&input);

        assert_eq!(evaluation.outcome, RiskOutcome::Allow);
        assert!(evaluation.required_amr.is_empty());
    }

    #[test]
    fn pep_destination_signals_drive_edge_actions() {
        let inspect = evaluate_risk(&RiskInput {
            subject: Some("user-1".to_string()),
            device_trust: DeviceTrustState::Managed,
            destination_reputation: DestinationReputation::KnownGood,
            pep: Some(PepSignal {
                edge_name: Some("egress-main".to_string()),
                route: Some("forward.direct".to_string()),
                destination_category: Some("newly-registered-domain".to_string()),
                destination_reputation: Some(DestinationReputation::Suspicious),
                host: Some("download.example.test".to_string()),
                ..PepSignal::default()
            }),
            token: Some(TokenSignal {
                sender_constrained: true,
                acr: Some("urn:qid:acr:phishing-resistant".to_string()),
                amr: vec!["webauthn".to_string()],
                ..TokenSignal::default()
            }),
            ..RiskInput::default()
        });
        assert_eq!(inspect.outcome, RiskOutcome::ForceInspect);
        assert!(inspect.pep_force_inspect);
        assert_eq!(inspect.audit_level.as_deref(), Some("high"));
        assert!(
            inspect
                .labels
                .contains(&"pep-suspicious-destination".to_string())
        );

        let tunnel = evaluate_risk(&RiskInput {
            device_trust: DeviceTrustState::Managed,
            destination_reputation: DestinationReputation::KnownGood,
            pep: Some(PepSignal {
                destination_category: Some("privacy".to_string()),
                destination_reputation: Some(DestinationReputation::KnownGood),
                ..PepSignal::default()
            }),
            ..RiskInput::default()
        });
        assert_eq!(tunnel.outcome, RiskOutcome::ForceTunnel);
        assert!(tunnel.pep_force_tunnel);
    }

    #[test]
    fn risk_input_accepts_pep_signal() {
        let input: RiskInput = serde_json::from_value(serde_json::json!({
            "device_trust": "managed",
            "destination_reputation": "known_good",
            "pep": {
                "edge_name": "egress-main",
                "destination_category": "privacy",
                "destination_reputation": "known_good"
            }
        }))
        .expect("risk input with PEP signal");

        assert_eq!(
            input
                .pep
                .as_ref()
                .and_then(|signal| signal.edge_name.as_deref()),
            Some("egress-main")
        );
        assert_eq!(evaluate_risk(&input).outcome, RiskOutcome::ForceTunnel);
    }

    #[test]
    fn risk_score_is_clamped_at_100() {
        // Multiple high-risk signals should be capped at score=100.
        let input = RiskInput {
            device_trust: DeviceTrustState::Compromised,
            high_risk_asn: true,
            anonymous_network: true,
            destination_reputation: DestinationReputation::Malicious,
            malicious_destination: true,
            device_posture: Some(DevicePostureSignal {
                managed: false,
                encrypted: false,
                edr: false,
                os_outdated: true,
                jailbreak_or_root: true,
            }),
            ..RiskInput::default()
        };
        let evaluation = evaluate_risk(&input);
        assert_eq!(evaluation.score, 100);
        assert_eq!(evaluation.outcome, RiskOutcome::Deny);
    }

    #[test]
    fn risk_score_can_be_zero() {
        // All safe signals should result in score=10 (the baseline).
        let input = RiskInput {
            device_trust: DeviceTrustState::Managed,
            destination_reputation: DestinationReputation::KnownGood,
            phishing_resistant_mfa_satisfied: true,
            token: Some(TokenSignal {
                sender_constrained: true,
                acr: Some("urn:qid:acr:phishing-resistant".to_string()),
                amr: vec!["webauthn".to_string()],
                ..TokenSignal::default()
            }),
            ..RiskInput::default()
        };
        let evaluation = evaluate_risk(&input);
        // Baseline 10 - 10 (sender-constrained) - 20 (phishing-resistant mfa) - 10
        // (strong-token-auth) = too low, but min via saturating_sub gives 0.
        assert!(evaluation.score <= 10);
        assert_eq!(evaluation.outcome, RiskOutcome::Allow);
    }

    #[test]
    fn risk_saturating_sub_never_underflows() {
        // The baseline (10) with sender-constrained (-10) and phishing-resistant
        // mfa (-20) should result in 0, not underflow.
        let input = RiskInput {
            device_trust: DeviceTrustState::Managed,
            destination_reputation: DestinationReputation::KnownGood,
            phishing_resistant_mfa_satisfied: true,
            token: Some(TokenSignal {
                sender_constrained: true,
                acr: Some("urn:qid:acr:phishing-resistant".to_string()),
                amr: vec!["webauthn".to_string()],
                ..TokenSignal::default()
            }),
            ..RiskInput::default()
        };
        let evaluation = evaluate_risk(&input);
        assert_eq!(evaluation.score, 0);
    }

    #[test]
    fn tenant_token_and_posture_signals_can_rate_limit_or_quarantine() {
        let rate_limited = evaluate_risk(&RiskInput {
            anonymous_network: true,
            destination_reputation: DestinationReputation::Unknown,
            device_trust: DeviceTrustState::Managed,
            ..RiskInput::default()
        });
        assert_eq!(rate_limited.outcome, RiskOutcome::RateLimit);
        assert_eq!(
            rate_limited.rate_limit_profile.as_deref(),
            Some("pep-standard")
        );

        let denied = evaluate_risk(&RiskInput {
            device_trust: DeviceTrustState::Managed,
            destination_reputation: DestinationReputation::KnownGood,
            device_posture: Some(DevicePostureSignal {
                managed: true,
                encrypted: true,
                edr: true,
                os_outdated: false,
                jailbreak_or_root: true,
            }),
            tenant_policy: Some(TenantPolicySignal {
                current_country: Some("ZZ".to_string()),
                allowed_countries: vec!["JP".to_string(), "US".to_string()],
                network_allowed: Some(false),
                working_hours_allowed: Some(false),
            }),
            ..RiskInput::default()
        });
        assert_eq!(denied.outcome, RiskOutcome::Deny);
        assert!(denied.labels.contains(&"country-not-allowed".to_string()));
        assert!(denied.labels.contains(&"network-not-allowed".to_string()));
        assert!(
            denied
                .labels
                .contains(&"posture-jailbreak-or-root".to_string())
        );
    }
}
