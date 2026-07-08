//! Canonical PEP pep_decision endpoint.

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use qid_core::{
    config::ServerPaths,
    error::{QidError, QidResult},
    state::SharedState,
};

use qid_observability::audit::AuditEvent;

use qid_ops::{CacheKey, CachePut};
use qid_policy::{Decision, DecisionDetails, NativePolicyEngine, PolicyContext, PolicyEngine};
use qid_risk::{
    DestinationReputation, DevicePostureSignal, DeviceTrustState, PepSignal, RiskInput,
    RiskOutcome, TokenSignal, evaluate_risk,
};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Add the canonical PEP pep_decision route.
pub fn pep_decision_routes<R: Repository>(paths: &ServerPaths) -> Router<Arc<SharedState<R>>> {
    Router::new()
        .route(&paths.authzen_evaluation, post(authzen_evaluate))
        .route(&paths.pep_decision, post(check))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthZenEvaluationRequest {
    pub subject: AuthZenEntity,
    pub action: AuthZenAction,
    pub resource: AuthZenEntity,
    #[serde(default)]
    pub context: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthZenEntity {
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub properties: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthZenAction {
    pub name: String,
    #[serde(default)]
    pub properties: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct AuthZenEvaluationResponse {
    pub decision: bool,
    pub context: AuthZenDecisionContext,
}

#[derive(Debug, Serialize)]
pub struct AuthZenDecisionContext {
    pub decision_id: String,
    pub policy_id: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub matched_rules: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policy_tags: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub obligations: Vec<AuthZenObligation>,
}

#[derive(Debug, Serialize)]
pub struct AuthZenObligation {
    pub namespace: String,
    pub version: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub parameters: serde_json::Value,
}

pub const PEP_DECISION_REQUEST_SCHEMA_ID: &str = "urn:qid:schema:pep-decision-request:v1";
pub const PEP_DECISION_RESPONSE_SCHEMA_ID: &str = "urn:qid:schema:pep-decision-response:v1";

#[derive(Debug)]
pub struct PepDecisionRequest {
    schema_id: String,
    request_id: Option<String>,
    traceparent: Option<String>,
    proxy: ProxyInfo,
    request: Option<RequestInfo>,
    identity: Option<IdentityInfo>,
    destination: Option<DestinationInfo>,
    risk_score: Option<u64>,
    context: HashMap<String, serde_json::Value>,
    extensions: HashMap<String, serde_json::Value>,
    auth_assertions: Option<PepAuthAssertions>,
    declared_capabilities: HashSet<String>,
    adapter_capabilities: HashSet<String>,
    adapter_realm_id: Option<String>,
    adapter_tenant_id: Option<String>,
}

impl<'de> Deserialize<'de> for PepDecisionRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = WirePepDecisionRequest::deserialize(deserializer)?;
        Self::try_from(wire).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePepDecisionRequest {
    #[serde(default)]
    schema_id: Option<String>,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    traceparent: Option<String>,
    #[serde(default)]
    principal: Option<DecisionPrincipal>,
    resource: DecisionResource,
    operation: DecisionOperation,
    pep: DecisionPep,
    #[serde(default)]
    risk: Option<DecisionRisk>,
    #[serde(default)]
    context: HashMap<String, serde_json::Value>,
    #[serde(default)]
    extensions: HashMap<String, serde_json::Value>,
    #[serde(default)]
    auth_assertions: Option<PepAuthAssertions>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct DecisionPrincipal {
    id: Option<String>,
    groups: Vec<String>,
    roles: Vec<String>,
    entitlements: Vec<String>,
    device_id: Option<String>,
    posture: Vec<String>,
    assurance_level: Option<String>,
    tenant: Option<String>,
    idp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionResource {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    sni: Option<String>,
    #[serde(default)]
    source_ip: Option<String>,
    #[serde(default)]
    selected_headers: HashMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionOperation {
    name: String,
    #[serde(default)]
    method: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionPep {
    registration: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    phase: Option<String>,
    #[serde(default)]
    capabilities: Vec<DecisionPepCapability>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionPepCapability {
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    phase: Option<String>,
    effect: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionRisk {
    #[serde(default)]
    score: Option<u64>,
    #[serde(default)]
    destination_category: Option<String>,
    #[serde(default)]
    destination_reputation: Option<String>,
    #[serde(default)]
    destination_application: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PepAuthAssertions {
    #[serde(default)]
    realm: Option<String>,
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    capabilities: Vec<String>,
}

impl TryFrom<WirePepDecisionRequest> for PepDecisionRequest {
    type Error = String;

    fn try_from(value: WirePepDecisionRequest) -> Result<Self, Self::Error> {
        let schema_id = value
            .schema_id
            .unwrap_or_else(|| PEP_DECISION_REQUEST_SCHEMA_ID.to_string());
        if schema_id != PEP_DECISION_REQUEST_SCHEMA_ID {
            return Err(format!(
                "unsupported PEP decision request schema_id: {schema_id}"
            ));
        }
        let registration = value.pep.registration.trim();
        if registration.is_empty() {
            return Err("pep.registration must not be empty".to_string());
        }
        let operation_name = value.operation.name.trim();
        if operation_name.is_empty() {
            return Err("operation.name must not be empty".to_string());
        }
        let declared_capabilities = normalize_wire_capabilities(&value.pep.capabilities);
        let principal = value.principal.unwrap_or_default();
        let destination = value.risk.as_ref().and_then(|risk| {
            (risk.destination_category.is_some()
                || risk.destination_reputation.is_some()
                || risk.destination_application.is_some())
            .then(|| DestinationInfo {
                category: risk.destination_category.clone(),
                reputation: risk.destination_reputation.clone(),
                application: risk.destination_application.clone(),
            })
        });
        let source = Some(format!(
            "qid-pep-decision;schema={PEP_DECISION_REQUEST_SCHEMA_ID}"
        ));

        Ok(Self {
            schema_id,
            request_id: value.request_id.clone(),
            traceparent: value.traceparent,
            proxy: ProxyInfo {
                proxy_name: registration.to_string(),
                scope_name: value
                    .pep
                    .mode
                    .clone()
                    .or_else(|| value.pep.phase.clone())
                    .or_else(|| value.request_id.clone())
                    .unwrap_or_default(),
                matched_rule: None,
                matched_route: value
                    .context
                    .get("route")
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string),
                action: Some(operation_name.to_ascii_lowercase()),
            },
            request: Some(RequestInfo {
                remote_ip: value.resource.source_ip,
                dst_port: value.resource.port,
                host: value.resource.host.or(value.resource.id),
                sni: value.resource.sni,
                method: value.operation.method,
                path: value.resource.path,
                uri: value.resource.uri,
                headers: value.resource.selected_headers,
            }),
            identity: Some(IdentityInfo {
                user: principal.id,
                groups: principal.groups,
                roles: principal.roles,
                entitlements: principal.entitlements,
                device_id: principal.device_id,
                posture: principal.posture,
                tenant: principal.tenant,
                auth_strength: principal.assurance_level,
                idp: principal.idp,
                source,
            }),
            destination,
            risk_score: value
                .risk
                .and_then(|risk| risk.score)
                .map(|score| score.min(100)),
            context: value.context,
            extensions: value.extensions,
            auth_assertions: value.auth_assertions,
            declared_capabilities,
            adapter_capabilities: HashSet::new(),
            adapter_realm_id: None,
            adapter_tenant_id: None,
        })
    }
}

#[derive(Debug)]
pub struct ProxyInfo {
    proxy_name: String,
    #[allow(dead_code)]
    scope_name: String,
    #[allow(dead_code)]
    matched_rule: Option<String>,
    #[allow(dead_code)]
    matched_route: Option<String>,
    action: Option<String>,
}

#[derive(Debug)]
pub struct RequestInfo {
    #[allow(dead_code)]
    remote_ip: Option<String>,
    #[allow(dead_code)]
    dst_port: Option<u16>,
    host: Option<String>,
    #[allow(dead_code)]
    sni: Option<String>,
    #[allow(dead_code)]
    method: Option<String>,
    #[allow(dead_code)]
    path: Option<String>,
    #[allow(dead_code)]
    uri: Option<String>,
    #[allow(dead_code)]
    headers: HashMap<String, Vec<String>>,
}

#[derive(Debug)]
pub struct IdentityInfo {
    user: Option<String>,
    groups: Vec<String>,
    roles: Vec<String>,
    entitlements: Vec<String>,
    device_id: Option<String>,
    posture: Vec<String>,
    #[allow(dead_code)]
    tenant: Option<String>,
    auth_strength: Option<String>,
    #[allow(dead_code)]
    idp: Option<String>,
    #[allow(dead_code)]
    source: Option<String>,
}

#[derive(Debug)]
pub struct DestinationInfo {
    category: Option<String>,
    reputation: Option<String>,
    application: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PepDecisionResponse {
    pub schema_id: String,
    pub decision: String,
    pub decision_id: String,
    pub policy_id: String,
    pub policy_revision: String,
    pub ttl_ms: u64,
    pub cacheable: bool,
    pub decision_scope: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligations: Vec<PepDecisionObligation>,
    pub audit: PepDecisionAuditInfo,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extensions: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PepDecisionObligation {
    pub namespace: String,
    pub version: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PepDecisionAuditInfo {
    pub severity: String,
    pub policy_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<u64>,
}

async fn check<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(mut req): Json<PepDecisionRequest>,
) -> impl IntoResponse {
    let auth = match authenticate_pep_decision_adapter(&headers, &state, &req) {
        Ok(auth) => auth,
        Err(e) => return qid_http::error_response(e),
    };
    req.adapter_capabilities = auth.capabilities;
    req.adapter_realm_id = Some(auth.realm_id);
    req.adapter_tenant_id = auth.tenant_id;
    match do_check(&state, &req).await {
        Ok(resp) => Json(resp).into_response(),
        Err(e) => {
            metrics::counter!("qid_proxy_pep_decision_fail_closed_total").increment(1);
            deny_response(&e)
        }
    }
}

#[derive(Debug)]
struct AdapterAuthentication {
    capabilities: HashSet<String>,
    realm_id: String,
    tenant_id: Option<String>,
}

fn authenticate_pep_decision_adapter<R: Repository>(
    headers: &HeaderMap,
    state: &SharedState<R>,
    req: &PepDecisionRequest,
) -> QidResult<AdapterAuthentication> {
    let token = bearer_token(headers).ok_or_else(|| QidError::Unauthorized {
        message: "PEP registration authentication token is required".to_string(),
    })?;
    let mut matches = Vec::new();
    for realm in &state.config.realms {
        for adapter in realm
            .pep_registrations
            .registrations
            .iter()
            .filter(|adapter| adapter.name == req.proxy.proxy_name)
        {
            let audience = adapter
                .audience
                .as_deref()
                .ok_or_else(|| QidError::Config {
                    message: format!(
                        "PEP registration {} must declare audience",
                        req.proxy.proxy_name
                    ),
                })?;
            let Ok(decoded) = state.signer.decode_with_aud(token, audience) else {
                continue;
            };
            let claims = decoded.claims;
            if claims.sub.as_deref() != Some(req.proxy.proxy_name.as_str()) {
                continue;
            }
            if let Some(realm_id) = claims
                .extra
                .get("realm_id")
                .and_then(|value| value.as_str())
                && realm_id != realm.id
            {
                continue;
            }
            validate_pep_registration_token(
                state,
                &claims,
                &adapter.auth,
                &realm.id,
                &adapter.name,
            )?;
            let capabilities = normalize_capabilities(&adapter.capabilities);
            validate_pep_request_binding(req, &realm.id, audience, &capabilities)?;
            if !req
                .declared_capabilities
                .iter()
                .all(|capability| capabilities.contains(capability))
            {
                continue;
            }
            matches.push(AdapterAuthentication {
                capabilities,
                realm_id: realm.id.clone(),
                tenant_id: realm.tenant_id.clone(),
            });
        }
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(QidError::Unauthorized {
            message: "invalid PEP registration authentication token".to_string(),
        }),
        _ => Err(QidError::Config {
            message: format!(
                "PEP registration {} authentication is ambiguous across realms",
                req.proxy.proxy_name
            ),
        }),
    }
}

fn validate_pep_registration_token<R: Repository>(
    state: &SharedState<R>,
    claims: &qid_core::jwt::JwtClaims,
    auth: &qid_core::config::PepRegistrationAuthConfig,
    realm_id: &str,
    registration_name: &str,
) -> QidResult<()> {
    let now = qid_core::util::now_seconds();
    let skew = auth.clock_skew_seconds;
    let Some(iat) = claims.iat.map(|value| value as u64) else {
        return Err(QidError::Unauthorized {
            message: "PEP registration token must include iat".to_string(),
        });
    };
    if iat > now.saturating_add(skew) {
        return Err(QidError::Unauthorized {
            message: "PEP registration token iat is in the future".to_string(),
        });
    }
    if now.saturating_sub(iat) > auth.token_max_age_seconds.saturating_add(skew) {
        return Err(QidError::Unauthorized {
            message: "PEP registration token is too old".to_string(),
        });
    }
    if auth.replay_protection {
        let Some(jti) = claims.jti.as_deref() else {
            return Err(QidError::Unauthorized {
                message:
                    "PEP registration token must include jti when replay protection is enabled"
                        .to_string(),
            });
        };
        let expires_at = iat
            .saturating_add(auth.token_max_age_seconds)
            .saturating_add(skew)
            .max(now.saturating_add(1));
        state
            .assertion_replay_cache
            .record_replay_key(
                &format!("pep-registration:{realm_id}:{registration_name}:{jti}"),
                expires_at,
                now,
                "PEP registration token replay detected",
            )
            .map_err(|err| QidError::Unauthorized {
                message: err.message().to_string(),
            })?;
    }
    Ok(())
}

fn validate_pep_request_binding(
    req: &PepDecisionRequest,
    realm_id: &str,
    audience: &str,
    capabilities: &HashSet<String>,
) -> QidResult<()> {
    let Some(assertions) = req.auth_assertions.as_ref() else {
        return Ok(());
    };
    if let Some(asserted_realm) = assertions.realm.as_deref()
        && asserted_realm != realm_id
    {
        return Err(QidError::Unauthorized {
            message: "PEP request realm assertion does not match authenticated credential"
                .to_string(),
        });
    }
    if let Some(asserted_audience) = assertions.audience.as_deref()
        && asserted_audience != audience
    {
        return Err(QidError::Unauthorized {
            message: "PEP request audience assertion does not match authenticated credential"
                .to_string(),
        });
    }
    let asserted_capabilities = normalize_string_capabilities(&assertions.capabilities);
    if !asserted_capabilities
        .iter()
        .all(|capability| capabilities.contains(capability))
    {
        return Err(QidError::Unauthorized {
            message: "PEP request capability assertion exceeds authenticated credential"
                .to_string(),
        });
    }
    Ok(())
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    qid_oauth::endpoints::extract_bearer_token(headers).ok()
}

/// Return a fail-closed 403 deny response for any error in the pep_decision path.
fn deny_response(_err: &QidError) -> axum::response::Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "schema_id": PEP_DECISION_RESPONSE_SCHEMA_ID,
            "decision": "deny",
            "decision_id": "fail-closed",
            "policy_id": "fail-closed",
            "policy_revision": "",
            "ttl_ms": 0,
            "cacheable": false,
            "decision_scope": "request",
            "obligations": [{
                "namespace": "urn:qid:decision:obligation:pep",
                "version": "1",
                "name": "local_response",
                "parameters": {
                    "status": 403,
                    "content_type": "application/json",
                    "body": {
                        "error": "access_denied",
                        "decision_id": "fail-closed"
                    }
                }
            }],
            "audit": {
                "severity": "high",
                "policy_id": "fail-closed"
            }
        })),
    )
        .into_response()
}

async fn authzen_evaluate<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Json(req): Json<AuthZenEvaluationRequest>,
) -> impl IntoResponse {
    let auth = match authenticate_authzen_adapter(&headers, &state) {
        Ok(auth) => auth,
        Err(e) => return qid_http::error_response(e),
    };
    match do_authzen_evaluate(&state, &req, &auth).await {
        Ok(resp) => Json(resp).into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

fn authenticate_authzen_adapter<R: Repository>(
    headers: &HeaderMap,
    state: &SharedState<R>,
) -> QidResult<AdapterAuthentication> {
    let token = bearer_token(headers).ok_or_else(|| QidError::Unauthorized {
        message: "AuthZEN adapter authentication token is required".to_string(),
    })?;
    let mut matches = Vec::new();
    for realm in &state.config.realms {
        for adapter in &realm.pep_registrations.registrations {
            let capabilities = normalize_capabilities(&adapter.capabilities);
            if !capabilities.contains("authzen") {
                continue;
            }
            let Some(audience) = adapter.audience.as_deref() else {
                continue;
            };
            let Ok(decoded) = state.signer.decode_with_aud(token, audience) else {
                continue;
            };
            let claims = decoded.claims;
            if claims.sub.as_deref() != Some(adapter.name.as_str()) {
                continue;
            }
            if let Some(realm_id) = claims
                .extra
                .get("realm_id")
                .and_then(|value| value.as_str())
                && realm_id != realm.id
            {
                continue;
            }
            if validate_pep_registration_token(
                state,
                &claims,
                &adapter.auth,
                &realm.id,
                &adapter.name,
            )
            .is_err()
            {
                continue;
            }
            matches.push(AdapterAuthentication {
                capabilities,
                realm_id: realm.id.clone(),
                tenant_id: realm.tenant_id.clone(),
            });
        }
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(QidError::Unauthorized {
            message: "invalid AuthZEN adapter authentication token".to_string(),
        }),
        _ => Err(QidError::Config {
            message: "AuthZEN adapter authentication is ambiguous across realms".to_string(),
        }),
    }
}

async fn do_authzen_evaluate<R: Repository>(
    state: &SharedState<R>,
    req: &AuthZenEvaluationRequest,
    auth: &AdapterAuthentication,
) -> QidResult<AuthZenEvaluationResponse> {
    let _start = std::time::Instant::now();
    let policy_engine = load_policy_engine(state, &auth.realm_id).await?;
    let ctx = authzen_policy_context(req)?;
    let details = policy_engine.decide(&ctx).await;
    let allowed = matches!(details.decision, Decision::Allow | Decision::AuditOnly);
    let reason = match details.decision {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
        Decision::StepUp => "challenge",
        Decision::ConsentRequired => "consent_required",
        Decision::LocalResponse => "local_response",
        Decision::ApprovalRequired => "approval_required",
        Decision::Quarantine => "quarantine",
        Decision::AuditOnly => "audit_only",
        Decision::Conditional => "conditional",
    };

    let event = AuditEvent {
        r#type: "authzen.evaluate".to_string(),
        time: qid_core::util::now_seconds().to_string(),
        tenant: auth.tenant_id.clone(),
        realm: Some(auth.realm_id.clone()),
        subject: ctx.subject_id.clone(),
        decision: Some(reason.to_string()),
        decision_id: Some(details.policy_id.clone()),
        extra: HashMap::new(),
    };
    tracing::info!(target: "audit", "{:?}", event);

    metrics::counter!("qid_proxy_authzen_evaluations_total", "decision" => reason.to_string())
        .increment(1);
    metrics::counter!("qid_policy_decisions_total", "decision" => reason.to_string()).increment(1);
    metrics::histogram!("qid_proxy_pep_decision_duration_seconds", "endpoint" => "authzen_evaluate")
        .record(_start.elapsed().as_secs_f64());
    let obligations = authzen_obligations(&details, &auth.capabilities)?;

    Ok(AuthZenEvaluationResponse {
        decision: allowed,
        context: AuthZenDecisionContext {
            decision_id: details.policy_id.clone(),
            policy_id: details.policy_id,
            reason: reason.to_string(),
            matched_rules: details.matched_rules,
            policy_tags: details.policy_tags,
            obligations,
        },
    })
}

fn authzen_obligations(
    details: &DecisionDetails,
    capabilities: &HashSet<String>,
) -> QidResult<Vec<AuthZenObligation>> {
    let mut obligations = Vec::new();
    for obligation in &details.obligations {
        if let Some(capability) = obligation.capability.as_deref() {
            require_authzen_capability(capabilities, capability)?;
        }
        obligations.push(AuthZenObligation {
            namespace: obligation.namespace.clone(),
            version: obligation.version.clone(),
            name: obligation.name.clone(),
            parameters: obligation.payload.clone(),
        });
    }

    match details.decision {
        Decision::Quarantine => {
            require_authzen_capability(capabilities, "quarantine")?;
            obligations.push(qid_pep_obligation("quarantine", serde_json::json!({})));
        }
        Decision::AuditOnly => {
            require_authzen_capability(capabilities, "audit")?;
            obligations.push(qid_pep_obligation(
                "audit",
                serde_json::json!({ "mode": "audit_only" }),
            ));
        }
        Decision::StepUp => {
            require_authzen_capability(capabilities, "challenge")?;
            obligations.push(qid_pep_obligation(
                "challenge",
                serde_json::json!({ "type": "step_up" }),
            ));
        }
        Decision::ConsentRequired => {
            require_authzen_capability(capabilities, "challenge")?;
            obligations.push(qid_pep_obligation(
                "challenge",
                serde_json::json!({ "type": "consent" }),
            ));
        }
        Decision::LocalResponse | Decision::ApprovalRequired => {
            require_authzen_capability(capabilities, "local_response")?;
            obligations.push(qid_pep_obligation(
                "local_response",
                serde_json::json!({ "decision": format!("{:?}", details.decision).to_ascii_lowercase() }),
            ));
        }
        Decision::Allow | Decision::Deny | Decision::Conditional => {}
    }

    if let Some(headers) = &details.inject_headers {
        require_authzen_capability(capabilities, "inject_headers")?;
        obligations.push(qid_pep_obligation(
            "inject_headers",
            serde_json::json!({ "request_set": headers }),
        ));
    }
    if let Some(profile) = &details.rate_limit_profile {
        require_authzen_capability_any(capabilities, &["rate_limit_profile", "rate_limit"])?;
        obligations.push(qid_pep_obligation(
            "rate_limit_profile",
            serde_json::json!({ "profile": profile }),
        ));
    }
    if details.pep.override_upstream.is_some()
        || details.pep.timeout_override_ms.is_some()
        || !details.pep.mirror_upstreams.is_empty()
    {
        require_authzen_capability(capabilities, "override_upstream")?;
        obligations.push(qid_pep_obligation(
            "override_upstream",
            serde_json::json!({
                "override_upstream": details.pep.override_upstream,
                "timeout_override_ms": details.pep.timeout_override_ms,
                "mirror_upstreams": details.pep.mirror_upstreams,
            }),
        ));
    }
    if let Some(enabled) = details.pep.force_inspect {
        require_authzen_capability(capabilities, "force_inspect")?;
        obligations.push(qid_pep_obligation(
            "force_inspect",
            serde_json::json!({ "enabled": enabled }),
        ));
    }
    if let Some(enabled) = details.pep.force_tunnel {
        require_authzen_capability(capabilities, "force_tunnel")?;
        obligations.push(qid_pep_obligation(
            "force_tunnel",
            serde_json::json!({ "enabled": enabled }),
        ));
    }
    if let Some(enabled) = details.pep.cache_bypass {
        require_authzen_capability(capabilities, "cache_bypass")?;
        obligations.push(qid_pep_obligation(
            "cache_bypass",
            serde_json::json!({ "enabled": enabled }),
        ));
    }
    if !details.policy_tags.is_empty() {
        require_authzen_capability(capabilities, "policy_tags")?;
        obligations.push(qid_pep_obligation(
            "policy_tags",
            serde_json::json!({ "tags": details.policy_tags }),
        ));
    }

    Ok(obligations)
}

fn qid_pep_obligation(name: &str, parameters: serde_json::Value) -> AuthZenObligation {
    AuthZenObligation {
        namespace: "urn:qid:authzen:extension:qid:pep".to_string(),
        version: "1".to_string(),
        name: name.to_string(),
        parameters,
    }
}

fn require_authzen_capability(capabilities: &HashSet<String>, capability: &str) -> QidResult<()> {
    if capabilities.contains(capability) {
        return Ok(());
    }
    Err(QidError::Unauthorized {
        message: format!("AuthZEN adapter lacks required obligation capability {capability}"),
    })
}

fn require_authzen_capability_any(
    capabilities: &HashSet<String>,
    accepted: &[&str],
) -> QidResult<()> {
    if accepted
        .iter()
        .any(|capability| capabilities.contains(*capability))
    {
        return Ok(());
    }
    Err(QidError::Unauthorized {
        message: format!(
            "authenticated AuthZEN adapter does not advertise required capability {}",
            accepted.join("|")
        ),
    })
}

async fn do_check<R: Repository>(
    state: &SharedState<R>,
    req: &PepDecisionRequest,
) -> QidResult<PepDecisionResponse> {
    let _start = std::time::Instant::now();

    // --- Decision cache lookup ---
    let cache_key_digest = {
        let revision = state.policy_revision();
        if !revision.is_empty() {
            pep_decision_cache_key(req, &revision)
                .ok()
                .map(|k| k.digest)
        } else {
            None
        }
    };
    if let Some(ref digest) = cache_key_digest
        && let Some(cached_json) = state.decision_cache_get(digest)
    {
        let cached: PepDecisionResponse =
            serde_json::from_value(cached_json).map_err(|e| QidError::Internal {
                message: format!("failed to deserialize cached pep_decision decision: {e}"),
            })?;
        metrics::counter!("qid_proxy_pep_decision_cache_hits_total").increment(1);
        return Ok(cached);
    }
    metrics::counter!("qid_proxy_pep_decision_cache_misses_total").increment(1);

    let adapter_realm_id = req.adapter_realm_id.clone().unwrap_or_else(|| {
        state
            .config
            .realms
            .first()
            .map(|realm| realm.id.clone())
            .unwrap_or_default()
    });
    let policy_engine = load_policy_engine(state, &adapter_realm_id).await?;

    let identity = req.identity.as_ref();
    let risk = pep_decision_risk_advisory(req);
    let ctx = PolicyContext {
        subject_id: identity.and_then(|i| i.user.clone()),
        groups: identity.map(|i| i.groups.clone()).unwrap_or_default(),
        roles: identity.map(|i| i.roles.clone()).unwrap_or_default(),
        entitlements: identity.map(|i| i.entitlements.clone()).unwrap_or_default(),
        device_id: identity.and_then(|i| i.device_id.clone()),
        posture: identity.map(|i| i.posture.clone()).unwrap_or_default(),
        acr: identity.and_then(|i| i.auth_strength.clone()),
        auth_age_seconds: None,
        risk_score: Some(req.risk_score.unwrap_or(risk.score)),
        resource_host: req.request.as_ref().and_then(|r| r.host.clone()),
        resource_action: req.proxy.action.clone(),
        pep_registration: Some(req.proxy.proxy_name.clone()),
    };

    let details = policy_engine.decide(&ctx).await;
    let decision_kind = details.decision.clone();

    for t in &details.trace {
        tracing::debug!(target: "policy", "{t}");
    }

    let decision = pep_decision_wire_decision(&decision_kind);

    let mut audit_extra = HashMap::new();
    if let Some(ref request_id) = req.request_id {
        audit_extra.insert(
            "request_id".to_string(),
            serde_json::Value::String(request_id.clone()),
        );
    }
    audit_extra.insert(
        "schema_id".to_string(),
        serde_json::Value::String(req.schema_id.clone()),
    );
    if let Some(traceparent) = &req.traceparent {
        audit_extra.insert(
            "traceparent".to_string(),
            serde_json::Value::String(traceparent.clone()),
        );
    }
    if !req.context.is_empty() {
        let mut keys = req.context.keys().cloned().collect::<Vec<_>>();
        keys.sort();
        audit_extra.insert("context_keys".to_string(), serde_json::json!(keys));
    }
    if !req.extensions.is_empty() {
        let mut keys = req.extensions.keys().cloned().collect::<Vec<_>>();
        keys.sort();
        audit_extra.insert("extension_keys".to_string(), serde_json::json!(keys));
    }
    let event = AuditEvent {
        r#type: "pep_decision.check".to_string(),
        time: qid_core::util::now_seconds().to_string(),
        tenant: req.adapter_tenant_id.clone(),
        realm: Some(adapter_realm_id.clone()),
        subject: ctx.subject_id.clone(),
        decision: Some(pep_decision_policy_decision_label(&decision_kind).to_string()),
        decision_id: Some(details.policy_id.clone()),
        extra: audit_extra,
    };
    tracing::info!(target: "audit", "{:?}", event);

    metrics::counter!("qid_proxy_pep_decision_requests_total", "decision" => decision.to_string())
        .increment(1);
    metrics::counter!("qid_policy_decisions_total", "decision" => decision.to_string())
        .increment(1);
    metrics::histogram!("qid_proxy_pep_decision_duration_seconds", "decision" => decision)
        .record(_start.elapsed().as_secs_f64());
    metrics::histogram!("qid_policy_decision_duration_seconds", "realm" => adapter_realm_id.clone())
        .record(_start.elapsed().as_secs_f64());

    let policy_id = details.policy_id.clone();
    let policy_revision = state.policy_revision();
    let policy_tags = merge_policy_tags(details.policy_tags.clone(), risk.policy_tags.clone());
    let cache_bypass = details
        .pep
        .cache_bypass
        .or(risk.cache_bypass)
        .unwrap_or(false);
    let ttl_ms = pep_decision_ttl_ms(&decision_kind);
    let response = PepDecisionResponse {
        schema_id: PEP_DECISION_RESPONSE_SCHEMA_ID.to_string(),
        decision: decision.to_string(),
        decision_id: details.policy_id.clone(),
        policy_id: details.policy_id.clone(),
        policy_revision: policy_revision.clone(),
        ttl_ms,
        cacheable: ttl_ms > 0 && !cache_bypass,
        decision_scope: "request".to_string(),
        obligations: pep_decision_obligations(
            &details,
            &risk,
            &policy_id,
            &req.adapter_capabilities,
        )?,
        audit: PepDecisionAuditInfo {
            severity: audit_severity(&decision_kind).to_string(),
            policy_id: details.policy_id,
            policy_tags,
            risk_score: Some(req.risk_score.unwrap_or(risk.score)),
        },
        extensions: HashMap::new(),
    };

    // --- Store in decision cache ---
    if let Some(digest) = cache_key_digest {
        let positive_ttl = state
            .config
            .realms
            .iter()
            .find(|realm| realm.id == req.adapter_realm_id.as_deref().unwrap_or_default())
            .and_then(|realm| {
                realm
                    .pep_registrations
                    .registrations
                    .iter()
                    .find(|adapter| adapter.name == req.proxy.proxy_name)
            })
            .map(|a| a.decision.cache.positive_ttl_seconds)
            .unwrap_or(30);
        let effective_ttl_ms = response.ttl_ms.min(positive_ttl * 1000);
        if response.cacheable
            && effective_ttl_ms > 0
            && let Ok(response_json) = serde_json::to_value(&response)
        {
            state.decision_cache_put(
                digest,
                response_json,
                effective_ttl_ms.div_ceil(1000).max(1),
            );
        }
    }

    Ok(response)
}

fn normalize_capabilities(
    capabilities: &[qid_core::config::PepCapabilityConfig],
) -> HashSet<String> {
    capabilities
        .iter()
        .map(|capability| capability.effect.trim().to_ascii_lowercase())
        .filter(|capability| !capability.is_empty())
        .collect()
}

fn normalize_string_capabilities(capabilities: &[String]) -> HashSet<String> {
    capabilities
        .iter()
        .map(|capability| capability.trim().to_ascii_lowercase())
        .filter(|capability| !capability.is_empty())
        .collect()
}

fn normalize_wire_capabilities(capabilities: &[DecisionPepCapability]) -> HashSet<String> {
    capabilities
        .iter()
        .map(|capability| {
            let _mode = capability.mode.as_deref();
            let _phase = capability.phase.as_deref();
            capability.effect.trim().to_ascii_lowercase()
        })
        .filter(|capability| !capability.is_empty())
        .collect()
}

fn pep_decision_obligations(
    details: &DecisionDetails,
    risk: &PepDecisionRiskAdvisory,
    decision_id: &str,
    capabilities: &HashSet<String>,
) -> QidResult<Vec<PepDecisionObligation>> {
    let mut obligations = Vec::new();
    for obligation in &details.obligations {
        if let Some(capability) = obligation.capability.as_deref() {
            require_pep_capability(capabilities, capability)?;
        }
        obligations.push(PepDecisionObligation {
            namespace: obligation.namespace.clone(),
            version: obligation.version.clone(),
            name: obligation.name.clone(),
            parameters: obligation.payload.clone(),
        });
    }

    match details.decision {
        Decision::StepUp | Decision::ConsentRequired => {
            require_pep_capability(capabilities, "challenge")?;
            obligations.push(qid_decision_obligation(
                "challenge",
                serde_json::json!({
                    "reason": pep_decision_policy_decision_label(&details.decision),
                    "decision_id": decision_id,
                }),
            ));
        }
        Decision::Deny
        | Decision::LocalResponse
        | Decision::ApprovalRequired
        | Decision::Quarantine
        | Decision::Conditional => {
            require_pep_capability(capabilities, "local_response")?;
            obligations.push(qid_decision_obligation(
                "local_response",
                qid_local_response_payload(&details.decision, decision_id),
            ));
        }
        Decision::Allow | Decision::AuditOnly => {}
    }

    if let Some(headers) = &details.inject_headers {
        require_pep_capability(capabilities, "inject_headers")?;
        obligations.push(qid_decision_obligation(
            "inject_headers",
            serde_json::json!({
                "request_set": headers,
                "request_add": {
                    "x-qid-decision-id": [decision_id],
                },
            }),
        ));
    }
    if let Some(profile) = details
        .rate_limit_profile
        .as_ref()
        .or(risk.rate_limit_profile.as_ref())
    {
        require_pep_capability_any(capabilities, &["rate_limit_profile", "rate_limit"])?;
        obligations.push(qid_decision_obligation(
            "rate_limit_profile",
            serde_json::json!({ "profile": profile }),
        ));
    }
    if details.pep.override_upstream.is_some()
        || details.pep.timeout_override_ms.is_some()
        || !details.pep.mirror_upstreams.is_empty()
    {
        require_pep_capability(capabilities, "override_upstream")?;
        obligations.push(qid_decision_obligation(
            "override_upstream",
            serde_json::json!({
                "override_upstream": details.pep.override_upstream,
                "timeout_override_ms": details.pep.timeout_override_ms,
                "mirror_upstreams": details.pep.mirror_upstreams,
            }),
        ));
    }
    if let Some(enabled) = details.pep.force_inspect.or(risk.force_inspect) {
        require_pep_capability(capabilities, "force_inspect")?;
        obligations.push(qid_decision_obligation(
            "force_inspect",
            serde_json::json!({ "enabled": enabled }),
        ));
    }
    if let Some(enabled) = details.pep.force_tunnel.or(risk.force_tunnel) {
        require_pep_capability(capabilities, "force_tunnel")?;
        obligations.push(qid_decision_obligation(
            "force_tunnel",
            serde_json::json!({ "enabled": enabled }),
        ));
    }
    if let Some(enabled) = details.pep.cache_bypass.or(risk.cache_bypass) {
        require_pep_capability(capabilities, "cache_bypass")?;
        obligations.push(qid_decision_obligation(
            "cache_bypass",
            serde_json::json!({ "enabled": enabled }),
        ));
    }
    Ok(obligations)
}

fn qid_decision_obligation(name: &str, parameters: serde_json::Value) -> PepDecisionObligation {
    PepDecisionObligation {
        namespace: "urn:qid:decision:obligation:pep".to_string(),
        version: "1".to_string(),
        name: name.to_string(),
        parameters,
    }
}

fn require_pep_capability(capabilities: &HashSet<String>, capability: &str) -> QidResult<()> {
    if capabilities.contains(capability) {
        return Ok(());
    }
    Err(QidError::Unauthorized {
        message: format!("PEP registration lacks required decision capability {capability}"),
    })
}

fn require_pep_capability_any(capabilities: &HashSet<String>, accepted: &[&str]) -> QidResult<()> {
    if accepted
        .iter()
        .any(|capability| capabilities.contains(*capability))
    {
        return Ok(());
    }
    Err(QidError::Unauthorized {
        message: format!(
            "PEP registration lacks required decision capability {}",
            accepted.join("|")
        ),
    })
}

fn pep_decision_wire_decision(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow | Decision::AuditOnly => "allow",
        Decision::Deny | Decision::Quarantine | Decision::Conditional => "deny",
        Decision::StepUp | Decision::ConsentRequired => "challenge",
        Decision::LocalResponse | Decision::ApprovalRequired => "local_response",
    }
}

fn pep_decision_policy_decision_label(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
        Decision::StepUp => "step_up",
        Decision::ConsentRequired => "consent_required",
        Decision::LocalResponse => "local_response",
        Decision::ApprovalRequired => "approval_required",
        Decision::Quarantine => "quarantine",
        Decision::AuditOnly => "audit_only",
        Decision::Conditional => "conditional",
    }
}

fn qid_local_response_payload(decision: &Decision, decision_id: &str) -> serde_json::Value {
    let (status, error) = match decision {
        Decision::Deny => (403, "access_denied"),
        Decision::StepUp => (302, "step_up_required"),
        Decision::ConsentRequired => (302, "consent_required"),
        Decision::LocalResponse => (403, "access_denied"),
        Decision::ApprovalRequired => (403, "approval_required"),
        Decision::Quarantine => (403, "quarantine_required"),
        Decision::Conditional => (403, "conditional_decision_unenforceable"),
        Decision::Allow | Decision::AuditOnly => (200, "ok"),
    };
    serde_json::json!({
        "status": status,
        "content_type": "application/json",
        "body": {
            "error": error,
            "decision_id": decision_id,
        },
    })
}

fn audit_severity(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow | Decision::AuditOnly | Decision::Quarantine => "normal",
        Decision::StepUp | Decision::ConsentRequired | Decision::ApprovalRequired => "medium",
        Decision::Deny | Decision::LocalResponse | Decision::Conditional => "high",
    }
}

mod decision;

use decision::*;
pub use decision::{pep_decision_cache_key, pep_decision_cache_put, pep_decision_ttl_ms};
async fn load_policy_engine<R: Repository>(
    state: &SharedState<R>,
    realm_id: &str,
) -> QidResult<NativePolicyEngine> {
    // Try the in-memory cache first (fast path, no DB)
    if let Ok(guard) = state.policy_bundle_cache.read()
        && let Some((ref name, ref compiled_json)) = *guard
    {
        let cache_prefix = format!("{realm_id}:");
        if name.starts_with(&cache_prefix) {
            if let Ok(policy_bundle) =
                serde_json::from_value::<qid_policy::PolicyBundle>(compiled_json.clone())
            {
                let mut engine = NativePolicyEngine::new();
                engine.load(policy_bundle, name.clone());
                return Ok(engine);
            }
            tracing::warn!("cached policy bundle is invalid, falling back to DB");
        }
    }

    // Cold path: load from DB and cache
    let mut engine = NativePolicyEngine::new();

    if let Some(bundle) = state
        .repo
        .get_active_policy_bundle(&realm_id.to_string().into())
        .await?
    {
        let policy_bundle: qid_policy::PolicyBundle =
            serde_json::from_value(bundle.compiled_json.clone()).map_err(|e| QidError::Config {
                message: format!("invalid policy bundle: {e}"),
            })?;
        // Use name before moving into cache
        engine.load(policy_bundle, bundle.name.clone());
        // Cache for subsequent requests (fast path avoids DB)
        *state
            .policy_bundle_cache
            .write()
            .unwrap_or_else(|e| e.into_inner()) =
            Some((format!("{realm_id}:{}", bundle.name), bundle.compiled_json));
    } else {
        // Default deny keeps PEP integration fail-closed when no bundle is configured.
        metrics::counter!("qid_proxy_pep_decision_fail_closed_total").increment(1);
        let default = qid_policy::PolicyBundle {
            version: "1".to_string(),
            rules: Vec::new(),
            default_decision: qid_policy::Decision::Deny,
        };
        engine.load(default, "default".to_string());
    }

    Ok(engine)
}

#[cfg(test)]
mod tests;
