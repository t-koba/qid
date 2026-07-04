use super::*;

pub(crate) struct PepDecisionRiskAdvisory {
    pub(crate) score: u64,
    pub(crate) force_inspect: Option<bool>,
    pub(crate) force_tunnel: Option<bool>,
    pub(crate) rate_limit_profile: Option<String>,
    pub(crate) cache_bypass: Option<bool>,
    pub(crate) policy_tags: Vec<String>,
}

pub(crate) fn pep_decision_risk_advisory(req: &PepDecisionRequest) -> PepDecisionRiskAdvisory {
    let identity = req.identity.as_ref();
    let destination = req.destination.as_ref();
    let risk_input = RiskInput {
        subject: identity.and_then(|identity| identity.user.clone()),
        destination_reputation: destination
            .and_then(|destination| destination.reputation.as_deref())
            .and_then(destination_reputation_from_signal)
            .unwrap_or(DestinationReputation::KnownGood),
        phishing_resistant_mfa_satisfied: identity
            .and_then(|identity| identity.auth_strength.as_deref())
            .is_some_and(|acr| acr.contains("phishing-resistant")),
        device_trust: device_trust_from_identity(identity),
        pep: Some(PepSignal {
            edge_name: Some(req.proxy.proxy_name.clone()),
            host: req
                .request
                .as_ref()
                .and_then(|request| request.host.clone()),
            sni: req.request.as_ref().and_then(|request| request.sni.clone()),
            method: req
                .request
                .as_ref()
                .and_then(|request| request.method.clone()),
            path: req
                .request
                .as_ref()
                .and_then(|request| request.path.clone()),
            destination_category: destination.and_then(|destination| destination.category.clone()),
            destination_reputation: destination
                .and_then(|destination| destination.reputation.as_deref())
                .and_then(destination_reputation_from_signal),
            application: destination.and_then(|destination| destination.application.clone()),
            ..PepSignal::default()
        }),
        device_posture: identity.map(device_posture_signal_from_identity),
        token: Some(TokenSignal {
            sender_constrained: false,
            acr: identity.and_then(|identity| identity.auth_strength.clone()),
            amr: identity
                .and_then(|identity| identity.auth_strength.clone())
                .into_iter()
                .collect(),
            ..TokenSignal::default()
        }),
        ..RiskInput::default()
    };

    let evaluation = evaluate_risk(&risk_input);
    let mut score = evaluation.score;
    let mut policy_tags = evaluation
        .labels
        .into_iter()
        .map(|label| format!("risk:{label}"))
        .collect::<Vec<_>>();

    if identity.is_none() {
        score = score.saturating_add(25);
        policy_tags.push("risk:anonymous".to_string());
    }
    if identity.is_some_and(|identity| identity.device_id.is_none()) {
        score = score.saturating_add(10);
        policy_tags.push("risk:missing-device".to_string());
    }
    if identity.is_some_and(|identity| {
        !identity
            .auth_strength
            .as_deref()
            .is_some_and(|acr| acr.contains("phishing-resistant"))
    }) {
        score = score.saturating_add(10);
        policy_tags.push("risk:non-phishing-resistant-auth".to_string());
    }
    append_destination_risk_tags(destination, &mut policy_tags);

    let force_inspect = if evaluation.pep_force_inspect
        || matches!(
            evaluation.outcome,
            RiskOutcome::Deny | RiskOutcome::Quarantine
        ) {
        Some(true)
    } else if evaluation.pep_force_tunnel {
        Some(false)
    } else {
        None
    };
    let force_tunnel = evaluation.pep_force_tunnel.then_some(true);
    let rate_limit_profile = evaluation.rate_limit_profile;
    let cache_bypass = matches!(
        evaluation.outcome,
        RiskOutcome::Deny | RiskOutcome::Quarantine | RiskOutcome::ForceInspect
    )
    .then_some(true);

    PepDecisionRiskAdvisory {
        score: score.min(100),
        force_inspect,
        force_tunnel,
        rate_limit_profile,
        cache_bypass,
        policy_tags: dedupe_strings(policy_tags),
    }
}

pub(crate) fn authzen_policy_context(req: &AuthZenEvaluationRequest) -> QidResult<PolicyContext> {
    if req.action.name.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "AuthZEN action.name must not be empty".to_string(),
        });
    }
    let subject_id = req
        .subject
        .id
        .clone()
        .or_else(|| string_property(&req.subject.properties, "sub"))
        .or_else(|| string_property(&req.subject.properties, "user"));
    let resource_host = string_property(&req.resource.properties, "host")
        .or_else(|| string_property(&req.resource.properties, "hostname"))
        .or_else(|| req.resource.id.clone());

    Ok(PolicyContext {
        subject_id,
        groups: string_array_property(&req.subject.properties, "groups"),
        roles: string_array_property(&req.subject.properties, "roles"),
        entitlements: string_array_property(&req.subject.properties, "entitlements"),
        device_id: string_property(&req.subject.properties, "device_id")
            .or_else(|| string_property(&req.context, "device_id")),
        posture: string_array_property(&req.subject.properties, "posture")
            .into_iter()
            .chain(string_array_property(&req.context, "posture"))
            .collect(),
        acr: string_property(&req.subject.properties, "acr").or_else(|| {
            req.context
                .get("auth")
                .and_then(|auth| auth.get("acr"))
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string)
        }),
        auth_age_seconds: req
            .context
            .get("auth_age_seconds")
            .and_then(serde_json::Value::as_u64),
        risk_score: req
            .context
            .get("risk_score")
            .and_then(serde_json::Value::as_u64)
            .or_else(|| {
                req.context
                    .get("risk")
                    .and_then(|risk| risk.get("score"))
                    .and_then(serde_json::Value::as_u64)
            }),
        resource_host,
        resource_action: Some(req.action.name.clone()),
        pep_registration: None,
    })
}

fn string_property(properties: &HashMap<String, serde_json::Value>, name: &str) -> Option<String> {
    properties
        .get(name)
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
}

fn string_array_property(
    properties: &HashMap<String, serde_json::Value>,
    name: &str,
) -> Vec<String> {
    properties
        .get(name)
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn append_destination_risk_tags(
    destination: Option<&DestinationInfo>,
    policy_tags: &mut Vec<String>,
) {
    let Some(destination) = destination else {
        return;
    };
    if let Some(reputation) = destination.reputation.as_deref() {
        match normalize_signal(reputation).as_str() {
            "unknown" => policy_tags.push("risk:unknown-destination".to_string()),
            "suspicious" => policy_tags.push("risk:suspicious-destination".to_string()),
            "malicious" => policy_tags.push("risk:malicious-destination".to_string()),
            other if other != "known-good" => {
                policy_tags.push(format!("risk:destination-reputation:{other}"));
            }
            _ => {}
        }
    }
    if let Some(category) = destination.category.as_deref() {
        match normalize_signal(category).as_str() {
            normalized @ ("privacy" | "health" | "banking") => {
                policy_tags.push(format!("risk:sensitive-category:{normalized}"));
            }
            normalized @ ("malware" | "phishing" | "command-and-control") => {
                policy_tags.push(format!("risk:malicious-category:{normalized}"));
            }
            normalized @ ("newly-registered-domain" | "unknown") => {
                policy_tags.push(format!("risk:unknown-category:{normalized}"));
            }
            _ => {}
        }
    }
    if let Some(application) = destination.application.as_deref() {
        policy_tags.push(format!(
            "risk:application:{}",
            normalize_signal(application)
        ));
    }
}

fn destination_reputation_from_signal(value: &str) -> Option<DestinationReputation> {
    match normalize_signal(value).as_str() {
        "known-good" => Some(DestinationReputation::KnownGood),
        "unknown" => Some(DestinationReputation::Unknown),
        "suspicious" => Some(DestinationReputation::Suspicious),
        "malicious" => Some(DestinationReputation::Malicious),
        _ => None,
    }
}

fn device_trust_from_identity(identity: Option<&IdentityInfo>) -> DeviceTrustState {
    let Some(identity) = identity else {
        return DeviceTrustState::Unknown;
    };
    if identity.posture.iter().any(|item| {
        matches!(
            normalize_signal(item).as_str(),
            "compromised" | "rooted" | "jailbroken"
        )
    }) {
        return DeviceTrustState::Compromised;
    }
    if identity.device_id.is_some()
        && identity
            .posture
            .iter()
            .any(|item| matches!(normalize_signal(item).as_str(), "trusted" | "managed"))
    {
        DeviceTrustState::Managed
    } else if identity.device_id.is_some() {
        DeviceTrustState::Registered
    } else {
        DeviceTrustState::Unknown
    }
}

fn device_posture_signal_from_identity(identity: &IdentityInfo) -> DevicePostureSignal {
    let posture = identity
        .posture
        .iter()
        .map(|item| normalize_signal(item))
        .collect::<Vec<_>>();
    DevicePostureSignal {
        managed: posture
            .iter()
            .any(|item| item == "managed" || item == "trusted"),
        encrypted: !posture.iter().any(|item| item == "unencrypted"),
        edr: !posture
            .iter()
            .any(|item| item == "no-edr" || item == "edr-missing"),
        os_outdated: posture.iter().any(|item| item == "outdated-os"),
        jailbreak_or_root: posture
            .iter()
            .any(|item| matches!(item.as_str(), "compromised" | "rooted" | "jailbroken")),
    }
}

fn normalize_signal(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('_', "-")
}

pub(crate) fn merge_policy_tags(
    mut policy_tags: Vec<String>,
    risk_tags: Vec<String>,
) -> Vec<String> {
    policy_tags.extend(risk_tags);
    dedupe_strings(policy_tags)
}

fn dedupe_strings(values: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for value in values {
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    unique
}

pub fn pep_decision_ttl_ms(decision: &Decision) -> u64 {
    match decision {
        Decision::Allow | Decision::AuditOnly | Decision::Quarantine => 30_000,
        _ => 5_000,
    }
}

pub fn pep_decision_cache_key(
    req: &PepDecisionRequest,
    policy_revision: &str,
) -> QidResult<CacheKey> {
    if policy_revision.trim().is_empty() {
        return Err(QidError::BadRequest {
            message: "policy revision must not be empty".to_string(),
        });
    }
    let identity = req.identity.as_ref();
    let material = serde_json::json!({
        "policy_revision": policy_revision,
        "proxy": {
            "proxy_name": req.proxy.proxy_name,
            "action": req.proxy.action,
        },
        "request": {
            "host": req.request.as_ref().and_then(|request| request.host.clone()),
            "method": req.request.as_ref().and_then(|request| request.method.clone()),
            "path": req.request.as_ref().and_then(|request| request.path.clone()),
            "sni": req.request.as_ref().and_then(|request| request.sni.clone()),
            "dst_port": req.request.as_ref().and_then(|request| request.dst_port),
            "destination": {
                "category": req.destination.as_ref().and_then(|destination| destination.category.clone()),
                "reputation": req.destination.as_ref().and_then(|destination| destination.reputation.clone()),
                "application": req.destination.as_ref().and_then(|destination| destination.application.clone()),
            }
        },
        "identity": {
            "user": identity.and_then(|identity| identity.user.clone()),
            "groups": identity.map(|identity| identity.groups.clone()).unwrap_or_default(),
            "device_id": identity.and_then(|identity| identity.device_id.clone()),
            "posture": identity.map(|identity| identity.posture.clone()).unwrap_or_default(),
            "auth_strength": identity.and_then(|identity| identity.auth_strength.clone()),
        }
    });
    let encoded = serde_json::to_vec(&material).map_err(|err| QidError::Internal {
        message: format!("failed to encode pep_decision cache material: {err}"),
    })?;
    CacheKey::new("pep_decision", encoded)
}

pub fn pep_decision_cache_put(
    req: &PepDecisionRequest,
    response: &PepDecisionResponse,
    policy_revision: &str,
) -> QidResult<Option<CachePut>> {
    if !response.cacheable {
        return Ok(None);
    }
    let ttl_ms = response.ttl_ms;
    if ttl_ms == 0 {
        return Ok(None);
    }
    let value = serde_json::to_vec(response).map_err(|err| QidError::Internal {
        message: format!("failed to encode pep_decision cache response: {err}"),
    })?;
    Ok(Some(CachePut {
        key: pep_decision_cache_key(req, policy_revision)?,
        value,
        ttl_seconds: ttl_ms.div_ceil(1000).max(1),
    }))
}
