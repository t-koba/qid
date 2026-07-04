use super::*;
use qid_ops::{CacheBackendConfig, CacheBackendKind};
use qid_policy::{DecisionDetails, PepPolicyActions};

fn request() -> PepDecisionRequest {
    PepDecisionRequest {
        schema_id: PEP_DECISION_REQUEST_SCHEMA_ID.to_string(),
        request_id: Some("req-1".to_string()),
        traceparent: Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00".to_string()),
        proxy: ProxyInfo {
            proxy_name: "egress-main".to_string(),
            scope_name: "forward_connect".to_string(),
            matched_rule: None,
            matched_route: Some("corp-egress".to_string()),
            action: Some("connect".to_string()),
        },
        request: Some(RequestInfo {
            remote_ip: Some("192.0.2.10".to_string()),
            dst_port: Some(443),
            host: Some("finance.example.com".to_string()),
            sni: Some("finance.example.com".to_string()),
            method: Some("CONNECT".to_string()),
            path: Some("/".to_string()),
            uri: Some("https://finance.example.com/".to_string()),
            headers: HashMap::new(),
        }),
        identity: Some(IdentityInfo {
            user: Some("alice@example.com".to_string()),
            groups: vec!["finance".to_string()],
            roles: vec!["analyst".to_string()],
            entitlements: vec!["app:erp:read".to_string()],
            device_id: Some("device-1".to_string()),
            posture: vec!["managed".to_string()],
            tenant: Some("corp".to_string()),
            auth_strength: Some("urn:qid:acr:phishing-resistant".to_string()),
            idp: Some("qid".to_string()),
            source: Some("test".to_string()),
        }),
        destination: Some(DestinationInfo {
            category: Some("banking".to_string()),
            reputation: Some("known-good".to_string()),
            application: Some("erp".to_string()),
        }),
        risk_score: Some(7),
        context: HashMap::new(),
        extensions: HashMap::new(),
        auth_assertions: Some(PepAuthAssertions {
            realm: Some("test".to_string()),
            audience: Some("urn:qid:pep:test/egress-main".to_string()),
            capabilities: vec!["local_response".to_string()],
        }),
        declared_capabilities: normalize_string_capabilities(&["local_response".to_string()]),
        adapter_capabilities: normalize_string_capabilities(&[
            "inject_headers".to_string(),
            "local_response".to_string(),
            "override_upstream".to_string(),
            "force_inspect".to_string(),
            "force_tunnel".to_string(),
            "cache_bypass".to_string(),
            "rate_limit".to_string(),
        ]),
        adapter_realm_id: Some("test".to_string()),
        adapter_tenant_id: Some("tenant-1".to_string()),
    }
}

fn authzen_request() -> AuthZenEvaluationRequest {
    AuthZenEvaluationRequest {
        subject: AuthZenEntity {
            r#type: Some("user".to_string()),
            id: Some("alice@example.com".to_string()),
            properties: HashMap::from([
                (
                    "groups".to_string(),
                    serde_json::json!(["finance", "engineering"]),
                ),
                (
                    "acr".to_string(),
                    serde_json::json!("urn:qid:acr:phishing-resistant"),
                ),
            ]),
        },
        action: AuthZenAction {
            name: "document.read".to_string(),
            properties: HashMap::new(),
        },
        resource: AuthZenEntity {
            r#type: Some("document".to_string()),
            id: Some("finance.example.com".to_string()),
            properties: HashMap::from([(
                "host".to_string(),
                serde_json::json!("finance.example.com"),
            )]),
        },
        context: HashMap::from([("risk_score".to_string(), serde_json::json!(10))]),
    }
}

fn response(decision: &str, ttl_ms: u64, cacheable: bool) -> PepDecisionResponse {
    PepDecisionResponse {
        schema_id: PEP_DECISION_RESPONSE_SCHEMA_ID.to_string(),
        decision: decision.to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        policy_revision: "policy-rev-1".to_string(),
        ttl_ms,
        cacheable,
        decision_scope: "request".to_string(),
        obligations: Vec::new(),
        audit: PepDecisionAuditInfo {
            severity: "normal".to_string(),
            policy_id: "policy-1".to_string(),
            policy_tags: vec!["qid:allow:policy-1".to_string()],
            risk_score: Some(7),
        },
        extensions: HashMap::new(),
    }
}

#[test]
fn pep_decision_request_accepts_qid_owned_shape() {
    let json = serde_json::json!({
        "schema_id": PEP_DECISION_REQUEST_SCHEMA_ID,
        "request_id": "req-1",
        "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",
        "principal": {
            "id": "alice@example.com",
            "groups": ["finance"],
            "roles": ["analyst"],
            "entitlements": ["app:erp:read"],
            "device_id": "device-1",
            "posture": ["managed"],
            "assurance_level": "urn:qid:acr:phishing-resistant",
            "tenant": "corp",
            "idp": "qid"
        },
        "resource": {
            "id": "finance.example.com",
            "host": "finance.example.com",
            "path": "/",
            "port": 443,
            "uri": "https://finance.example.com/",
            "sni": "finance.example.com",
            "source_ip": "192.0.2.10"
        },
        "operation": {
            "name": "connect",
            "method": "CONNECT"
        },
        "pep": {
            "registration": "egress-main",
            "mode": "forward_connect",
            "capabilities": [
                { "effect": "local_response" },
                { "mode": "forward_connect", "phase": "request", "effect": "inject_headers" }
            ]
        },
        "risk": {
            "score": 7,
            "destination_category": "banking",
            "destination_reputation": "known-good",
            "destination_application": "erp"
        },
        "context": {
            "route": "corp-egress"
        },
        "auth_assertions": {
            "realm": "test",
            "audience": "urn:qid:pep:test/egress-main",
            "capabilities": ["local_response"]
        }
    });

    let req: PepDecisionRequest = serde_json::from_value(json).unwrap();

    assert_eq!(req.proxy.proxy_name, "egress-main");
    assert_eq!(req.proxy.action.as_deref(), Some("connect"));
    assert_eq!(
        req.identity
            .as_ref()
            .and_then(|identity| identity.user.as_deref()),
        Some("alice@example.com")
    );
    assert!(req.declared_capabilities.contains("local_response"));
    assert!(req.declared_capabilities.contains("inject_headers"));
}

#[test]
fn pep_decision_request_rejects_old_qpx_shape() {
    let json = serde_json::json!({
        "request_id": "req-1",
        "edge": { "name": "egress-main" },
        "traffic": { "host": "finance.example.com", "method": "CONNECT" }
    });

    let err = serde_json::from_value::<PepDecisionRequest>(json).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("unknown field") || message.contains("missing field"));
}

#[test]
fn authzen_request_maps_to_policy_context() {
    let ctx = authzen_policy_context(&authzen_request()).unwrap();

    assert_eq!(ctx.subject_id.as_deref(), Some("alice@example.com"));
    assert_eq!(ctx.groups, vec!["finance", "engineering"]);
    assert_eq!(ctx.acr.as_deref(), Some("urn:qid:acr:phishing-resistant"));
    assert_eq!(ctx.resource_action.as_deref(), Some("document.read"));
    assert_eq!(ctx.resource_host.as_deref(), Some("finance.example.com"));
    assert_eq!(ctx.risk_score, Some(10));

    let mut invalid = authzen_request();
    invalid.action.name = " ".to_string();
    let err = authzen_policy_context(&invalid).unwrap_err();
    assert!(err.message().contains("action.name"));
}

#[test]
fn pep_decision_cache_key_hashes_identity_material() {
    let key = pep_decision_cache_key(&request(), "policy-rev-1").unwrap();
    let rendered = key
        .render(&CacheBackendConfig {
            kind: CacheBackendKind::Redis,
            endpoints: vec!["redis://127.0.0.1:6379".to_string()],
            key_prefix: "qid".to_string(),
            ttl_seconds: 30,
        })
        .unwrap();

    assert!(rendered.starts_with("qid:pep_decision:"));
    assert!(!rendered.contains("alice@example.com"));
    assert!(!rendered.contains("finance.example.com"));
    assert_ne!(
        key.digest,
        pep_decision_cache_key(&request(), "policy-rev-2")
            .unwrap()
            .digest
    );
}

#[test]
fn pep_decision_response_does_not_expose_qpx_effect_shape() {
    let mut response = response("allow", 30_000, true);
    response.obligations.push(qid_decision_obligation(
        "inject_headers",
        serde_json::json!({ "request_set": { "x-qid-user": "alice" } }),
    ));

    let value = serde_json::to_value(response).unwrap();

    assert_eq!(value["schema_id"], PEP_DECISION_RESPONSE_SCHEMA_ID);
    assert!(value.get("inject_headers").is_none());
    assert!(value.get("local_response").is_none());
    assert!(value.get("override_upstream").is_none());
    assert_eq!(value["obligations"][0]["name"], "inject_headers");
}

#[test]
fn pep_decision_obligations_fail_closed_when_capability_is_missing() {
    let details = DecisionDetails {
        decision: Decision::Allow,
        policy_id: "policy-1".to_string(),
        inject_headers: Some(HashMap::from([(
            "x-qid-user".to_string(),
            "alice".to_string(),
        )])),
        ..DecisionDetails::default()
    };
    let risk = PepDecisionRiskAdvisory {
        score: 7,
        force_inspect: None,
        force_tunnel: None,
        rate_limit_profile: None,
        cache_bypass: None,
        policy_tags: Vec::new(),
    };

    let err = pep_decision_obligations(&details, &risk, "decision-1", &HashSet::new()).unwrap_err();
    assert!(err.message().contains("inject_headers"));

    let obligations = pep_decision_obligations(
        &details,
        &risk,
        "decision-1",
        &normalize_string_capabilities(&["inject_headers".to_string()]),
    )
    .unwrap();
    assert_eq!(obligations[0].name, "inject_headers");
}

#[test]
fn pep_decision_obligations_preserve_qid_owned_policy_actions() {
    let details = DecisionDetails {
        decision: Decision::Deny,
        policy_id: "policy-1".to_string(),
        pep: PepPolicyActions {
            force_inspect: Some(true),
            ..PepPolicyActions::default()
        },
        ..DecisionDetails::default()
    };
    let risk = PepDecisionRiskAdvisory {
        score: 80,
        force_inspect: None,
        force_tunnel: None,
        rate_limit_profile: None,
        cache_bypass: Some(true),
        policy_tags: vec!["risk:high".to_string()],
    };
    let capabilities = normalize_string_capabilities(&[
        "local_response".to_string(),
        "force_inspect".to_string(),
        "cache_bypass".to_string(),
    ]);

    let obligations =
        pep_decision_obligations(&details, &risk, "decision-1", &capabilities).unwrap();

    assert!(
        obligations
            .iter()
            .any(|obligation| obligation.name == "local_response")
    );
    assert!(
        obligations
            .iter()
            .any(|obligation| obligation.name == "force_inspect")
    );
    assert!(
        obligations
            .iter()
            .any(|obligation| obligation.name == "cache_bypass")
    );
}

#[test]
fn pep_decision_cache_put_respects_cacheable_flag() {
    assert!(
        pep_decision_cache_put(
            &request(),
            &response("allow", 30_000, false),
            "policy-rev-1"
        )
        .unwrap()
        .is_none()
    );

    let put = pep_decision_cache_put(&request(), &response("allow", 30_000, true), "policy-rev-1")
        .unwrap()
        .unwrap();
    assert_eq!(put.ttl_seconds, 30);
    let cached: PepDecisionResponse = serde_json::from_slice(&put.value).unwrap();
    assert_eq!(cached.schema_id, PEP_DECISION_RESPONSE_SCHEMA_ID);
}

#[test]
fn pep_decision_ttl_matches_decision_cache_policy() {
    assert_eq!(pep_decision_ttl_ms(&Decision::Allow), 30_000);
    assert_eq!(pep_decision_ttl_ms(&Decision::AuditOnly), 30_000);
    assert_eq!(pep_decision_ttl_ms(&Decision::Quarantine), 30_000);
    assert_eq!(pep_decision_ttl_ms(&Decision::Deny), 5_000);
    assert_eq!(pep_decision_ttl_ms(&Decision::StepUp), 5_000);
    assert_eq!(pep_decision_ttl_ms(&Decision::ApprovalRequired), 5_000);
}
