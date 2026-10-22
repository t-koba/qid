use super::*;
use qid_core::config::DecisionCacheClass;
use qid_ops::{CacheBackendConfig, CacheBackendKind};
use qid_policy::{DecisionDetails, PepPolicyActions};

fn request() -> PepDecisionRequest {
    PepDecisionRequest {
        schema_id: PEP_DECISION_REQUEST_SCHEMA_ID.to_string(),
        request_id: Some("req-1".to_string()),
        traceparent: Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00".to_string()),
        proxy: ProxyInfo {
            proxy_name: "egress-main".to_string(),
            action: Some("connect".to_string()),
        },
        request: Some(RequestInfo {
            dst_port: Some(443),
            host: Some("finance.example.com".to_string()),
            sni: Some("finance.example.com".to_string()),
            method: Some("CONNECT".to_string()),
            path: Some("/".to_string()),
        }),
        identity: Some(IdentityInfo {
            user: Some("alice@example.com".to_string()),
            groups: vec!["finance".to_string()],
            roles: vec!["analyst".to_string()],
            entitlements: vec!["app:erp:read".to_string()],
            device_id: Some("device-1".to_string()),
            posture: vec!["managed".to_string()],
            auth_strength: Some("urn:qid:acr:phishing-resistant".to_string()),
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
            "assurance_level": "urn:qid:acr:phishing-resistant"
        },
        "resource": {
            "id": "finance.example.com",
            "host": "finance.example.com",
            "path": "/",
            "port": 443,
            "sni": "finance.example.com"
        },
        "operation": {
            "name": "connect",
            "method": "CONNECT"
        },
        "pep": {
            "registration": "egress-main",
            "capabilities": [
                { "effect": "local_response" },
                { "effect": "inject_headers" }
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
fn authzen_request_ignores_unknown_fields_for_forward_compat() {
    let json = serde_json::json!({
        "subject": {
            "type": "user",
            "id": "alice@example.com",
            "properties": {},
            "future_subject_field": "ignore-me"
        },
        "action": {
            "name": "document.read",
            "properties": {},
            "future_action_field": 1
        },
        "resource": {
            "type": "document",
            "id": "doc-1",
            "properties": {},
            "future_resource_field": true
        },
        "context": {},
        "future_top_level_field": { "nested": true }
    });
    let req: AuthZenEvaluationRequest =
        serde_json::from_value(json).expect("AuthZEN receivers must ignore unknown fields");
    assert_eq!(req.action.name, "document.read");
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
fn the_registration_names_the_lifetime_of_each_decision_class() {
    let config = cache_ttl_test_config(Some((2, 7)));
    let registration = config.realms[0]
        .pep_registrations
        .registrations
        .iter()
        .find(|registration| registration.name == "egress-main")
        .expect("the registration");
    assert_eq!(
        registration
            .decision
            .cache
            .ttl_ms(DecisionCacheClass::Positive),
        7_000
    );
    assert_eq!(
        registration
            .decision
            .cache
            .ttl_ms(DecisionCacheClass::Negative),
        2_000
    );
}

fn rebac_test_config() -> QidConfig {
    serde_json::from_value(serde_json::json!({
        "server": {"listen": "127.0.0.1:1", "public_base_url": "https://proxy.example.com"},
        "realms": [
            {"id": "realm-a", "issuer": "https://proxy.example.com/realm-a", "tenant_id": "tenant-a",
             "policy": {"default_decision": "step_up"}},
            {"id": "realm-b", "issuer": "https://proxy.example.com/realm-b"},
            {"id": "realm-c", "issuer": "https://proxy.example.com/realm-c",
             "policy": {"default_decision": "bogus"}}
        ]
    }))
    .expect("test config must deserialize")
}

#[test]
fn rebac_scope_prefers_realm_tenant() {
    let config = rebac_test_config();
    assert_eq!(rebac_scope_for_realm(&config, "realm-a"), "tenant-a");
}

#[test]
fn rebac_scope_falls_back_to_realm_without_tenant() {
    let config = rebac_test_config();
    assert_eq!(rebac_scope_for_realm(&config, "realm-b"), "realm-b");
    assert_eq!(
        rebac_scope_for_realm(&config, "unknown-realm"),
        "unknown-realm"
    );
}

#[test]
fn fallback_bundle_uses_realm_default_decision() {
    let config = rebac_test_config();
    let bundle = fallback_bundle_for_realm(&config, "realm-a").unwrap();
    assert!(bundle.rules.is_empty());
    assert_eq!(
        bundle.default_decision,
        qid_policy::Decision::StepUp,
        "realm default must be honored, not silently denied"
    );
    let plain = fallback_bundle_for_realm(&config, "realm-b").unwrap();
    assert_eq!(plain.default_decision, qid_policy::Decision::Deny);
    let unknown = fallback_bundle_for_realm(&config, "unknown-realm").unwrap();
    assert_eq!(unknown.default_decision, qid_policy::Decision::Deny);
    assert!(
        fallback_bundle_for_realm(&config, "realm-c").is_err(),
        "unknown default_decision values must fail loudly"
    );
}

#[tokio::test]
async fn rebac_tenant_tuples_drive_pep_decisions_without_cross_tenant_leak() {
    let config = rebac_test_config();
    let path = std::env::temp_dir().join(format!(
        "qid-pep-rebac-isolation-{}.json",
        ulid::Ulid::new()
    ));
    let repo = qid_storage::FileRepository::new(path.to_str().expect("valid temp path"))
        .await
        .expect("file repository");
    repo.migrate().await.expect("file repository migration");

    // Tuple as stored by the tenant-scoped admin API (`{tenant}::{namespace}`).
    qid_iga::write_tuples(
        &repo,
        &[qid_core::models::RelationshipTuple {
            namespace: "tenant-a::document".to_string(),
            object_id: "doc-1".to_string(),
            relation: "viewer".to_string(),
            subject_namespace: "tenant-a::user".to_string(),
            subject_id: "alice".to_string(),
            subject_relation: String::new(),
            created_at_epoch_seconds: qid_core::util::now_seconds(),
        }],
    )
    .await
    .expect("relationship tuple write");

    // Same unscoped ReBAC allow rule for both realms; only the tenant scope differs.
    let compiled = serde_json::json!({
        "version": "1",
        "default_decision": "deny",
        "rules": [{
            "name": "rebac-viewer",
            "type": "allow",
            "action": "*",
            "expression": {
                "namespace": "document",
                "object_id": "doc-1",
                "relation": "viewer",
                "subject_namespace": "user"
            }
        }]
    });
    for (realm_id, id) in [("realm-a", "bundle-a"), ("realm-b", "bundle-b")] {
        repo.create_policy_bundle(&qid_core::models::PolicyBundle {
            id: id.to_string(),
            realm_id: realm_id.to_string(),
            name: "rebac-bundle".to_string(),
            source_hash: "sha256:test".to_string(),
            compiled_json: compiled.clone(),
            version: 1,
            active: true,
        })
        .await
        .expect("policy bundle stored");
    }

    let signer = Arc::new(qid_crypto::LocalSigner::from_secret(
        "test",
        b"test-secret-for-rebac-tenant-isolation",
    ));
    let state = SharedState::new(config, Arc::new(repo), signer, serde_json::json!({}))
        .expect("shared state");

    let ctx = PolicyContext {
        subject_id: Some("alice".to_string()),
        ..PolicyContext::default()
    };

    // Both the cold DB path and the cached path must attach the evaluator.
    for realm in ["realm-a", "realm-b"] {
        let expected = if realm == "realm-a" {
            Decision::Allow
        } else {
            Decision::Deny
        };
        for _ in 0..2 {
            let engine = load_policy_engine(&state, realm)
                .await
                .expect("engine loads");
            assert_eq!(
                engine.decide(&ctx).await.decision,
                expected,
                "{realm} stays isolated"
            );
        }
    }

    std::fs::remove_file(path).ok();
}

fn pep_adapter_config(enabled: bool) -> QidConfig {
    serde_json::from_value(serde_json::json!({
        "server": {"listen": "127.0.0.1:1", "public_base_url": "https://proxy.example.com"},
        "realms": [
            {
                "id": "test",
                "issuer": "https://proxy.example.com/realm-test",
                "pep_registrations": {
                    "enabled": enabled,
                    "registrations": [{
                        "name": "egress-main",
                        "audience": "urn:qid:pep:test/egress-main",
                        "capabilities": [{"effect": "local_response"}],
                        "decision": {"fail_policy": "deny"}
                    }]
                }
            }
        ]
    }))
    .expect("test config must deserialize")
}

async fn pep_adapter_state(
    enabled: bool,
) -> (SharedState<qid_storage::FileRepository>, std::path::PathBuf) {
    let path =
        std::env::temp_dir().join(format!("qid-pep-registration-{}.json", ulid::Ulid::new()));
    let repo = qid_storage::FileRepository::new(path.to_str().expect("valid temp path"))
        .await
        .expect("file repository");
    repo.migrate().await.expect("file repository migration");
    let signer = Arc::new(qid_crypto::LocalSigner::from_secret(
        "test",
        b"test-secret-for-disabled-pep-registrations",
    ));
    let state = SharedState::new(
        pep_adapter_config(enabled),
        Arc::new(repo),
        signer,
        serde_json::json!({}),
    )
    .expect("shared state");
    (state, path)
}

fn pep_adapter_token(state: &SharedState<qid_storage::FileRepository>) -> String {
    let now = qid_core::util::now_seconds();
    let mut extra = HashMap::new();
    extra.insert(
        "realm_id".to_string(),
        serde_json::Value::String("test".to_string()),
    );
    state
        .signer
        .sign(&qid_core::jwt::JwtClaims {
            iss: Some("https://proxy.example.com".to_string()),
            sub: Some("egress-main".to_string()),
            aud: Some(qid_core::jwt::Audience::single(
                "urn:qid:pep:test/egress-main".to_string(),
            )),
            exp: Some((now + 60) as usize),
            nbf: Some((now - 5) as usize),
            iat: Some(now as usize),
            jti: Some(format!("pep-adapter-{now}")),
            extra,
        })
        .expect("adapter token")
}

#[tokio::test]
async fn a_realm_that_disables_its_registrations_serves_no_pep() {
    let (enabled_state, enabled_path) = pep_adapter_state(true).await;
    let token = pep_adapter_token(&enabled_state);
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}")
            .parse()
            .expect("authorization header"),
    );
    let req = request();

    let auth = authenticate_pep_decision_adapter(&headers, &enabled_state, &req)
        .expect("the enabled realm serves its registration");
    assert_eq!(auth.realm_id, "test");

    let (disabled_state, disabled_path) = pep_adapter_state(false).await;
    let err = authenticate_pep_decision_adapter(&headers, &disabled_state, &req)
        .expect_err("a realm that disables its registrations serves no PEP");
    assert!(
        err.message()
            .contains("invalid PEP registration authentication token")
    );

    std::fs::remove_file(enabled_path).ok();
    std::fs::remove_file(disabled_path).ok();
}

fn cache_ttl_test_config(cache: Option<(u64, u64)>) -> QidConfig {
    let mut registration = serde_json::json!({
        "name": "egress-main",
        "decision": {"fail_policy": "deny"}
    });
    if let Some((negative_ttl, positive_ttl)) = cache {
        registration["decision"]["cache"] = serde_json::json!({
            "positive_ttl_seconds": positive_ttl,
            "negative_ttl_seconds": negative_ttl
        });
    }
    serde_json::from_value(serde_json::json!({
        "server": {"listen": "127.0.0.1:1", "public_base_url": "https://proxy.example.com"},
        "realms": [
            {
                "id": "test",
                "issuer": "https://proxy.example.com/realm-test",
                "pep_registrations": {
                    "enabled": true,
                    "registrations": [registration]
                }
            }
        ]
    }))
    .expect("test config must deserialize")
}

async fn cache_ttl_state(
    config: QidConfig,
    default_decision: &str,
) -> (SharedState<qid_storage::FileRepository>, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("qid-pep-cache-ttl-{}.json", ulid::Ulid::new()));
    let repo = qid_storage::FileRepository::new(path.to_str().expect("valid temp path"))
        .await
        .expect("file repository");
    repo.migrate().await.expect("file repository migration");
    repo.create_policy_bundle(&qid_core::models::PolicyBundle {
        id: "bundle-test".to_string(),
        realm_id: "test".to_string(),
        name: "bundle-test".to_string(),
        source_hash: "sha256:test".to_string(),
        compiled_json: serde_json::json!({
            "version": "1",
            "default_decision": default_decision,
            "rules": []
        }),
        version: 1,
        active: true,
    })
    .await
    .expect("policy bundle stored");
    let signer = Arc::new(qid_crypto::LocalSigner::from_secret(
        "test",
        b"test-secret-for-pep-decision-cache-ttl",
    ));
    let state = SharedState::new(config, Arc::new(repo), signer, serde_json::json!({}))
        .expect("shared state");
    (state, path)
}

/// How long the cached decision still lives, or `None` when the decision is
/// not cached.
fn cached_lifetime(
    state: &SharedState<qid_storage::FileRepository>,
    req: &PepDecisionRequest,
) -> Option<std::time::Duration> {
    let digest = pep_decision_cache_key(req, &state.policy_revision())
        .expect("cache key")
        .digest;
    let cache = state.decision_cache.read().expect("cache lock");
    cache.get(&digest).map(|entry| {
        entry
            .expires_at
            .saturating_duration_since(std::time::Instant::now())
    })
}

#[tokio::test]
async fn the_registration_lifetime_bounds_the_cached_negative_decision() {
    let (state, path) = cache_ttl_state(cache_ttl_test_config(Some((2, 7))), "deny").await;
    let req = request();
    // The first decision loads the policy bundle, so the second one can key the cache.
    for _ in 0..2 {
        let response = do_check(&state, &req).await.expect("decision");
        assert_eq!(response.decision, "deny");
        assert_eq!(
            response.ttl_ms, 2_000,
            "the wire names the lifetime the registration asks for"
        );
    }
    let remaining = cached_lifetime(&state, &req).expect("the decision is cached");
    assert!(
        remaining <= std::time::Duration::from_secs(2),
        "the negative decision lives for the registration's negative lifetime, not longer: {remaining:?}"
    );
    assert!(
        remaining > std::time::Duration::from_millis(500),
        "the negative decision is still cached: {remaining:?}"
    );
    std::fs::remove_file(path).ok();
}

#[tokio::test]
async fn a_zero_negative_lifetime_keeps_the_negative_decision_out_of_the_cache() {
    let (state, path) = cache_ttl_state(cache_ttl_test_config(Some((0, 7))), "deny").await;
    let req = request();
    for _ in 0..2 {
        let response = do_check(&state, &req).await.expect("decision");
        assert_eq!(response.decision, "deny");
        assert_eq!(response.ttl_ms, 0, "a lifetime of zero is no lifetime");
        assert!(!response.cacheable);
    }
    assert!(
        cached_lifetime(&state, &req).is_none(),
        "a registration that names no negative lifetime keeps negative decisions out of the cache"
    );
    std::fs::remove_file(path).ok();
}

#[tokio::test]
async fn the_registration_lifetime_bounds_the_cached_positive_decision() {
    let (state, path) = cache_ttl_state(cache_ttl_test_config(Some((2, 7))), "allow").await;
    let req = request();
    for _ in 0..2 {
        let response = do_check(&state, &req).await.expect("decision");
        assert_eq!(response.decision, "allow");
        assert_eq!(
            response.ttl_ms, 7_000,
            "the wire names the lifetime the registration asks for"
        );
    }
    let remaining = cached_lifetime(&state, &req).expect("the decision is cached");
    assert!(
        remaining <= std::time::Duration::from_secs(7),
        "the positive decision lives for the registration's positive lifetime, not longer: {remaining:?}"
    );
    std::fs::remove_file(path).ok();
}

#[tokio::test]
async fn a_registration_without_a_lifetime_keeps_the_product_defaults() {
    let (state, path) = cache_ttl_state(cache_ttl_test_config(None), "allow").await;
    let req = request();
    let response = do_check(&state, &req).await.expect("decision");
    assert_eq!(response.decision, "allow");
    assert_eq!(response.ttl_ms, 30_000);
    std::fs::remove_file(path).ok();

    let (state, path) = cache_ttl_state(cache_ttl_test_config(None), "deny").await;
    let response = do_check(&state, &req).await.expect("decision");
    assert_eq!(response.decision, "deny");
    assert_eq!(response.ttl_ms, 5_000);
    std::fs::remove_file(path).ok();
}
