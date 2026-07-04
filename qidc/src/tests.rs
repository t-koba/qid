use super::*;
use qid_core::config::{
    AdminConfig, AuthenticationConfig, CorsConfig, CryptoConfig, DeploymentProfile, KeyringConfig,
    OAuthResourceServerConfig, ObservabilityConfig, OpsConfig, PepRegistrationsConfig,
    PolicyConfig, ProtocolConfig, RealmConfig, RotationConfig, ServerConfig, ServerPaths,
    SignerConfig, StorageConfig,
};
use qid_ops::KeyPurpose;
use qid_policy::{Decision, DecisionDetails};
use std::collections::HashMap;

fn minimal_config() -> QidConfig {
    QidConfig {
        include: Vec::new(),
        profile: DeploymentProfile::Oidc,
        server: ServerConfig {
            listen: "127.0.0.1:8443".to_string(),
            public_base_url: "https://id.example.com".to_string(),
            tls: None,
            http_message_signatures: Default::default(),
            cors: CorsConfig::default(),
            paths: ServerPaths::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig {
            default_alg: "ES256".to_string(),
            keyrings: vec![KeyringConfig {
                name: "corp-main".to_string(),
                realm_id: Some("corp".to_string()),
                purposes: vec!["oidc_token".to_string()],
                signer: SignerConfig::default(),
                rotation: RotationConfig::default(),
            }],
        },
        realms: vec![RealmConfig {
            id: "corp".to_string(),
            issuer: "https://id.example.com/realms/corp".to_string(),
            display_name: None,
            tenant_id: None,
            clients: Vec::new(),
            protocols: ProtocolConfig::default(),
            authentication: AuthenticationConfig::default(),
            sessions: Default::default(),
            pep_registrations: PepRegistrationsConfig::default(),
            policy: PolicyConfig {
                bundles: Vec::new(),
                default_decision: "deny".to_string(),
            },
        }],
        observability: ObservabilityConfig::default(),
        ops: OpsConfig::default(),
    }
}

#[test]
fn key_rotation_plan_parses_cli_inventory_and_rejects_shared_local_pep_keyring() {
    let inventory = vec![
        parse_keyring_inventory_record(
            "corp,corp-shared,shared-1,pep_assertion,local,100,100,10000",
        )
        .expect("PEP inventory"),
        parse_keyring_inventory_record("corp,corp-shared,shared-2,oidc_token,local,100,100,10000")
            .expect("oidc inventory"),
    ];
    let requirement = parse_key_rotation_requirement("corp,pep_assertion,90,14,true,true")
        .expect("rotation requirement");

    let plans = plan_key_rotation(&inventory, &[requirement], 1_000);
    let plan = plans.first().expect("key rotation plan");

    assert_eq!(plan.status, qid_ops::KeyRotationPlanStatus::Rejected);
    assert_eq!(plan.realm_id, "corp");
    assert_eq!(plan.purpose, KeyPurpose::PepAssertion);
    assert!(
        plan.reasons
            .contains(&"dedicated_keyring_required:corp-shared".to_string())
    );
    assert!(
        plan.reasons
            .contains(&"remote_signer_required:corp-shared".to_string())
    );
}

#[test]
fn key_rotation_plan_parser_rejects_ambiguous_fields() {
    let err = parse_keyring_inventory_record("corp,corp-main,kid-1,pep_assertion,local,100,100")
        .expect_err("short inventory should fail");
    assert!(err.to_string().contains("8 or 9 fields"));

    let requirement = parse_key_rotation_requirement("corp,pep_assertion,90,91,true,true")
        .expect("requirement parsing");
    let plan = plan_key_rotation(&[], &[requirement], 1_000);

    assert_eq!(plan[0].status, qid_ops::KeyRotationPlanStatus::Rejected);
    assert!(
        plan[0]
            .reasons
            .contains(&"invalid_overlap_exceeds_max_age".to_string())
    );
}

#[test]
fn explain_json_includes_client_token_pep_claim_and_audit_fields() {
    let mut config = minimal_config();
    config.realms[0].protocols.oauth.resource_servers = vec![OAuthResourceServerConfig {
        audience: "api://corp/payments".to_string(),
        resources: vec!["https://api.example.com/payments".to_string()],
        scopes: vec!["payments".to_string()],
        introspection_client_ids: vec!["payments-gateway".to_string()],
        require_sender_constraint: true,
        high_risk: true,
    }];
    let ctx = PolicyContext {
        subject_id: Some("user-1".to_string()),
        groups: vec!["engineering".to_string()],
        roles: vec!["admin".to_string()],
        entitlements: vec!["proxy.connect".to_string()],
        device_id: Some("device-1".to_string()),
        posture: vec!["trusted".to_string()],
        acr: Some("urn:qid:acr:phishing-resistant".to_string()),
        auth_age_seconds: Some(42),
        risk_score: Some(7),
        resource_host: Some("api.example.com".to_string()),
        resource_action: Some("connect".to_string()),
        pep_registration: Some("egress-main".to_string()),
    };
    let result = DecisionDetails {
        obligations: Vec::new(),
        context: None,
        decision: Decision::Allow,
        policy_id: "allow-admin".to_string(),
        rate_limit_profile: Some("standard".to_string()),
        policy_tags: vec!["qid:allow:allow-admin".to_string()],
        inject_headers: Some(HashMap::from([(
            "x-qid-subject".to_string(),
            "user-1".to_string(),
        )])),
        pep: qid_policy::PepPolicyActions {
            override_upstream: Some("https://upstream.example.com".to_string()),
            timeout_override_ms: Some(2_500),
            mirror_upstreams: vec!["https://mirror.example.com".to_string()],
            force_inspect: Some(true),
            force_tunnel: Some(false),
            cache_bypass: Some(true),
        },
        matched_rules: vec!["allow-admin".to_string()],
        trace: vec!["Rule allow-admin: MATCH (allow)".to_string()],
    };

    let explanation = build_explain_json(
        config.profile,
        Some(&config.realms[0]),
        &ctx,
        &result,
        Some("authenticated-read"),
        None,
    );

    assert_eq!(
        explanation["deployment_profile"]["name"],
        config.profile.as_str()
    );
    assert_eq!(
        explanation["deployment_profile"]["obligations"]["requires_par"],
        false
    );
    assert_eq!(
        explanation["deployment_profile"]["obligations"]["requires_pep_registration"],
        false
    );
    assert_eq!(
        explanation["effective_client_policy"]["pkce_required"],
        true
    );
    assert_eq!(
        explanation["effective_token_policy"]["access_token_ttl_seconds"],
        3600
    );
    assert_eq!(
        explanation["effective_token_policy"]["resource_servers"][0]["audience"],
        "api://corp/payments"
    );
    assert_eq!(
        explanation["effective_token_policy"]["resource_servers"][0]["sender_constraint_required"],
        true
    );
    assert_eq!(
        explanation["effective_token_policy"]["resource_servers"][0]["introspection_client_ids"],
        serde_json::json!(["payments-gateway"])
    );
    assert_eq!(explanation["pep_actions"]["decision"], "allow");
    assert_eq!(explanation["pep_actions"]["ttl_ms"], 30000);
    assert_eq!(
        explanation["pep_actions"]["request_add"]["x-qid-decision-id"][0],
        "allow-admin"
    );
    assert_eq!(explanation["pep_actions"]["force_inspect"], true);
    assert_eq!(explanation["pep_actions"]["force_tunnel"], false);
    assert_eq!(explanation["pep_actions"]["cache_bypass"], true);
    assert_eq!(
        explanation["pep_actions"]["mirror_upstreams"][0],
        "https://mirror.example.com"
    );
    assert_eq!(
        explanation["pep_actions"]["override_upstream"],
        "https://upstream.example.com"
    );
    assert_eq!(explanation["pep_actions"]["timeout_override_ms"], 2500);
    assert!(
        explanation["claim_release_plan"]["released_claims"]
            .as_array()
            .expect("released claims")
            .iter()
            .any(|claim| claim == "groups")
    );
    assert_eq!(
        explanation["audit_fields"]["active_policy_bundle"],
        "authenticated-read"
    );
    assert_eq!(
        explanation["audit_fields"]["pep_registration"],
        "egress-main"
    );
    assert_eq!(explanation["audit_fields"]["decision"], "allow");
}

#[test]
fn explain_json_maps_step_up_to_pep_challenge() {
    let ctx = PolicyContext {
        subject_id: Some("user-1".to_string()),
        resource_action: Some("connect".to_string()),
        ..PolicyContext::default()
    };
    let result = DecisionDetails {
        obligations: Vec::new(),
        context: None,
        decision: Decision::StepUp,
        policy_id: "step-up-risk".to_string(),
        policy_tags: vec!["qid:step-up:step-up-risk".to_string()],
        matched_rules: vec!["step-up-risk".to_string()],
        ..DecisionDetails::default()
    };

    let explanation = build_explain_json(DeploymentProfile::Oidc, None, &ctx, &result, None, None);

    assert_eq!(explanation["pep_actions"]["decision"], "challenge");
    assert_eq!(explanation["pep_actions"]["status"], 302);
    assert_eq!(explanation["required_auth"]["step_up_required"], true);
    assert_eq!(explanation["required_auth"]["amr"][0], "webauthn");
}

#[test]
fn explain_json_maps_deny_to_local_response() {
    let ctx = PolicyContext {
        subject_id: Some("user-1".to_string()),
        resource_action: Some("connect".to_string()),
        ..PolicyContext::default()
    };
    let result = DecisionDetails {
        obligations: Vec::new(),
        context: None,
        decision: Decision::Deny,
        policy_id: "authenticated-read".to_string(),
        policy_tags: vec!["qid:default-deny".to_string()],
        ..DecisionDetails::default()
    };

    let explanation = build_explain_json(DeploymentProfile::Oidc, None, &ctx, &result, None, None);

    assert_eq!(explanation["pep_actions"]["decision"], "deny");
    assert_eq!(explanation["pep_actions"]["status"], 403);
    assert_eq!(
        explanation["pep_actions"]["local_response"]["body"]["error"],
        "access_denied"
    );
    assert_eq!(explanation["required_auth"]["step_up_required"], false);
}

#[test]
fn explain_json_reports_fapi_profile_obligations_and_realm_status() {
    let mut config = minimal_config();
    config.profile = DeploymentProfile::Fapi;
    config.server.http_message_signatures.enabled = true;
    config.server.http_message_signatures.shared_secret =
        Some("0123456789abcdef0123456789abcdef".to_string());
    config.realms[0].protocols.oauth.par.enabled = true;
    config.realms[0].protocols.oauth.rar.enabled = true;
    config.realms[0].protocols.oauth.dpop.enabled = true;
    config.realms[0].protocols.oauth.mtls.enabled = true;
    config.realms[0].protocols.oauth.private_key_jwt.enabled = true;
    config.realms[0].protocols.oauth.introspection.jwt_response = true;
    config.realms[0].protocols.oauth.resource_servers = vec![OAuthResourceServerConfig {
        audience: "api://payments".to_string(),
        resources: vec!["https://api.example.com/payments".to_string()],
        scopes: vec!["payments".to_string()],
        introspection_client_ids: vec!["payments-gateway".to_string()],
        require_sender_constraint: true,
        high_risk: true,
    }];
    let ctx = PolicyContext::default();
    let result = DecisionDetails::default();

    let explanation = build_explain_json(
        config.profile,
        Some(&config.realms[0]),
        &ctx,
        &result,
        None,
        None,
    );

    assert_eq!(explanation["deployment_profile"]["name"], "fapi");
    assert_eq!(
        explanation["deployment_profile"]["obligations"]["requires_par"],
        true
    );
    assert_eq!(
        explanation["deployment_profile"]["obligations"]["requires_http_message_signatures"],
        true
    );
    assert_eq!(
        explanation["deployment_profile"]["obligations"]["requires_signed_request_object"],
        true
    );
    assert_eq!(
        explanation["deployment_profile"]["obligations"]["requires_sender_constrained_resource_servers"],
        true
    );
    assert_eq!(
        explanation["deployment_profile"]["realm_status"]["pep_registrations"],
        0
    );
    assert_eq!(
        explanation["deployment_profile"]["realm_status"]["jwt_introspection_enabled"],
        true
    );
    assert_eq!(
        explanation["deployment_profile"]["realm_status"]["sender_constrained_resource_servers"],
        true
    );
}

#[test]
fn explain_json_reports_vc_profile_as_fapi_plus_vc_obligations() {
    let config = minimal_config();
    let explanation = build_explain_json(
        DeploymentProfile::Vc,
        Some(&config.realms[0]),
        &PolicyContext::default(),
        &DecisionDetails::default(),
        None,
        None,
    );

    let obligations = &explanation["deployment_profile"]["obligations"];
    assert_eq!(obligations["requires_http_message_signatures"], true);
    assert_eq!(obligations["requires_par"], true);
    assert_eq!(obligations["requires_rar"], true);
    assert_eq!(obligations["requires_dpop"], true);
    assert_eq!(obligations["requires_mtls"], true);
    assert_eq!(obligations["requires_private_key_jwt"], true);
    assert_eq!(obligations["requires_jarm"], true);
    assert_eq!(obligations["requires_signed_request_object"], true);
    assert_eq!(obligations["requires_jwt_introspection"], true);
    assert_eq!(
        obligations["requires_sender_constrained_resource_servers"],
        true
    );
    assert_eq!(obligations["requires_oid4vci"], true);
    assert_eq!(obligations["requires_oid4vp"], true);
    assert_eq!(obligations["requires_haip"], true);
    assert_eq!(obligations["requires_vc_data_model_2_0"], true);
    assert_eq!(obligations["requires_jose_cose"], true);
    assert_eq!(obligations["requires_vc_status_list"], true);
    assert_eq!(obligations["requires_holder_binding"], true);
}

#[test]
fn explain_json_reports_edge_pep_profile_obligations_from_core_validation() {
    let config = minimal_config();
    let explanation = build_explain_json(
        DeploymentProfile::EdgePep,
        Some(&config.realms[0]),
        &PolicyContext::default(),
        &DecisionDetails::default(),
        None,
        None,
    );

    let obligations = &explanation["deployment_profile"]["obligations"];
    assert_eq!(obligations["requires_http_message_signatures"], true);
    assert_eq!(obligations["requires_pep_registration"], true);
    assert_eq!(obligations["requires_fail_closed_pep_decision"], true);
    assert_eq!(obligations["requires_mtls"], true);
    assert!(
        obligations["requires_capability_effects"]
            .as_array()
            .expect("capability effects")
            .iter()
            .any(|effect| effect == "mirror_upstreams")
    );
}

#[test]
fn explain_json_reports_ciam_profile_obligations_separately_from_enterprise() {
    let config = minimal_config();
    let explanation = build_explain_json(
        DeploymentProfile::Ciam,
        Some(&config.realms[0]),
        &PolicyContext::default(),
        &DecisionDetails::default(),
        None,
        None,
    );

    let obligations = &explanation["deployment_profile"]["obligations"];
    assert_eq!(obligations["requires_scim"], false);
    assert_eq!(obligations["requires_oidc_discovery"], true);
    assert_eq!(obligations["requires_oidc_userinfo"], true);
    assert_eq!(obligations["requires_oidc_authorization_code"], true);
    assert_eq!(obligations["requires_pkce"], true);
    assert_eq!(obligations["requires_fedcm"], true);
    assert_eq!(obligations["requires_ciam_consent"], true);
    assert_eq!(obligations["requires_ciam_progressive_profile"], true);
    assert_eq!(obligations["requires_ciam_identity_proofing"], true);
    assert_eq!(obligations["requires_ciam_privacy_dashboard"], true);
    assert_eq!(obligations["requires_inbound_federation"], true);
    assert_eq!(
        obligations["requires_inbound_oidc_or_social_provider"],
        true
    );
}

#[test]
fn explain_json_reports_high_assurance_specific_obligations() {
    let config = minimal_config();
    let explanation = build_explain_json(
        DeploymentProfile::HighAssurance,
        Some(&config.realms[0]),
        &PolicyContext::default(),
        &DecisionDetails::default(),
        None,
        None,
    );

    let obligations = &explanation["deployment_profile"]["obligations"];
    assert_eq!(obligations["requires_http_message_signatures"], true);
    assert_eq!(obligations["requires_par"], true);
    assert_eq!(obligations["requires_rar"], true);
    assert_eq!(obligations["requires_dpop"], true);
    assert_eq!(obligations["requires_mtls"], true);
    assert_eq!(obligations["requires_private_key_jwt"], true);
    assert_eq!(obligations["requires_jarm"], true);
    assert_eq!(obligations["requires_signed_request_object"], true);
    assert_eq!(obligations["requires_jwt_introspection"], true);
    assert_eq!(
        obligations["requires_sender_constrained_resource_servers"],
        true
    );
    assert_eq!(
        obligations["requires_remote_kms_hsm_or_pkcs11_keyrings"],
        true
    );
    assert_eq!(obligations["requires_admin_approval"], true);
    assert_eq!(obligations["requires_admin_step_up"], true);
    assert_eq!(obligations["requires_backup"], true);
    assert_eq!(obligations["requires_passkeys"], true);
    assert_eq!(obligations["requires_passwordless_only"], true);
}

#[test]
fn explain_json_reports_network_aaa_obligations_from_core_validation() {
    let config = minimal_config();
    let explanation = build_explain_json(
        DeploymentProfile::NetworkAaa,
        Some(&config.realms[0]),
        &PolicyContext::default(),
        &DecisionDetails::default(),
        None,
        None,
    );

    let obligations = &explanation["deployment_profile"]["obligations"];
    assert_eq!(obligations["requires_radius"], true);
    assert_eq!(obligations["requires_radius_tls"], true);
    assert_eq!(obligations["requires_eap"], true);
    assert_eq!(obligations["requires_eap_tls"], true);
    assert_eq!(obligations["requires_capport"], true);
    assert_eq!(obligations["requires_coa"], true);
    assert_eq!(obligations["requires_accounting"], true);
    assert_eq!(obligations["requires_directory_authority"], true);
    assert_eq!(obligations["requires_mtls"], true);
    assert_eq!(obligations["requires_shared_secret"], true);
    assert_eq!(obligations["requires_radius_authentication_bind"], true);
    assert_eq!(obligations["requires_radius_tls_bind"], true);
    assert_eq!(obligations["requires_accounting_bind"], true);
    assert_eq!(obligations["requires_coa_bind"], true);
    assert_eq!(obligations["requires_radius_tls_certificate_path"], true);
    assert_eq!(obligations["requires_radius_tls_private_key_path"], true);
    assert_eq!(obligations["requires_radius_tls_client_ca_path"], true);
    assert_eq!(obligations["requires_enabled_directory_authority"], true);
    assert!(obligations.get("requires_radius_dtls").is_none());
    assert!(obligations.get("implemented").is_none());
}

#[test]
fn explain_json_merges_risk_evaluation_into_required_auth_pep_and_audit() {
    let ctx = PolicyContext {
        subject_id: Some("user-1".to_string()),
        resource_action: Some("connect".to_string()),
        resource_host: Some("download.example.test".to_string()),
        pep_registration: Some("egress-main".to_string()),
        risk_score: Some(70),
        ..PolicyContext::default()
    };
    let result = DecisionDetails {
        obligations: Vec::new(),
        context: None,
        decision: Decision::Allow,
        policy_id: "allow-egress".to_string(),
        policy_tags: vec!["qid:allow:allow-egress".to_string()],
        ..DecisionDetails::default()
    };
    let risk = evaluate_risk(&RiskInput {
        subject: Some("user-1".to_string()),
        device_trust: DeviceTrustState::Managed,
        destination_reputation: DestinationReputation::KnownGood,
        pep: Some(PepSignal {
            edge_name: Some("egress-main".to_string()),
            host: Some("download.example.test".to_string()),
            destination_category: Some("newly-registered-domain".to_string()),
            destination_reputation: Some(DestinationReputation::Suspicious),
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

    let explanation = build_explain_json(
        DeploymentProfile::Oidc,
        None,
        &ctx,
        &result,
        None,
        Some(&risk),
    );

    assert_eq!(explanation["risk_evaluation"]["outcome"], "force_inspect");
    assert_eq!(explanation["pep_actions"]["force_inspect"], true);
    assert_eq!(explanation["pep_actions"]["cache_bypass"], true);
    assert!(
        explanation["pep_actions"]["policy_tags"]
            .as_array()
            .expect("policy tags")
            .iter()
            .any(|tag| tag == "risk:pep-suspicious-destination")
    );
    assert_eq!(explanation["audit_fields"]["risk_score"], risk.score);
    assert_eq!(explanation["audit_fields"]["risk_outcome"], "force_inspect");
    assert_eq!(explanation["audit_fields"]["audit_level"], "high");

    let step_up_risk = evaluate_risk(&RiskInput {
        device_trust: DeviceTrustState::Unknown,
        destination_reputation: DestinationReputation::Suspicious,
        ..RiskInput::default()
    });
    let explanation = build_explain_json(
        DeploymentProfile::Oidc,
        None,
        &ctx,
        &result,
        None,
        Some(&step_up_risk),
    );
    assert_eq!(explanation["required_auth"]["step_up_required"], true);
    assert_eq!(
        explanation["required_auth"]["acr"],
        "urn:qid:acr:phishing-resistant"
    );
    assert_eq!(explanation["required_auth"]["amr"][0], "webauthn");
}
