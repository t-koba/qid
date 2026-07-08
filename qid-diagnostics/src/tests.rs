use super::*;
use qid_core::config::{
    AdminConfig, AuthenticationConfig, CryptoConfig, DeploymentProfile, KeyringConfig,
    OAuthResourceServerConfig, ObservabilityConfig, OpsConfig, PepAuthorityConfig,
    PepCapabilityConfig, PepCapabilityConstraintsConfig, PepRegistrationConfig,
    PepRegistrationsConfig, PolicyBundleConfig, PolicyConfig, ProtocolConfig, RealmConfig,
    RotationConfig, ServerConfig, ServerPaths, SignerConfig, StaticClientConfig, StorageConfig,
};
use qid_core::models::ClientType;
use std::time::{SystemTime, UNIX_EPOCH};

fn minimal_config() -> QidConfig {
    QidConfig {
        include: Vec::new(),
        profile: DeploymentProfile::Oidc,
        server: ServerConfig {
            listen: "127.0.0.1:8443".to_string(),
            public_base_url: "https://id.example.com".to_string(),
            tls: None,
            http_message_signatures: Default::default(),
            cors: qid_core::config::CorsConfig::default(),
            paths: ServerPaths::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig {
            default_alg: "ES256".to_string(),
            key_passphrase_file: None,
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

fn temp_config_dir(name: &str) -> std::path::PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("qid-diagnostics-{name}-{suffix}"))
}

fn pep_capability(effect: &str) -> PepCapabilityConfig {
    PepCapabilityConfig {
        mode: Some("forward_http".to_string()),
        phase: Some("pre_upstream".to_string()),
        effect: effect.to_string(),
        constraints: PepCapabilityConstraintsConfig::default(),
        authority: PepAuthorityConfig::default(),
        build_features: Vec::new(),
    }
}

#[tokio::test]
async fn storage_saas_audit_reports_broken_oidc_client_reference() {
    let dir = temp_config_dir("storage-saas-broken-oidc");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let store_path = dir.join("qid-store.json");
    let store = serde_json::json!({
        "realm_issuers": {
            "corp": "https://id.example.com/realms/corp"
        },
        "realm_tenants": {
            "corp": "tenant-corp"
        },
        "users": {},
        "credentials_password": {},
        "clients": {},
        "sessions": {},
        "authorization_codes": {},
        "token_families": {},
        "access_tokens": {},
        "webauthn_credentials": {},
        "service_accounts": {},
        "policy_bundles": {},
        "totp_credentials": {},
        "vc_credential_statuses": {},
        "devices": {},
        "par_requests": {},
        "device_authorization_grants": {},
        "backchannel_authentication_grants": {},
        "scim_users": {},
        "scim_groups": {},
        "fedcm_identities": {},
        "workload_identities": {},
        "custom_domains": {},
        "app_catalog_entries": {
            "app-broken": {
                "id": "app-broken",
                "tenant_id": "tenant-corp",
                "realm_id": "corp",
                "display_name": "Broken App",
                "category": "sales",
                "oidc_client_id": "missing-client",
                "saml_entity_id": null,
                "scim_enabled": false,
                "marketplace_connector_id": null
            }
        },
        "marketplace_connectors": {},
        "usage_billing_events": {},
        "compliance_evidence_packs": {},
        "iga_entitlements": {},
        "iga_access_packages": {},
        "iga_access_requests": {},
        "iga_approvals": {},
        "iga_access_grants": {},
        "iga_jit_privilege_grants": {},
        "iga_access_review_campaigns": {},
        "iga_access_review_decisions": {},
        "iga_certifications": {},
        "iga_findings": {},
        "audit_events": [],
        "audit_retention_configs": {}
    });
    std::fs::write(&store_path, store.to_string()).expect("store file");
    let repo = qid_storage::FileRepository::new(store_path.to_str().expect("utf-8 store path"))
        .await
        .expect("file repository");
    let config = minimal_config();

    let checks = check_storage_saas_with_repo(&config, &repo)
        .await
        .expect("storage audit");

    assert!(checks.iter().any(|check| {
        check.name == "storage.saas.tenant-corp.app_catalog.app-broken"
            && check.status == CheckStatus::Error
            && check.message.contains("OIDC client missing-client")
    }));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn check_report_covers_policy_pep_metrics_and_keyrings() {
    let dir = temp_config_dir("ok");
    std::fs::create_dir_all(dir.join("policies")).expect("temp dir");
    std::fs::write(dir.join("policies/authenticated-read.json"), "{}").expect("policy file");
    let mut config = minimal_config();
    config.realms[0].policy.bundles = vec![PolicyBundleConfig {
        name: "authenticated-read".to_string(),
        source: "file://./policies/authenticated-read.json".to_string(),
        mode: "enforce".to_string(),
    }];
    config.realms[0].clients = vec![StaticClientConfig {
        client_id: "web".to_string(),
        id: Some("client-web".to_string()),
        client_type: ClientType::Public,
        token_endpoint_auth_method: "none".to_string(),
        client_secret: None,
        client_secret_hash: None,
        mtls_certificate_thumbprints: Vec::new(),
        jwks: qid_core::models::default_client_jwks(),
        redirect_uris: vec!["https://app.example.com/callback".to_string()],
        grant_types: vec!["authorization_code".to_string()],
    }];
    config.realms[0].pep_registrations.enabled = true;
    config.realms[0].pep_registrations.registrations = vec![PepRegistrationConfig {
        name: "egress-main".to_string(),
        audience: Some("urn:qid:pep:qpx:corp/egress-main".to_string()),
        capabilities: Vec::new(),
        assertion: Default::default(),
        decision: Default::default(),
        auth: Default::default(),
    }];
    config.crypto.keyrings.push(KeyringConfig {
        name: "corp-pep-assertion".to_string(),
        realm_id: Some("corp".to_string()),
        purposes: vec!["pep_assertion".to_string()],
        signer: SignerConfig::default(),
        rotation: RotationConfig::default(),
    });
    config.realms[0].authentication.mfa.totp.enabled = true;
    config.realms[0].protocols.oauth.resource_servers = vec![OAuthResourceServerConfig {
        audience: "api://corp/payments".to_string(),
        resources: vec!["https://api.example.com/payments".to_string()],
        scopes: vec!["payments".to_string()],
        introspection_client_ids: vec!["payments-gateway".to_string()],
        require_sender_constraint: true,
        high_risk: true,
    }];
    let plan = qid_core::plan::RuntimePlan::from_config(&config).expect("runtime plan");

    let report = build_check_report(&config, &plan, &dir.join("qid.yaml"));

    assert_eq!(report.status, "ok");
    assert_eq!(report.summary.realms, 1);
    assert_eq!(report.summary.pep_registrations, 1);
    assert_eq!(report.summary.pep_registrations_count, 1);
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "profile.oidc" && check.status == CheckStatus::Ok)
    );
    assert!(report.checks.iter().any(|check| check.name
        == "policy_bundle.corp.authenticated-read"
        && check.status == CheckStatus::Ok));
    assert!(report.checks.iter().any(|check| {
        check.name == "pep_registration.corp.egress-main" && check.status == CheckStatus::Ok
    }));
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "keyring.corp-main" && check.status == CheckStatus::Ok)
    );
    assert!(report.checks.iter().any(|check| {
        check.name == "keyring.corp.pep_assertion" && check.status == CheckStatus::Ok
    }));
    assert!(report.checks.iter().any(|check| check.name
        == "resource_server.corp.api://corp/payments"
        && check.status == CheckStatus::Ok));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn check_report_warns_for_resource_server_policy_gaps() {
    let dir = temp_config_dir("resource-server-warning");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let mut config = minimal_config();
    config.realms[0].authentication.mfa.totp.enabled = true;
    config.realms[0].protocols.oauth.resource_servers = vec![
        OAuthResourceServerConfig {
            audience: "api://open".to_string(),
            resources: vec!["https://api.example.com/open".to_string()],
            scopes: Vec::new(),
            introspection_client_ids: Vec::new(),
            require_sender_constraint: false,
            high_risk: false,
        },
        OAuthResourceServerConfig {
            audience: "api://payments".to_string(),
            resources: vec!["https://api.example.com/payments".to_string()],
            scopes: vec!["payments".to_string()],
            introspection_client_ids: Vec::new(),
            require_sender_constraint: false,
            high_risk: true,
        },
    ];
    let plan = qid_core::plan::RuntimePlan::from_config(&config).expect("runtime plan");

    let report = build_check_report(&config, &plan, &dir.join("qid.yaml"));

    assert_eq!(report.status, "warning");
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "resource_server.corp.api://open"
                && check.status == CheckStatus::Warning)
    );
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "resource_server.corp.api://payments"
                && check.status == CheckStatus::Warning)
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn check_report_errors_when_pep_realm_lacks_dedicated_assertion_keyring() {
    let dir = temp_config_dir("missing-pep-keyring");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let mut config = minimal_config();
    config.realms[0].pep_registrations.enabled = true;
    config.realms[0].pep_registrations.registrations = vec![PepRegistrationConfig {
        name: "egress-main".to_string(),
        audience: Some("urn:qid:pep:qpx:corp/egress-main".to_string()),
        capabilities: Vec::new(),
        assertion: Default::default(),
        decision: Default::default(),
        auth: Default::default(),
    }];
    config.crypto.keyrings[0].purposes =
        vec!["oidc_token".to_string(), "pep_assertion".to_string()];
    let plan = qid_core::plan::RuntimePlan::from_config(&config).expect("runtime plan");

    let report = build_check_report(&config, &plan, &dir.join("qid.yaml"));

    assert_eq!(report.status, "error");
    assert!(report.checks.iter().any(|check| {
        check.name == "keyring.corp.pep_assertion"
            && check.status == CheckStatus::Error
            && check.message.contains("must be dedicated")
    }));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn edge_pep_profile_diagnostics_match_core_required_surface() {
    let dir = temp_config_dir("edge-pep-profile");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let mut config = minimal_config();
    config.profile = DeploymentProfile::EdgePep;
    config.realms[0].pep_registrations.enabled = true;
    config.realms[0].protocols.oauth.mtls.enabled = true;
    config.realms[0].pep_registrations.registrations = vec![PepRegistrationConfig {
        name: "egress-main".to_string(),
        audience: Some("urn:qid:pep:qpx:corp/egress-main".to_string()),
        capabilities: vec![pep_capability("challenge")],
        assertion: Default::default(),
        decision: Default::default(),
        auth: Default::default(),
    }];
    let plan_config = minimal_config();
    let plan = qid_core::plan::RuntimePlan::from_config(&plan_config).expect("runtime plan");

    let report = build_check_report(&config, &plan, &dir.join("qid.yaml"));

    assert_eq!(report.status, "error");
    assert!(report.checks.iter().any(|check| check.name
        == "profile.edge-pep.http_message_signatures"
        && check.status == CheckStatus::Error));
    assert!(report.checks.iter().any(|check| check.name
        == "profile.edge-pep.capability.realm.corp.egress-main.inject_headers"
        && check.status == CheckStatus::Error));
    assert!(report.checks.iter().any(|check| check.name
        == "profile.edge-pep.capability.realm.corp.egress-main.challenge"
        && check.status == CheckStatus::Ok));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn edge_pep_profile_diagnostics_ignore_disabled_registration_realms() {
    let dir = temp_config_dir("edge-pep-disabled-profile");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let mut config = minimal_config();
    config.profile = DeploymentProfile::EdgePep;
    config.server.http_message_signatures.enabled = true;
    config.realms[0].pep_registrations.enabled = false;
    config.realms[0].pep_registrations.registrations = vec![PepRegistrationConfig {
        name: "egress-main".to_string(),
        audience: Some("urn:qid:pep:qpx:corp/egress-main".to_string()),
        capabilities: vec![pep_capability("challenge")],
        assertion: Default::default(),
        decision: Default::default(),
        auth: Default::default(),
    }];
    let plan_config = minimal_config();
    let plan = qid_core::plan::RuntimePlan::from_config(&plan_config).expect("runtime plan");

    let report = build_check_report(&config, &plan, &dir.join("qid.yaml"));

    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "profile.edge-pep.registrations"
                && check.status == CheckStatus::Error)
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn vc_profile_diagnostics_include_fapi_prerequisites() {
    let dir = temp_config_dir("vc-profile");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let mut config = minimal_config();
    config.profile = DeploymentProfile::Vc;
    config.realms[0].protocols.vc.oid4vci = true;
    config.realms[0].protocols.vc.oid4vp = true;
    config.realms[0].protocols.vc.haip = true;
    config.realms[0].protocols.vc.vc_data_model_2_0 = true;
    config.realms[0].protocols.vc.jose_cose = true;
    config.realms[0].protocols.vc.status_list = true;
    config.realms[0].protocols.vc.holder_binding_required = true;
    config.realms[0].protocols.vc.issuer_key_ref = Some("kms://qid/vc".to_string());
    let plan_config = minimal_config();
    let plan = qid_core::plan::RuntimePlan::from_config(&plan_config).expect("runtime plan");

    let report = build_check_report(&config, &plan, &dir.join("qid.yaml"));

    assert_eq!(report.status, "error");
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "profile.vc.http_message_signatures"
                && check.status == CheckStatus::Error)
    );
    assert!(report.checks.iter().any(
        |check| check.name == "profile.vc.rar.realm.corp" && check.status == CheckStatus::Error
    ));
    assert!(report.checks.iter().any(|check| check.name
        == "profile.vc.sender_constrained_resource_servers.realm.corp"
        && check.status == CheckStatus::Error));
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "profile.vc.OID4VCI.realm.corp"
                && check.status == CheckStatus::Ok)
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn high_assurance_profile_diagnostics_include_fapi_prerequisites() {
    let dir = temp_config_dir("high-assurance-profile");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let mut config = minimal_config();
    config.profile = DeploymentProfile::HighAssurance;
    config.crypto.keyrings[0].signer.r#type = "kms".to_string();
    config.admin.security.require_approval = true;
    config.admin.security.require_step_up = true;
    config.ops.backup.enabled = true;
    config.ops.backup.object_store_uri = Some("s3://qid-test-backups/ha".to_string());
    config.ops.backup.migration_version = Some("20250628000002".to_string());
    config.realms[0].authentication.passkeys.enabled = true;
    config.realms[0].authentication.passwordless_only = true;
    let plan_config = minimal_config();
    let plan = qid_core::plan::RuntimePlan::from_config(&plan_config).expect("runtime plan");

    let report = build_check_report(&config, &plan, &dir.join("qid.yaml"));

    assert_eq!(report.status, "error");
    assert!(report.checks.iter().any(|check| check.name
        == "profile.high-assurance.http_message_signatures"
        && check.status == CheckStatus::Error));
    assert!(report.checks.iter().any(|check| check.name
        == "profile.high-assurance.par.realm.corp"
        && check.status == CheckStatus::Error));
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "profile.high-assurance.keyrings"
                && check.status == CheckStatus::Ok)
    );
    assert!(report.checks.iter().any(|check| check.name
        == "profile.high-assurance.passwordless.realm.corp"
        && check.status == CheckStatus::Ok));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn check_report_warns_for_misaligned_issuer_and_missing_policy_source() {
    let dir = temp_config_dir("warn");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let mut config = minimal_config();
    config.realms[0].issuer = "https://issuer.other.example/realms/corp".to_string();
    config.realms[0].policy.bundles = vec![PolicyBundleConfig {
        name: "missing".to_string(),
        source: "file://./policies/missing.json".to_string(),
        mode: "enforce".to_string(),
    }];
    let plan = qid_core::plan::RuntimePlan::from_config(&config).expect("runtime plan");

    let report = build_check_report(&config, &plan, &dir.join("qid.yaml"));

    assert_eq!(report.status, "warning");
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "issuer.corp" && check.status == CheckStatus::Warning)
    );
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "policy_bundle.corp.missing"
                && check.status == CheckStatus::Warning)
    );
    std::fs::remove_dir_all(&dir).ok();
}
