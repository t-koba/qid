use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use qid_core::config::{
    AdminConfig, AuthenticationConfig, CryptoConfig, DeploymentProfile, InboundProviderConfig,
    KeyringConfig, OAuthResourceServerConfig, ObservabilityConfig, OpsConfig, PepCapabilityConfig,
    PepRegistrationConfig, PepRegistrationsConfig, PolicyBundleConfig, PolicyConfig,
    ProtocolConfig, RealmConfig, RotationConfig, ServerConfig, ServerPaths, SignerConfig,
    StaticClientConfig, StorageConfig,
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
            hsts: Default::default(),
            quic: Default::default(),
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
        effect: effect.to_string(),
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
    std::fs::write(
        dir.join("policies/authenticated-read.json"),
        serde_json::json!({
            "version": "1",
            "default_decision": "deny",
            "rules": [{
                "name": "allow-authenticated-read",
                "type": "allow",
                "action": "read",
                "resource_host": "*"
            }]
        })
        .to_string(),
    )
    .expect("policy file");
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
fn ciam_profile_diagnostics_follow_shared_inbound_provider_requirement() {
    let mut config = minimal_config();
    config.profile = DeploymentProfile::Ciam;
    config.realms[0].protocols.federation.enabled = true;
    config.realms[0]
        .protocols
        .federation
        .inbound_providers
        .push(InboundProviderConfig {
            id: "social-google".to_string(),
            kind: "social".to_string(),
            issuer: "https://accounts.google.com".to_string(),
            enabled: true,
            domains: vec!["example.com".to_string()],
            social_provider: Some("google".to_string()),
            client_id: Some("google-client".to_string()),
            client_secret: Some("secret://google".to_string()),
            token_url: None,
            userinfo_url: None,
            jit_provisioning: true,
            account_linking: true,
            claim_mappings: Vec::new(),
            jwks_uri: None,
            jwks: None,
            saml_signing_certificates: Vec::new(),
        });
    let federation_status = |config: &QidConfig| {
        check_profile_obligations(config)
            .into_iter()
            .find(|check| check.name == "profile.ciam.federation.realm.corp")
            .expect("CIAM federation profile check")
            .status
    };
    assert_eq!(federation_status(&config), CheckStatus::Ok);

    config.realms[0].protocols.federation.inbound_providers[0].client_secret = None;
    assert_eq!(federation_status(&config), CheckStatus::Error);
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
fn pep_registration_diagnostics_report_only_the_registrations_a_realm_serves() {
    let dir = temp_config_dir("pep-registration-served");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let mut config = minimal_config();
    config.realms[0].pep_registrations.enabled = false;
    config.realms[0].pep_registrations.registrations = vec![PepRegistrationConfig {
        name: "egress-main".to_string(),
        audience: Some("urn:qid:pep:qpx:corp/egress-main".to_string()),
        capabilities: Vec::new(),
        assertion: Default::default(),
        decision: Default::default(),
        auth: Default::default(),
    }];
    let plan = qid_core::plan::RuntimePlan::from_config(&config).expect("runtime plan");

    let report = build_check_report(&config, &plan, &dir.join("qid.yaml"));

    assert_eq!(report.summary.pep_registrations, 0);
    // The report names the registration as declared but not served, and
    // never as a healthy registration of the realm.
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "pep_registration.corp"
                && check.status == CheckStatus::NotApplicable
                && check.message.contains("not served"))
    );
    assert!(
        !report
            .checks
            .iter()
            .any(|check| check.name == "pep_registration.corp.egress-main"
                && check.status == CheckStatus::Ok)
    );
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

#[test]
fn high_risk_mfa_requires_an_enabled_factor() {
    fn high_risk_config() -> QidConfig {
        let mut config = minimal_config();
        config.realms[0].protocols.oauth.resource_servers = vec![OAuthResourceServerConfig {
            audience: "api://corp/payments".to_string(),
            resources: vec!["https://api.example.com/payments".to_string()],
            scopes: vec!["payments".to_string()],
            introspection_client_ids: Vec::new(),
            require_sender_constraint: false,
            high_risk: true,
        }];
        config
    }
    fn weak_mfa_status(config: &QidConfig) -> (CheckStatus, String) {
        let check = check_weak_flows(config)
            .into_iter()
            .find(|check| check.name == "weak_mfa.corp")
            .expect("weak_mfa.corp check");
        (check.status, check.message)
    }

    // With every factor disabled the realm has no strong MFA.
    let config = high_risk_config();
    assert!(!config.realms[0].authentication.mfa.totp.enabled);
    assert!(!config.realms[0].authentication.passkeys.enabled);
    let (status, message) = weak_mfa_status(&config);
    assert_eq!(status, CheckStatus::Error);
    assert!(message.contains("no MFA"), "unexpected message: {message}");
    assert!(message.contains("TOTP"), "unexpected message: {message}");
    assert!(
        message.contains("passkeys"),
        "unexpected message: {message}"
    );

    // Each factor the product can perform satisfies the diagnostic, and the
    // check names the factors the realm can actually use.
    let mut config = high_risk_config();
    config.realms[0].authentication.mfa.totp.enabled = true;
    let (status, message) = weak_mfa_status(&config);
    assert_eq!(status, CheckStatus::Ok);
    assert!(message.contains("TOTP"), "unexpected message: {message}");

    let mut config = high_risk_config();
    config.realms[0].authentication.passkeys.enabled = true;
    let (status, message) = weak_mfa_status(&config);
    assert_eq!(status, CheckStatus::Ok);
    assert!(
        message.contains("passkeys"),
        "unexpected message: {message}"
    );
}

fn minimal_native_bundle(name: &str) -> String {
    serde_json::json!({
        "version": "1",
        "default_decision": "deny",
        "rules": [{
            "name": name,
            "type": "allow",
            "action": "read",
            "resource_host": "*"
        }]
    })
    .to_string()
}

fn policy_check_for(
    dir: &std::path::Path,
    source: &str,
    content: Option<(&str, &str)>,
) -> CheckItem {
    if let Some((rel, body)) = content {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("policy parent");
        }
        std::fs::write(&path, body).expect("policy file");
    }
    let mut config = minimal_config();
    config.realms[0].policy.bundles = vec![PolicyBundleConfig {
        name: "bundle".to_string(),
        source: source.to_string(),
        mode: "enforce".to_string(),
    }];
    check_policy_bundles(&config, &dir.join("qid.yaml"))
        .into_iter()
        .find(|check| check.name == "policy_bundle.corp.bundle")
        .expect("policy bundle check")
}

#[test]
fn policy_bundles_reject_structurally_invalid_json() {
    let dir = temp_config_dir("policy-invalid-shape");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let check = policy_check_for(
        &dir,
        "file://policies/bundle.json",
        Some(("policies/bundle.json", r#"{"version": "1"}"#)),
    );
    assert_eq!(check.status, CheckStatus::Error, "{check:?}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn policy_bundles_reject_non_json_content_with_plausible_extension() {
    let dir = temp_config_dir("policy-non-json");
    std::fs::create_dir_all(&dir).expect("temp dir");
    for (source, path, content) in [
        (
            "file://policies/bundle.yaml",
            "policies/bundle.yaml",
            "version: 1\ndefault_decision: deny\nrules: []\n",
        ),
        (
            "file://policies/bundle.rego",
            "policies/bundle.rego",
            "package authz\nallow = true\n",
        ),
    ] {
        let check = policy_check_for(&dir, source, Some((path, content)));
        assert_eq!(check.status, CheckStatus::Error, "{check:?}");
        assert!(
            check.message.contains("not valid JSON") || check.message.contains("invalid policy"),
            "unexpected message: {}",
            check.message
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn policy_bundles_report_remote_sources_as_errors() {
    let dir = temp_config_dir("policy-remote");
    std::fs::create_dir_all(&dir).expect("temp dir");
    for source in [
        "https://example.com/bundle.json",
        "http://example.com/bundle.json",
    ] {
        let check = policy_check_for(&dir, source, None);
        assert_eq!(check.status, CheckStatus::Error, "{check:?}");
        assert!(
            check.message.contains("not supported at startup"),
            "unexpected message: {}",
            check.message
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn policy_bundles_resolve_relative_file_and_bare_paths_from_config_dir() {
    let dir = temp_config_dir("policy-relative");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let bundle = minimal_native_bundle("allow-read");
    let file_check = policy_check_for(
        &dir,
        "file://policies/bundle.json",
        Some(("policies/bundle.json", &bundle)),
    );
    assert_eq!(file_check.status, CheckStatus::Ok, "{file_check:?}");

    let dir2 = temp_config_dir("policy-relative-bare");
    std::fs::create_dir_all(&dir2).expect("temp dir");
    let bare_check = policy_check_for(
        &dir2,
        "policies/bundle.json",
        Some(("policies/bundle.json", &bundle)),
    );
    assert_eq!(bare_check.status, CheckStatus::Ok, "{bare_check:?}");
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&dir2).ok();
}

#[test]
fn policy_bundles_accept_absolute_paths() {
    let dir = temp_config_dir("policy-absolute");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let target = dir.join("policies/bundle.json");
    std::fs::create_dir_all(target.parent().expect("parent")).expect("temp dir");
    std::fs::write(&target, minimal_native_bundle("allow-read")).expect("policy file");
    let absolute = target.to_str().expect("utf-8 path").to_string();
    let check = policy_check_for(&dir, &absolute, None);
    assert_eq!(check.status, CheckStatus::Ok, "{check:?}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn scim_custom_schemas_are_reported_as_unsupported() {
    use qid_core::config::{CustomScimAttributeConfig, CustomScimSchemaConfig};
    fn custom(id: &str) -> CustomScimSchemaConfig {
        CustomScimSchemaConfig {
            id: id.to_string(),
            name: "Custom".to_string(),
            description: "custom".to_string(),
            attributes: vec![CustomScimAttributeConfig {
                name: "customAttr".to_string(),
                r#type: "string".to_string(),
                multi_valued: false,
                required: false,
                case_exact: false,
                mutability: "readWrite".to_string(),
                returned: "default".to_string(),
            }],
        }
    }
    for enabled in [true, false] {
        let mut config = minimal_config();
        config.realms[0].protocols.scim.enabled = enabled;
        config.realms[0].protocols.scim.custom_schemas = vec![custom("urn:example:Custom")];
        let checks = check_scim_schemas(&config);
        let error = checks
            .iter()
            .find(|c| c.name == "scim.schema.realm.corp")
            .expect("unsupported declaration must be reported");
        assert_eq!(error.status, CheckStatus::Error);
        assert!(error.message.contains("unsupported"), "{error:?}");
        assert!(
            !error.message.contains("urn:example:Custom"),
            "diagnostic must not echo values: {error:?}"
        );
    }
    let mut clean = minimal_config();
    clean.realms[0].protocols.scim.enabled = true;
    let checks = check_scim_schemas(&clean);
    assert!(
        checks
            .iter()
            .any(|c| c.name == "scim.realm.corp" && c.status == CheckStatus::Ok)
    );
    assert!(
        !checks
            .iter()
            .any(|c| c.status == CheckStatus::Error && c.name.starts_with("scim.schema"))
    );
}

const SAML_TEST_CERTIFICATE_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIUBklt5yFAf9IfAMSY3gfu71ytLNkwDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yNjA2MjMxNjAwMThaFw0yNzA2MjMxNjAw
MThaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC+s1dflRD/3v+RyxIvc38/kZqJOiihSPSgAn5bxza4TLK7WSwzFS4S4kaG
wdYecsP9LB6NrOl2Hfx5y1nBOQQLHbQGMt9gzToVHcofQLn+2qqlOqtilGaNfYm6
FURG71zn1WLgDT1cUuwHUjSLKjsIPuS12+mKwseyqK17g/VSWHs9aDTHZyzxAQjd
v+4pD4r65We9L7N7ZWCogjBFmFrkExsn7csH1tMWgq5SQtuJzH4ksq8+iW+1uRoL
5lg1gE9ICpogIAOtQhTMCvhmlJ0go5+eB2aX999ejTLkbllGG7L4Q3/wZ3j9bq7/
jH4ElAfwASJn97wjePmVisPLzq+NAgMBAAGjUzBRMB0GA1UdDgQWBBRSr8sT8LIG
mRyacAk/70h0hB1PCzAfBgNVHSMEGDAWgBRSr8sT8LIGmRyacAk/70h0hB1PCzAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBfqg5gAEXnXeEkQuNf
CqEMxeueHdLbRFAx36DgKVLju79dQthuzf1ivjBcxxIoXrA+Nfi1/cTxOH9nvEnk
1vxhuPxsvSriC9pyTeMaV5pqmUG0hvaGpyRw2UHn1b3dIhG2wCtbVIDMtzDOOB4w
VlgZPT+tfVzEVy9p2FTTJV62cwpo8+az/narUloBdH7sqK3Vdb0OLNFC4hvUaa03
YC/puz1Ykv6XmDxAOVTkZ+xLJncQq7+l942aYoDdnb0+U2RbFxnSdF3ldu7f+TpN
xXH34azFfDbpP5BnN1dZUOrFzmBUg/qlEXwe3eWCHGgA13q5p8PNw+SxETUnV9T6
Cw5L
-----END CERTIFICATE-----"#;

#[test]
fn saml_certificate_diagnostics_accept_pem_and_bare_base64() {
    let pem = SAML_TEST_CERTIFICATE_PEM;
    let bare_base64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let now =
        x509_parser::time::ASN1Time::from_timestamp(1_800_000_000).expect("fixed test timestamp");

    for (purpose, certificate) in [
        (SamlCertificatePurpose::Signing, pem.to_string()),
        (SamlCertificatePurpose::Signing, bare_base64.clone()),
        (SamlCertificatePurpose::Encryption, bare_base64.clone()),
    ] {
        let check = check_saml_certificates_at("saml.test", &[certificate], purpose, now)
            .pop()
            .expect("one configured certificate yields one diagnostic");
        assert_eq!(check.status, CheckStatus::Ok, "{check:?}");
        assert!(check.message.contains("valid certificate"), "{check:?}");
    }

    let encryption_pem = check_saml_certificates_at(
        "saml.test",
        &[pem.to_string()],
        SamlCertificatePurpose::Encryption,
        now,
    )
    .pop()
    .expect("diagnostic");
    assert_eq!(encryption_pem.status, CheckStatus::Error);
    assert!(encryption_pem.message.contains("invalid base64"));
}

#[test]
fn saml_certificate_diagnostics_reject_malformed_and_preserve_validity_checks() {
    let pem = SAML_TEST_CERTIFICATE_PEM;
    let malformed_der = STANDARD.encode(b"not an X.509 certificate");
    let future =
        x509_parser::time::ASN1Time::from_timestamp(1_700_000_000).expect("fixed test timestamp");
    let valid =
        x509_parser::time::ASN1Time::from_timestamp(1_800_000_000).expect("fixed test timestamp");
    let expired_at =
        x509_parser::time::ASN1Time::from_timestamp(1_900_000_000).expect("fixed test timestamp");

    let malformed_base64 = check_saml_certificates_at(
        "saml.test",
        &["not base64!".to_string()],
        SamlCertificatePurpose::Signing,
        valid,
    )
    .pop()
    .expect("diagnostic");
    assert_eq!(malformed_base64.status, CheckStatus::Error);
    assert!(malformed_base64.message.contains("invalid base64"));

    let malformed_certificate = check_saml_certificates_at(
        "saml.test",
        &[malformed_der],
        SamlCertificatePurpose::Signing,
        valid,
    )
    .pop()
    .expect("diagnostic");
    assert_eq!(malformed_certificate.status, CheckStatus::Error);
    assert!(malformed_certificate.message.contains("invalid X.509"));

    let not_yet_valid = check_saml_certificates_at(
        "saml.test",
        &[pem.to_string()],
        SamlCertificatePurpose::Signing,
        future,
    )
    .pop()
    .expect("diagnostic");
    assert_eq!(not_yet_valid.status, CheckStatus::Warning);
    assert!(not_yet_valid.message.contains("not yet valid"));

    let expired = check_saml_certificates_at(
        "saml.test",
        &[pem.to_string()],
        SamlCertificatePurpose::Signing,
        expired_at,
    )
    .pop()
    .expect("diagnostic");
    assert_eq!(expired.status, CheckStatus::Error);
    assert!(expired.message.contains("certificate expired"));
}
