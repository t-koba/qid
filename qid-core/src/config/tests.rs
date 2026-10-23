use super::*;

fn minimal_config() -> QidConfig {
    QidConfig {
        include: Vec::new(),
        profile: DeploymentProfile::Oidc,
        server: ServerConfig {
            listen: "0.0.0.0:8443".to_string(),
            public_base_url: "https://id.example.com".to_string(),
            tls: None,
            http_message_signatures: Default::default(),
            cors: CorsConfig::default(),
            paths: ServerPaths::default(),
            hsts: Default::default(),
            quic: Default::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig::default(),
        realms: vec![RealmConfig {
            id: "corp".to_string(),
            issuer: "https://id.example.com/realms/corp".to_string(),
            display_name: None,
            tenant_id: None,
            clients: Vec::new(),
            protocols: ProtocolConfig::default(),
            authentication: AuthenticationConfig::default(),
            sessions: SessionConfig::default(),
            pep_registrations: PepRegistrationsConfig::default(),
            policy: PolicyConfig::default(),
        }],
        observability: ObservabilityConfig::default(),
        ops: OpsConfig::default(),
    }
}

fn pep_capability(effect: &str) -> PepCapabilityConfig {
    PepCapabilityConfig {
        effect: effect.to_string(),
    }
}

fn es256_public_jwk(kid: &str) -> serde_json::Value {
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "y": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "kid": kid,
        "use": "sig",
        "alg": "ES256"
    })
}

fn temp_config_path(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("qid-config-test-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).expect("temp config dir");
    dir.join(name)
}

#[test]
fn config_loader_merges_includes_before_parent_and_later_config_overrides() {
    let base = temp_config_path("base.yaml");
    let overlay = base.with_file_name("overlay.yaml");
    let second = base.with_file_name("second.yaml");
    std::fs::write(
        &base,
        r#"
server:
  listen: "127.0.0.1:8443"
  public_base_url: "https://id.example.com"
realms:
  - id: corp
    issuer: "https://id.example.com/realms/corp"
"#,
    )
    .expect("write base config");
    std::fs::write(
        &overlay,
        r#"
include:
  - base.yaml
server:
  listen: "127.0.0.1:9443"
"#,
    )
    .expect("write overlay config");
    std::fs::write(
        &second,
        r#"
server:
  listen: "127.0.0.1:10443"
"#,
    )
    .expect("write second config");

    let config = QidConfig::from_files([overlay, second]).expect("merged config");

    assert_eq!(config.server.listen, "127.0.0.1:10443");
    assert_eq!(config.realms[0].id, "corp");
}

#[test]
fn config_loader_rejects_include_cycles() {
    let first = temp_config_path("first.yaml");
    let second = first.with_file_name("second.yaml");
    std::fs::write(
        &first,
        r#"
include:
  - second.yaml
server:
  listen: "127.0.0.1:8443"
  public_base_url: "https://id.example.com"
realms:
  - id: corp
    issuer: "https://id.example.com/realms/corp"
"#,
    )
    .expect("write first config");
    std::fs::write(
        &second,
        r#"
include:
  - first.yaml
"#,
    )
    .expect("write second config");

    let err = QidConfig::from_file(first.to_str().expect("temp path utf-8")).unwrap_err();

    assert!(err.message().contains("include cycle"));
}

#[test]
fn test_minimal_config_validation() {
    let config = QidConfig {
        include: Vec::new(),
        profile: DeploymentProfile::Oidc,
        server: ServerConfig {
            listen: "0.0.0.0:8443".to_string(),
            public_base_url: "https://id.example.com".to_string(),
            tls: None,
            http_message_signatures: Default::default(),
            cors: CorsConfig::default(),
            paths: ServerPaths::default(),
            hsts: Default::default(),
            quic: Default::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig::default(),
        realms: vec![RealmConfig {
            id: "corp".to_string(),
            issuer: "https://id.example.com/realms/corp".to_string(),
            display_name: None,
            tenant_id: None,
            clients: Vec::new(),
            protocols: ProtocolConfig::default(),
            authentication: AuthenticationConfig::default(),
            sessions: SessionConfig::default(),
            pep_registrations: PepRegistrationsConfig::default(),
            policy: PolicyConfig::default(),
        }],
        observability: ObservabilityConfig::default(),
        ops: OpsConfig::default(),
    };
    assert!(config.validate().is_ok());
}

#[test]
fn server_cors_rejects_wildcard_credentials_and_non_origins() {
    let mut config = minimal_config();
    config.server.cors.allowed_origins = vec!["*".to_string()];
    config.server.cors.allow_credentials = true;
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("wildcard origin"));

    let mut config = minimal_config();
    config.server.cors.allowed_origins = vec!["https://app.example.com/callback".to_string()];
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("path"));
}

#[test]
fn rust_defaults_match_serde_defaults_for_nested_config() {
    assert_eq!(
        serde_json::from_value::<CorsConfig>(serde_json::json!({})).unwrap(),
        CorsConfig::default()
    );
    assert_eq!(
        serde_json::from_value::<PrimaryStorageConfig>(serde_json::json!({})).unwrap(),
        PrimaryStorageConfig::default()
    );
    assert_eq!(
        serde_json::from_value::<FileStorageConfig>(serde_json::json!({})).unwrap(),
        FileStorageConfig::default()
    );
    assert_eq!(
        serde_json::from_value::<ScimProtocolConfig>(serde_json::json!({})).unwrap(),
        ScimProtocolConfig::default()
    );
    assert_eq!(
        serde_json::from_value::<PasskeyConfig>(serde_json::json!({})).unwrap(),
        PasskeyConfig::default()
    );
    assert_eq!(
        serde_json::from_value::<PasswordConfig>(serde_json::json!({})).unwrap(),
        PasswordConfig::default()
    );
    assert_eq!(
        serde_json::from_value::<TotpConfig>(serde_json::json!({})).unwrap(),
        TotpConfig::default()
    );
    assert_eq!(
        serde_json::from_value::<BrowserSessionConfig>(serde_json::json!({})).unwrap(),
        BrowserSessionConfig::default()
    );
    assert_eq!(
        serde_json::from_value::<RefreshTokenConfig>(serde_json::json!({})).unwrap(),
        RefreshTokenConfig::default()
    );
    assert_eq!(
        serde_json::from_value::<ProxyAssertionConfig>(serde_json::json!({})).unwrap(),
        ProxyAssertionConfig::default()
    );
    assert_eq!(
        serde_json::from_value::<PepDecisionConfig>(serde_json::json!({})).unwrap(),
        PepDecisionConfig::default()
    );
    let decision: PepDecisionConfig =
        serde_json::from_value(serde_json::json!({ "fail_policy": "deny" })).unwrap();
    assert_eq!(decision.fail_policy, "deny");
    assert_eq!(
        serde_json::from_value::<PepDecisionCacheConfig>(serde_json::json!({})).unwrap(),
        PepDecisionCacheConfig::default()
    );
    assert_eq!(
        serde_json::from_value::<PolicyConfig>(serde_json::json!({})).unwrap(),
        PolicyConfig::default()
    );
    assert_eq!(
        serde_json::from_value::<LogConfig>(serde_json::json!({})).unwrap(),
        LogConfig::default()
    );
    assert_eq!(
        serde_json::from_value::<MetricsConfig>(serde_json::json!({})).unwrap(),
        MetricsConfig::default()
    );
    assert_eq!(PrimaryStorageConfig::default().r#type, "sqlite");
    assert_eq!(ScimProtocolConfig::default().base_path, "/scim/v2");
    assert!(
        ScimProtocolConfig::default()
            .event_callback_allowed_hosts
            .is_empty()
    );
    assert_eq!(MetricsConfig::default().listen, "127.0.0.1:9464");
}

#[test]
fn file_storage_flush_mode_is_validated() {
    let mut config = minimal_config();
    config.storage.file.flush_mode = "interval_ms(250)".to_string();
    config.validate().unwrap();
    assert_eq!(config.storage.file.flush_interval_ms().unwrap(), Some(250));

    config.storage.file.flush_mode = "interval_ms(0)".to_string();
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("greater than zero"));
}

#[test]
fn scim_event_callback_allowlist_rejects_unsafe_hosts() {
    let mut config = minimal_config();
    config.realms[0].protocols.scim.enabled = true;
    config.realms[0].protocols.scim.cursor_secret =
        Some("01234567890123456789012345678901".to_string());
    config.realms[0].protocols.scim.event_callback_allowed_hosts =
        vec!["events.example.com".to_string()];
    config.validate().unwrap();

    config.realms[0].protocols.scim.event_callback_allowed_hosts = vec!["localhost".to_string()];
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("event_callback_allowed_hosts"));
}

#[test]
fn crypto_config_rejects_unsafe_keyrings() {
    let mut config = minimal_config();
    config.crypto.default_alg = "HS256".to_string();
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("crypto.default_alg"));

    config.crypto.default_alg = "EdDSA".to_string();
    config.crypto.keyrings = vec![KeyringConfig {
        name: "corp-main".to_string(),
        realm_id: Some("corp".to_string()),
        purposes: vec!["oidc_token".to_string()],
        signer: SignerConfig {
            r#type: "kms".to_string(),
            uri: None,
            public_jwk: None,
        },
        rotation: RotationConfig::default(),
    }];
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("requires uri"));

    config.crypto.keyrings[0].signer.uri = Some("hsm://slot/1".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("signer kms uri"));

    config.crypto.keyrings[0].signer.uri = Some("kms://alias/qid-corp".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("requires public_jwk"));

    config.crypto.keyrings[0].signer.public_jwk = Some(es256_public_jwk("corp-main"));
    config
        .crypto
        .keyrings
        .push(config.crypto.keyrings[0].clone());
    let err = config.validate().unwrap_err();
    assert!(
        err.message().contains("duplicate crypto keyring"),
        "{}",
        err.message()
    );

    config.crypto.keyrings.truncate(1);
    config.crypto.keyrings[0].signer.uri = Some("aws-kms://alias/qid-corp".to_string());
    config.crypto.keyrings[0].rotation.overlap_days = 91;
    config.crypto.keyrings[0].rotation.max_age_days = 90;
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("rotation.overlap_days"));

    config.crypto.keyrings[0].rotation.overlap_days = 14;
    assert!(config.validate().is_ok());

    config.crypto.keyrings[0].purposes = vec!["pep_assertion".to_string()];
    assert!(config.validate().is_ok());

    config.crypto.keyrings[0].purposes =
        vec!["pep_assertion".to_string(), "pep_assertion".to_string()];
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("duplicate purpose"));

    config.crypto.keyrings[0].purposes = vec!["weak-purpose".to_string()];
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("unsupported purpose"));
}

#[test]
fn static_client_config_rejects_weak_or_ambiguous_redirects() {
    let mut config = minimal_config();
    config.realms[0].clients = vec![StaticClientConfig {
        client_id: "web".to_string(),
        id: None,
        client_type: ClientType::Public,
        token_endpoint_auth_method: "none".to_string(),
        client_secret: None,
        client_secret_hash: None,
        mtls_certificate_thumbprints: Vec::new(),
        jwks: crate::models::default_client_jwks(),
        redirect_uris: vec!["https://app.example.com/callback".to_string()],
        grant_types: vec!["authorization_code".to_string()],
    }];
    assert!(config.validate().is_ok());

    config.realms[0].clients[0].redirect_uris = vec!["https://*.example.com/callback".to_string()];
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("wildcards"));

    config.realms[0].clients[0].redirect_uris = vec!["http://app.example.com/callback".to_string()];
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("https"));

    config.realms[0].clients[0].redirect_uris =
        vec!["https://app.example.com/callback".to_string()];
    config.realms[0].clients[0].grant_types = vec!["password".to_string()];
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("forbidden weak grant"));

    config.realms[0].clients[0].grant_types = vec!["client_credentials".to_string()];
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("public static client"));
}

#[test]
fn test_duplicate_realm_rejected() {
    let config = QidConfig {
        include: Vec::new(),
        profile: DeploymentProfile::Oidc,
        server: ServerConfig {
            listen: "0.0.0.0:8443".to_string(),
            public_base_url: "https://id.example.com".to_string(),
            tls: None,
            http_message_signatures: Default::default(),
            cors: CorsConfig::default(),
            paths: ServerPaths::default(),
            hsts: Default::default(),
            quic: Default::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig::default(),
        realms: vec![
            RealmConfig {
                id: "corp".to_string(),
                issuer: "https://id.example.com/realms/corp".to_string(),
                display_name: None,
                tenant_id: None,
                clients: Vec::new(),
                protocols: ProtocolConfig::default(),
                authentication: AuthenticationConfig::default(),
                sessions: SessionConfig::default(),
                pep_registrations: PepRegistrationsConfig::default(),
                policy: PolicyConfig::default(),
            },
            RealmConfig {
                id: "corp".to_string(),
                issuer: "https://id.example.com/realms/corp".to_string(),
                display_name: None,
                tenant_id: None,
                clients: Vec::new(),
                protocols: ProtocolConfig::default(),
                authentication: AuthenticationConfig::default(),
                sessions: SessionConfig::default(),
                pep_registrations: PepRegistrationsConfig::default(),
                policy: PolicyConfig::default(),
            },
        ],
        observability: ObservabilityConfig::default(),
        ops: OpsConfig::default(),
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_config_validation_no_realms() {
    let config = QidConfig {
        include: Vec::new(),
        profile: DeploymentProfile::Oidc,
        server: ServerConfig {
            listen: "0.0.0.0:8443".to_string(),
            public_base_url: "https://id.example.com".to_string(),
            tls: None,
            http_message_signatures: Default::default(),
            cors: CorsConfig::default(),
            paths: ServerPaths::default(),
            hsts: Default::default(),
            quic: Default::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig::default(),
        realms: vec![],
        observability: ObservabilityConfig::default(),
        ops: OpsConfig::default(),
    };
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("at least one realm"));
}

#[test]
fn test_issuer_url_validation() {
    let config = QidConfig {
        include: Vec::new(),
        profile: DeploymentProfile::Oidc,
        server: ServerConfig {
            listen: "0.0.0.0:8443".to_string(),
            public_base_url: "https://id.example.com".to_string(),
            tls: None,
            http_message_signatures: Default::default(),
            cors: CorsConfig::default(),
            paths: ServerPaths::default(),
            hsts: Default::default(),
            quic: Default::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig::default(),
        realms: vec![RealmConfig {
            id: "test".to_string(),
            issuer: "not-a-valid-url".to_string(),
            display_name: None,
            tenant_id: None,
            clients: Vec::new(),
            protocols: ProtocolConfig::default(),
            authentication: AuthenticationConfig::default(),
            sessions: SessionConfig::default(),
            pep_registrations: PepRegistrationsConfig::default(),
            policy: PolicyConfig::default(),
        }],
        observability: ObservabilityConfig::default(),
        ops: OpsConfig::default(),
    };
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("issuer"));
}

#[test]
fn realm_id_must_be_url_path_segment_safe() {
    let mut config = minimal_config();
    config.realms[0].id = "tenant/corp".to_string();
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("URL path segment"));
}

#[test]
fn multi_realm_issuer_must_match_realm_scoped_discovery_route() {
    let mut config = minimal_config();
    config.realms.push(RealmConfig {
        id: "retail".to_string(),
        issuer: "https://retail.example.com".to_string(),
        display_name: None,
        tenant_id: None,
        clients: Vec::new(),
        protocols: ProtocolConfig::default(),
        authentication: AuthenticationConfig::default(),
        sessions: SessionConfig::default(),
        pep_registrations: PepRegistrationsConfig::default(),
        policy: PolicyConfig::default(),
    });
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("multi-realm issuer"));

    config.realms[1].issuer = "https://id.example.com/realms/retail".to_string();
    assert!(config.validate().is_ok());
}

#[test]
fn ops_config_rejects_incomplete_cache_and_multi_region() {
    let mut config = QidConfig {
        include: Vec::new(),
        profile: DeploymentProfile::Oidc,
        server: ServerConfig {
            listen: "0.0.0.0:8443".to_string(),
            public_base_url: "https://id.example.com".to_string(),
            tls: None,
            http_message_signatures: Default::default(),
            cors: CorsConfig::default(),
            paths: ServerPaths::default(),
            hsts: Default::default(),
            quic: Default::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig::default(),
        realms: vec![RealmConfig {
            id: "corp".to_string(),
            issuer: "https://id.example.com/realms/corp".to_string(),
            display_name: None,
            tenant_id: None,
            clients: Vec::new(),
            protocols: ProtocolConfig::default(),
            authentication: AuthenticationConfig::default(),
            sessions: SessionConfig::default(),
            pep_registrations: PepRegistrationsConfig::default(),
            policy: PolicyConfig::default(),
        }],
        observability: ObservabilityConfig::default(),
        ops: OpsConfig::default(),
    };

    config.ops.cache.kind = "redis".to_string();
    let err = config.validate().unwrap_err();
    assert!(
        err.message()
            .contains("ops.cache.kind=redis requires endpoints")
    );

    config.ops.cache.endpoints = vec!["redis://127.0.0.1:6379".to_string()];
    config.ops.cluster.multi_region_active_active = true;
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("ops.cluster.cluster_id"));

    config.ops.cluster.cluster_id = Some("cluster-a".to_string());
    config.ops.cluster.region = Some("us-east-1".to_string());
    config.ops.cluster.node_id = Some("node-a".to_string());
    assert!(config.validate().is_ok());
}

#[test]
fn server_paths_default_values() {
    let p = ServerPaths::default();
    assert_eq!(p.health, "/health");
    assert_eq!(p.ready, "/ready");
    assert_eq!(p.jwks, "/jwks");
    assert_eq!(
        p.well_known_openid_configuration,
        "/.well-known/openid-configuration"
    );
    assert_eq!(
        p.well_known_oauth_authorization_server,
        "/.well-known/oauth-authorization-server"
    );
    assert_eq!(
        p.well_known_oauth_protected_resource,
        "/.well-known/oauth-protected-resource"
    );
    assert_eq!(p.authorize, "/oauth2/authorize");
    assert_eq!(p.par, "/oauth2/par");
    assert_eq!(p.device_authorization, "/oauth2/device_authorization");
    assert_eq!(p.device_verification, "/oauth2/device");
    assert_eq!(
        p.backchannel_authentication,
        "/oauth2/backchannel-authentication"
    );
    assert_eq!(p.dynamic_client_registration, "/oauth2/register");
    assert_eq!(
        p.dynamic_client_registration_management,
        "/oauth2/register/:client_id"
    );
    assert_eq!(p.userinfo, "/oidc/userinfo");
    assert_eq!(p.token, "/oauth2/token");
    assert_eq!(p.introspect, "/oauth2/introspect");
    assert_eq!(p.revoke, "/oauth2/revoke");
    assert_eq!(p.pep_decision, "/pep/decision/v1/evaluate");
    assert_eq!(p.authzen_evaluation, "/access/v1/evaluation");
    assert_eq!(p.assertion, "/pep/:realm/assertion");
    assert_eq!(p.auth_password, "/api/v1/:realm/auth/password");
    assert_eq!(
        p.auth_session_refresh,
        "/api/v1/:realm/auth/session/refresh"
    );
    assert_eq!(p.auth_session_revoke, "/api/v1/:realm/auth/session/revoke");
    assert_eq!(p.logout, "/oidc/logout");
    assert_eq!(p.backchannel_logout, "/oidc/logout/backchannel");
    assert_eq!(p.frontchannel_logout, "/oidc/logout/frontchannel");
    assert_eq!(p.auth_webauthn_start, "/api/v1/:realm/auth/webauthn/start");
    assert_eq!(
        p.auth_webauthn_finish,
        "/api/v1/:realm/auth/webauthn/finish"
    );
    assert_eq!(
        p.auth_webauthn_auth_start,
        "/api/v1/:realm/auth/webauthn/auth/start"
    );
    assert_eq!(
        p.auth_webauthn_auth_finish,
        "/api/v1/:realm/auth/webauthn/auth/finish"
    );
}

#[test]
fn vc_max_credential_lifetime_defaults_to_24h() {
    let vc = VcProtocolConfig::default();
    assert_eq!(vc.max_credential_lifetime_seconds, 86400);
    // Missing field in stored config keeps parsing and takes the default.
    let parsed: VcProtocolConfig = serde_json::from_value(serde_json::json!({})).unwrap();
    assert_eq!(parsed.max_credential_lifetime_seconds, 86400);
}

#[test]
fn token_ttl_default_values() {
    let ttl = TokenTtlConfig::default();
    assert_eq!(ttl.access_token_ttl_seconds, 3600);
    assert_eq!(ttl.refresh_token_ttl_seconds, 86400);
    assert_eq!(ttl.id_token_ttl_seconds, 3600);
    assert_eq!(ttl.auth_code_ttl_seconds, 300);
    assert_eq!(ttl.par_request_ttl_seconds, 300);
    assert_eq!(ttl.device_code_ttl_seconds, 1800);
    assert_eq!(ttl.access_token_format, TokenFormat::Jwt);
}

#[test]
fn admin_security_config_rejects_unsafe_step_up_and_elevation() {
    let mut config = minimal_config();
    assert!(config.admin.security.require_reason);
    assert!(config.admin.security.require_step_up);
    assert_eq!(
        config.admin.security.required_acr,
        "urn:qid:acr:phishing-resistant"
    );
    assert_eq!(config.admin.security.max_elevation_seconds, 900);

    config.admin.security.required_amr.clear();
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("required_amr"));

    let mut config = minimal_config();
    config.admin.security.max_elevation_seconds = 0;
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("max_elevation_seconds"));

    let mut config = minimal_config();
    config.admin.security.require_approval = true;
    config.admin.security.max_approval_age_seconds = 0;
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("max_approval_age_seconds"));
}

#[test]
fn oidc_protocol_defaults() {
    let oidc = OidcProtocolConfig::default();
    assert!(oidc.enabled);
    assert!(oidc.authorization_code.enabled);
    assert!(oidc.authorization_code.pkce_required);
    assert!(!oidc.implicit.enabled);
    assert!(!oidc.ropc.enabled);
    assert!(oidc.discovery);
    assert!(oidc.userinfo);
    assert!(oidc.logout.backchannel);
    assert!(oidc.logout.frontchannel);
    assert_eq!(oidc.default_scope, "openid");
}

#[test]
fn oidc_protocol_accepts_canonical_structured_yaml() {
    let yaml = r#"
server:
  listen: "127.0.0.1:8443"
  public_base_url: "https://id.example.com"
realms:
  - id: corp
    issuer: "https://id.example.com/realms/corp"
    protocols:
      oidc:
        enabled: true
        authorization_code:
          enabled: true
          pkce_required: true
        implicit:
          enabled: false
        ropc:
          enabled: false
        discovery: true
        userinfo: true
        logout:
          backchannel: true
          frontchannel: true
"#;
    let config: QidConfig = Figment::new().merge(Yaml::string(yaml)).extract().unwrap();
    config.validate().unwrap();
    let oidc = &config.realms[0].protocols.oidc;
    assert!(oidc.authorization_code.enabled);
    assert!(oidc.authorization_code.pkce_required);
    assert!(!oidc.implicit.enabled);
    assert!(!oidc.ropc.enabled);
    assert!(oidc.logout.backchannel);
    assert!(oidc.logout.frontchannel);
}

#[test]
fn oauth_resource_server_config_rejects_duplicates() {
    let mut config = minimal_config();
    config.realms[0].protocols.oauth.resource_servers = vec![
        OAuthResourceServerConfig {
            audience: "api://payments".to_string(),
            resources: vec!["https://api.example.com/payments".to_string()],
            scopes: vec!["payments".to_string()],
            introspection_client_ids: Vec::new(),
            require_sender_constraint: true,
            high_risk: true,
        },
        OAuthResourceServerConfig {
            audience: "api://payments".to_string(),
            resources: vec!["https://api.example.com/refunds".to_string()],
            scopes: vec!["refunds".to_string()],
            introspection_client_ids: Vec::new(),
            require_sender_constraint: false,
            high_risk: false,
        },
    ];
    let err = config.validate().unwrap_err();
    assert!(
        err.message()
            .contains("duplicate OAuth resource server audience")
    );

    config.realms[0].protocols.oauth.resource_servers[1].audience = "api://refunds".to_string();
    config.realms[0].protocols.oauth.resource_servers[1].resources =
        vec!["https://api.example.com/payments".to_string()];
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("duplicate OAuth resource indicator"));

    config.realms[0].protocols.oauth.resource_servers[1].resources =
        vec!["https://api.example.com/refunds".to_string()];
    config.realms[0].protocols.oauth.resource_servers[0].introspection_client_ids =
        vec!["gateway".to_string(), "gateway".to_string()];
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("duplicate introspection client id"));
}

#[test]
fn pep_registration_requires_explicit_audience() {
    let mut config = minimal_config();
    config.realms[0].pep_registrations.enabled = true;
    config.realms[0].pep_registrations.registrations = vec![PepRegistrationConfig {
        name: "egress-main".to_string(),
        audience: None,
        capabilities: Vec::new(),
        assertion: ProxyAssertionConfig::default(),
        decision: PepDecisionConfig::default(),
        auth: PepRegistrationAuthConfig::default(),
    }];

    let err = config.validate().unwrap_err();
    assert!(err.message().contains("must declare audience"));
}

#[test]
fn a_realm_that_disables_its_pep_registrations_serves_none_of_them() {
    let mut config = minimal_config();
    config.realms[0].pep_registrations.registrations = vec![PepRegistrationConfig {
        name: "egress-main".to_string(),
        audience: Some("urn:qid:pep:qpx:corp/egress-main".to_string()),
        capabilities: Vec::new(),
        assertion: ProxyAssertionConfig::default(),
        decision: PepDecisionConfig::default(),
        auth: PepRegistrationAuthConfig::default(),
    }];

    assert!(
        config.realms[0].pep_registrations.served().is_empty(),
        "a realm that disables its registrations serves none of them"
    );

    config.realms[0].pep_registrations.enabled = true;
    assert_eq!(config.realms[0].pep_registrations.served().len(), 1);
}

#[test]
fn deployment_profiles_enforce_required_capabilities() {
    assert_eq!(
        serde_json::from_value::<DeploymentProfile>(serde_json::json!("edge-pep")).unwrap(),
        DeploymentProfile::EdgePep
    );
    let mut pep_config = minimal_config();
    pep_config.profile = DeploymentProfile::EdgePep;
    pep_config.server.http_message_signatures.enabled = true;
    pep_config.server.http_message_signatures.shared_secret =
        Some("0123456789abcdef0123456789abcdef".to_string());
    let err = pep_config.validate().unwrap_err();
    assert!(
        err.message()
            .contains("requires at least one PEP registration")
    );
    pep_config.realms[0].pep_registrations.registrations = vec![PepRegistrationConfig {
        name: "egress-main".to_string(),
        audience: Some("urn:qid:pep:qpx:corp/egress-main".to_string()),
        capabilities: Vec::new(),
        assertion: ProxyAssertionConfig::default(),
        decision: PepDecisionConfig::default(),
        auth: PepRegistrationAuthConfig::default(),
    }];
    let err = pep_config.validate().unwrap_err();
    assert!(
        err.message()
            .contains("requires at least one PEP registration")
    );

    pep_config.realms[0].pep_registrations.enabled = true;
    pep_config.realms[0].protocols.oauth.mtls = ProtocolFeatureConfig::enabled();
    pep_config.realms[0].pep_registrations.registrations = vec![PepRegistrationConfig {
        name: "egress-main".to_string(),
        audience: Some("urn:qid:pep:qpx:corp/egress-main".to_string()),
        capabilities: vec![
            pep_capability("challenge"),
            pep_capability("inject_headers"),
            pep_capability("local_response"),
            pep_capability("override_upstream"),
            pep_capability("cache_bypass"),
            pep_capability("mirror_upstreams"),
            pep_capability("force_inspect"),
            pep_capability("force_tunnel"),
            pep_capability("rate_limit"),
            pep_capability("rate_limit_profile"),
            pep_capability("policy_tags"),
        ],
        assertion: ProxyAssertionConfig::default(),
        decision: PepDecisionConfig::default(),
        auth: PepRegistrationAuthConfig::default(),
    }];
    pep_config.validate().unwrap();

    let mut fapi_config = minimal_config();
    fapi_config.profile = DeploymentProfile::Fapi;
    let err = fapi_config.validate().unwrap_err();
    assert!(err.message().contains("HTTP Message Signatures"));

    fapi_config.server.http_message_signatures.enabled = true;
    fapi_config.server.http_message_signatures.shared_secret =
        Some("0123456789abcdef0123456789abcdef".to_string());
    assert!(fapi_config.validate().is_err());

    let oauth = &mut fapi_config.realms[0].protocols.oauth;
    oauth.par.enabled = true;
    oauth.require_pushed_authorization_requests = true;
    oauth.rar = ProtocolFeatureConfig::enabled();
    oauth.dpop.enabled = true;
    oauth.mtls = ProtocolFeatureConfig::enabled();
    oauth.private_key_jwt = ProtocolFeatureConfig::enabled();
    oauth.jarm = ProtocolFeatureConfig::enabled();
    oauth.introspection.jwt_response = true;
    oauth.resource_servers = vec![OAuthResourceServerConfig {
        audience: "api://payments".to_string(),
        resources: vec!["https://api.example.com/payments".to_string()],
        scopes: vec!["payments".to_string()],
        introspection_client_ids: vec!["payments-gateway".to_string()],
        require_sender_constraint: true,
        high_risk: true,
    }];
    fapi_config.realms[0]
        .protocols
        .oidc
        .authorization_code
        .require_signed_request_object = true;
    fapi_config.validate().unwrap();

    let mut ciam_config = minimal_config();
    ciam_config.profile = DeploymentProfile::Ciam;
    ciam_config.realms[0].authentication.passkeys.enabled = true;
    ciam_config.realms[0].protocols.fedcm.enabled = true;
    ciam_config.realms[0].protocols.ciam.consent = true;
    ciam_config.realms[0].protocols.ciam.progressive_profile = true;
    ciam_config.realms[0].protocols.ciam.identity_proofing = true;
    ciam_config.realms[0].protocols.ciam.privacy_dashboard = true;
    ciam_config.realms[0].protocols.federation.enabled = true;
    ciam_config.realms[0].protocols.federation.inbound_providers = vec![InboundProviderConfig {
        id: "google".to_string(),
        kind: "social".to_string(),
        issuer: "https://accounts.google.com".to_string(),
        enabled: true,
        domains: vec!["shop.example.com".to_string()],
        social_provider: Some("google".to_string()),
        client_id: Some("google-client-id".to_string()),
        client_secret: Some("secret://qid/social/google".to_string()),
        token_url: Some("https://oauth2.googleapis.com/token".to_string()),
        userinfo_url: Some("https://openidconnect.googleapis.com/v1/userinfo".to_string()),
        jit_provisioning: true,
        account_linking: true,
        claim_mappings: Vec::new(),
        jwks_uri: None,
        jwks: None,
        saml_signing_certificates: Vec::new(),
    }];
    assert!(ciam_config.realms[0].has_ciam_compatible_inbound_provider());
    let mut incomplete_ciam_realm = ciam_config.realms[0].clone();
    incomplete_ciam_realm.protocols.federation.inbound_providers[0].client_secret = None;
    assert!(!incomplete_ciam_realm.has_ciam_compatible_inbound_provider());
    let mut missing_social_provider = ciam_config.realms[0].clone();
    missing_social_provider
        .protocols
        .federation
        .inbound_providers[0]
        .social_provider = None;
    assert!(!missing_social_provider.has_ciam_compatible_inbound_provider());
    let mut oidc_provider = ciam_config.realms[0].clone();
    oidc_provider.protocols.federation.inbound_providers[0].kind = "oidc".to_string();
    oidc_provider.protocols.federation.inbound_providers[0].social_provider = None;
    assert!(oidc_provider.has_ciam_compatible_inbound_provider());
    ciam_config.validate().unwrap();
    assert!(!ciam_config.realms[0].protocols.scim.enabled);
    assert!(!ciam_config.realms[0].protocols.saml.enabled);

    let mut ha_config = fapi_config.clone();
    ha_config.profile = DeploymentProfile::HighAssurance;
    ha_config.admin.security.require_approval = true;
    ha_config.admin.security.require_step_up = true;
    ha_config.ops.backup.enabled = true;
    ha_config.ops.backup.object_store_uri = Some("s3://qid-test-backups/ha".to_string());
    ha_config.ops.backup.migration_version = Some("20250628000002".to_string());
    ha_config.realms[0].authentication.passkeys.enabled = true;
    ha_config.realms[0].authentication.passwordless_only = true;
    let err = ha_config.validate().unwrap_err();
    assert!(
        err.message().contains("remote KMS/HSM/PKCS#11 keyrings"),
        "{}",
        err.message()
    );

    ha_config.crypto.keyrings = vec![KeyringConfig {
        name: "ha-local".to_string(),
        realm_id: Some("corp".to_string()),
        purposes: vec!["oidc_token".to_string()],
        signer: SignerConfig {
            r#type: "local".to_string(),
            uri: None,
            public_jwk: None,
        },
        rotation: RotationConfig::default(),
    }];
    let err = ha_config.validate().unwrap_err();
    assert!(
        err.message().contains("remote KMS/HSM/PKCS#11 keyrings"),
        "{}",
        err.message()
    );

    ha_config.crypto.keyrings[0] = KeyringConfig {
        name: "ha-kms".to_string(),
        realm_id: Some("corp".to_string()),
        purposes: vec!["oidc_token".to_string()],
        signer: SignerConfig {
            r#type: "kms".to_string(),
            uri: Some("aws-kms://alias/qid-ha".to_string()),
            public_jwk: Some(es256_public_jwk("ha-kms")),
        },
        rotation: RotationConfig::default(),
    };
    ha_config.validate().unwrap();
}

#[test]
fn saml_service_provider_config_validates_trust_material() {
    let mut config = QidConfig {
        include: Vec::new(),
        profile: DeploymentProfile::Oidc,
        server: ServerConfig {
            listen: "0.0.0.0:8443".to_string(),
            public_base_url: "https://id.example.com".to_string(),
            tls: None,
            http_message_signatures: Default::default(),
            cors: CorsConfig::default(),
            paths: ServerPaths::default(),
            hsts: Default::default(),
            quic: Default::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig::default(),
        realms: vec![RealmConfig {
            id: "corp".to_string(),
            issuer: "https://id.example.com/realms/corp".to_string(),
            display_name: None,
            tenant_id: None,
            clients: Vec::new(),
            protocols: ProtocolConfig {
                saml: SamlProtocolConfig {
                    enabled: true,
                    sign_assertions: true,
                    encrypt_assertions: Some("required".to_string()),
                    max_clock_skew_seconds: 60,
                    sign_metadata: false,
                    idp_signing_key_pem_path: Some("/etc/qid/saml/idp-signing.key".to_string()),
                    idp_encryption_key_pem_path: None,
                    service_providers: vec![SamlServiceProviderConfig {
                        entity_id: "https://sp.example.com/metadata".to_string(),
                        acs_url: "https://sp.example.com/acs".to_string(),
                        slo_url: Some("https://sp.example.com/slo".to_string()),
                        name_id_formats: vec![
                            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
                        ],
                        attribute_release_policy: Vec::new(),
                        signing_certificates: vec!["MIIBsigning".to_string()],
                        encryption_certificates: vec!["MIIBencryption".to_string()],
                        want_assertions_signed: true,
                    }],
                },
                ..ProtocolConfig::default()
            },
            authentication: AuthenticationConfig::default(),
            sessions: SessionConfig::default(),
            pep_registrations: PepRegistrationsConfig::default(),
            policy: PolicyConfig::default(),
        }],
        observability: ObservabilityConfig::default(),
        ops: OpsConfig::default(),
    };
    config.validate().unwrap();

    config.realms[0].protocols.saml.service_providers[0]
        .signing_certificates
        .clear();
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("signing_certificates"));
}

#[test]
fn saml_service_provider_config_rejects_duplicates_and_missing_encryption() {
    let sp = SamlServiceProviderConfig {
        entity_id: "https://sp.example.com/metadata".to_string(),
        acs_url: "https://sp.example.com/acs".to_string(),
        slo_url: None,
        name_id_formats: vec![],
        attribute_release_policy: Vec::new(),
        signing_certificates: vec!["MIIBsigning".to_string()],
        encryption_certificates: vec!["MIIBencryption".to_string()],
        want_assertions_signed: false,
    };
    let config = QidConfig {
        include: Vec::new(),
        profile: DeploymentProfile::Oidc,
        server: ServerConfig {
            listen: "0.0.0.0:8443".to_string(),
            public_base_url: "https://id.example.com".to_string(),
            tls: None,
            http_message_signatures: Default::default(),
            cors: CorsConfig::default(),
            paths: ServerPaths::default(),
            hsts: Default::default(),
            quic: Default::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig::default(),
        realms: vec![RealmConfig {
            id: "corp".to_string(),
            issuer: "https://id.example.com/realms/corp".to_string(),
            display_name: None,
            tenant_id: None,
            clients: Vec::new(),
            protocols: ProtocolConfig {
                saml: SamlProtocolConfig {
                    enabled: true,
                    sign_assertions: true,
                    encrypt_assertions: Some("required".to_string()),
                    max_clock_skew_seconds: 60,
                    sign_metadata: false,
                    idp_signing_key_pem_path: Some("/etc/qid/saml/idp-signing.key".to_string()),
                    idp_encryption_key_pem_path: None,
                    service_providers: vec![sp.clone(), sp],
                },
                ..ProtocolConfig::default()
            },
            authentication: AuthenticationConfig::default(),
            sessions: SessionConfig::default(),
            pep_registrations: PepRegistrationsConfig::default(),
            policy: PolicyConfig::default(),
        }],
        observability: ObservabilityConfig::default(),
        ops: OpsConfig::default(),
    };
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("duplicate SAML SP entity_id"));

    let mut missing_encryption = config;
    missing_encryption.realms[0]
        .protocols
        .saml
        .service_providers
        .truncate(1);
    missing_encryption.realms[0]
        .protocols
        .saml
        .service_providers[0]
        .encryption_certificates
        .clear();
    let err = missing_encryption.validate().unwrap_err();
    assert!(err.message().contains("encryption_certificates"));
}

#[test]
fn oauth_protocol_defaults() {
    let oauth = OAuthProtocolConfig::default();
    assert!(oauth.introspection.enabled);
    assert!(!oauth.introspection.jwt_response);
    assert!(oauth.revocation.enabled);
    assert!(!oauth.par.enabled);
    assert!(!oauth.rar.enabled);
    assert!(!oauth.dpop.enabled);
    assert!(oauth.dpop.replay_cache);
    assert!(!oauth.mtls.enabled);
    assert!(!oauth.device_authorization.enabled);
    assert!(!oauth.ciba.enabled);
    assert!(!oauth.dynamic_client_registration.enabled);
    assert!(!oauth.private_key_jwt.enabled);
    assert_eq!(oauth.default_scope, "api");
}

#[test]
fn server_paths_capport_details_default_and_validation() {
    let paths = ServerPaths::default();
    assert_eq!(
        paths.capport_details,
        "/api/v1/:realm/captive-portal/api/v1/details"
    );

    let mut config = minimal_config();
    config.server.paths.capport_details = "/capport/custom/:realm/details".to_string();
    assert!(config.validate().is_ok());

    let mut config = minimal_config();
    config.server.paths.capport_details = "/capport/without-realm/details".to_string();
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("capport_details"));

    let mut config = minimal_config();
    config.server.paths.capport_details = "/capport/foo:realm/details".to_string();
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("capport_details"));

    let mut config = minimal_config();
    config.server.paths.capport_details = String::new();
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("must not be empty"));

    let mut config = minimal_config();
    config.server.paths.capport_details = "no-leading-slash/:realm".to_string();
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("must start with '/'"));

    let mut config = minimal_config();
    config.server.paths.capport_details = config.server.paths.health.clone();
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("duplicate"));

    for reserved in [CAPPORT_BIND_PATH, CAPPORT_UNBIND_PATH, CAPPORT_LOOKUP_PATH] {
        let mut config = minimal_config();
        config.server.paths.capport_details = reserved.to_string();
        let err = config.validate().unwrap_err();
        assert!(err.message().contains("fixed CAPPORT control route"));
    }
}

#[test]
fn server_quic_defaults_to_disabled() {
    let quic = QuicConfig::default();
    assert!(!quic.enabled);
    assert_eq!(quic.bind, "[::]:4433");
    assert!(quic.certificate_path.is_none());
    assert!(quic.private_key_path.is_none());
    assert_eq!(quic.max_bidi_streams, 100);

    let config = minimal_config();
    assert!(!config.server.quic.enabled);
    assert!(config.validate().is_ok());
}

#[test]
fn server_quic_enabled_config_validates_fail_closed() {
    let mut config = minimal_config();
    config.server.quic.enabled = true;
    config.server.quic.certificate_path = Some("/etc/qid/quic-cert.pem".to_string());
    config.server.quic.private_key_path = Some("/etc/qid/quic-key.pem".to_string());
    assert!(config.validate().is_ok());

    let mut config = minimal_config();
    config.server.quic.enabled = true;
    config.server.quic.certificate_path = Some("/etc/qid/quic-cert.pem".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("private_key_path"));

    let mut config = minimal_config();
    config.server.quic.enabled = true;
    config.server.quic.private_key_path = Some("/etc/qid/quic-key.pem".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("certificate_path"));

    let mut config = minimal_config();
    config.server.quic.enabled = true;
    config.server.quic.certificate_path = Some("  ".to_string());
    config.server.quic.private_key_path = Some("/etc/qid/quic-key.pem".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("certificate_path"));

    let mut config = minimal_config();
    config.server.quic.enabled = true;
    config.server.quic.bind = "not-a-socket-address".to_string();
    config.server.quic.certificate_path = Some("/etc/qid/quic-cert.pem".to_string());
    config.server.quic.private_key_path = Some("/etc/qid/quic-key.pem".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("server.quic.bind"));

    let mut config = minimal_config();
    config.server.quic.enabled = true;
    config.server.quic.certificate_path = Some("/etc/qid/quic-cert.pem".to_string());
    config.server.quic.private_key_path = Some("/etc/qid/quic-key.pem".to_string());
    config.server.quic.max_bidi_streams = 0;
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("max_bidi_streams"));
}

#[test]
fn protocol_features_accept_a_bare_boolean_or_an_object() {
    // A bare boolean takes the configuration's own defaults.
    let bare: OAuthProtocolConfig = serde_json::from_str(r#"{"dpop":true}"#).unwrap();
    assert!(bare.dpop.enabled);
    assert!(bare.dpop.replay_cache);
    assert!(!bare.dpop.nonce);
    // An object carries the settings, and a missing one keeps its default.
    let object: OAuthProtocolConfig =
        serde_json::from_str(r#"{"dpop":{"enabled":true,"nonce":true}}"#).unwrap();
    assert!(object.dpop.enabled);
    assert!(object.dpop.replay_cache);
    assert!(object.dpop.nonce);
    let partial: OAuthProtocolConfig = serde_json::from_str(r#"{"dpop":{"nonce":true}}"#).unwrap();
    assert!(!partial.dpop.enabled);
    assert!(partial.dpop.replay_cache);
    assert!(partial.dpop.nonce);
    // The same shape serves the other feature configurations.
    let oidc: OidcProtocolConfig =
        serde_json::from_str(r#"{"implicit":{"allow_open_registration":true}}"#).unwrap();
    assert!(!oidc.implicit.enabled);
    assert!(oidc.implicit.allow_open_registration);
    let ciba: OAuthProtocolConfig = serde_json::from_str(r#"{"ciba":true}"#).unwrap();
    assert!(ciba.ciba.enabled);
    assert_eq!(ciba.ciba.mode, CibaMode::Poll);
    let par: OAuthProtocolConfig = serde_json::from_str(r#"{"par":{"enabled":true}}"#).unwrap();
    assert!(par.par.enabled);
    let introspection: OAuthProtocolConfig =
        serde_json::from_str(r#"{"introspection":{"jwt_response":true}}"#).unwrap();
    assert!(introspection.introspection.jwt_response);
}

#[test]
fn boolean_or_object_settings_reject_an_unknown_key() {
    // The object form of every configuration in that family rejects an unknown
    // key, like every other configuration.
    for json in [
        r#"{"oidc":{"implicit":{"typo":true}}}"#,
        r#"{"oauth":{"introspection":{"typo":true}}}"#,
        r#"{"oauth":{"dpop":{"typo":true}}}"#,
        r#"{"oauth":{"ciba":{"typo":true}}}"#,
        r#"{"oauth":{"par":{"typo":true}}}"#,
        r#"{"oauth":{"revocation":{"typo":true}}}"#,
    ] {
        assert!(
            serde_json::from_str::<ProtocolConfig>(json).is_err(),
            "an unknown key must be rejected: {json}"
        );
    }
}

#[test]
fn revocation_settings_keep_their_own_defaults() {
    // The bare boolean form carries the enabled flag, and the object form
    // keeps the same default of true.
    let bare: OAuthProtocolConfig = serde_json::from_str(r#"{"revocation":false}"#).unwrap();
    assert!(!bare.revocation.enabled);
    let bare: OAuthProtocolConfig = serde_json::from_str(r#"{"revocation":true}"#).unwrap();
    assert!(bare.revocation.enabled);
    let object: OAuthProtocolConfig =
        serde_json::from_str(r#"{"revocation":{"enabled":false}}"#).unwrap();
    assert!(!object.revocation.enabled);
    let object: OAuthProtocolConfig = serde_json::from_str(r#"{"revocation":{}}"#).unwrap();
    assert!(
        object.revocation.enabled,
        "a missing enabled keeps the default"
    );
}

#[test]
fn introspection_object_form_keeps_the_endpoint_enabled() {
    // The object form must not contradict the configuration's own default.
    let config: OAuthProtocolConfig = serde_json::from_str(r#"{"introspection":{}}"#).unwrap();
    assert!(config.introspection.enabled);
    let config: OAuthProtocolConfig =
        serde_json::from_str(r#"{"introspection":{"jwt_response":true}}"#).unwrap();
    assert!(config.introspection.enabled);
    assert!(config.introspection.jwt_response);
}

#[test]
fn the_removed_directory_default_provider_key_is_rejected() {
    // `default_provider_id` named a provider the sync never consulted: every
    // call path requires an explicit provider id. A configuration that still
    // sets it is a configuration error, not a silently ignored key.
    let err = serde_json::from_str::<ProtocolConfig>(
        r#"{"directory":{"default_provider_id":"corp-ldap"}}"#,
    )
    .expect_err("the removed key is rejected");
    assert!(
        err.to_string().contains("default_provider_id"),
        "the error names the removed key: {err}"
    );
}

#[test]
fn the_removed_directory_sync_keys_are_rejected() {
    // `group_search_filter` and `full_sync_on_start` named behaviour the
    // product never had: there is no group search, and a sync always runs
    // its full pass. A configuration that still sets them is a configuration
    // error, not a silently ignored key.
    for (key, value) in [
        ("group_search_filter", "\"(objectClass=group)\""),
        ("full_sync_on_start", "true"),
    ] {
        let err = serde_json::from_str::<ProtocolConfig>(&format!(
            r#"{{"directory":{{"providers":[{{"id":"corp-ldap","type":"ldap","sync":{{"{key}":{value}}}}}]}}}}"#
        ))
        .expect_err("the removed key is rejected");
        assert!(
            err.to_string().contains(key),
            "the error names the removed key: {err}"
        );
    }
}

#[test]
fn the_refresh_token_settings_must_name_the_enforced_behaviour() {
    // The refresh path always rotates the token on every use and always
    // revokes the family of a superseded or concurrently redeemed token, so a
    // configured setting may only state that behaviour.
    let mut config = minimal_config();
    config.realms[0].sessions.refresh_tokens.reuse_detection =
        Some(REFRESH_REUSE_DETECTION_REVOKE_FAMILY.to_string());
    config.validate().expect("the enforced mode is accepted");

    let mut config = minimal_config();
    config.realms[0].sessions.refresh_tokens.reuse_detection = Some("none".to_string());
    let err = config
        .validate()
        .expect_err("an unsupported mode is rejected");
    assert!(
        err.message().contains("reuse_detection"),
        "the error names the key: {err}"
    );

    // Rotation is not a setting: the product has no mode without it, so a
    // configuration that turns it off is rejected on the key that contradicts
    // the product, not on the reuse-detection mode the product still enforces.
    let mut config = minimal_config();
    config.realms[0].sessions.refresh_tokens.rotation = false;
    let err = config.validate().expect_err("rotation cannot be disabled");
    assert!(
        err.message().contains("rotation"),
        "the error names the key: {err}"
    );

    let mut config = minimal_config();
    config.realms[0].sessions.refresh_tokens.reuse_detection =
        Some(REFRESH_REUSE_DETECTION_REVOKE_FAMILY.to_string());
    config.realms[0].sessions.refresh_tokens.rotation = false;
    let err = config.validate().expect_err("rotation cannot be disabled");
    assert!(
        err.message().contains("rotation"),
        "the error names the key: {err}"
    );
}

#[test]
fn the_removed_mfa_keys_are_rejected() {
    // `required_for_admins` named a realm policy the product never applied:
    // administrators are tenant records whose elevation carries the
    // authentication methods, and `admin.security` owns that requirement.
    // `allowed_certificate_attributes` named an allowlist for a factor the
    // product cannot perform: the client-certificate factor has no route and
    // no registry of user certificates, so the switch is gone with it. The
    // `allowed` list was a label nothing read, and the TOTP digits and period
    // belong to the credential rather than to the realm configuration. A
    // configuration that still sets them is a configuration error, not a
    // silently ignored key.
    let err =
        serde_json::from_str::<AuthenticationConfig>(r#"{"mfa":{"required_for_admins":true}}"#)
            .expect_err("the removed key is rejected");
    assert!(
        err.to_string().contains("required_for_admins"),
        "the error names the removed key: {err}"
    );

    // The whole client-certificate block is gone, so the error names the
    // block the operator set.
    let err = serde_json::from_str::<AuthenticationConfig>(
        r#"{"mfa":{"client_certificate":{"allowed_certificate_attributes":["san_uri"]}}}"#,
    )
    .expect_err("the removed key is rejected");
    assert!(
        err.to_string().contains("client_certificate"),
        "the error names the removed key: {err}"
    );

    let err = serde_json::from_str::<AuthenticationConfig>(
        r#"{"mfa":{"client_certificate":{"enabled":true}}}"#,
    )
    .expect_err("the removed key is rejected");
    assert!(
        err.to_string().contains("client_certificate"),
        "the error names the removed key: {err}"
    );

    let err = serde_json::from_str::<AuthenticationConfig>(r#"{"mfa":{"allowed":["totp"]}}"#)
        .expect_err("the removed key is rejected");
    assert!(
        err.to_string().contains("allowed"),
        "the error names the removed key: {err}"
    );

    let err = serde_json::from_str::<AuthenticationConfig>(r#"{"mfa":{"totp":{"digits":8}}}"#)
        .expect_err("the removed key is rejected");
    assert!(
        err.to_string().contains("digits"),
        "the error names the removed key: {err}"
    );

    let err = serde_json::from_str::<AuthenticationConfig>(r#"{"mfa":{"totp":{"period":60}}}"#)
        .expect_err("the removed key is rejected");
    assert!(
        err.to_string().contains("period"),
        "the error names the removed key: {err}"
    );
}

#[test]
fn the_removed_sms_mfa_switch_is_rejected() {
    // The product has no SMS factor, no SMS delivery adapter and no SMS
    // route, so the switch named a factor the deployment could never
    // perform. A configuration that still sets it is a configuration error
    // naming the key.
    let err = serde_json::from_str::<AuthenticationConfig>(r#"{"mfa":{"sms":{"enabled":true}}}"#)
        .expect_err("the removed switch is rejected");
    assert!(
        err.to_string().contains("sms"),
        "the error names the removed key: {err}"
    );
}

#[test]
fn the_removed_par_required_for_setting_is_rejected() {
    // The list-valued `oauth.par.required_for` setting named client IDs but
    // was never applied. Per-client policy is now the RFC 9126 metadata on
    // Client; this obsolete config shape remains a configuration error.
    let err = serde_json::from_str::<OAuthProtocolConfig>(r#"{"par":{"required_for":["openid"]}}"#)
        .expect_err("the removed setting is rejected");
    assert!(
        err.to_string().contains("required_for"),
        "the error names the removed key: {err}"
    );
}

#[test]
fn the_removed_passkey_attestation_setting_is_rejected() {
    // The registration ceremony requests attestation "none" and the product
    // verifies no attestation statement, so a setting that chose an
    // attestation policy named a capability the product does not have: any
    // value but "none" was refused at the ceremony. A configuration that
    // still sets it is a configuration error naming the key.
    let err = serde_json::from_str::<AuthenticationConfig>(
        r#"{"passkeys":{"enabled":true,"attestation":"enterprise"}}"#,
    )
    .expect_err("the removed setting is rejected");
    assert!(
        err.to_string().contains("attestation"),
        "the error names the removed key: {err}"
    );
}

#[test]
fn the_removed_passkey_preferred_setting_is_rejected() {
    // The product offers the passkey and the password routes side by side
    // and never orders one factor over another, so a setting that stated
    // a preference named a behaviour the product does not have. A
    // configuration that still sets it is a configuration error naming the
    // key.
    let err = serde_json::from_str::<AuthenticationConfig>(
        r#"{"passkeys":{"enabled":true,"preferred":true}}"#,
    )
    .expect_err("the removed setting is rejected");
    assert!(
        err.to_string().contains("preferred"),
        "the error names the removed key: {err}"
    );
}

#[test]
fn the_totp_switch_is_read() {
    let enabled: AuthenticationConfig =
        serde_json::from_str(r#"{"mfa":{"totp":{"enabled":true}}}"#).expect("the switch parses");
    assert!(enabled.mfa.totp.enabled);
    let disabled: AuthenticationConfig =
        serde_json::from_str(r#"{"mfa":{"totp":{"enabled":false}}}"#).expect("the switch parses");
    assert!(!disabled.mfa.totp.enabled);
}

#[test]
fn a_directory_provider_needs_usable_bind_credentials() {
    let mut config = minimal_config();
    config.realms[0].protocols.directory.providers = vec![DirectoryProviderConfig {
        webhook: None,
        id: "ldap-main".to_string(),
        provider_type: "ldap".to_string(),
        enabled: true,
        connection: DirectoryConnectionConfig {
            url: "ldaps://dir.example.com".to_string(),
            bind_dn: Some("CN=svc".to_string()),
            ..DirectoryConnectionConfig::default()
        },
        sync: DirectorySyncConfig::default(),
        attribute_mapping: DirectoryAttributeMapping::default(),
    }];
    // The provider must fail when the configuration loads, not at the first
    // sync: a bind DN without a password is an unauthenticated bind.
    let err = config
        .validate()
        .expect_err("a bind DN without a password is a configuration fault");
    assert!(err.message().contains("bind password"), "{}", err.message());
    // The fault names the provider and the realm, like every other
    // directory provider configuration error.
    assert!(err.message().contains("ldap-main"), "{}", err.message());
    assert!(err.message().contains("corp"), "{}", err.message());
}

#[test]
fn a_directory_provider_must_be_one_the_sync_can_connect() {
    let mut config = minimal_config();
    config.realms[0].protocols.directory.providers = vec![DirectoryProviderConfig {
        webhook: None,
        id: "ldap-main".to_string(),
        provider_type: "scim".to_string(),
        enabled: true,
        connection: DirectoryConnectionConfig {
            url: "https://dir.example.com".to_string(),
            ..DirectoryConnectionConfig::default()
        },
        sync: DirectorySyncConfig::default(),
        attribute_mapping: DirectoryAttributeMapping::default(),
    }];
    // The sync connects only LDAP and Active Directory providers, so an
    // unsupported type is found when the configuration loads.
    let err = config
        .validate()
        .expect_err("an unsupported provider type is a configuration fault");
    assert!(
        err.message().contains("unsupported type"),
        "{}",
        err.message()
    );

    config.realms[0].protocols.directory.providers[0].provider_type = "ldap".to_string();
    config.realms[0].protocols.directory.providers[0]
        .connection
        .url = "ldap:/dir.example.com".to_string();
    let err = config
        .validate()
        .expect_err("a mistyped URL scheme is a configuration fault");
    assert!(err.message().contains("ldaps://"), "{}", err.message());
}

#[test]
fn the_boolean_or_object_form_names_the_offending_field() {
    // The object form reports an unknown key by name and a wrong type as
    // itself, like every other configuration.
    let err = serde_json::from_value::<OAuthProtocolConfig>(serde_json::json!({
        "dpop": {"unknown_key": true}
    }))
    .expect_err("an unknown key is rejected");
    assert!(err.to_string().contains("unknown_key"), "{err}");
    let err = serde_json::from_value::<OAuthProtocolConfig>(serde_json::json!({
        "dpop": 5
    }))
    .expect_err("a wrong type is rejected");
    assert!(err.to_string().contains("boolean"), "{err}");
    // The boolean form still works.
    let config: OAuthProtocolConfig =
        serde_json::from_value(serde_json::json!({"dpop": true})).expect("the boolean form");
    assert!(config.dpop.enabled);
}

#[test]
fn a_directory_entry_ceiling_must_be_within_the_supported_range() {
    let mut config = minimal_config();
    config.realms[0].protocols.directory.providers = vec![DirectoryProviderConfig {
        webhook: None,
        id: "ldap-main".to_string(),
        provider_type: "ldap".to_string(),
        enabled: true,
        connection: DirectoryConnectionConfig {
            url: "ldaps://dir.example.com".to_string(),
            max_entries: Some(0),
            ..DirectoryConnectionConfig::default()
        },
        sync: DirectorySyncConfig::default(),
        attribute_mapping: DirectoryAttributeMapping::default(),
    }];
    // The ceiling is checked when the configuration loads, so an operator
    // learns about a wrong value before the first sync.
    let err = config
        .validate()
        .expect_err("a ceiling of zero is a configuration fault");
    assert!(err.message().contains("max_entries"), "{}", err.message());
    config.realms[0].protocols.directory.providers[0]
        .connection
        .max_entries = Some(10_000_001);
    let err = config
        .validate()
        .expect_err("a ceiling above the limit is a configuration fault");
    assert!(err.message().contains("max_entries"), "{}", err.message());
    config.realms[0].protocols.directory.providers[0]
        .connection
        .max_entries = Some(2_000_000);
    config
        .validate()
        .expect("a ceiling within the range is accepted");
}

#[test]
fn a_directory_page_size_must_be_within_the_supported_range() {
    let mut config = minimal_config();
    config.realms[0].protocols.directory.providers = vec![DirectoryProviderConfig {
        webhook: None,
        id: "ldap-main".to_string(),
        provider_type: "ldap".to_string(),
        enabled: true,
        connection: DirectoryConnectionConfig {
            url: "ldaps://dir.example.com".to_string(),
            page_size: Some(0),
            ..DirectoryConnectionConfig::default()
        },
        sync: DirectorySyncConfig::default(),
        attribute_mapping: DirectoryAttributeMapping::default(),
    }];
    // A page size is checked when the configuration loads, so an operator
    // learns about a wrong value before the first sync.
    let err = config
        .validate()
        .expect_err("a page size of zero is a configuration fault");
    assert!(err.message().contains("page_size"), "{}", err.message());
    config.realms[0].protocols.directory.providers[0]
        .connection
        .page_size = Some(1001);
    let err = config
        .validate()
        .expect_err("a page size above the bound is a configuration fault");
    assert!(err.message().contains("page_size"), "{}", err.message());
    config.realms[0].protocols.directory.providers[0]
        .connection
        .page_size = Some(500);
    config
        .validate()
        .expect("a page size within the range is accepted");
}

#[test]
fn the_log_format_selects_the_daemon_log_shape() {
    // The daemon writes the logs the configuration asks for: `json` writes
    // structured logs, `text` writes plain ones, and any other value is a
    // load-time error naming the key.
    let mut config = minimal_config();
    config.observability.logs.format = "text".to_string();
    config.validate().expect("the text format is accepted");
    assert!(!config.observability.logs.json());

    config.observability.logs.format = "json".to_string();
    config.validate().expect("the json format is accepted");
    assert!(config.observability.logs.json());

    config.observability.logs.format = "xml".to_string();
    let err = config
        .validate()
        .expect_err("an unsupported log format is rejected");
    assert!(
        err.message().contains("observability.logs.format"),
        "the error names the key: {err}"
    );
}

#[test]
fn the_removed_observability_keys_are_rejected() {
    // `redact_pii` named a redaction the product never performed, the old OTLP
    // endpoint key named an environment variable nothing read, and the audit sink
    // named a file the product never wrote. A configuration that still sets
    // them is a configuration error, not a silently ignored key.
    let err = serde_json::from_str::<ObservabilityConfig>(r#"{"logs":{"redact_pii":true}}"#)
        .expect_err("the removed key is rejected");
    assert!(
        err.to_string().contains("redact_pii"),
        "the error names the removed key: {err}"
    );

    let err = serde_json::from_str::<ObservabilityConfig>(
        r#"{"tracing":{"otlp_endpoint_env":"QID_OTLP_ENDPOINT"}}"#,
    )
    .expect_err("the removed key is rejected");
    assert!(
        err.to_string().contains("otlp_endpoint_env"),
        "the error names the removed key: {err}"
    );

    let err = serde_json::from_str::<ObservabilityConfig>(
        r#"{"audit":{"sink":{"type":"file","path":"/var/log/qid/audit.jsonl"}}}"#,
    )
    .expect_err("the removed key is rejected");
    assert!(
        err.to_string().contains("audit"),
        "the error names the removed key: {err}"
    );
}

#[test]
fn the_removed_pep_registration_keys_are_rejected() {
    // The capability mode and phase describe the enforcement point, which qid
    // never consults; the assertion header and algorithm name a delivery and
    // a signing choice the product does not make - the assertion is returned
    // in the response body and signed with the realm's pep_assertion
    // keyring; and the per-registration decision endpoint duplicates the
    // server path that owns it. A configuration that still sets them is a
    // configuration error, not a silently ignored key.
    for (key, value) in [("mode", "\"enforce\""), ("phase", "\"steady\"")] {
        let err = serde_json::from_str::<PepCapabilityConfig>(&format!(
            r#"{{"{key}":{value},"effect":"authzen"}}"#
        ))
        .expect_err("the removed key is rejected");
        assert!(
            err.to_string().contains(key),
            "the error names the removed key: {err}"
        );
    }

    let err = serde_json::from_str::<ProxyAssertionConfig>(r#"{"header":"x-qid-assertion"}"#)
        .expect_err("the removed key is rejected");
    assert!(
        err.to_string().contains("header"),
        "the error names the removed key: {err}"
    );

    let err = serde_json::from_str::<ProxyAssertionConfig>(r#"{"alg":"ES256"}"#)
        .expect_err("the removed key is rejected");
    assert!(
        err.to_string().contains("alg"),
        "the error names the removed key: {err}"
    );

    let err =
        serde_json::from_str::<PepDecisionConfig>(r#"{"endpoint":"/pep/decision/v1/evaluate"}"#)
            .expect_err("the removed key is rejected");
    assert!(
        err.to_string().contains("endpoint"),
        "the error names the removed key: {err}"
    );
}

#[test]
fn the_removed_pep_credential_keys_are_rejected() {
    // `key_rotation` named a rotation policy for the PEP credential that
    // nothing applied, and the message-signature settings belonged to a
    // method the product does not implement - `auth.active_method` accepts
    // only `bearer_jwt` - so they were unreachable as well as unread. A
    // configuration that still sets them is a configuration error, not a
    // silently ignored key.
    let err = serde_json::from_str::<PepRegistrationAuthConfig>(r#"{"key_rotation":"off"}"#)
        .expect_err("the removed key is rejected");
    assert!(
        err.to_string().contains("key_rotation"),
        "the error names the removed key: {err}"
    );

    let err = serde_json::from_str::<PepRegistrationAuthConfig>(
        r#"{"http_message_signatures":{"content_digest_required":false}}"#,
    )
    .expect_err("the removed key is rejected");
    assert!(
        err.to_string().contains("http_message_signatures"),
        "the error names the removed key: {err}"
    );
}

#[test]
fn the_obsolete_password_pepper_reference_is_rejected() {
    // The obsolete unversioned reference is still unsupported.
    let err = serde_json::from_str::<PasswordConfig>(
        r#"{"pepper_ref":"secret://qid/retail/password-pepper"}"#,
    )
    .expect_err("the removed key is rejected");
    assert!(
        err.to_string().contains("pepper_ref"),
        "the error names the removed key: {err}"
    );
}

#[test]
fn a_realm_password_hash_the_product_cannot_create_is_rejected() {
    // `hash` names the algorithm the product creates credentials with,
    // and the product creates Argon2id only. Any other value names a
    // capability the product does not have, so it is a configuration
    // error naming the key.
    let mut config = minimal_config();
    config.realms[0].authentication.password.hash = "bcrypt".to_string();
    let err = config
        .validate()
        .expect_err("the hash algorithm is rejected");
    let message = err.message();
    assert!(
        message.contains("hash"),
        "the error names the key: {message}"
    );
    assert!(
        message.contains("argon2id"),
        "the error names the accepted algorithm: {message}"
    );
}

#[test]
fn a_realm_password_lockout_limit_of_zero_is_rejected() {
    // A realm that locks the account after zero failed attempts would
    // lock every account on the first login, so the limit must be a
    // usable number.
    let mut config = minimal_config();
    config.realms[0].authentication.password.max_failed_attempts = 0;
    let err = config
        .validate()
        .expect_err("a zero failed-attempt limit is rejected");
    let message = err.message();
    assert!(
        message.contains("max_failed_attempts"),
        "the error names the key: {message}"
    );

    let mut config = minimal_config();
    config.realms[0]
        .authentication
        .password
        .lockout_duration_seconds = 0;
    let err = config
        .validate()
        .expect_err("a zero lockout duration is rejected");
    assert!(
        err.message().contains("lockout_duration_seconds"),
        "the error names the key: {}",
        err.message()
    );
}

#[test]
fn a_realm_password_budget_of_zero_is_rejected() {
    // A realm that accepts no failed login at all would refuse every
    // password login, so the budget must be a usable number.
    let mut config = minimal_config();
    config.realms[0]
        .authentication
        .password
        .max_failed_attempts_per_realm = 0;
    let err = config
        .validate()
        .expect_err("a zero realm failure budget is rejected");
    assert!(
        err.message().contains("max_failed_attempts_per_realm"),
        "the error names the key: {}",
        err.message()
    );
}

#[test]
fn a_realm_password_argon2id_cost_the_product_cannot_use_is_rejected() {
    // The cost is the calibration the product hashes with, so a cost the
    // Argon2id parameters cannot express must fail at load time rather
    // than at the first password the realm creates.
    let mut config = minimal_config();
    config.realms[0].authentication.password.argon2id.time_cost = 0;
    let err = config.validate().expect_err("a zero time cost is rejected");
    assert!(
        err.message().contains("time_cost"),
        "the error names the key: {}",
        err.message()
    );

    let mut config = minimal_config();
    config.realms[0]
        .authentication
        .password
        .argon2id
        .parallelism = 0;
    let err = config
        .validate()
        .expect_err("a zero parallelism is rejected");
    assert!(
        err.message().contains("parallelism"),
        "the error names the key: {}",
        err.message()
    );

    let mut config = minimal_config();
    config.realms[0].authentication.password.argon2id.memory_kib = 8;
    config.realms[0]
        .authentication
        .password
        .argon2id
        .parallelism = 2;
    let err = config
        .validate()
        .expect_err("a memory cost below 8 KiB per lane is rejected");
    assert!(
        err.message().contains("memory_kib"),
        "the error names the key: {}",
        err.message()
    );
}

#[test]
fn the_decision_cache_lifetime_follows_the_class_of_the_decision() {
    let config = PepDecisionCacheConfig {
        positive_ttl_seconds: 7,
        negative_ttl_seconds: 2,
    };
    assert_eq!(config.ttl_ms(DecisionCacheClass::Positive), 7_000);
    assert_eq!(config.ttl_ms(DecisionCacheClass::Negative), 2_000);
    let default = PepDecisionCacheConfig::default();
    assert_eq!(default.ttl_ms(DecisionCacheClass::Positive), 30_000);
    assert_eq!(default.ttl_ms(DecisionCacheClass::Negative), 5_000);
}

fn csv_provider(url: &str) -> DirectoryProviderConfig {
    DirectoryProviderConfig {
        webhook: None,
        id: "hr-csv".to_string(),
        provider_type: "csv".to_string(),
        enabled: true,
        connection: DirectoryConnectionConfig {
            url: url.to_string(),
            ..DirectoryConnectionConfig::default()
        },
        sync: DirectorySyncConfig::default(),
        attribute_mapping: DirectoryAttributeMapping::default(),
    }
}

#[test]
fn a_csv_directory_provider_reads_a_local_file() {
    let mut config = minimal_config();
    config.realms[0].protocols.directory.providers =
        vec![csv_provider("/var/lib/qid/hr/workforce.csv")];
    config
        .validate()
        .expect("a csv provider with defaults is accepted");
}

#[test]
fn a_csv_directory_provider_rejects_unusable_paths() {
    for url in [
        "",
        "   ",
        "ldap://dir.example.com",
        "https://hr.example.com/qid/events",
    ] {
        let mut config = minimal_config();
        config.realms[0].protocols.directory.providers = vec![csv_provider(url)];
        let err = config
            .validate()
            .expect_err("an unusable csv path is a configuration fault");
        assert!(
            err.message().contains("connection.url"),
            "the error names connection.url: {}",
            err.message()
        );
    }
}

#[test]
fn a_csv_directory_provider_rejects_ldap_only_settings() {
    let mut ldap_only = csv_provider("/var/lib/qid/hr/workforce.csv");
    ldap_only.connection.bind_dn = Some("CN=svc".to_string());
    ldap_only.connection.bind_password = Some("secret".to_string());
    ldap_only.connection.base_dn = Some("dc=example,dc=com".to_string());
    ldap_only.connection.page_size = Some(100);
    ldap_only.connection.tls_insecure_skip_verify = true;
    ldap_only.sync.user_search_filter = Some("(objectClass=group)".to_string());
    ldap_only.attribute_mapping.uid = None;
    let mut config = minimal_config();
    config.realms[0].protocols.directory.providers = vec![ldap_only];
    let err = config
        .validate()
        .expect_err("ldap-only settings are a configuration fault for csv");
    // The first rejected key fails the load; each run names the key it hit.
    assert!(
        [
            "bind_dn",
            "base_dn",
            "page_size",
            "tls_insecure_skip_verify",
            "user_search_filter",
            "attribute_mapping"
        ]
        .iter()
        .any(|key| err.message().contains(key)),
        "the error names the ignored key: {}",
        err.message()
    );

    // Each LDAP-only connection key is rejected on its own as well.
    for mutate in [
        "bind_dn",
        "bind_password",
        "base_dn",
        "page_size",
        "connect_timeout_seconds",
        "tls_insecure_skip_verify",
    ] {
        let mut provider = csv_provider("/var/lib/qid/hr/workforce.csv");
        match mutate {
            "bind_dn" => provider.connection.bind_dn = Some("CN=svc".to_string()),
            "bind_password" => provider.connection.bind_password = Some("secret".to_string()),
            "base_dn" => provider.connection.base_dn = Some("dc=example,dc=com".to_string()),
            "page_size" => provider.connection.page_size = Some(100),
            "connect_timeout_seconds" => provider.connection.connect_timeout_seconds = Some(20),
            _ => provider.connection.tls_insecure_skip_verify = true,
        }
        let mut config = minimal_config();
        config.realms[0].protocols.directory.providers = vec![provider];
        let err = config
            .validate()
            .expect_err("an ldap-only connection key is rejected for csv");
        assert!(
            err.message().contains(mutate),
            "the error names {mutate}: {}",
            err.message()
        );
    }
}

#[test]
fn a_csv_directory_provider_rejects_snapshot_deactivation() {
    for deactivate_missing in [None, Some(false)] {
        let mut provider = csv_provider("/var/lib/qid/hr/workforce.csv");
        provider.sync.deactivate_missing = deactivate_missing;
        let mut config = minimal_config();
        config.realms[0].protocols.directory.providers = vec![provider];
        config
            .validate()
            .expect("CSV event batches accept unset or false snapshot deactivation");
    }

    let mut provider = csv_provider("/var/lib/qid/hr/workforce.csv");
    provider.sync.deactivate_missing = Some(true);
    let mut config = minimal_config();
    config.realms[0].protocols.directory.providers = vec![provider];
    let err = config
        .validate()
        .expect_err("CSV must reject an ignored snapshot-deactivation request");
    assert!(
        err.message().contains("sync.deactivate_missing"),
        "{}",
        err.message()
    );
}

#[test]
fn a_csv_directory_provider_keeps_a_settable_record_ceiling() {
    let mut config = minimal_config();
    let mut provider = csv_provider("/var/lib/qid/hr/workforce.csv");
    provider.connection.max_entries = Some(10);
    config.realms[0].protocols.directory.providers = vec![provider];
    config.validate().expect("a csv record ceiling is accepted");

    let mut config = minimal_config();
    let mut provider = csv_provider("/var/lib/qid/hr/workforce.csv");
    provider.connection.max_entries = Some(0);
    config.realms[0].protocols.directory.providers = vec![provider];
    let err = config
        .validate()
        .expect_err("an unusable csv record ceiling is rejected");
    assert!(err.message().contains("max_entries"), "{}", err.message());
}

#[test]
fn a_csv_directory_provider_accepts_only_default_or_unset_connect_timeout() {
    for timeout in [None, Some(10), Some(0), Some(1), Some(20)] {
        let mut provider = csv_provider("  /var/lib/qid/hr/workforce.csv  ");
        provider.connection.connect_timeout_seconds = timeout;
        let mut config = minimal_config();
        config.realms[0].protocols.directory.providers = vec![provider];
        let result = config.validate();
        if matches!(timeout, None | Some(10)) {
            result.expect("default or unset timeout and trimmed local path accepted");
        } else {
            let err = result.expect_err("custom LDAP timeout rejected for CSV");
            assert!(err.message().contains("connect_timeout_seconds"));
        }
    }
}

#[test]
fn webhook_configuration_is_bounded_disabled_by_default_and_type_specific() {
    use super::protocol::*;
    let mut provider = csv_provider("unused");
    provider.provider_type = "webhook".into();
    provider.connection = Default::default();
    provider.sync = Default::default();
    provider.enabled = false;
    assert!(validate_webhook_provider(&provider).is_ok());
    let limits = DirectoryWebhookConfig::default();
    assert_eq!(limits.max_request_bytes, MAX_HR_REQUEST_BYTES);
    assert_eq!(limits.max_records, MAX_DIRECTORY_SEARCH_ENTRIES);
    for bytes in [0, MAX_HR_REQUEST_BYTES + 1] {
        provider.webhook = Some(DirectoryWebhookConfig {
            max_request_bytes: bytes,
            ..Default::default()
        });
        assert!(validate_webhook_provider(&provider).is_err());
    }
    for count in [0, MAX_DIRECTORY_SEARCH_ENTRIES_LIMIT + 1] {
        provider.webhook = Some(DirectoryWebhookConfig {
            max_records: count,
            ..Default::default()
        });
        assert!(validate_webhook_provider(&provider).is_err());
    }
    provider.webhook = Some(DirectoryWebhookConfig {
        max_request_bytes: 1,
        max_records: 1,
    });
    assert!(validate_webhook_provider(&provider).is_ok());
    provider.webhook = Some(DirectoryWebhookConfig {
        max_request_bytes: MAX_HR_REQUEST_BYTES,
        max_records: MAX_DIRECTORY_SEARCH_ENTRIES_LIMIT,
    });
    assert!(validate_webhook_provider(&provider).is_ok());
    provider.connection.url = "ldap://unused.invalid".into();
    assert!(validate_webhook_provider(&provider).is_err());
    provider.connection = Default::default();
    provider.sync.deactivate_missing = Some(false);
    assert!(validate_webhook_provider(&provider).is_err());
    provider.sync = Default::default();
    provider.attribute_mapping.mail = Some("mailOverride".into());
    assert!(validate_webhook_provider(&provider).is_err());
    for kind in ["csv", "ldap", "active-directory"] {
        provider.provider_type = kind.into();
        assert!(validate_webhook_provider(&provider).is_err());
    }
    let mut config = minimal_config();
    config.realms[0].tenant_id = Some("tenant".into());
    config.realms[0].protocols.directory.enabled = true;
    provider.provider_type = "webhook".into();
    provider.attribute_mapping = Default::default();
    provider.enabled = true;
    config.realms[0].protocols.directory.providers = vec![provider];
    assert!(config.validate().is_ok());
    config.realms[0].tenant_id = None;
    assert!(config.validate().is_err());
    config.realms[0].tenant_id = Some("tenant".into());
    let duplicate = config.realms[0].protocols.directory.providers[0].clone();
    config.realms[0]
        .protocols
        .directory
        .providers
        .push(duplicate);
    assert!(config.validate().is_err());
    // Deserialization does not activate an inbound binding implicitly.
    let dir = std::env::temp_dir().join(format!("qid-webhook-config-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.yaml");
    std::fs::write(&path,"server:\n  listen: 127.0.0.1:0\n  public_base_url: https://id.example.com\nstorage:\n  primary:\n    url: unused.json\nrealms:\n  - id: corp\n    issuer: https://id.example.com/corp\n    protocols:\n      directory:\n        providers:\n          - id: hr\n            type: webhook\n").unwrap();
    let config = QidConfig::from_file(path.to_str().unwrap()).unwrap();
    assert!(!config.realms[0].protocols.directory.providers[0].enabled);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn tracing_config_is_explicit_and_validated() {
    let mut config = minimal_config();
    assert_eq!(config.observability.tracing.endpoint, None);
    let defaults: TracingConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(defaults, TracingConfig::default());
    for endpoint in ["http://127.0.0.1:4317", "https://collector.example.com"] {
        config.observability.tracing.endpoint = Some(endpoint.into());
        config.validate().unwrap();
    }
    for endpoint in [
        "",
        "secret",
        "ftp://secret",
        "http://user:secret@localhost",
        "http://localhost?secret",
        "http://localhost#secret",
    ] {
        config.observability.tracing.endpoint = Some(endpoint.into());
        let message = config.validate().unwrap_err().to_string();
        assert!(message.contains("observability.tracing"));
        assert!(!message.contains("secret"));
    }
    let mut tracing = defaults;
    tracing.max_export_batch_size = tracing.max_queue_size + 1;
    assert!(tracing.validate().is_err());
    tracing.max_export_batch_size = 0;
    assert!(tracing.validate().is_err());
    tracing.max_export_batch_size = 1;
    tracing.max_queue_size = 0;
    assert!(tracing.validate().is_err());
    tracing.max_queue_size = 1;
    tracing.export_timeout_ms = 0;
    assert!(tracing.validate().is_err());
    tracing.export_timeout_ms = 1;
    tracing.scheduled_delay_ms = 0;
    assert!(tracing.validate().is_err());
    tracing.scheduled_delay_ms = 1;
    tracing.service_name.clear();
    assert!(tracing.validate().is_err());
}

#[test]
fn realm_password_pepper_sources_are_explicit_and_validated() {
    let config: PasswordConfig = Figment::new()
        .merge(Yaml::string(
            r#"
pepper:
  active: key2
  keys:
    key1: { env: QID_TEST_PASSWORD_KEY_ONE }
    key2: { file: ./test-pepper.key }
"#,
        ))
        .extract()
        .unwrap();
    config.validate("test").unwrap();
    for value in [
        serde_json::json!({"active":"unknown", "keys":{"key1":{"env":"TEST"}}}),
        serde_json::json!({"active":"123456789", "keys":{"123456789":{"env":"TEST"}}}),
        serde_json::json!({"active":"key1", "keys":{"key1":{"env":""}}}),
        serde_json::json!({"active":"key1", "keys":{"key1":{"file":""}}}),
    ] {
        let invalid: PasswordConfig =
            serde_json::from_value(serde_json::json!({"pepper":value})).unwrap();
        assert!(invalid.validate("test").is_err());
    }
    for source in [
        serde_json::json!("inline secret"),
        serde_json::json!({"env":"TEST", "file":"test"}),
        serde_json::json!({"value":"secret"}),
    ] {
        assert!(
            serde_json::from_value::<PasswordConfig>(
                serde_json::json!({"pepper":{"active":"key1", "keys":{"key1":source}}})
            )
            .is_err()
        );
    }
}
