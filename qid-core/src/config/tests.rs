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
        mode: None,
        phase: None,
        effect: effect.to_string(),
        constraints: PepCapabilityConstraintsConfig::default(),
        authority: PepAuthorityConfig::default(),
        build_features: Vec::new(),
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
    let decision: PepDecisionConfig = serde_json::from_value(serde_json::json!({
        "endpoint": "/pep/decision/v1/evaluate",
        "fail_policy": "deny"
    }))
    .unwrap();
    assert_eq!(decision.endpoint, "/pep/decision/v1/evaluate");
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
fn token_ttl_default_values() {
    let ttl = TokenTtlConfig::default();
    assert_eq!(ttl.access_token_ttl_seconds, 3600);
    assert_eq!(ttl.refresh_token_ttl_seconds, 86400);
    assert_eq!(ttl.id_token_ttl_seconds, 3600);
    assert_eq!(ttl.auth_code_ttl_seconds, 600);
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
