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
            notification: None,
            quic: Default::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig::default(),
        realms: vec![RealmConfig {
            client_callback_destinations: Default::default(),
            pairwise_subject_secret: None,

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
        iga: Default::default(),
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
            notification: None,
            quic: Default::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig::default(),
        realms: vec![RealmConfig {
            client_callback_destinations: Default::default(),
            pairwise_subject_secret: None,

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
        iga: Default::default(),
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
    let decision: PepDecisionConfig =
        serde_json::from_value(serde_json::json!({ "fail_policy": "allow" })).unwrap();
    assert_eq!(decision.fail_policy, "allow");
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
fn static_client_config_validates_grant_types_against_implemented_set() {
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
        redirect_uris: Vec::new(),
        grant_types: vec!["urn:ietf:params:oauth:grant-type:jwt-bearer".to_string()],
    }];
    assert!(config.validate().is_ok());

    config.realms[0].clients[0].grant_types = vec!["authorization_codee".to_string()];
    let err = config.validate().unwrap_err();
    assert!(
        err.message().contains(
            "realm corp static client web has unsupported grant_type: authorization_codee"
        ),
        "{}",
        err.message()
    );
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
            notification: None,
            quic: Default::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig::default(),
        realms: vec![
            RealmConfig {
                client_callback_destinations: Default::default(),
                pairwise_subject_secret: None,

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
                client_callback_destinations: Default::default(),
                pairwise_subject_secret: None,

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
        iga: Default::default(),
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
            notification: None,
            quic: Default::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig::default(),
        realms: vec![],
        observability: ObservabilityConfig::default(),
        iga: Default::default(),
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
            notification: None,
            quic: Default::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig::default(),
        realms: vec![RealmConfig {
            client_callback_destinations: Default::default(),
            pairwise_subject_secret: None,

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
        iga: Default::default(),
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
fn dot_segment_realm_ids_are_rejected_for_every_realm() {
    for id in [".", ".."] {
        let mut plain = minimal_config();
        plain.realms[0].id = id.into();
        let message = plain.validate().unwrap_err().message().to_string();
        assert!(
            message.contains(&format!(
                "realm {id} id must be a non-dot-segment URL path segment"
            )),
            "realm id {id:?} must be rejected: {message}"
        );

        let mut federated = config_with_provider_kind("social");
        federated.realms[0].protocols.federation.enabled = true;
        let provider = &mut federated.realms[0].protocols.federation.inbound_providers[0];
        provider.enabled = true;
        provider.social_provider = Some("google".into());
        federated.realms[0].id = id.into();
        let message = federated.validate().unwrap_err().message().to_string();
        assert!(
            message.contains(&format!(
                "realm {id} id must be a non-dot-segment URL path segment"
            )),
            "federated realm id {id:?} must be rejected: {message}"
        );
    }

    let mut valid = minimal_config();
    valid.realms[0].id = "corp.v2".into();
    valid.validate().unwrap();
}

#[test]
fn multi_realm_issuer_must_match_realm_scoped_discovery_route() {
    let mut config = minimal_config();
    config.realms.push(RealmConfig {
        client_callback_destinations: Default::default(),
        pairwise_subject_secret: None,

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
            notification: None,
            quic: Default::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig::default(),
        realms: vec![RealmConfig {
            client_callback_destinations: Default::default(),
            pairwise_subject_secret: None,

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
        iga: Default::default(),
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
fn ops_cache_rejects_blank_endpoints_and_accepts_valid_ones() {
    let mut ops = OpsConfig::default();
    ops.cache.kind = "valkey".to_string();
    ops.cache.endpoints = vec![" valkey://cache:6379 ".to_string()];
    assert!(ops.validate().is_ok());

    ops.cache.endpoints = vec!["valkey://cache:6379".to_string(), " \t ".to_string()];
    let err = ops.validate().unwrap_err();
    assert!(matches!(err, QidError::Config { .. }));
    assert!(err.message().contains("ops.cache.endpoints"));
    assert!(err.message().contains("blank"));
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
        p.auth_email_magic_link_send,
        "/api/v1/:realm/auth/email-magic-link/send"
    );
    assert_eq!(
        p.auth_email_magic_link_verify,
        "/api/v1/:realm/auth/email-magic-link/verify"
    );
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
fn vc_consumer_audiences_are_optional_exact_and_validated() {
    let mut config = minimal_config();
    let parsed: VcProtocolConfig = serde_json::from_value(serde_json::json!({})).unwrap();
    assert!(parsed.credential_audience.is_none());
    assert!(parsed.status_audience.is_none());
    config.validate().unwrap();
    for name in ["credential_audience", "status_audience"] {
        for value in [
            "",
            " ",
            "\t",
            " api://qid/vc",
            "api://qid/vc ",
            "api://qid/v c",
        ] {
            config.realms[0].protocols.vc =
                serde_json::from_value(serde_json::json!({name: value})).unwrap();
            let error = config.validate().unwrap_err();
            assert!(error.message().contains(name), "{error}");
        }
    }
    config.realms[0].protocols.vc = serde_json::from_value(serde_json::json!({
        "credential_audience": "api://qid/vc",
        "status_audience": "api://qid/vc-status"
    }))
    .unwrap();
    config.validate().unwrap();
    let plan = crate::plan::RuntimePlan::from_config(&config).unwrap();
    let realm = plan.first_realm().unwrap();
    assert_eq!(
        realm.vc_credential_audience.as_deref(),
        Some("api://qid/vc")
    );
    assert_eq!(
        realm.vc_status_audience.as_deref(),
        Some("api://qid/vc-status")
    );
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
    assert_eq!(config.admin.security.required_acr, "phr");
    assert_eq!(config.admin.security.required_amr, ["webauthn"]);
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
            token_exchange_requester_client_ids: Vec::new(),
            require_sender_constraint: true,
            high_risk: true,
        },
        OAuthResourceServerConfig {
            audience: "api://payments".to_string(),
            resources: vec!["https://api.example.com/refunds".to_string()],
            scopes: vec!["refunds".to_string()],
            introspection_client_ids: Vec::new(),
            token_exchange_requester_client_ids: Vec::new(),
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
fn oauth_resource_server_requester_allowlist_defaults_to_empty() {
    let yaml = r#"
server:
  listen: "127.0.0.1:8443"
  public_base_url: "https://id.example.com"
realms:
  - id: corp
    issuer: "https://id.example.com/realms/corp"
    protocols:
      oauth:
        resource_servers:
          - audience: "api://payments"
"#;
    let config: QidConfig = Figment::new().merge(Yaml::string(yaml)).extract().unwrap();
    config.validate().unwrap();
    assert!(
        config.realms[0].protocols.oauth.resource_servers[0]
            .token_exchange_requester_client_ids
            .is_empty()
    );
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

    pep_config.realms[0].pep_registrations.registrations[0]
        .decision
        .fail_policy = "allow".to_string();
    let err = pep_config.validate().unwrap_err();
    assert!(
        err.message().contains("requires fail_policy=deny"),
        "edge-pep stays deny-only: {}",
        err.message()
    );

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
        token_exchange_requester_client_ids: Vec::new(),
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
        authorization_response_iss_parameter_supported: false,
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
        trusted_audiences: Vec::new(),
        kerberos_spnego: None,
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
fn saml_enabled_requires_session_index_binding_key_without_signing() {
    let mut config = minimal_config();
    config.realms[0].protocols.saml = SamlProtocolConfig {
        enabled: true,
        sign_assertions: false,
        sign_metadata: false,
        service_providers: vec![SamlServiceProviderConfig {
            entity_id: "https://sp.example.com/metadata".to_string(),
            acs_url: "https://sp.example.com/acs".to_string(),
            slo_url: None,
            name_id_formats: vec![],
            attribute_release_policy: vec![],
            signing_certificates: vec!["MIIBsigning".to_string()],
            encryption_certificates: vec![],
            want_assertions_signed: false,
        }],
        ..SamlProtocolConfig::default()
    };

    for key_path in [None, Some(" \t\n".to_string())] {
        config.realms[0].protocols.saml.idp_signing_key_pem_path = key_path;
        let err = config.validate().unwrap_err();
        assert!(matches!(err, QidError::Config { .. }));
        assert_eq!(
            err.message(),
            "config error: realm corp SAML SSO/SLO SessionIndex binding requires idp_signing_key_pem_path"
        );
    }

    config.realms[0].protocols.saml.idp_signing_key_pem_path =
        Some("saml/idp-signing.key".to_string());
    config.validate().unwrap();
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
            notification: None,
            quic: Default::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig::default(),
        realms: vec![RealmConfig {
            client_callback_destinations: Default::default(),
            pairwise_subject_secret: None,

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
        iga: Default::default(),
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
            notification: None,
            quic: Default::default(),
        },
        admin: AdminConfig::default(),
        storage: StorageConfig::default(),
        crypto: CryptoConfig::default(),
        realms: vec![RealmConfig {
            client_callback_destinations: Default::default(),
            pairwise_subject_secret: None,

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
        iga: Default::default(),
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
fn browser_session_cookie_settings_accept_defaults_and_valid_tokens() {
    minimal_config()
        .validate()
        .expect("the default browser cookie settings are valid");

    let mut config = minimal_config();
    config.realms[0].sessions.browser.cookie_name = "qid_session+v1.0~prod".to_string();
    config.realms[0].sessions.browser.same_site = "None".to_string();
    config
        .validate()
        .expect("a token cookie name and a supported SameSite value are valid");
}

#[test]
fn browser_session_same_site_cannot_carry_more_cookie_attributes() {
    let mut config = minimal_config();
    config.realms[0].sessions.browser.same_site = "Lax; Domain=evil.test".to_string();
    let err = config
        .validate()
        .expect_err("an injected cookie attribute is rejected");
    assert!(
        err.message().contains("same_site") && err.message().contains("corp"),
        "the error names the key and the realm: {err}"
    );
}

#[test]
fn browser_session_cookie_name_must_be_a_single_token() {
    for name in ["qid; Domain=evil.test", "qid=other", "qid with space", ""] {
        let mut config = minimal_config();
        config.realms[0].sessions.browser.cookie_name = name.to_string();
        let err = config
            .validate()
            .expect_err("a non-token cookie name is rejected");
        assert!(
            err.message().contains("cookie_name") && err.message().contains("corp"),
            "the error names the key and the realm: {err}"
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
fn the_legacy_string_passkey_attestation_setting_is_rejected() {
    // Attestation is now a typed required-packed policy, never an unchecked
    // browser conveyance preference (including the old "enterprise" value).
    assert!(
        serde_json::from_str::<AuthenticationConfig>(
            r#"{"passkeys":{"enabled":true,"attestation":"enterprise"}}"#,
        )
        .is_err()
    );
    let defaults: PasskeyConfig = serde_json::from_str("{}").unwrap();
    assert!(defaults.attestation.is_none());
    assert!(PasskeyConfig::default().attestation.is_none());
}

#[test]
fn passkey_preference_defaults_to_false_and_requires_enabled_passkeys() {
    let default: PasskeyConfig = serde_json::from_str("{}").unwrap();
    assert!(!default.preferred);
    assert!(!PasskeyConfig::default().preferred);
    let preferred: AuthenticationConfig =
        serde_json::from_str(r#"{"passkeys":{"enabled":true,"preferred":true}}"#).unwrap();
    assert!(preferred.passkeys.preferred);
    let mut config = minimal_config();
    config.realms[0].authentication = preferred;
    config.validate().unwrap();
    config.realms[0].authentication.passkeys.enabled = false;
    let err = config.validate().unwrap_err();
    assert!(err.message().contains("passkeys.preferred"));
    config.realms[0].authentication.passkeys.preferred = false;
    config.validate().unwrap();
}

#[test]
fn the_totp_attempt_policy_defaults_are_conservative() {
    let config = TotpConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.max_failed_attempts, 5);
    assert_eq!(config.failed_attempt_window_seconds, 300);
}

#[test]
fn a_realm_totp_attempt_policy_outside_its_bounds_is_rejected() {
    // A realm that admits no TOTP proof at all would refuse every proof, and
    // an unbounded budget or window is not a policy the product can keep, so
    // both numbers must stay inside their documented ranges.
    for (attempts, window) in [(0, 300), (101, 300), (5, 0), (5, 86_401)] {
        let mut config = minimal_config();
        config.realms[0].authentication.mfa.totp.enabled = true;
        config.realms[0].authentication.mfa.totp.max_failed_attempts = attempts;
        config.realms[0]
            .authentication
            .mfa
            .totp
            .failed_attempt_window_seconds = window;
        let err = config
            .validate()
            .expect_err("an out-of-bounds TOTP policy is rejected");
        let message = err.message();
        assert!(
            message.contains("mfa.totp"),
            "the error names the key: {message}"
        );
    }

    let mut config = minimal_config();
    config.realms[0].authentication.mfa.totp.enabled = true;
    config.realms[0].authentication.mfa.totp.max_failed_attempts = 5;
    config.realms[0]
        .authentication
        .mfa
        .totp
        .failed_attempt_window_seconds = 300;
    config.validate().expect("a bounded TOTP policy loads");
}

#[test]
fn the_totp_switch_is_read() {
    let enabled: AuthenticationConfig =
        serde_json::from_str(r#"{"mfa":{"totp":{"enabled":true}}}"#).expect("the switch parses");
    assert!(enabled.mfa.totp.enabled);
    assert_eq!(enabled.mfa.totp.max_failed_attempts, 5);
    assert_eq!(enabled.mfa.totp.failed_attempt_window_seconds, 300);
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

#[test]
fn directory_sync_rejects_the_removed_interval_setting() {
    let error = serde_json::from_str::<DirectorySyncConfig>(r#"{"sync_interval_minutes":60}"#)
        .expect_err("unsupported settings must not be silently ignored");
    assert!(error.to_string().contains("unknown field"));
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

#[test]
fn server_notification_is_absent_by_default() {
    let config = minimal_config();
    assert!(config.server.notification.is_none());
    config.validate().expect("minimal config validates");
}

#[test]
fn server_notification_accepts_supported_providers() {
    for provider in [
        "https://hooks.example.com/notify",
        "smtp://mail.example.com",
        "smtps://mail.example.com:465",
    ] {
        let mut config = minimal_config();
        config.server.notification = Some(ServerNotificationConfig {
            provider: provider.to_string(),
            timeout_seconds: 10,
            max_concurrent_deliveries: 16,
        });
        config.validate().expect("supported provider validates");
    }
}

#[test]
fn server_notification_rejects_invalid_provider_and_timeout() {
    for provider in [
        "",
        "not-a-url",
        "http://hooks.example.com/notify",
        "ftp://hooks.example.com/notify",
        "https://user:secret@hooks.example.com/notify",
        "https://hooks.example.com/notify?access_token=secret",
        "https://hooks.example.com/notify#fragment",
        " https://hooks.example.com/notify",
        "smtp://user:secret@mail.example.com",
        "smtp://mail.example.com?tls=required",
        "smtp://mail.example.com#fragment",
        "smtp://mail.example.com/ehlo",
        "smtp://",
    ] {
        let mut config = minimal_config();
        config.server.notification = Some(ServerNotificationConfig {
            provider: provider.to_string(),
            timeout_seconds: 10,
            max_concurrent_deliveries: 16,
        });
        let message = config
            .validate()
            .expect_err("invalid provider must fail")
            .to_string();
        assert!(
            message.contains("server.notification.provider"),
            "unexpected message for {provider:?}: {message}"
        );
        assert!(
            !message.contains("secret"),
            "notification error must not echo credentials: {message}"
        );
    }
    let mut config = minimal_config();
    config.server.notification = Some(ServerNotificationConfig {
        provider: "https://hooks.example.com/notify".to_string(),
        timeout_seconds: 0,
        max_concurrent_deliveries: 16,
    });
    let message = config
        .validate()
        .expect_err("zero timeout must fail")
        .to_string();
    assert!(message.contains("server.notification.timeout_seconds"));
}

#[test]
fn server_notification_debug_redacts_provider_url() {
    let notification = ServerNotificationConfig {
        provider: "https://hooks.example.com/path-secret".to_string(),
        timeout_seconds: 10,
        max_concurrent_deliveries: 16,
    };
    let debug = format!("{notification:?}");
    assert!(!debug.contains("path-secret"));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn email_verification_policy_defaults_and_bounds() {
    let mut config = minimal_config();
    let policy = &config.realms[0].authentication.email_verification;
    assert_eq!(
        (
            policy.ttl_seconds,
            policy.max_attempts,
            policy.max_issuances_per_window,
            policy.issuance_window_seconds
        ),
        (600, 5, 5, 3600)
    );
    for (ttl, attempts, issuances, window) in [(1, 1, 1, 1), (3600, 10, 100, 86400)] {
        config.realms[0].authentication.email_verification = EmailVerificationConfig {
            ttl_seconds: ttl,
            max_attempts: attempts,
            max_issuances_per_window: issuances,
            issuance_window_seconds: window,
        };
        config.validate().unwrap();
    }
    for (ttl, attempts, issuances, window) in [
        (0, 5, 5, 3600),
        (3601, 5, 5, 3600),
        (600, 0, 5, 3600),
        (600, 5, 0, 3600),
        (600, 5, 101, 3600),
        (600, 5, 5, 0),
        (600, 5, 5, 86401),
    ] {
        config.realms[0].authentication.email_verification = EmailVerificationConfig {
            ttl_seconds: ttl,
            max_attempts: attempts,
            max_issuances_per_window: issuances,
            issuance_window_seconds: window,
        };
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("email_verification")
        );
    }
    assert!(
        serde_json::from_value::<EmailVerificationConfig>(serde_json::json!({"unexpected":1}))
            .is_err()
    );
    let parsed: AuthenticationConfig = serde_json::from_value(serde_json::json!({
        "email_verification":{"ttl_seconds":120,"max_attempts":2}
    }))
    .unwrap();
    assert_eq!(
        (
            parsed.email_verification.ttl_seconds,
            parsed.email_verification.max_attempts,
            parsed.email_verification.max_issuances_per_window,
            parsed.email_verification.issuance_window_seconds
        ),
        (120, 2, 5, 3600)
    );
    for (json, issuances, window) in [
        (serde_json::json!({"max_issuances_per_window": 2}), 2, 3600),
        (serde_json::json!({"issuance_window_seconds": 60}), 5, 60),
    ] {
        let policy: EmailVerificationConfig = serde_json::from_value(json).unwrap();
        assert_eq!((policy.ttl_seconds, policy.max_attempts), (600, 5));
        assert_eq!(
            (
                policy.max_issuances_per_window,
                policy.issuance_window_seconds
            ),
            (issuances, window)
        );
        policy.validate().unwrap();
    }
}

#[test]
fn password_reset_policy_and_notification_capacity_defaults_and_bounds() {
    let mut config = minimal_config();
    assert_eq!(
        config.realms[0].authentication.password_reset,
        PasswordResetConfig::default()
    );
    let notification: ServerNotificationConfig = serde_json::from_value(serde_json::json!({
        "provider":"https://delivery.example.com"
    }))
    .unwrap();
    assert_eq!(notification.max_concurrent_deliveries, 16);
    config.server.notification = Some(notification);
    for (ttl, max, window, valid) in [
        (900, 5, 3600, true),
        (1, 1, 1, true),
        (1800, u32::MAX, 86400, true),
        (0, 5, 3600, false),
        (1801, 5, 3600, false),
        (900, 0, 3600, false),
        (900, 5, 0, false),
        (900, 5, 86401, false),
    ] {
        config.realms[0].authentication.password_reset = PasswordResetConfig {
            ttl_seconds: ttl,
            max_issuances_per_window: max,
            issuance_window_seconds: window,
        };
        assert_eq!(config.validate().is_ok(), valid, "{ttl}/{max}/{window}");
    }
    config.realms[0].authentication.password_reset = PasswordResetConfig::default();
    for (limit, valid) in [
        (0, false),
        (1, true),
        (16, true),
        (1024, true),
        (1025, false),
    ] {
        config
            .server
            .notification
            .as_mut()
            .unwrap()
            .max_concurrent_deliveries = limit;
        assert_eq!(config.validate().is_ok(), valid, "{limit}");
    }
    assert!(
        serde_json::from_value::<PasswordResetConfig>(serde_json::json!({"unknown":1})).is_err()
    );
}

#[test]
fn email_magic_link_defaults_validation_and_runtime_policy() {
    let mut config = minimal_config();
    let policy = &config.realms[0].authentication.email_magic_link;
    assert!(!policy.enabled);
    assert_eq!(
        (
            policy.ttl_seconds,
            policy.max_attempts,
            policy.max_issuances_per_window,
            policy.issuance_window_seconds
        ),
        (600, 5, 5, 3600)
    );
    config.realms[0].authentication.email_magic_link.enabled = true;
    assert!(config.validate().is_err());
    config.server.notification = Some(ServerNotificationConfig {
        provider: "https://delivery.example.com".into(),
        timeout_seconds: 10,
        max_concurrent_deliveries: 1,
    });
    config.validate().unwrap();
    let mut collision = config.clone();
    let mut other = collision.realms[0].clone();
    other.id = "other".into();
    other.issuer = "https://id.example.com/realms/other".into();
    other.sessions.browser.cookie_name = EMAIL_MAGIC_LINK_BINDING_COOKIE_NAME.into();
    collision.realms.push(other);
    assert!(collision.validate().is_err());
    let plan = crate::plan::RuntimePlan::from_config(&config).unwrap();
    assert!(plan.realms[0].email_magic_link.enabled);
    for id in [".", ".."] {
        let mut bad = config.clone();
        bad.realms[0].id = id.into();
        assert!(bad.validate().is_err());
    }
    for base in [
        "http://id.example.com",
        "https://user@id.example.com",
        "https://id.example.com/?query",
        "https://id.example.com/#fragment",
    ] {
        let mut bad = config.clone();
        bad.server.public_base_url = base.into();
        assert!(bad.validate().is_err(), "{base}");
    }
    for (ttl, attempts, issuances, window) in [
        (0, 5, 5, 3600),
        (3601, 5, 5, 3600),
        (600, 0, 5, 3600),
        (600, 21, 5, 3600),
        (600, 5, 0, 3600),
        (600, 5, 101, 3600),
        (600, 5, 5, 0),
        (600, 5, 5, 86401),
    ] {
        let policy = EmailMagicLinkConfig {
            enabled: false,
            ttl_seconds: ttl,
            max_attempts: attempts,
            max_issuances_per_window: issuances,
            issuance_window_seconds: window,
        };
        assert!(policy.validate().is_err());
    }
    for path in [
        "/verify",
        "//:realm/verify",
        "/:realm/../verify",
        "/:realm/verify?redirect=x",
        "/:realm/:realm",
        "/:realm/:other",
        "/:realm/%2fverify",
        "/:realm/*tail",
    ] {
        let mut bad = config.clone();
        bad.server.paths.auth_email_magic_link_verify = path.into();
        assert!(bad.validate().is_err(), "{path}");
    }
    let paths: ServerPaths = serde_json::from_value(serde_json::json!({
        "auth_email_magic_link_send": "/mail/:realm/send", "auth_email_magic_link_verify": "/mail/:realm/verify"
    })).unwrap();
    config.server.paths = paths;
    config.validate().unwrap();
    let auth: AuthenticationConfig =
        serde_json::from_value(serde_json::json!({"email_magic_link": {"enabled": true}})).unwrap();
    assert_eq!(auth.email_magic_link.ttl_seconds, 600);
    assert!(
        serde_json::from_value::<AuthenticationConfig>(
            serde_json::json!({"email_magic_link": {"redirect_url": "https://evil.example"}})
        )
        .is_err()
    );
}

#[test]
fn federation_transaction_ttl_defaults_to_a_positive_policy() {
    let config = minimal_config();
    assert_eq!(
        config.realms[0]
            .protocols
            .federation
            .transaction_ttl_seconds,
        DEFAULT_FEDERATION_TRANSACTION_TTL_SECONDS
    );
    let parsed: FederationProtocolConfig = serde_json::from_value(serde_json::json!({})).unwrap();
    assert_eq!(
        parsed.transaction_ttl_seconds,
        DEFAULT_FEDERATION_TRANSACTION_TTL_SECONDS
    );

    let mut invalid = config;
    invalid.realms[0]
        .protocols
        .federation
        .transaction_ttl_seconds = 0;
    assert!(invalid.validate().is_err());
}

#[test]
fn inbound_provider_authorization_response_iss_parameter_defaults_false_and_deserializes_true() {
    let defaults: InboundProviderConfig = serde_json::from_value(serde_json::json!({
        "id": "default-oidc",
        "kind": "oidc",
        "issuer": "https://login.partner.example"
    }))
    .unwrap();
    assert!(!defaults.authorization_response_iss_parameter_supported);

    let supporting: InboundProviderConfig = serde_json::from_value(serde_json::json!({
        "id": "rfc9207-oidc",
        "kind": "oidc",
        "issuer": "https://login.partner.example",
        "authorization_response_iss_parameter_supported": true
    }))
    .unwrap();
    assert!(supporting.authorization_response_iss_parameter_supported);
}

#[test]
fn inbound_oidc_trusted_audiences_are_defaulted_and_validated() {
    let mut config = minimal_config();
    config.realms[0].protocols.federation.enabled = true;
    let defaults: InboundProviderConfig = serde_json::from_value(serde_json::json!({
        "id": "default-oidc",
        "kind": "oidc",
        "issuer": "https://login.partner.example"
    }))
    .unwrap();
    assert!(defaults.trusted_audiences.is_empty());

    let provider: InboundProviderConfig = serde_json::from_value(serde_json::json!({
        "id": "partner-oidc",
        "kind": "oidc",
        "issuer": "https://login.partner.example",
        "enabled": true,
        "client_id": "qid-partner-broker",
        "trusted_audiences": ["partner-legacy-audience"]
    }))
    .unwrap();
    assert_eq!(
        provider.trusted_audiences,
        vec!["partner-legacy-audience".to_string()]
    );
    config.realms[0]
        .protocols
        .federation
        .inbound_providers
        .push(provider);
    config.validate().unwrap();

    let mut omitted = config.clone();
    omitted.realms[0].protocols.federation.inbound_providers[0]
        .trusted_audiences
        .clear();
    assert!(omitted.validate().is_ok());

    let mut empty = config.clone();
    empty.realms[0].protocols.federation.inbound_providers[0].trusted_audiences = vec!["  ".into()];
    assert!(empty.validate().is_err());

    let mut duplicate = config.clone();
    duplicate.realms[0].protocols.federation.inbound_providers[0].trusted_audiences =
        vec!["legacy".into(), "legacy".into()];
    assert!(duplicate.validate().is_err());

    let mut unsupported = config;
    unsupported.realms[0].protocols.federation.inbound_providers[0].kind = "saml".into();
    unsupported.realms[0].protocols.federation.inbound_providers[0].enabled = false;
    assert!(unsupported.validate().is_err());
}

#[test]
fn pep_decision_fail_policy_defaults_to_deny_and_accepts_only_deny_or_allow() {
    let mut config = minimal_config();
    config.realms[0].pep_registrations.enabled = true;
    config.realms[0].pep_registrations.registrations = vec![PepRegistrationConfig {
        name: "egress-main".to_string(),
        audience: Some("urn:qid:pep:corp/egress-main".to_string()),
        capabilities: vec![pep_capability("local_response")],
        assertion: ProxyAssertionConfig::default(),
        decision: PepDecisionConfig::default(),
        auth: PepRegistrationAuthConfig::default(),
    }];
    assert_eq!(
        config.realms[0].pep_registrations.registrations[0]
            .decision
            .fail_policy,
        "deny"
    );
    config.validate().unwrap();

    config.realms[0].pep_registrations.registrations[0]
        .decision
        .fail_policy = "allow".to_string();
    config.validate().unwrap();

    for rejected in ["sometimes", "", "ALLOW", "deny,allow"] {
        config.realms[0].pep_registrations.registrations[0]
            .decision
            .fail_policy = rejected.to_string();
        let err = config.validate().unwrap_err();
        assert!(
            err.message().contains("must be deny or allow"),
            "fail_policy={rejected:?} must be rejected: {}",
            err.message()
        );
    }
}

#[test]
fn vc_issuer_reference_is_exact_dedicated_and_realm_owned() {
    let mut config = minimal_config();
    let realm = config.realms[0].id.clone();
    config.realms[0].protocols.vc.issuer_key_ref = Some("vc-key".into());
    let key = KeyringConfig {
        name: "vc-key".into(),
        realm_id: Some(realm),
        purposes: vec!["other:vc_issuer".into()],
        signer: Default::default(),
        rotation: Default::default(),
    };
    let primary = KeyringConfig {
        name: "oidc-primary".into(),
        realm_id: None,
        purposes: vec!["oidc_token".into()],
        signer: Default::default(),
        rotation: Default::default(),
    };
    config.crypto.keyrings = vec![key.clone(), primary];
    config.validate().unwrap();
    for issuer in [
        "http://id.example.com/realms/corp",
        "https://user@id.example.com/realms/corp",
        "https://id.example.com/realms/corp?query",
        "https://id.example.com/realms/corp#fragment",
    ] {
        let mut invalid = config.clone();
        invalid.realms[0].issuer = issuer.into();
        assert!(
            invalid
                .validate()
                .unwrap_err()
                .message()
                .contains("HTTPS URL")
        );
    }
    let mut no_primary = config.clone();
    no_primary
        .crypto
        .keyrings
        .retain(|key| key.name != "oidc-primary");
    assert!(
        no_primary
            .validate()
            .unwrap_err()
            .message()
            .contains("deployment-level oidc_token keyring")
    );
    let mut realm_scoped_primary = config.clone();
    realm_scoped_primary.crypto.keyrings[1].realm_id = Some("corp".into());
    assert!(
        realm_scoped_primary
            .validate()
            .unwrap_err()
            .message()
            .contains("deployment-level oidc_token keyring")
    );
    for reference in ["", " vc-key", "vc-key ", "missing"] {
        let mut invalid = config.clone();
        invalid.realms[0].protocols.vc.issuer_key_ref = Some(reference.into());
        assert!(invalid.validate().is_err(), "{reference}");
    }
    for realm_id in [None, Some("other".into())] {
        let mut invalid = config.clone();
        invalid.crypto.keyrings[0].realm_id = realm_id;
        assert!(invalid.validate().is_err());
    }
    for purposes in [
        vec![],
        vec!["oidc_token".into()],
        vec!["other:vc_issuer".into(), "oidc_token".into()],
    ] {
        let mut invalid = config.clone();
        invalid.crypto.keyrings[0].purposes = purposes;
        assert!(invalid.validate().is_err());
    }
    let mut invalid = config.clone();
    invalid.crypto.keyrings.push(key);
    assert!(invalid.validate_vc_issuer_keys().is_err());
    let mut invalid = config.clone();
    invalid.realms.push(config.realms[0].clone());
    invalid.realms[1].id = "other".into();
    invalid.realms[1].protocols.vc.issuer_key_ref = None;
    assert!(
        invalid.validate().is_err(),
        "issuer must identify only one realm"
    );
}

#[test]
fn vc_profile_requires_issuer_key_reference_without_capability_switches() {
    let mut config = minimal_config();
    config.profile = DeploymentProfile::Vc;
    config.server.http_message_signatures.enabled = true;
    config.realms[0]
        .protocols
        .oidc
        .authorization_code
        .require_signed_request_object = true;
    let oauth = &mut config.realms[0].protocols.oauth;
    oauth.par.enabled = true;
    oauth.rar.enabled = true;
    oauth.dpop.enabled = true;
    oauth.mtls.enabled = true;
    oauth.private_key_jwt.enabled = true;
    oauth.jarm.enabled = true;
    oauth.require_pushed_authorization_requests = true;
    oauth.introspection.jwt_response = true;
    oauth.resource_servers = vec![OAuthResourceServerConfig {
        audience: "api://qid/vc".into(),
        resources: vec!["https://id.example.com/vc/v1".into()],
        scopes: vec!["qid_identity".into()],
        introspection_client_ids: Vec::new(),
        token_exchange_requester_client_ids: Vec::new(),
        require_sender_constraint: true,
        high_risk: false,
    }];
    config.realms[0].protocols.vc.issuer_key_ref = None;
    assert!(
        validate_vc_profile(&config)
            .unwrap_err()
            .message()
            .contains("issuer_key_ref")
    );
    config.realms[0].protocols.vc.issuer_key_ref = Some("vc-key".into());
    validate_vc_profile(&config).unwrap();
}

#[test]
fn push_policy_is_disabled_bounded_and_strict() {
    let defaults: AuthenticationConfig = serde_json::from_str("{}").unwrap();
    assert!(!defaults.mfa.push.enabled);
    assert_eq!(defaults.mfa.push.resend_cooldown_seconds, 30);
    assert_eq!(defaults.mfa.push, PushConfig::default());
    let policy: PushConfig = serde_json::from_str(r#"{"enabled":true}"#).unwrap();
    assert!(policy.validate().is_ok());
    assert!(
        PushConfig {
            max_proof_bytes: 256,
            ..PushConfig::default()
        }
        .validate()
        .is_ok()
    );
    assert!(
        PushConfig {
            max_proof_bytes: 128,
            ..PushConfig::default()
        }
        .validate()
        .is_err()
    );
    for key in [
        "ttl_seconds",
        "max_attempts",
        "max_issuances_per_window",
        "issuance_window_seconds",
        "resend_cooldown_seconds",
        "recent_reauth_seconds",
        "max_destination_bytes",
        "max_proof_bytes",
    ] {
        for value in [0, 100_000] {
            let candidate = serde_json::json!({key: value});
            let policy: PushConfig = serde_json::from_value(candidate).unwrap();
            assert!(policy.validate().is_err(), "{key}={value}");
        }
    }
    assert!(serde_json::from_str::<MfaConfig>(r#"{"push":{"algorithm":"none"}}"#).is_err());
    assert!(serde_json::from_str::<MfaConfig>(r#"{"require_step_up":true}"#).is_err());
}

#[test]
fn rebac_budgets_config_defaults_and_validation() {
    let base = r#"
server:
  listen: "127.0.0.1:8443"
  public_base_url: "https://id.example.com"
realms:
  - id: corp
    issuer: "https://id.example.com/realms/corp"
"#;
    for section in ["", "iga: {}", "iga: {rebac: {}}"] {
        let config: QidConfig = Figment::from(Yaml::string(&format!("{base}\n{section}")))
            .extract()
            .unwrap();
        assert_eq!(config.iga.rebac.expand_max_response_bytes.get(), 2_097_152);
        assert_eq!(config.iga.rebac.expand_max_tuples.get(), 10_000);
    }
    for key in ["expand_max_response_bytes", "expand_max_tuples"] {
        for (value, valid) in [
            ("1", true),
            ("12345", true),
            ("0", false),
            ("-1", false),
            ("1.5", false),
            ("18446744073709551616", false),
        ] {
            let result = Figment::from(Yaml::string(&format!(
                "{base}\niga:\n  rebac:\n    {key}: {value}\n"
            )))
            .extract::<QidConfig>();
            assert_eq!(result.is_ok(), valid);
            if let Ok(config) = result {
                assert_eq!(
                    if key == "expand_max_tuples" {
                        config.iga.rebac.expand_max_tuples.get()
                    } else {
                        config.iga.rebac.expand_max_response_bytes.get()
                    },
                    value.parse::<usize>().unwrap()
                );
            }
        }
    }
}

#[test]
fn rebac_budgets_environment_override() {
    // Re-execute in a child rather than mutate the parallel test process's env.
    // Keep its libtest output out of the parent Cargo timing stream.
    if std::env::var_os("REBAC_BUDGET_ENV_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "config::tests::rebac_budgets_environment_override",
            ])
            .env("REBAC_BUDGET_ENV_CHILD", "1")
            .env("QID_IGA__REBAC__EXPAND_MAX_RESPONSE_BYTES", "37")
            .env("QID_IGA__REBAC__EXPAND_MAX_TUPLES", "19")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated config test process exited with {}",
            output.status
        );
        return;
    }
    let path = temp_config_path("rebac-env.yaml");
    std::fs::write(
        &path,
        r#"
server:
  listen: "127.0.0.1:8443"
  public_base_url: "https://id.example.com"
realms:
  - id: corp
    issuer: "https://id.example.com/realms/corp"
iga:
  rebac:
    expand_max_response_bytes: 2097152
"#,
    )
    .unwrap();
    let config = QidConfig::from_file(path.to_str().unwrap()).unwrap();
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    assert_eq!(config.iga.rebac.expand_max_response_bytes.get(), 37);
    assert_eq!(config.iga.rebac.expand_max_tuples.get(), 19);
}

#[test]
fn password_screening_is_opt_in_and_validates_sources_and_bounds() {
    assert!(PasswordConfig::default().screening.is_none());
    let parse = |screening| {
        serde_json::from_value::<PasswordConfig>(serde_json::json!({"screening":screening}))
    };
    let valid = serde_json::json!({"sha256_hex":["aB".repeat(32)]});
    let config = parse(valid.clone()).unwrap();
    config.validate("test").unwrap();
    let screening = config.screening.unwrap();
    assert_eq!(screening.on_unavailable, ScreeningUnavailable::Deny);
    assert_eq!(screening.timeout_ms, 3000);
    assert_eq!(screening.max_retries, 0);
    assert_eq!(screening.retry_delay_ms, 250);
    assert_eq!(screening.max_response_bytes, 1024 * 1024);
    for invalid in [
        serde_json::json!({}),
        serde_json::json!({"sha256_hex":["a".repeat(63)]}),
        serde_json::json!({"sha256_hex":["g".repeat(64)]}),
        serde_json::json!({"sha256_hex":["é".repeat(32)]}),
        serde_json::json!({"range_url":"http://range.example/range"}),
        serde_json::json!({"range_url":"https://user@range.example/range"}),
        serde_json::json!({"range_url":"https://range.example/range?q=1"}),
        serde_json::json!({"range_url":"https://range.example/range#fragment"}),
        serde_json::json!({"range_url":"https:///"}),
        serde_json::json!({"range_url":"not a URL"}),
        serde_json::json!({"sha256_hex":["a".repeat(64)],"timeout_ms":0}),
        serde_json::json!({"sha256_hex":["a".repeat(64)],"max_response_bytes":0}),
    ] {
        assert!(parse(invalid).unwrap().validate("test").is_err());
    }
    assert!(
        parse(serde_json::json!({"sha256_hex":["a".repeat(64)],"on_unavailable":"ignore"}))
            .is_err()
    );
    let config = parse(
        serde_json::json!({"range_url":"https://range.example/range/", "on_unavailable":"allow",
            "max_retries":2, "retry_delay_ms":0}),
    )
    .unwrap();
    config.validate("test").unwrap();
    let screening = config.screening.unwrap();
    assert_eq!(screening.on_unavailable, ScreeningUnavailable::Allow);
    assert_eq!(screening.max_retries, 2);
    assert_eq!(screening.retry_delay_ms, 0);
}

#[test]
fn iga_access_request_audience_requires_a_registered_realm_permission() {
    let mut config = minimal_config();
    assert!(
        config.realms[0]
            .protocols
            .iga
            .access_request_audience
            .is_none()
    );
    config.validate().unwrap();
    let protocols: ProtocolConfig = serde_json::from_value(serde_json::json!({
        "iga": {"access_request_audience": "api://iga"},
        "oauth": {"resource_servers": [{"audience": "api://iga", "scopes": ["qid_iga_access_request"]}]}
    })).unwrap();
    config.realms[0].protocols = protocols;
    config.validate().unwrap();
    let plan = crate::plan::RuntimePlan::from_config(&config).unwrap();
    assert_eq!(
        plan.realms[0].iga_access_request_audience.as_deref(),
        Some("api://iga")
    );

    for target in [
        "",
        " ",
        "api://iga ",
        "api://iga\n",
        "api://iga\u{0000}",
        "api://unknown",
    ] {
        let mut invalid = config.clone();
        invalid.realms[0].protocols.iga.access_request_audience = Some(target.into());
        assert!(
            invalid
                .validate()
                .unwrap_err()
                .message()
                .contains("IGA access_request_audience"),
            "{target:?}"
        );
        assert!(crate::plan::RuntimePlan::from_config(&invalid).is_err());
    }
    // A registration in a different realm cannot authorize the target realm.
    let mut other_realm = config.realms[0].clone();
    other_realm.id = "other".into();
    config.realms.push(other_realm);
    config.realms[0].protocols.oauth.resource_servers.clear();
    assert!(config.validate().is_err());
    assert!(crate::plan::RuntimePlan::from_config(&config).is_err());
    config.realms[0].protocols.oauth.resource_servers =
        config.realms[1].protocols.oauth.resource_servers.clone();
    for scopes in [
        vec![],
        vec!["qid_identity".into()],
        vec!["qid_iga_access_request_extra".into()],
    ] {
        config.realms[0].protocols.oauth.resource_servers[0].scopes = scopes;
        assert!(config.validate().is_err());
        assert!(crate::plan::RuntimePlan::from_config(&config).is_err());
    }
}

#[test]
fn workload_ca_references_are_exact_local_dedicated_and_realm_owned() {
    let mut config = minimal_config();
    config.profile = DeploymentProfile::Workload;
    config.realms[0].protocols.workload.workload_ca_key_ref = Some("ca".into());
    config.crypto.keyrings = vec![
        KeyringConfig {
            name: "ca".into(),
            realm_id: Some(config.realms[0].id.clone()),
            purposes: vec!["other:workload_ca".into()],
            signer: Default::default(),
            rotation: Default::default(),
        },
        KeyringConfig {
            name: "jwt".into(),
            realm_id: None,
            purposes: vec!["oidc_token".into()],
            signer: Default::default(),
            rotation: Default::default(),
        },
    ];
    config.validate_workload_ca_keys().unwrap();
    for reference in [
        None,
        Some(""),
        Some("CA"),
        Some(" ca"),
        Some("ca "),
        Some("missing"),
    ] {
        let mut invalid = config.clone();
        invalid.realms[0].protocols.workload.workload_ca_key_ref = reference.map(str::to_string);
        assert!(
            invalid.validate_workload_ca_keys().is_err(),
            "{reference:?}"
        );
    }
    for owner in [None, Some("foreign")] {
        let mut invalid = config.clone();
        invalid.crypto.keyrings[0].realm_id = owner.map(str::to_string);
        assert!(invalid.validate_workload_ca_keys().is_err());
    }
    for purposes in [
        vec![],
        vec!["oidc_token".into()],
        vec!["other:workload_ca".into(), "oidc_token".into()],
    ] {
        let mut invalid = config.clone();
        invalid.crypto.keyrings[0].purposes = purposes;
        assert!(invalid.validate_workload_ca_keys().is_err());
    }
    for signer in ["kms", "hsm", "pkcs11"] {
        let mut invalid = config.clone();
        invalid.crypto.keyrings[0].signer.r#type = signer.into();
        assert!(invalid.validate_workload_ca_keys().is_err());
    }
    let mut invalid = config.clone();
    invalid.crypto.default_alg = "EdDSA".into();
    assert!(invalid.validate_workload_ca_keys().is_err());
    let mut invalid = config.clone();
    invalid
        .crypto
        .keyrings
        .push(config.crypto.keyrings[0].clone());
    assert!(invalid.validate_workload_ca_keys().is_err());
    let mut invalid = config.clone();
    invalid.realms.push(config.realms[0].clone());
    invalid.realms[1].id = "foreign".into();
    assert!(invalid.validate_workload_ca_keys().is_err());
    let mut invalid = config.clone();
    invalid.crypto.keyrings.pop();
    assert!(invalid.validate_workload_ca_keys().is_err());
    let mut invalid = config.clone();
    invalid.crypto.keyrings[1].realm_id = Some(config.realms[0].id.clone());
    assert!(invalid.validate_workload_ca_keys().is_err());
    let mut orphan = config.clone();
    orphan.crypto.keyrings.push(KeyringConfig {
        name: "unused-ca".into(),
        realm_id: Some(config.realms[0].id.clone()),
        purposes: vec!["other:workload_ca".into()],
        signer: Default::default(),
        rotation: Default::default(),
    });
    assert!(orphan.validate_workload_ca_keys().is_err());
    let mut dormant = minimal_config();
    dormant.crypto.keyrings.push(KeyringConfig {
        name: "unused-ca".into(),
        realm_id: Some(dormant.realms[0].id.clone()),
        purposes: vec!["other:workload_ca".into()],
        signer: Default::default(),
        rotation: Default::default(),
    });
    assert!(dormant.validate_workload_ca_keys().is_err());
    config.realms.push(config.realms[0].clone());
    config.realms[1].id = "second".into();
    config.realms[1].protocols.workload.workload_ca_key_ref = Some("second-ca".into());
    let mut ca = config.crypto.keyrings[0].clone();
    ca.name = "second-ca".into();
    ca.realm_id = Some("second".into());
    config.crypto.keyrings.push(ca);
    config.validate_workload_ca_keys().unwrap();
}

#[test]
fn workload_csr_limit_defaults_and_overrides() {
    let default = WorkloadProtocolConfig::default();
    assert_eq!(default.max_csr_bytes, 16_384);
    let omitted: WorkloadProtocolConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(omitted, default);
    assert_eq!(ProtocolConfig::default().workload.max_csr_bytes, 16_384);
    for limit in [0, 473, 32_768] {
        let parsed: WorkloadProtocolConfig =
            serde_json::from_value(serde_json::json!({"max_csr_bytes": limit})).unwrap();
        assert_eq!(parsed.max_csr_bytes, limit);
    }
    assert!(serde_json::from_str::<WorkloadProtocolConfig>(r#"{"max_csr_bytes":-1}"#).is_err());
}

#[test]
fn config_rejects_multiple_enforcing_policy_bundles() {
    let mut config = minimal_config();
    config.realms[0].policy.bundles = vec![
        PolicyBundleConfig {
            name: "enforced".into(),
            source: "file://policies/enforced.json".into(),
            mode: "enforce".into(),
        },
        PolicyBundleConfig {
            name: "observed".into(),
            source: "file://policies/observed.json".into(),
            mode: "monitor".into(),
        },
    ];
    config
        .validate()
        .expect("one enforcing bundle and a non-enforcing bundle are unambiguous");

    config.realms[0].policy.bundles[1].mode = "enforce".into();
    assert!(matches!(
        config.validate(),
        Err(QidError::Config { message })
            if message.contains("corp") && message.contains("multiple enforcing policy bundles")
    ));
}

#[test]
fn workload_lifetime_defaults_and_partial_overrides() {
    let defaults = WorkloadProtocolConfig::default();
    assert_eq!(
        serde_json::from_str::<WorkloadProtocolConfig>("{}").unwrap(),
        defaults
    );
    assert_eq!(
        (
            defaults.jwt_svid_default_ttl_seconds,
            defaults.jwt_svid_min_ttl_seconds,
            defaults.jwt_svid_max_ttl_seconds
        ),
        (3600, 0, 86_400)
    );
    assert_eq!(
        (
            defaults.x509_default_ttl_seconds,
            defaults.x509_min_ttl_seconds,
            defaults.x509_max_ttl_seconds
        ),
        (3600, 60, 3600)
    );
    for (field, value) in [
        ("jwt_svid_default_ttl_seconds", 7200),
        ("jwt_svid_min_ttl_seconds", 1),
        ("jwt_svid_max_ttl_seconds", u64::MAX),
        ("x509_default_ttl_seconds", 120),
        ("x509_min_ttl_seconds", 1),
        (
            "x509_max_ttl_seconds",
            crate::models::WorkloadCertificate::MAX_LIFETIME_SECONDS,
        ),
    ] {
        let mut config = minimal_config();
        let policy: WorkloadProtocolConfig =
            serde_json::from_value(serde_json::json!({field: value})).unwrap();
        let mut expected = defaults.clone();
        match field {
            "jwt_svid_default_ttl_seconds" => expected.jwt_svid_default_ttl_seconds = value,
            "jwt_svid_min_ttl_seconds" => expected.jwt_svid_min_ttl_seconds = value,
            "jwt_svid_max_ttl_seconds" => expected.jwt_svid_max_ttl_seconds = value,
            "x509_default_ttl_seconds" => expected.x509_default_ttl_seconds = value,
            "x509_min_ttl_seconds" => expected.x509_min_ttl_seconds = value,
            _ => expected.x509_max_ttl_seconds = value,
        }
        assert_eq!(policy, expected);
        config.realms[0].protocols.workload = policy;
        config.validate().unwrap();
    }
}

#[test]
fn workload_lifetime_invalid_bounds_rejected_at_config_validation() {
    for kind in ["jwt_svid", "x509"] {
        for (default, min, max) in [(0, 0, 1), (10, 11, 20), (10, 1, 9), (10, 20, 1), (1, 0, 0)] {
            let mut config = minimal_config();
            config.realms[0].protocols.workload = serde_json::from_value(serde_json::json!({
                format!("{kind}_default_ttl_seconds"): default,
                format!("{kind}_min_ttl_seconds"): min,
                format!("{kind}_max_ttl_seconds"): max,
            }))
            .unwrap();
            assert!(
                matches!(config.validate(), Err(QidError::Config { message }) if message.contains(kind) && message.contains("corp"))
            );
        }
    }
    let mut config = minimal_config();
    config.realms[0].protocols.workload.x509_min_ttl_seconds = 0;
    assert!(config.validate().is_err());
    config.realms[0].protocols.workload.x509_min_ttl_seconds = 60;
    config.realms[0].protocols.workload.x509_max_ttl_seconds =
        crate::models::WorkloadCertificate::MAX_LIFETIME_SECONDS + 1;
    assert!(config.validate().is_err());
    config.realms[0].protocols.workload.x509_max_ttl_seconds =
        crate::models::WorkloadCertificate::MAX_LIFETIME_SECONDS;
    config.validate().unwrap();
    config.realms[0].protocols.workload.x509_min_ttl_seconds = 3600;
    config.realms[0].protocols.workload.jwt_svid_min_ttl_seconds = 3600;
    config.realms[0].protocols.workload.jwt_svid_max_ttl_seconds = 3600;
    config.validate().unwrap();
}

#[test]
fn workload_est_is_opt_in_and_requires_existing_capabilities() {
    let defaults: WorkloadProtocolConfig = serde_json::from_str("{}").unwrap();
    assert!(!defaults.est);
    assert!(!ProtocolConfig::default().workload.est);
    let enabled: WorkloadProtocolConfig = serde_json::from_value(serde_json::json!({
        "est": true, "jwt_svid": true, "x509_svid": true, "workload_ca_key_ref": "ca"
    }))
    .unwrap();
    assert!(enabled.est);
    enabled.validate("test").unwrap();
    for missing in ["jwt", "x509", "ca", "blank"] {
        let mut invalid = enabled.clone();
        match missing {
            "jwt" => invalid.jwt_svid = false,
            "x509" => invalid.x509_svid = false,
            "ca" => invalid.workload_ca_key_ref = None,
            _ => invalid.workload_ca_key_ref = Some(" ".into()),
        }
        assert!(invalid.validate("test").is_err());
    }
    assert!(serde_json::from_str::<WorkloadProtocolConfig>(r#"{"est":"true"}"#).is_err());
}

#[test]
fn sms_recovery_defaults_validation_and_redaction() {
    let mut config = minimal_config();
    let policy = &config.realms[0].authentication.mfa.sms_recovery;
    assert!(!policy.enabled && policy.destinations.is_empty());
    assert_eq!(
        (
            policy.ttl_seconds,
            policy.max_attempts,
            policy.max_issuances_per_window,
            policy.issuance_window_seconds
        ),
        (300, 5, 5, 3600)
    );
    config.realms[0].authentication.mfa.sms_recovery.enabled = true;
    assert!(config.validate().is_err());
    config.server.notification = Some(ServerNotificationConfig {
        provider: "https://notify.example.com".into(),
        timeout_seconds: 10,
        max_concurrent_deliveries: 1,
    });
    config.realms[0]
        .authentication
        .mfa
        .sms_recovery
        .destinations
        .insert("account".into(), "+12025550123".into());
    config.validate().unwrap();
    let plan = crate::plan::RuntimePlan::from_config(&config).unwrap();
    assert!(plan.realms[0].mfa.sms_recovery.enabled);
    assert!(
        !format!("{:?}", config.realms[0].authentication.mfa.sms_recovery).contains("+12025550123")
    );
    for base in [
        "http://id.example.com",
        "https://u:p@id.example.com",
        "https://id.example.com/?query",
        "https://id.example.com/#fragment",
    ] {
        let mut bad = config.clone();
        bad.server.public_base_url = base.into();
        assert!(bad.validate().is_err());
    }
    for case in [
        "ttl",
        "attempts",
        "issuances",
        "window",
        "destination",
        "cookie",
    ] {
        let mut bad = config.clone();
        let p = &mut bad.realms[0].authentication.mfa.sms_recovery;
        match case {
            "ttl" => p.ttl_seconds = 0,
            "attempts" => p.max_attempts = 0,
            "issuances" => p.max_issuances_per_window = 0,
            "window" => p.issuance_window_seconds = 86401,
            "destination" => {
                p.destinations
                    .insert("account".into(), "request supplied phone".into());
            }
            _ => {
                bad.realms[0].sessions.browser.cookie_name = SMS_RECOVERY_BINDING_COOKIE_NAME.into()
            }
        }
        assert!(bad.validate().is_err());
    }
    let mfa: MfaConfig =
        serde_json::from_value(serde_json::json!({"sms_recovery":{"enabled":true}})).unwrap();
    assert!(mfa.sms_recovery.enabled);
    assert!(
        serde_json::from_value::<MfaConfig>(
            serde_json::json!({"sms_recovery":{"phone":"untrusted"}})
        )
        .is_err()
    );
}

#[test]
fn callback_destinations_are_validated_when_loading_config() {
    let path = temp_config_path("callbacks.yaml");
    let base = "server:\n  listen: '127.0.0.1:8443'\n  public_base_url: 'https://id.example.com'\nrealms:\n  - id: corp\n    issuer: 'https://id.example.com'\n";
    std::fs::write(&path, base).unwrap();
    let config = QidConfig::from_file(path.to_str().unwrap()).unwrap();
    assert!(
        config.realms[0]
            .client_callback_destinations
            .backchannel_logout
            .authorize("https://id.example.com")
            .is_err()
    );
    for policy in [
        "      unknown: {}\n",
        "      backchannel_logout:\n        unknown: []\n",
        "      backchannel_logout:\n        allowed_origins: ['https://example.com/path']\n",
        "      ciba_notification:\n        allowed_origins: ['https://*.example.com']\n",
    ] {
        std::fs::write(
            &path,
            format!("{base}    client_callback_destinations:\n{policy}"),
        )
        .unwrap();
        assert!(matches!(
            QidConfig::from_file(path.to_str().unwrap()),
            Err(QidError::Config { .. })
        ));
    }
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn yaml_provider_preserves_serde_yaml_scalar_semantics() {
    // The YAML provider replaces serde_yaml 0.9. Operator configs must keep the
    // same accepted semantics; pin the scalar forms that differ between YAML
    // 1.1 defaults and serde_yaml's YAML 1.2-style inference.
    let value: serde_json::Value = Figment::from(Yaml::string(
        "word: yes\nneg: no\non: on\noff: off\nleading: 012\nunder: 1_000\nnan: .nan\ninf: .inf\ndup: 1\ndup: 2\n",
    ))
    .extract()
    .expect("extract untyped yaml");
    assert_eq!(value["word"], serde_json::json!("yes"));
    assert_eq!(value["neg"], serde_json::json!("no"));
    assert_eq!(value["on"], serde_json::json!("on"));
    assert_eq!(value["off"], serde_json::json!("off"));
    assert_eq!(value["leading"], serde_json::json!("012"));
    assert_eq!(value["under"], serde_json::json!("1_000"));
    assert_eq!(value["nan"], serde_json::Value::Null);
    assert_eq!(value["inf"], serde_json::Value::Null);
    assert_eq!(value["dup"], serde_json::json!(2));
}

fn config_with_provider_kind(kind: &str) -> QidConfig {
    let mut config = minimal_config();
    config.realms[0].protocols.federation.inbound_providers = vec![InboundProviderConfig {
        id: "provider".to_string(),
        kind: kind.to_string(),
        issuer: "https://idp.example.com".to_string(),
        authorization_response_iss_parameter_supported: false,
        enabled: false,
        domains: Vec::new(),
        social_provider: None,
        client_id: None,
        client_secret: None,
        token_url: None,
        userinfo_url: None,
        jit_provisioning: false,
        account_linking: false,
        claim_mappings: Vec::new(),
        jwks_uri: None,
        jwks: None,
        saml_signing_certificates: Vec::new(),
        trusted_audiences: Vec::new(),
        kerberos_spnego: None,
    }];
    config
}

fn config_with_kerberos_provider(kind: &str, kerberos: Option<KerberosSpnegoConfig>) -> QidConfig {
    let mut config = config_with_provider_kind(kind);
    let provider = &mut config.realms[0].protocols.federation.inbound_providers[0];
    provider.enabled = true;
    provider.kerberos_spnego = kerberos;
    config
}

fn kerberos_spnego_config() -> KerberosSpnegoConfig {
    KerberosSpnegoConfig {
        realm: "CORP.EXAMPLE".to_string(),
        service_principal: "HTTP/id.example.com@CORP.EXAMPLE".to_string(),
        keytab_path: "/etc/qid/corp.keytab".to_string(),
    }
}

#[test]
fn inbound_provider_unknown_kind_is_rejected_at_config_load() {
    for kind in [
        "oidc",
        "saml",
        "entra_id",
        "entra",
        "azure_ad",
        "google_workspace",
        "google",
        "okta",
        "ldap_ad_bind",
        "ldap",
        "social",
        "kerberos",
        "kerberos_spnego",
    ] {
        config_with_provider_kind(kind)
            .validate()
            .unwrap_or_else(|err| {
                panic!(
                    "known inbound provider kind {kind} must be accepted: {}",
                    err.message()
                )
            });
    }

    for kind in ["bogus", ""] {
        let err = config_with_provider_kind(kind).validate().unwrap_err();
        assert!(
            err.message().contains("unknown kind"),
            "unexpected validation result for kind {kind}: {}",
            err.message()
        );
    }
}

#[test]
fn inbound_kerberos_provider_accepts_keytab_path_reference() {
    for kind in ["kerberos_spnego", "kerberos"] {
        config_with_kerberos_provider(kind, Some(kerberos_spnego_config()))
            .validate()
            .unwrap_or_else(|err| {
                panic!(
                    "enabled inbound Kerberos provider must be accepted: {}",
                    err.message()
                )
            });
    }
}

#[test]
fn inbound_kerberos_provider_rejects_missing_or_blank_settings_at_config_load() {
    let cases = [
        (None, "requires kerberos_spnego configuration"),
        (
            Some(KerberosSpnegoConfig {
                realm: " ".to_string(),
                ..kerberos_spnego_config()
            }),
            "requires a non-empty realm",
        ),
        (
            Some(KerberosSpnegoConfig {
                service_principal: "\t".to_string(),
                ..kerberos_spnego_config()
            }),
            "requires a non-empty service principal",
        ),
        (
            Some(KerberosSpnegoConfig {
                keytab_path: String::new(),
                ..kerberos_spnego_config()
            }),
            "requires a non-empty keytab_path",
        ),
    ];
    for (kerberos, expected) in cases {
        let err = config_with_kerberos_provider("kerberos_spnego", kerberos)
            .validate()
            .unwrap_err();
        assert!(
            err.message().contains("inbound Kerberos provider") && err.message().contains(expected),
            "unexpected validation result: {}",
            err.message()
        );
    }
}

#[test]
fn inbound_kerberos_provider_rejects_trusted_audiences() {
    let mut config =
        config_with_kerberos_provider("kerberos_spnego", Some(kerberos_spnego_config()));
    config.realms[0].protocols.federation.inbound_providers[0].trusted_audiences =
        vec!["legacy-audience".to_string()];
    let err = config.validate().unwrap_err();
    assert!(
        err.message()
            .contains("trusted_audiences only for OIDC ID-token providers"),
        "unexpected validation result: {}",
        err.message()
    );
}

#[test]
fn inbound_kerberos_provider_rejects_inline_key_material() {
    for key_field in ["service_key", "service_key_b64"] {
        let mut kerberos = serde_json::json!({
            "realm": "CORP.EXAMPLE",
            "service_principal": "HTTP/id.example.com@CORP.EXAMPLE",
            "keytab_path": "/etc/qid/corp.keytab",
        });
        kerberos
            .as_object_mut()
            .unwrap()
            .insert(key_field.to_string(), serde_json::json!("placeholder"));
        let result: Result<InboundProviderConfig, _> = serde_json::from_value(serde_json::json!({
            "id": "corp-kerberos",
            "kind": "kerberos_spnego",
            "issuer": "https://idp.example.com",
            "kerberos_spnego": kerberos,
        }));
        assert!(
            result.is_err(),
            "inline key field {key_field} must be rejected by the keytab-reference config"
        );
    }
}

#[test]
fn public_url_scheme_falls_back_to_https() {
    assert_eq!(public_url_scheme("http://localhost:8080"), "http");
    for url in [
        "https://id.example.com",
        "ftp://id.example.com",
        "not a url",
        "",
    ] {
        assert_eq!(public_url_scheme(url), "https", "url {url}");
    }
}

#[test]
fn inbound_provider_issuer_uniqueness_matches_kinds_case_insensitively() {
    let config = config_with_two_inbound_providers("OIDC", "Social");
    let providers = &config.realms[0].protocols.federation.inbound_providers;
    validate_inbound_provider_issuer_uniqueness("corp", providers)
        .unwrap_or_else(|err| panic!("unconfigured endpoints must match: {}", err.message()));

    let mut conflict = providers.clone();
    conflict[1].token_url = Some("https://other.example.com/token".to_string());
    let message = validate_inbound_provider_issuer_uniqueness("corp", &conflict)
        .unwrap_err()
        .message()
        .to_string();
    assert!(
        message.contains("registration-a") && message.contains("registration-b"),
        "case-insensitive kinds must still be checked: {message}"
    );
}

fn config_with_two_inbound_providers(first_kind: &str, second_kind: &str) -> QidConfig {
    let mut config = config_with_provider_kind(first_kind);
    let providers = &mut config.realms[0].protocols.federation.inbound_providers;
    providers[0].id = "registration-a".to_string();
    providers[0].enabled = true;
    let mut second = providers[0].clone();
    second.id = "registration-b".to_string();
    second.kind = second_kind.to_string();
    providers.push(second);
    config
}

#[test]
fn inbound_providers_sharing_issuer_with_different_upstream_endpoints_are_rejected() {
    for (first_kind, second_kind) in [
        ("oidc", "oidc"),
        ("oidc", "social"),
        ("social", "oidc"),
        ("oidc", "entra_id"),
        ("google_workspace", "okta"),
        ("entra_id", "entra"),
        ("entra_id", "azure_ad"),
        ("entra_id", "google"),
        ("google_workspace", "google"),
    ] {
        let mut config = config_with_two_inbound_providers(first_kind, second_kind);
        for provider in &mut config.realms[0].protocols.federation.inbound_providers {
            provider.token_url = Some("https://idp.example.com/token".to_string());
            provider.userinfo_url = Some("https://idp.example.com/userinfo".to_string());
            provider.jwks_uri = Some("https://idp.example.com/jwks".to_string());
            provider.jwks = Some(serde_json::json!({"keys": [{"kty": "RSA"}]}));
        }
        for case in 0..5 {
            let mut conflict = config.clone();
            let second = &mut conflict.realms[0].protocols.federation.inbound_providers[1];
            match case {
                0 => second.token_url = Some("https://idp.example.com/token-v2".to_string()),
                1 => second.userinfo_url = Some("https://idp.example.com/userinfo-v2".to_string()),
                2 => second.jwks_uri = Some("https://idp.example.com/jwks-v2".to_string()),
                3 => second.jwks_uri = None,
                4 => second.token_url = None,
                _ => unreachable!(),
            }
            let message = conflict.validate().unwrap_err().message().to_string();
            assert!(
                message.contains("realm corp")
                    && message.contains("registration-a")
                    && message.contains("registration-b")
                    && message.contains("https://idp.example.com")
                    && message.contains("different upstream endpoints"),
                "unexpected validation result for {first_kind}/{second_kind} case {case}: {message}"
            );
        }
    }
}

#[test]
fn inbound_providers_sharing_issuer_and_upstream_endpoints_allow_multiple_registrations() {
    for kind in [
        "oidc",
        "social",
        "entra_id",
        "entra",
        "azure_ad",
        "google_workspace",
        "google",
        "okta",
    ] {
        let mut config = config_with_two_inbound_providers(kind, kind);
        let providers = &mut config.realms[0].protocols.federation.inbound_providers;
        for (index, provider) in providers.iter_mut().enumerate() {
            provider.client_id = Some(format!("client-{index}"));
            provider.client_secret = Some(format!("secret-{index}"));
            provider.domains = vec![format!("app{index}.example.com")];
            provider.token_url = Some("https://idp.example.com/token".to_string());
            provider.userinfo_url = Some("https://idp.example.com/userinfo".to_string());
            provider.jwks_uri = Some("https://idp.example.com/jwks".to_string());
        }
        let first_keys = serde_json::json!({
            "keys": [
                {"kty": "RSA", "kid": "key-a"},
                {"kty": "EC", "kid": "key-b"}
            ]
        });
        let reordered_keys = serde_json::json!({
            "keys": [
                {"kid": "key-b", "kty": "EC"},
                {"kid": "key-a", "kty": "RSA"}
            ]
        });
        providers[0].jwks = Some(first_keys);
        providers[1].jwks = Some(reordered_keys);
        providers[1].social_provider = Some("google".to_string());
        config.validate().unwrap_or_else(|err| {
            panic!(
                "multiple registrations at one upstream must be accepted: {}",
                err.message()
            )
        });
    }
}

#[test]
fn disabled_inbound_provider_is_exempt_from_issuer_endpoint_uniqueness() {
    let mut config = config_with_two_inbound_providers("oidc", "social");
    let providers = &mut config.realms[0].protocols.federation.inbound_providers;
    providers[0].token_url = Some("https://idp.example.com/token".to_string());
    providers[1].enabled = false;
    providers[1].token_url = Some("https://other.example.com/token".to_string());
    config
        .validate()
        .unwrap_or_else(|err| panic!("disabled provider must not conflict: {}", err.message()));

    config.realms[0].protocols.federation.inbound_providers[1].enabled = true;
    let message = config.validate().unwrap_err().message().to_string();
    assert!(
        message.contains("different upstream endpoints"),
        "enabled provider must conflict: {message}"
    );
}

#[test]
fn enabled_social_providers_allow_shared_aliases() {
    for (first_alias, second_alias) in [("Google", "google"), ("google", "google")] {
        let mut config = config_with_two_inbound_providers("social", "social");
        let providers = &mut config.realms[0].protocols.federation.inbound_providers;
        providers[0].social_provider = Some(first_alias.to_string());
        providers[1].social_provider = Some(second_alias.to_string());
        config.validate().unwrap_or_else(|err| {
            panic!(
                "aliases {first_alias}/{second_alias} may share a callback path: {}",
                err.message()
            )
        });
    }
}

#[test]
fn inbound_provider_issuer_uniqueness_ignores_non_front_channel_kinds() {
    for kind in ["saml", "ldap"] {
        let mut config = config_with_two_inbound_providers(kind, kind);
        for provider in &mut config.realms[0].protocols.federation.inbound_providers {
            provider.saml_signing_certificates = vec!["dummy-certificate".to_string()];
            provider.token_url = Some("https://idp.example.com/token".to_string());
        }
        config.realms[0].protocols.federation.inbound_providers[1].token_url =
            Some("https://idp.example.com/token-v2".to_string());
        config.validate().unwrap_or_else(|err| {
            panic!(
                "{kind} providers are outside RFC 9207 front-channel validation: {}",
                err.message()
            )
        });
    }
}

#[test]
fn front_channel_inbound_provider_accepts_https_issuer_with_path() {
    for kind in [
        "oidc",
        "entra_id",
        "entra",
        "azure_ad",
        "google_workspace",
        "google",
        "okta",
        "social",
    ] {
        let mut config = config_with_provider_kind(kind);
        let provider = &mut config.realms[0].protocols.federation.inbound_providers[0];
        provider.enabled = true;
        provider.issuer = "https://login.example.com/realms/partner".to_string();
        config.validate().unwrap_or_else(|err| {
            panic!(
                "front-channel provider {kind} must accept an HTTPS issuer with a path: {}",
                err.message()
            )
        });
    }
}

#[test]
fn front_channel_inbound_provider_accepts_uppercase_https_scheme() {
    let mut config = config_with_provider_kind("oidc");
    let provider = &mut config.realms[0].protocols.federation.inbound_providers[0];
    provider.enabled = true;
    provider.issuer = "HTTPS://login.example.com/realms/partner".to_string();
    config
        .validate()
        .unwrap_or_else(|err| panic!("scheme names are case-insensitive: {}", err.message()));
}

#[test]
fn front_channel_inbound_provider_rejects_unsafe_issuer_syntax() {
    for issuer in [
        "http://login.example.com/realms/partner",
        "not-a-valid-url",
        "https://:443/path",
        "https://login.example.com/realms/partner?tenant=corp",
        "https://login.example.com/realms/partner#section",
        "https://user@login.example.com/realms/partner",
        "https://user:password@login.example.com/realms/partner",
        "https://login.example.com/realms/part ner",
        "https://login.example.com/realms/part\tner",
        "https:login.example.com/realms/partner",
        "https://login.example.com/realms/part<ner>",
        "https://@login.example.com/realms/partner",
        "https://:@login.example.com/realms/partner",
        "https://login.example.com:/realms/partner",
        "https://login.example.com/a/../issuer",
        "https://login.example.com/realms/partner/%2e%2e/x",
        "https://login.example.com/realms/partner%",
        "https://login.example.com/realms/partner%2",
        "https://login.example.com/realms/part%2Gner",
    ] {
        let mut config = config_with_provider_kind("oidc");
        let provider = &mut config.realms[0].protocols.federation.inbound_providers[0];
        provider.enabled = true;
        provider.issuer = issuer.to_string();
        let message = config.validate().unwrap_err().message().to_string();
        assert!(
            message.contains("realm corp inbound provider provider")
                && message.contains("issuer must be an exact ASCII HTTPS URL")
                && message.contains("well-formed percent escapes")
                && message.contains("no dot-path segments"),
            "issuer {issuer} must be rejected with a realm/provider-specific message: {message}"
        );
    }
}

#[test]
fn front_channel_inbound_provider_accepts_valid_percent_escapes() {
    let mut config = config_with_provider_kind("oidc");
    let provider = &mut config.realms[0].protocols.federation.inbound_providers[0];
    provider.enabled = true;
    provider.issuer = "https://login.example.com/realms/part%20ner".to_string();
    config
        .validate()
        .unwrap_or_else(|err| panic!("valid percent escape must be preserved: {}", err.message()));
}

#[test]
fn disabled_and_non_front_channel_providers_are_exempt_from_issuer_syntax() {
    let mut config = config_with_provider_kind("oidc");
    config.realms[0].protocols.federation.inbound_providers[0].issuer =
        "not-a-valid-url".to_string();
    config
        .validate()
        .unwrap_or_else(|err| panic!("disabled provider must be exempt: {}", err.message()));

    let mut config = config_with_provider_kind("saml");
    let provider = &mut config.realms[0].protocols.federation.inbound_providers[0];
    provider.enabled = true;
    provider.issuer = "not-a-valid-url".to_string();
    provider.saml_signing_certificates = vec!["dummy-certificate".to_string()];
    config
        .validate()
        .unwrap_or_else(|err| panic!("SAML provider must be exempt: {}", err.message()));
}

#[test]
fn inbound_provider_ids_must_be_exact_and_callback_safe() {
    for id in ["", " partner", "partner ", ".", "..", "%2e", "%2E%2e"] {
        let mut config = config_with_provider_kind("oidc");
        config.realms[0].protocols.federation.inbound_providers[0].id = id.to_string();
        let message = config.validate().unwrap_err().message().to_string();
        assert!(
            message.contains("realm corp inbound provider")
                && message.contains("canonical provider ids must be exact and callback-safe"),
            "id {id:?} must be rejected with a realm/provider-specific message: {message}"
        );
    }

    for id in ["partner.v2", "partner-1"] {
        let mut config = config_with_provider_kind("oidc");
        config.realms[0].protocols.federation.inbound_providers[0].id = id.to_string();
        config
            .validate()
            .unwrap_or_else(|err| panic!("canonical id {id} must be accepted: {}", err.message()));
    }
}

#[test]
fn enabled_social_provider_aliases_must_be_exact_and_callback_safe() {
    for alias in ["", " google", "google ", ".", "..", "%2e"] {
        let mut config = config_with_provider_kind("social");
        let provider = &mut config.realms[0].protocols.federation.inbound_providers[0];
        provider.enabled = true;
        provider.social_provider = Some(alias.to_string());
        let message = config.validate().unwrap_err().message();
        assert!(
            message.contains("realm corp inbound provider provider")
                && message.contains("social_provider alias must be exact and callback-safe"),
            "alias {alias:?} must be rejected with a realm/provider-specific message: {message}"
        );
    }

    let mut config = config_with_provider_kind("social");
    let provider = &mut config.realms[0].protocols.federation.inbound_providers[0];
    provider.enabled = true;
    provider.social_provider = Some("Google".to_string());
    config
        .validate()
        .unwrap_or_else(|err| panic!("mixed-case alias must be accepted: {}", err.message()));

    for (kind, enabled) in [("social", false), ("oidc", true)] {
        let mut config = config_with_provider_kind(kind);
        let provider = &mut config.realms[0].protocols.federation.inbound_providers[0];
        provider.enabled = enabled;
        provider.social_provider = Some("..".to_string());
        config.validate().unwrap_or_else(|err| {
            panic!(
                "{kind} provider with enabled={enabled} is exempt: {}",
                err.message()
            )
        });
    }
}

#[test]
fn pairwise_subject_secret_requires_32_bytes_and_redacts_debug() {
    let mut config = minimal_config();
    config.realms[0].pairwise_subject_secret = Some(PairwiseSubjectSecret::new("too-short"));
    let message = config.validate().unwrap_err().message();
    assert!(
        message.contains("realm corp")
            && message.contains("pairwise_subject_secret")
            && message.contains("32 bytes")
            && !message.contains("too-short"),
        "validation must name the realm and field without the secret: {message}"
    );

    let secret = "0123456789abcdef0123456789abcdef";
    config.realms[0].pairwise_subject_secret = Some(PairwiseSubjectSecret::new(secret));
    config.validate().expect("32-byte secret is valid");
    let debug = format!("{:?}", config.realms[0]);
    assert!(!debug.contains(secret));
    assert!(debug.contains("redacted"));
}

#[test]
fn pairwise_subject_secret_defaults_to_absent_in_config_files() {
    let secret = "0123456789abcdef0123456789abcdef";
    let path = temp_config_path("pairwise.yaml");
    std::fs::write(
        &path,
        format!(
            r#"
server:
  listen: "127.0.0.1:8443"
  public_base_url: "https://id.example.com"
realms:
  - id: corp
    issuer: "https://id.example.com/realms/corp"
    pairwise_subject_secret: "{secret}"
"#
        ),
    )
    .expect("write config with pairwise secret");
    let parsed = QidConfig::from_file(path.to_str().unwrap()).expect("parse pairwise secret");
    assert_eq!(
        parsed.realms[0]
            .pairwise_subject_secret
            .as_ref()
            .expect("configured secret")
            .as_bytes(),
        secret.as_bytes()
    );

    std::fs::write(
        &path,
        r#"
server:
  listen: "127.0.0.1:8443"
  public_base_url: "https://id.example.com"
realms:
  - id: corp
    issuer: "https://id.example.com/realms/corp"
"#,
    )
    .expect("write config without pairwise secret");
    let parsed = QidConfig::from_file(path.to_str().unwrap()).expect("parse config without secret");
    assert!(parsed.realms[0].pairwise_subject_secret.is_none());
}

#[test]
fn saml_persistent_nameid_samples_have_pairwise_secrets() {
    const PERSISTENT_NAMEID: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let samples = [
        "config/usecases/04-federation-and-sso/saml-idp-service-provider.yaml",
        "config/usecases/04-federation-and-sso/saml-to-oidc-migration.yaml",
        "config/usecases/05-lifecycle-and-provisioning/enterprise-workforce-suite.yaml",
    ];

    for sample in samples {
        let path = root.join(sample);
        let config = QidConfig::from_file(path.to_str().expect("sample path is UTF-8"))
            .unwrap_or_else(|err| panic!("{sample} must load: {err}"));
        let mut realms_checked = 0;
        for realm in &config.realms {
            let persistent = realm.protocols.saml.service_providers.iter().any(|sp| {
                sp.name_id_formats
                    .iter()
                    .any(|format| format == PERSISTENT_NAMEID)
            });
            if !persistent {
                continue;
            }
            realms_checked += 1;
            let secret = realm
                .pairwise_subject_secret
                .as_ref()
                .unwrap_or_else(|| panic!("{sample}: realm {} needs a pairwise secret", realm.id));
            assert!(
                secret.as_bytes().len() >= PAIRWISE_SUBJECT_SECRET_MIN_BYTES,
                "{sample}: realm {} needs a secret of at least {PAIRWISE_SUBJECT_SECRET_MIN_BYTES} bytes",
                realm.id
            );
        }
        assert!(realms_checked > 0, "{sample}: no persistent NameID SP");
    }
}
