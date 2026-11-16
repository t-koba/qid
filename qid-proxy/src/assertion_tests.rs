use super::*;

#[test]
fn test_jti_format() {
    let jti = generate_jti();
    assert!(
        jti.starts_with("qas_"),
        "JTI should start with 'qas_', got: {jti}"
    );
    assert!(jti.len() > 4, "JTI should have content after prefix");
}

#[test]
fn test_now_seconds_positive() {
    let now = qid_core::util::now_seconds();
    assert!(now > 1_700_000_000, "should be a reasonable unix timestamp");
}

#[test]
fn test_assertion_request_deserialize() {
    let json = r#"{"edge":"edge1"}"#;
    let req: AssertionRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.edge.as_deref(), Some("edge1"));
    assert!(req.session.is_none());
}

#[test]
fn assertion_audience_requires_edge_config_audience() {
    let edge = qid_core::config::PepRegistrationConfig {
        name: "egress-main".to_string(),
        audience: None,
        capabilities: Vec::new(),
        assertion: qid_core::config::ProxyAssertionConfig::default(),
        decision: qid_core::config::PepDecisionConfig::default(),
        auth: qid_core::config::PepRegistrationAuthConfig::default(),
    };
    let err = assertion_audience(&edge, &edge.name).unwrap_err();
    assert!(err.message().contains("must declare audience"));

    let edge = qid_core::config::PepRegistrationConfig {
        audience: Some("urn:qid:pep:qpx:corp/egress-main".to_string()),
        ..edge
    };
    assert_eq!(
        assertion_audience(&edge, &edge.name).unwrap(),
        "urn:qid:pep:qpx:corp/egress-main"
    );
}

#[test]
fn assertion_session_validation_fails_closed() {
    let now = 1_800_000_000;
    let session = session(now);

    validate_assertion_session(&session, "corp", now).unwrap();

    let mut revoked = session.clone();
    revoked.revoked = true;
    assert!(validate_assertion_session(&revoked, "corp", now).is_err());

    let mut idle_expired = session.clone();
    idle_expired.idle_expires_at = now;
    assert!(validate_assertion_session(&idle_expired, "corp", now).is_err());

    let mut absolute_expired = session.clone();
    absolute_expired.absolute_expires_at = now;
    assert!(validate_assertion_session(&absolute_expired, "corp", now).is_err());

    let mut other_realm = session;
    other_realm.realm_id = "other".to_string();
    assert!(validate_assertion_session(&other_realm, "corp", now).is_err());
}

#[tokio::test]
async fn assertion_rejects_cached_session_after_regeneration_and_accepts_replacement()
-> anyhow::Result<()> {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use qid_core::models::PasswordCredential;
    use qid_crypto::{ARGON2ID_ALGORITHM, Argon2idParams, hash_password_with_params};
    use tower::ServiceExt;

    let mut config = qid_core::test_helpers::test_config();
    config.realms[0].pep_registrations.enabled = true;
    config.realms[0].pep_registrations.registrations =
        vec![qid_core::config::PepRegistrationConfig {
            name: "egress-main".to_string(),
            audience: Some("urn:qid:pep:qpx:test/egress-main".to_string()),
            capabilities: Vec::new(),
            assertion: qid_core::config::ProxyAssertionConfig::default(),
            decision: qid_core::config::PepDecisionConfig::default(),
            auth: qid_core::config::PepRegistrationAuthConfig::default(),
        }];
    // Exercise session regeneration, not the production Argon2 work factor.
    let cost = &mut config.realms[0].authentication.password.argon2id;
    cost.memory_kib = 8;
    cost.time_cost = 1;
    cost.parallelism = 1;
    let cookie_name = config.realms[0].sessions.browser.cookie_name.clone();
    let login_path = config.server.paths.auth_password.replace(":realm", "test");
    let path = std::env::temp_dir().join(format!(
        "qid-proxy-assertion-regeneration-{}.json",
        ulid::Ulid::new()
    ));
    let repo = Arc::new(qid_storage::FileRepository::new(path.to_str().unwrap()).await?);
    repo.migrate().await?;
    let user = User {
        id: "usr_regeneration".to_string(),
        realm_id: "test".to_string(),
        email: Some("alice@example.com".to_string()),
        email_verified: true,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    repo.create_user(&user).await?;
    repo.store_password_credential(&PasswordCredential {
        user_id: user.id.clone(),
        hash: hash_password_with_params("correct-password", &Argon2idParams::new(8, 1, 1))?,
        algorithm: ARGON2ID_ALGORITHM.to_string(),
    })
    .await?;
    let manager = qid_session::browser::SessionManager::new(repo.clone(), 30, 8);
    let old = manager
        .create("test", &user.id, "pwd", &["pwd".to_string()])
        .await?;
    let state = Arc::new(SharedState::new_with_pep_assertion_signers(
        config,
        repo.clone(),
        Arc::new(qid_crypto::LocalSigner::from_secret(
            "oidc",
            b"test-oidc-key",
        )),
        std::collections::BTreeMap::from([(
            "test".to_string(),
            Arc::new(qid_crypto::LocalSigner::from_secret("pep", b"test-pep-key"))
                as Arc<dyn qid_core::jwt::Signer>,
        )]),
        serde_json::json!({}),
    )?);
    let mut request = AssertionRequest {
        edge: Some("egress-main".to_string()),
        session: Some(old.id.clone()),
        access_token: None,
    };
    // Warm the exact hot cache consumed by assertion issuance with an active session.
    do_issue_assertion(&state, "test", &request, &HeaderMap::new()).await?;
    let cached = state
        .session_cache_get(&old.id)
        .expect("old session cached");
    let cached_session = decode_cached_session(&cached, qid_core::util::now_seconds())?
        .expect("cached session is active");
    validate_assertion_session(&cached_session, "test", qid_core::util::now_seconds())?;

    // The public login route constructs the cache-aware SessionManager and calls
    // create_with_regeneration; the bare constructor above has no invalidator.
    let response = qid_session::auth_routes(&state.config.server.paths)
        .with_state(state.clone())
        .oneshot(
            Request::post(login_path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, format!("{cookie_name}={}", old.id))
                .body(Body::from(
                    serde_json::json!({"email": "alice@example.com", "password": "correct-password"})
                        .to_string(),
                ))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    let replacement_id = body["session"].as_str().expect("replacement session id");
    assert_ne!(replacement_id, old.id);
    assert!(
        repo.get_session(&old.id)
            .await?
            .expect("old session")
            .revoked
    );

    let err = do_issue_assertion(&state, "test", &request, &HeaderMap::new())
        .await
        .expect_err("regenerated session must not issue an assertion from stale cache");
    assert!(matches!(err, QidError::Unauthorized { .. }));
    assert_eq!(state.session_cache_get(&old.id), None);

    request.session = Some(replacement_id.to_string());
    let assertion = do_issue_assertion(&state, "test", &request, &HeaderMap::new()).await?;
    let claims = state
        .pep_assertion_signer("test")
        .unwrap()
        .decode_with_aud(&assertion.assertion, "urn:qid:pep:qpx:test/egress-main")?
        .claims;
    assert_eq!(claims.extra["sid"], replacement_id);
    assert_eq!(claims.sub.as_deref(), Some(user.id.as_str()));
    drop(state);
    drop(manager);
    drop(repo);
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn assertion_extra_claims_use_authoritative_session_auth() {
    let now = 1_800_000_000;
    let user = User {
        id: "usr_01J".to_string(),
        realm_id: "corp".to_string(),
        email: Some("alice@example.com".to_string()),
        email_verified: true,
        display_name: Some("Alice".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    let session = session(now);

    let claims = assertion_extra_claims(
        "corp",
        &user,
        &session,
        AssertionSubjectContext {
            groups: vec!["finance".to_string()],
            roles: vec!["admin".to_string()],
            entitlements: vec!["role:admin".to_string(), "app:erp:read".to_string()],
        },
        AssertionDeviceContext {
            id: Some("dev_01J".to_string()),
            posture: vec!["managed".to_string(), "encrypted".to_string()],
            trust_level: "managed".to_string(),
        },
    );

    assert_eq!(claims["sid"], session.id);
    assert_eq!(claims["tid"], "corp");
    assert_eq!(claims["email"], "alice@example.com");
    assert_eq!(claims["email_verified"], true);
    assert_eq!(claims["auth"]["acr"], "phr");
    assert_eq!(claims["auth"]["amr"][0], "pwd");
    assert_eq!(claims["auth"]["amr"][1], "hwk");
    assert_eq!(claims["auth"]["auth_time"], now - 120);
    assert_eq!(claims["cnf"], serde_json::json!({}));
    assert_eq!(claims["device"]["id"], "dev_01J");
    assert_eq!(claims["device"]["posture"][0], "managed");
    assert_eq!(claims["device"]["trust_level"], "managed");
    assert_eq!(claims["policy_tags"][0], "qid-session");
    assert_eq!(claims["groups"][0], "finance");
    assert_eq!(claims["roles"][0], "admin");
    assert_eq!(claims["entitlements"][0], "role:admin");
    assert_eq!(claims["entitlements"][1], "app:erp:read");
}

#[tokio::test]
async fn assertion_subject_context_scopes_iga_to_tenant_and_scim_to_realm() {
    let now = 1_800_000_000;
    let path = std::env::temp_dir().join(format!(
        "qid-proxy-assertion-tenant-{}.json",
        ulid::Ulid::new()
    ));
    let repo = qid_storage::FileRepository::new(path.to_str().expect("valid temp path"))
        .await
        .expect("file repository");
    repo.migrate().await.expect("file repository migration");
    let tenant_id = qid_core::tenant::TenantId("company".to_string());
    let realm_id = RealmId("employees".to_string());
    repo.create_realm(&tenant_id, &realm_id, "https://employees.example.com", None)
        .await
        .expect("realm tenant binding stored");
    let user = User {
        id: "usr_01J".to_string(),
        realm_id: "employees".to_string(),
        email: None,
        email_verified: false,
        display_name: None,
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    for (id, realm_id, display_name) in [
        ("realm-group", "employees", "finance"),
        ("tenant-group", "company", "wrong-realm"),
    ] {
        repo.create_scim_group(&ScimGroup {
            external_id: None,
            id: id.to_string(),
            realm_id: realm_id.to_string(),
            display_name: display_name.to_string(),
            members_json: serde_json::json!([{"value": "usr_01J"}]),
        })
        .await
        .expect("SCIM group stored");
    }
    for grant in [
        grant_for_tenant(
            "own-role",
            "company",
            "role:admin",
            Some(now + 600),
            false,
            now,
        ),
        grant_for_tenant("own-read", "company", "app:erp:read", None, false, now),
        grant_for_tenant(
            "realm-collision",
            "employees",
            "role:wrong-tenant",
            None,
            false,
            now,
        ),
        grant_for_tenant(
            "own-expired",
            "company",
            "app:expired",
            Some(now),
            false,
            now,
        ),
        grant_for_tenant("own-revoked", "company", "app:revoked", None, true, now),
    ] {
        repo.store_iga_access_grant(&grant)
            .await
            .expect("IGA grant stored");
    }

    let context = assertion_subject_context(&repo, "employees", &user, now)
        .await
        .expect("assertion context");

    assert_eq!(context.groups, vec!["finance"]);
    assert_eq!(context.entitlements, vec!["app:erp:read", "role:admin"]);
    assert_eq!(context.roles, vec!["admin"]);
    drop(repo);
    std::fs::remove_file(path).expect("remove test repository");
}

#[test]
fn assertion_subject_context_helpers_extract_groups_entitlements_and_roles() {
    let now = 1_800_000_000;
    let user = User {
        id: "usr_01J".to_string(),
        realm_id: "corp".to_string(),
        email: Some("alice@example.com".to_string()),
        email_verified: true,
        display_name: Some("Alice".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    let groups = vec![
        ScimGroup {
            external_id: None,
            id: "group-1".to_string(),
            realm_id: "corp".to_string(),
            display_name: "finance".to_string(),
            members_json: serde_json::json!([
                {"value": "usr_01J", "display": "Alice"}
            ]),
        },
        ScimGroup {
            external_id: None,
            id: "group-2".to_string(),
            realm_id: "corp".to_string(),
            display_name: "email-match".to_string(),
            members_json: serde_json::json!([
                {"display": "alice@example.com"}
            ]),
        },
        ScimGroup {
            external_id: None,
            id: "group-3".to_string(),
            realm_id: "corp".to_string(),
            display_name: "other".to_string(),
            members_json: serde_json::json!([
                {"value": "usr_other"}
            ]),
        },
    ];

    assert_eq!(
        scim_group_names_for_user(groups, &user),
        vec!["email-match".to_string(), "finance".to_string()]
    );

    let entitlements = active_entitlements(
        vec![
            grant("grant-1", "app:erp:read", None, false, now),
            grant("grant-2", "role:admin", Some(now + 600), false, now),
            grant("grant-3", "app:expired", Some(now), false, now),
            grant("grant-4", "app:revoked", None, true, now),
            grant("grant-5", "app:erp:read", None, false, now),
        ],
        now,
    );
    assert_eq!(
        entitlements,
        vec!["app:erp:read".to_string(), "role:admin".to_string()]
    );
    assert_eq!(
        role_claims_from_entitlements(&entitlements),
        vec!["admin".to_string()]
    );
}

#[tokio::test]
async fn assertion_issuance_requires_dedicated_pep_signer() {
    let mut config = qid_core::test_helpers::test_config();
    config.realms[0].pep_registrations.enabled = true;
    config.realms[0].pep_registrations.registrations =
        vec![qid_core::config::PepRegistrationConfig {
            name: "egress-main".to_string(),
            audience: Some("urn:qid:pep:qpx:test/egress-main".to_string()),
            capabilities: Vec::new(),
            assertion: qid_core::config::ProxyAssertionConfig::default(),
            decision: qid_core::config::PepDecisionConfig::default(),
            auth: qid_core::config::PepRegistrationAuthConfig::default(),
        }];
    let path = std::env::temp_dir().join(format!("qid-proxy-assertion-{}.json", ulid::Ulid::new()));
    let repo = qid_storage::FileRepository::new(path.to_str().expect("valid temp path"))
        .await
        .expect("file repository");
    repo.migrate().await.expect("file repository migration");
    let now = qid_core::util::now_seconds();
    let user = User {
        id: "usr_qpx_missing_signer".to_string(),
        realm_id: "test".to_string(),
        email: Some("alice@example.com".to_string()),
        email_verified: true,
        display_name: Some("Alice".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    repo.create_user(&user).await.expect("user created");
    repo.create_session(&Session {
        id: "sess_qpx_missing_signer".to_string(),
        realm_id: "test".to_string(),
        user_id: user.id.clone(),
        auth_time: now - 30,
        acr: Some("urn:qid:acr:password".to_string()),
        amr: vec!["pwd".to_string()],
        idle_expires_at: now + 300,
        absolute_expires_at: now + 3_600,
        revoked: false,
        created_at: now - 30,
        cnf: None,
    })
    .await
    .expect("session created");

    let signer = Arc::new(qid_crypto::LocalSigner::from_secret(
        "oidc-token",
        b"test-secret-for-pep-assertion-fail-closed",
    ));
    let state = SharedState::new(config, Arc::new(repo), signer, serde_json::json!({}))
        .expect("shared state");

    let err = do_issue_assertion(
        &state,
        "test",
        &AssertionRequest {
            edge: Some("egress-main".to_string()),
            session: Some("sess_qpx_missing_signer".to_string()),
            access_token: None,
        },
        &HeaderMap::new(),
    )
    .await
    .expect_err("PEP assertion without dedicated signer must fail closed");

    assert!(
        err.message().contains("dedicated pep_assertion keyring"),
        "unexpected error: {}",
        err.message()
    );
    std::fs::remove_file(path).ok();
}

#[tokio::test]
async fn a_realm_that_disables_its_registrations_serves_no_assertion() {
    let mut config = qid_core::test_helpers::test_config();
    config.realms[0].pep_registrations.enabled = false;
    config.realms[0].pep_registrations.registrations =
        vec![qid_core::config::PepRegistrationConfig {
            name: "egress-main".to_string(),
            audience: Some("urn:qid:pep:qpx:test/egress-main".to_string()),
            capabilities: Vec::new(),
            assertion: qid_core::config::ProxyAssertionConfig::default(),
            decision: qid_core::config::PepDecisionConfig::default(),
            auth: qid_core::config::PepRegistrationAuthConfig::default(),
        }];
    let path = std::env::temp_dir().join(format!("qid-proxy-assertion-{}.json", ulid::Ulid::new()));
    let repo = qid_storage::FileRepository::new(path.to_str().expect("valid temp path"))
        .await
        .expect("file repository");
    repo.migrate().await.expect("file repository migration");
    let now = qid_core::util::now_seconds();
    let user = User {
        id: "usr_qpx_disabled_registration".to_string(),
        realm_id: "test".to_string(),
        email: Some("alice@example.com".to_string()),
        email_verified: true,
        display_name: Some("Alice".to_string()),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };
    repo.create_user(&user).await.expect("user created");
    repo.create_session(&Session {
        id: "sess_qpx_disabled_registration".to_string(),
        realm_id: "test".to_string(),
        user_id: user.id.clone(),
        auth_time: now - 30,
        acr: Some("urn:qid:acr:password".to_string()),
        amr: vec!["pwd".to_string()],
        idle_expires_at: now + 300,
        absolute_expires_at: now + 3_600,
        revoked: false,
        created_at: now - 30,
        cnf: None,
    })
    .await
    .expect("session created");

    let signer = Arc::new(qid_crypto::LocalSigner::from_secret(
        "oidc-token",
        b"test-secret-for-disabled-pep-registration",
    ));
    let state = SharedState::new(config, Arc::new(repo), signer, serde_json::json!({}))
        .expect("shared state");

    let err = do_issue_assertion(
        &state,
        "test",
        &AssertionRequest {
            edge: Some("egress-main".to_string()),
            session: Some("sess_qpx_disabled_registration".to_string()),
            access_token: None,
        },
        &HeaderMap::new(),
    )
    .await
    .expect_err("a realm that disables its registrations serves no assertion");

    assert!(
        err.message().contains("unknown PEP adapter"),
        "unexpected error: {}",
        err.message()
    );
    std::fs::remove_file(path).ok();
}

fn session(now: u64) -> Session {
    Session {
        id: "sid_01J".to_string(),
        realm_id: "corp".to_string(),
        user_id: "usr_01J".to_string(),
        auth_time: now - 120,
        acr: Some("phr".to_string()),
        amr: vec!["pwd".to_string(), "hwk".to_string()],
        idle_expires_at: now + 300,
        absolute_expires_at: now + 3600,
        revoked: false,
        created_at: now - 120,
        cnf: None,
    }
}

fn grant(
    id: &str,
    entitlement: &str,
    expires_at_epoch_seconds: Option<u64>,
    revoked: bool,
    now: u64,
) -> IgaAccessGrantRecord {
    grant_for_tenant(
        id,
        "corp",
        entitlement,
        expires_at_epoch_seconds,
        revoked,
        now,
    )
}

fn grant_for_tenant(
    id: &str,
    tenant_id: &str,
    entitlement: &str,
    expires_at_epoch_seconds: Option<u64>,
    revoked: bool,
    now: u64,
) -> IgaAccessGrantRecord {
    IgaAccessGrantRecord {
        id: id.to_string(),
        tenant_id: tenant_id.to_string(),
        request_id: format!("req-{id}"),
        subject: "usr_01J".to_string(),
        entitlement: entitlement.to_string(),
        granted_at_epoch_seconds: now - 60,
        expires_at_epoch_seconds,
        approval_ids: vec!["approval-1".to_string()],
        revoked,
    }
}
