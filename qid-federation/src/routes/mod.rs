use axum::{
    Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use qid_core::{
    QidError,
    models::{AuditEvent, CiamIdentityLink, User},
    state::SharedState,
    tenant::RealmId,
};
use qid_storage::prelude::*;
use serde::Deserialize;
use std::sync::Arc;

use crate::{
    BrokerAccountLink, ExternalIdentityClaims, HomeRealmDiscoveryRequest, InboundIdentityProvider,
    InboundProviderKind, plan_inbound_login,
};

pub mod discovery;
pub mod oidc;
pub mod saml;
pub mod social;
pub mod spnego;
pub(crate) mod transaction;
pub mod trust_chain;

pub use oidc::{exchange_code_for_tokens, fetch_userinfo};
pub use trust_chain::{TrustChainValidationRequest, TrustChainValidationResponse};

/// Convert config `InboundProviderConfig` vec to broker `InboundIdentityProvider` vec.
pub fn providers_from_config(
    cfgs: &[qid_core::config::InboundProviderConfig],
) -> Vec<InboundIdentityProvider> {
    cfgs.iter()
        .filter_map(|cfg| {
            let kind = InboundProviderKind::from_kind_str(&cfg.kind)?;
            Some(InboundIdentityProvider {
                id: cfg.id.clone(),
                kind,
                issuer: cfg.issuer.clone(),
                enabled: cfg.enabled,
                domains: cfg.domains.clone(),
                social_provider: cfg.social_provider.clone(),
                client_id: cfg.client_id.clone(),
                client_secret: cfg.client_secret.clone(),
                token_url: cfg.token_url.clone(),
                userinfo_url: cfg.userinfo_url.clone(),
                jit_provisioning: cfg.jit_provisioning,
                account_linking: cfg.account_linking,
                claim_mappings: cfg
                    .claim_mappings
                    .iter()
                    .map(|cm| crate::ClaimMapping {
                        source: cm.source.clone(),
                        target: cm.target.clone(),
                        required: cm.required,
                    })
                    .collect(),
                jwks_uri: cfg.jwks_uri.clone(),
                jwks: cfg.jwks.clone(),
                saml_signing_certificates: cfg.saml_signing_certificates.clone(),
                trusted_audiences: cfg.trusted_audiences.clone(),
                kerberos_spnego: cfg.kerberos_spnego.as_ref().map(|kerberos| {
                    crate::KerberosSpnegoConfig {
                        realm: kerberos.realm.clone(),
                        service_principal: kerberos.service_principal.clone(),
                        keytab_path: kerberos.keytab_path.clone(),
                    }
                }),
            })
        })
        .collect()
}

/// Load existing broker account links from the CIAM identity link store.
async fn load_broker_links<R: Repository>(
    repo: &R,
    realm_id: &str,
    provider: &str,
    claims: &ExternalIdentityClaims,
) -> Result<Vec<BrokerAccountLink>, QidError> {
    let realm = RealmId(realm_id.to_string());
    Ok(repo
        .get_ciam_identity_link_by_external_subject(&realm, provider, &claims.subject)
        .await?
        .into_iter()
        .map(|link| BrokerAccountLink {
            provider_id: link.provider,
            external_subject: claims.subject.clone(),
            local_subject: link.user_id,
        })
        .collect())
}

#[derive(Debug)]
enum BrokerLoginPlanError {
    LinkLookup,
    Plan(QidError),
}

async fn plan_broker_login<R: Repository>(
    repo: &R,
    realm_id: &str,
    provider_id: &str,
    providers: &[InboundIdentityProvider],
    request: &HomeRealmDiscoveryRequest,
    claims: &ExternalIdentityClaims,
) -> Result<crate::BrokerLoginPlan, BrokerLoginPlanError> {
    let links = load_broker_links(repo, realm_id, provider_id, claims)
        .await
        .map_err(|_| BrokerLoginPlanError::LinkLookup)?;
    plan_inbound_login(providers, request, claims, &links).map_err(BrokerLoginPlanError::Plan)
}

fn broker_login_plan_error_response(error: BrokerLoginPlanError) -> Response {
    match error {
        BrokerLoginPlanError::LinkLookup => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "identity_link_lookup_failed"})),
        )
            .into_response(),
        BrokerLoginPlanError::Plan(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "login_plan_failed", "message": error.to_string()})),
        )
            .into_response(),
    }
}

/// Execute a broker login plan: create a local user and persist its CIAM identity
/// link on first login, or reuse the already verified link on returning login.
async fn exec_broker_login_plan<R: Repository>(
    repo: &R,
    realm_id: &str,
    provider_id: &str,
    claims: &ExternalIdentityClaims,
    plan: &crate::BrokerLoginPlan,
) -> Result<String, QidError> {
    let now = qid_core::util::now_seconds();

    // §8.2: Check email_verified before JIT account creation to prevent
    // account takeover via an unverified email claim.
    if plan.create_subject && plan.route.jit_provisioning {
        let email_present = plan.normalized_claims.contains_key("email");
        let email_verified = plan
            .normalized_claims
            .get("email_verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if email_present && !email_verified {
            return Err(QidError::BadRequest {
                message: "JIT provisioning requires email_verified to be true".to_string(),
            });
        }
    }

    // Determine local user ID
    let local_user_id: String = if let Some(ref linked) = plan.linked_subject {
        linked.clone()
    } else if plan.create_subject {
        if plan.route.account_linking && plan.route.jit_provisioning {
            let email = plan
                .normalized_claims
                .get("email")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let display_name = plan
                .normalized_claims
                .get("display_name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let user = User {
                id: format!("usr_{}", ulid::Ulid::new()),
                realm_id: realm_id.to_string(),
                email,
                email_verified: false,
                display_name,
                failed_login_attempts: 0,
                locked_until: None,
                org: None,
            };
            repo.create_user(&user).await?;

            // §8.3: Audit JIT new account creation
            let audit_event = jit_audit_event(
                &user.id,
                realm_id,
                provider_id,
                "jit_account_created",
                plan,
                now,
            );
            repo.append_audit_event(&audit_event).await?;

            user.id
        } else {
            return Err(QidError::BadRequest {
                message: "JIT provisioning is disabled and no account link exists".to_string(),
            });
        }
    } else {
        return Err(QidError::BadRequest {
            message: "login plan did not resolve to a local subject".to_string(),
        });
    };

    // §8.3: Audit JIT account linking (re-link to existing subject)
    if plan.linked_subject.is_some() {
        let audit_event = jit_audit_event(
            &local_user_id,
            realm_id,
            provider_id,
            "jit_account_linked",
            plan,
            now,
        );
        repo.append_audit_event(&audit_event).await?;
    }

    if plan.linked_subject.is_none() {
        let link = CiamIdentityLink {
            id: format!("cil_{}", ulid::Ulid::new()),
            realm_id: realm_id.to_string(),
            user_id: local_user_id.clone(),
            provider: provider_id.to_string(),
            external_subject: claims.subject.clone(),
            external_email: claims
                .claims
                .get("email")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            profile_json: serde_json::Value::Object(claims.claims.clone().into_iter().collect()),
            linked_at_epoch_seconds: now,
            verified: true,
        };
        repo.store_ciam_identity_link(&link).await?;

        // §8.3: Audit CIAM identity link storage on first login.
        let link_audit = jit_audit_event(
            &local_user_id,
            realm_id,
            provider_id,
            "ciam_identity_link_stored",
            plan,
            now,
        );
        repo.append_audit_event(&link_audit).await?;
    }

    Ok(local_user_id)
}

/// Build an audit event for a broker JIT provisioning operation.
fn jit_audit_event(
    local_user_id: &str,
    realm_id: &str,
    provider_id: &str,
    action: &str,
    plan: &crate::BrokerLoginPlan,
    now: u64,
) -> AuditEvent {
    AuditEvent {
        id: format!("fed_jit_{}_{}", action, ulid::Ulid::new()),
        realm_id: Some(realm_id.to_string()),
        actor: "federation-broker".to_string(),
        action: format!("federation.{}", action),
        target_type: "ciam_identity".to_string(),
        target_id: local_user_id.to_string(),
        reason: format!("JIT provisioning via provider {provider_id}"),
        metadata_json: serde_json::json!({
            "provider_id": provider_id,
            "external_subject": plan.normalized_claims.get("external_subject"),
            "create_subject": plan.create_subject,
            "linked_subject": plan.linked_subject,
        }),
        created_at: now,
        previous_hash: None,
        event_hash: None,
    }
}

pub fn federation_routes<R: Repository>() -> Router<Arc<SharedState<R>>> {
    Router::new()
        .route(
            "/.well-known/openid-federation",
            get(discovery::entity_statement::<R>),
        )
        .route(
            "/federation/v1/trust-chain/validate",
            post(trust_chain::validate_trust_chain_endpoint::<R>),
        )
        .route(
            "/federation/:realm/discover",
            post(discovery::discover_provider::<R>),
        )
        .route(
            "/federation/:realm/oidc/callback",
            get(oidc::oidc_inbound_callback::<R>),
        )
        .route(
            "/federation/:realm/oidc/:provider/callback",
            get(oidc::oidc_inbound_callback_for_provider::<R>),
        )
        .route(
            "/federation/:realm/saml/acs",
            post(saml::saml_inbound_acs::<R>),
        )
        .route(
            "/federation/:realm/spnego/negotiate",
            post(spnego::spnego_negotiate::<R>),
        )
        .route(
            "/federation/:realm/social/:provider/callback",
            get(social::social_login_callback::<R>),
        )
        .merge(transaction::routes::<R>())
}

#[derive(Debug, Deserialize)]
pub(crate) struct OidcCallbackQuery {
    code: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    pub(crate) iss: Option<String>,
}

/// Whether the selected provider is configured as advertising RFC 9207
/// front-channel issuer support.
pub(crate) fn authorization_response_iss_supported(
    cfgs: &[qid_core::config::InboundProviderConfig],
    provider_id: &str,
) -> bool {
    cfgs.iter()
        .find(|cfg| cfg.id == provider_id)
        .is_some_and(|cfg| cfg.authorization_response_iss_parameter_supported)
}

/// Bind an upstream authorization response to the provider selected by the
/// verified transaction proof. `ambiguous_target` is true when several enabled
/// providers share this callback target. `supported` is the selected provider's
/// RFC 9207 configuration: a provider that advertises support must supply `iss`
/// even on an unambiguous callback target.
pub(crate) fn verify_authorization_response_issuer(
    received: Option<&str>,
    expected: &str,
    ambiguous_target: bool,
    supported: bool,
) -> Result<(), QidError> {
    match received {
        Some(issuer) if issuer == expected => Ok(()),
        Some(_) => Err(QidError::BadRequest {
            message: "authorization response issuer mismatch".to_string(),
        }),
        None if supported => Err(QidError::BadRequest {
            message: "authorization response issuer required by provider configuration".to_string(),
        }),
        None if ambiguous_target => Err(QidError::BadRequest {
            message: "authorization response issuer required for this callback target".to_string(),
        }),
        None => Ok(()),
    }
}

#[cfg(test)]
mod issuer_binding_tests {
    use super::verify_authorization_response_issuer;

    #[test]
    fn issuer_check_accepts_exact_match_and_unambiguous_absence() {
        assert!(
            verify_authorization_response_issuer(
                Some("https://login.example"),
                "https://login.example",
                false,
                false,
            )
            .is_ok()
        );
        assert!(
            verify_authorization_response_issuer(None, "https://login.example", false, false)
                .is_ok()
        );
        assert!(
            verify_authorization_response_issuer(
                Some("https://login.example"),
                "https://login.example",
                false,
                true,
            )
            .is_ok()
        );
    }

    #[test]
    fn issuer_check_requires_iss_when_provider_advertises_support() {
        let error =
            verify_authorization_response_issuer(None, "https://login.example", false, true)
                .unwrap_err();
        assert!(
            error
                .message()
                .contains("authorization response issuer required by provider configuration"),
            "{error}"
        );
        assert!(
            verify_authorization_response_issuer(None, "https://login.example", true, true)
                .unwrap_err()
                .message()
                .contains("authorization response issuer required by provider configuration")
        );
    }

    #[test]
    fn issuer_check_rejects_mismatch_and_ambiguous_absence() {
        let expected = "https://login.example";
        let cases = [
            (
                Some("https://login.example/"),
                false,
                false,
                "authorization response issuer mismatch",
            ),
            (
                Some("https://other.example"),
                true,
                true,
                "authorization response issuer mismatch",
            ),
            (
                None,
                true,
                false,
                "authorization response issuer required for this callback target",
            ),
        ];
        for (received, ambiguous, supported, message) in cases {
            let error =
                verify_authorization_response_issuer(received, expected, ambiguous, supported)
                    .unwrap_err();
            assert!(error.message().contains(message), "{error}");
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct SamlAcsForm {
    #[serde(default, rename = "SAMLResponse")]
    saml_response: Option<String>,
}

#[cfg(test)]
mod login_tests {
    use super::*;
    use crate::{ClaimMapping, ExternalIdentityClaims, HomeRealmDiscoveryRequest};
    use qid_core::tenant::TenantId;
    use qid_storage::AnyRepository;
    use std::{collections::BTreeMap, path::PathBuf};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "qid-federation-returning-login-{}",
                ulid::Ulid::new()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn provider() -> InboundIdentityProvider {
        InboundIdentityProvider {
            id: "corp-oidc".to_string(),
            kind: InboundProviderKind::Oidc,
            issuer: "https://login.corp.example".to_string(),
            enabled: true,
            domains: vec!["corp.example".to_string()],
            social_provider: None,
            jit_provisioning: true,
            account_linking: true,
            client_id: None,
            client_secret: None,
            token_url: None,
            userinfo_url: None,
            jwks_uri: None,
            jwks: None,
            saml_signing_certificates: Vec::new(),
            trusted_audiences: Vec::new(),
            kerberos_spnego: None,
            claim_mappings: vec![
                ClaimMapping {
                    source: "email".to_string(),
                    target: "email".to_string(),
                    required: true,
                },
                ClaimMapping {
                    source: "email_verified".to_string(),
                    target: "email_verified".to_string(),
                    required: true,
                },
            ],
        }
    }

    async fn assert_returning_login_reuses_link(repo: &impl Repository) {
        let realm = RealmId::from("federation-returning-login");
        repo.create_realm(
            &TenantId::from("test-tenant"),
            &realm,
            "https://qid.example",
            Some("test realm"),
        )
        .await
        .unwrap();

        let providers = vec![provider()];
        let request = HomeRealmDiscoveryRequest {
            idp_hint: Some("corp-oidc".to_string()),
            ..Default::default()
        };
        let claims = ExternalIdentityClaims {
            issuer: "https://login.corp.example".to_string(),
            subject: "external-alice".to_string(),
            claims: BTreeMap::from([
                (
                    "email".to_string(),
                    serde_json::Value::String("alice@corp.example".to_string()),
                ),
                ("email_verified".to_string(), serde_json::Value::Bool(true)),
            ]),
        };

        let first_plan = plan_broker_login(
            repo,
            realm.as_str(),
            "corp-oidc",
            &providers,
            &request,
            &claims,
        )
        .await
        .unwrap();
        assert!(first_plan.create_subject);
        assert!(first_plan.linked_subject.is_none());
        let first_user =
            exec_broker_login_plan(repo, realm.as_str(), "corp-oidc", &claims, &first_plan)
                .await
                .unwrap();

        let link_before = repo
            .get_ciam_identity_link_by_external_subject(&realm, "corp-oidc", &claims.subject)
            .await
            .unwrap()
            .expect("first login stores the verified identity link");
        assert_eq!(link_before.user_id, first_user);

        let returning_plan = plan_broker_login(
            repo,
            realm.as_str(),
            "corp-oidc",
            &providers,
            &request,
            &claims,
        )
        .await
        .unwrap();
        assert!(!returning_plan.create_subject);
        assert_eq!(
            returning_plan.linked_subject.as_deref(),
            Some(first_user.as_str())
        );
        let returning_user =
            exec_broker_login_plan(repo, realm.as_str(), "corp-oidc", &claims, &returning_plan)
                .await
                .expect("returning login must reuse the existing verified link");

        assert_eq!(returning_user, first_user);
        let link_after = repo
            .get_ciam_identity_link_by_external_subject(&realm, "corp-oidc", &claims.subject)
            .await
            .unwrap()
            .expect("verified identity link remains available");
        assert_eq!(link_after, link_before);
        assert_eq!(
            repo.list_ciam_identity_links(&realm, &first_user)
                .await
                .unwrap(),
            vec![link_before],
            "returning login must not add a duplicate link"
        );

        let audit = repo.list_audit_events(Some(&realm), 10).await.unwrap();
        for (action, count) in [
            ("federation.jit_account_created", 1),
            ("federation.jit_account_linked", 1),
            ("federation.ciam_identity_link_stored", 1),
        ] {
            assert_eq!(
                audit.iter().filter(|event| event.action == action).count(),
                count,
                "unexpected {action} audit count"
            );
        }
    }

    fn test_user(id: &str, realm_id: &str, email: &str) -> User {
        User {
            id: id.to_string(),
            realm_id: realm_id.to_string(),
            email: Some(email.to_string()),
            email_verified: false,
            display_name: None,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        }
    }

    fn external_claims() -> ExternalIdentityClaims {
        ExternalIdentityClaims {
            issuer: "https://login.corp.example".to_string(),
            subject: "external-alice".to_string(),
            claims: BTreeMap::from([
                (
                    "email".to_string(),
                    serde_json::Value::String("alice@corp.example".to_string()),
                ),
                ("email_verified".to_string(), serde_json::Value::Bool(true)),
            ]),
        }
    }

    fn login_request() -> HomeRealmDiscoveryRequest {
        HomeRealmDiscoveryRequest {
            idp_hint: Some("corp-oidc".to_string()),
            ..Default::default()
        }
    }

    async fn assert_no_jit_side_effects(repo: &impl Repository, realm: &RealmId, users: usize) {
        assert_eq!(repo.list_users(realm).await.unwrap().len(), users);
        assert!(
            repo.get_user_by_email(realm, "alice@corp.example")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repo.list_audit_events(Some(realm), 10)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn ambiguous_identity_link_aborts_planning_without_jit_side_effects() {
        let directory = TestDirectory::new();
        let path = directory.0.join("ambiguous-links.json");
        let realm = RealmId::from("ambiguous-link-realm");
        let file_repo = match AnyRepository::connect(path.to_str().unwrap())
            .await
            .unwrap()
        {
            AnyRepository::File(repo) => repo,
            AnyRepository::Sql(_) => unreachable!(),
        };
        file_repo
            .create_realm(
                &TenantId::from("test-tenant"),
                &realm,
                "https://qid.example",
                None,
            )
            .await
            .unwrap();
        for (id, email) in [
            ("user-one", "one@corp.example"),
            ("user-two", "two@corp.example"),
        ] {
            file_repo
                .create_user(&test_user(id, realm.as_str(), email))
                .await
                .unwrap();
        }
        let first_link = CiamIdentityLink {
            id: "link-one".to_string(),
            realm_id: realm.0.clone(),
            user_id: "user-one".to_string(),
            provider: "corp-oidc".to_string(),
            external_subject: "external-alice".to_string(),
            external_email: Some("alice@corp.example".to_string()),
            profile_json: serde_json::json!({}),
            linked_at_epoch_seconds: 1_800_000_000,
            verified: true,
        };
        file_repo
            .store_ciam_identity_link(&first_link)
            .await
            .unwrap();
        file_repo.flush().await.unwrap();
        drop(file_repo);

        let mut stored: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let links = stored["ciam_identity_links"].as_object_mut().unwrap();
        let mut second_link = links.get("link-one").unwrap().clone();
        second_link["id"] = serde_json::Value::String("link-two".to_string());
        second_link["user_id"] = serde_json::Value::String("user-two".to_string());
        links.insert("link-two".to_string(), second_link);
        std::fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();

        let repo = AnyRepository::connect(path.to_str().unwrap())
            .await
            .unwrap();
        let result = plan_broker_login(
            &repo,
            realm.as_str(),
            "corp-oidc",
            &[provider()],
            &login_request(),
            &external_claims(),
        )
        .await;
        assert!(matches!(
            load_broker_links(&repo, realm.as_str(), "corp-oidc", &external_claims()).await,
            Err(QidError::Conflict { .. })
        ));
        assert!(matches!(result, Err(BrokerLoginPlanError::LinkLookup)));
        assert_no_jit_side_effects(&repo, &realm, 2).await;
        for user_id in ["user-one", "user-two"] {
            assert_eq!(
                repo.list_ciam_identity_links(&realm, user_id)
                    .await
                    .unwrap()
                    .len(),
                1
            );
        }
    }

    #[tokio::test]
    async fn identity_link_repository_failure_aborts_planning_without_jit_side_effects() {
        let directory = TestDirectory::new();
        let path = directory.0.join("lookup-failure.db");
        let url = format!("sqlite:{}", path.display());
        let realm = RealmId::from("lookup-failure-realm");
        let sql_repo = match AnyRepository::connect(&url).await.unwrap() {
            AnyRepository::Sql(repo) => repo,
            AnyRepository::File(_) => unreachable!(),
        };
        sql_repo
            .create_realm(
                &TenantId::from("test-tenant"),
                &realm,
                "https://qid.example",
                None,
            )
            .await
            .unwrap();
        sql_repo
            .create_user(&test_user(
                "existing-user",
                realm.as_str(),
                "existing@corp.example",
            ))
            .await
            .unwrap();
        let lookup_repo = AnyRepository::Sql(sql_repo.clone());
        sql_repo.close().await;

        let result = plan_broker_login(
            &lookup_repo,
            realm.as_str(),
            "corp-oidc",
            &[provider()],
            &login_request(),
            &external_claims(),
        )
        .await;
        assert!(matches!(result, Err(BrokerLoginPlanError::LinkLookup)));
        drop(lookup_repo);

        let repo = AnyRepository::connect(&url).await.unwrap();
        assert_no_jit_side_effects(&repo, &realm, 1).await;
        assert!(
            repo.list_ciam_identity_links(&realm, "existing-user")
                .await
                .unwrap()
                .is_empty()
        );
        match repo {
            AnyRepository::Sql(repo) => repo.close().await,
            AnyRepository::File(_) => unreachable!(),
        }
    }

    #[tokio::test]
    async fn returning_login_reuses_verified_link_in_file_and_sqlite() {
        let directory = TestDirectory::new();
        let file_path = directory.0.join("file.json");
        let sqlite_path = directory.0.join("sqlite.db");

        let file_repo = AnyRepository::connect(file_path.to_str().unwrap())
            .await
            .unwrap();
        assert_returning_login_reuses_link(&file_repo).await;
        match file_repo {
            AnyRepository::File(repo) => repo.flush().await.unwrap(),
            AnyRepository::Sql(_) => unreachable!(),
        }

        let sqlite_url = format!("sqlite:{}", sqlite_path.display());
        let sqlite_repo = AnyRepository::connect(&sqlite_url).await.unwrap();
        assert_returning_login_reuses_link(&sqlite_repo).await;
        match sqlite_repo {
            AnyRepository::Sql(repo) => repo.close().await,
            AnyRepository::File(_) => unreachable!(),
        }

        std::fs::remove_dir_all(&directory.0).unwrap();
    }
}
