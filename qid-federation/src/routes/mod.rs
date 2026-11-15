use axum::{
    Router,
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
    BrokerAccountLink, ExternalIdentityClaims, InboundIdentityProvider, InboundProviderKind,
};

pub mod discovery;
pub mod oidc;
pub mod saml;
pub mod social;
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
) -> Vec<BrokerAccountLink> {
    let realm = RealmId(realm_id.to_string());
    match repo
        .get_ciam_identity_link_by_external_subject(&realm, provider, &claims.subject)
        .await
    {
        Ok(Some(link)) => vec![BrokerAccountLink {
            provider_id: link.provider.clone(),
            external_subject: claims.subject.clone(),
            local_subject: link.user_id,
        }],
        Ok(None) => Vec::new(),
        Err(_) => Vec::new(),
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
            "/federation/:realm/saml/acs",
            post(saml::saml_inbound_acs::<R>),
        )
        .route(
            "/federation/:realm/social/:provider/callback",
            get(social::social_login_callback::<R>),
        )
}

#[derive(Debug, Deserialize)]
pub(crate) struct OidcCallbackQuery {
    code: String,
    #[serde(default)]
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SamlAcsForm {
    #[serde(default, rename = "SAMLResponse")]
    saml_response: Option<String>,
}

#[cfg(test)]
mod login_tests {
    use super::*;
    use crate::{
        ClaimMapping, ExternalIdentityClaims, HomeRealmDiscoveryRequest, plan_inbound_login,
    };
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

        let first_plan = plan_inbound_login(&providers, &request, &claims, &[]).unwrap();
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

        let links = load_broker_links(repo, realm.as_str(), "corp-oidc", &claims).await;
        assert_eq!(links.len(), 1);
        let returning_plan = plan_inbound_login(&providers, &request, &claims, &links).unwrap();
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
