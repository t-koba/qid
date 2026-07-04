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

/// Execute a broker login plan: create local user if JIT provisioning
/// is requested, persist CIAM identity link, and return the local user ID.
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

    // Persist CIAM identity link
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

    // §8.3: Audit CIAM identity link storage (always recorded)
    let link_audit = jit_audit_event(
        &local_user_id,
        realm_id,
        provider_id,
        "ciam_identity_link_stored",
        plan,
        now,
    );
    repo.append_audit_event(&link_audit).await?;

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
    #[serde(default, rename = "RelayState")]
    #[allow(dead_code)]
    relay_state: Option<String>,
}
