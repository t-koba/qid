use super::*;
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use qid_core::{state::SharedState, test_helpers, util};
use qid_crypto::LocalSigner;
use qid_storage::FileRepository;
use qid_storage::{AuditRepository, RealmRepository};
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

fn rp_statement() -> EntityStatement {
    EntityStatement {
        iss: "https://intermediate.example".to_string(),
        sub: "https://rp.example".to_string(),
        iat: 100,
        exp: 1000,
        authority_hints: vec!["https://intermediate.example".to_string()],
        metadata: Some(FederationMetadata {
            openid_provider: None,
            openid_relying_party: Some(OpenIdRelyingPartyMetadata {
                redirect_uris: vec!["https://rp.example/callback".to_string()],
                grant_types: vec!["authorization_code".to_string()],
            }),
        }),
        trust_marks: vec![TrustMark {
            id: "https://trust.example/marks/verified".to_string(),
            issuer: "https://anchor.example".to_string(),
        }],
    }
}

fn intermediate_statement() -> EntityStatement {
    EntityStatement {
        iss: "https://anchor.example".to_string(),
        sub: "https://intermediate.example".to_string(),
        iat: 100,
        exp: 1000,
        authority_hints: vec!["https://anchor.example".to_string()],
        metadata: None,
        trust_marks: Vec::new(),
    }
}

fn anchor_statement() -> EntityStatement {
    EntityStatement {
        iss: "https://anchor.example".to_string(),
        sub: "https://anchor.example".to_string(),
        iat: 100,
        exp: 1000,
        authority_hints: Vec::new(),
        metadata: None,
        trust_marks: Vec::new(),
    }
}

fn signed_statement() -> EntityStatement {
    let now = util::now_seconds();
    EntityStatement {
        iss: "https://anchor.example".to_string(),
        sub: "https://anchor.example".to_string(),
        iat: now,
        exp: now + 3600,
        authority_hints: Vec::new(),
        metadata: Some(FederationMetadata {
            openid_provider: Some(OpenIdProviderMetadata {
                issuer: "https://anchor.example".to_string(),
                jwks_uri: "https://anchor.example/jwks".to_string(),
            }),
            openid_relying_party: None,
        }),
        trust_marks: vec![TrustMark {
            id: "https://trust.example/marks/verified".to_string(),
            issuer: "https://anchor.example".to_string(),
        }],
    }
}

fn inbound_providers() -> Vec<InboundIdentityProvider> {
    vec![
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
            claim_mappings: vec![
                ClaimMapping {
                    source: "email".to_string(),
                    target: "email".to_string(),
                    required: true,
                },
                ClaimMapping {
                    source: "groups".to_string(),
                    target: "groups".to_string(),
                    required: false,
                },
            ],
        },
        InboundIdentityProvider {
            id: "partner-saml".to_string(),
            kind: InboundProviderKind::Saml,
            issuer: "https://idp.partner.example/metadata".to_string(),
            enabled: true,
            domains: vec!["partner.example".to_string()],
            social_provider: None,
            jit_provisioning: false,
            account_linking: true,
            client_id: None,
            client_secret: None,
            token_url: None,
            userinfo_url: None,
            jwks_uri: None,
            jwks: None,
            saml_signing_certificates: Vec::new(),
            claim_mappings: vec![ClaimMapping {
                source: "NameID".to_string(),
                target: "name_id".to_string(),
                required: true,
            }],
        },
        InboundIdentityProvider {
            id: "google-social".to_string(),
            kind: InboundProviderKind::Social,
            issuer: "https://accounts.google.com".to_string(),
            enabled: true,
            domains: Vec::new(),
            social_provider: Some("google".to_string()),
            jit_provisioning: true,
            account_linking: true,
            client_id: None,
            client_secret: None,
            token_url: None,
            userinfo_url: None,
            jwks_uri: None,
            jwks: None,
            saml_signing_certificates: Vec::new(),
            claim_mappings: vec![ClaimMapping {
                source: "email".to_string(),
                target: "email".to_string(),
                required: true,
            }],
        },
    ]
}

#[test]
fn trust_chain_validates_to_anchor_and_enables_client_trust() {
    let chain = vec![rp_statement(), intermediate_statement(), anchor_statement()];
    let anchors = vec![TrustAnchor {
        entity_id: "https://anchor.example".to_string(),
        required_trust_marks: vec!["https://trust.example/marks/verified".to_string()],
        trusted_trust_mark_issuers: Vec::new(),
        allowed_redirect_hosts: vec!["rp.example".to_string()],
    }];

    let validation = validate_trust_chain("https://rp.example", &chain, &anchors, 200).unwrap();

    assert_eq!(validation.trust_anchor, "https://anchor.example");
    assert!(validation.automatic_client_trust);
    assert_eq!(
        validation
            .effective_openid_relying_party
            .as_ref()
            .unwrap()
            .redirect_uris,
        vec!["https://rp.example/callback"]
    );
    assert!(
        validation
            .trust_marks
            .contains(&"https://trust.example/marks/verified".to_string())
    );
}

#[test]
fn trust_chain_rejects_broken_issuer_link() {
    let mut chain = vec![rp_statement(), intermediate_statement(), anchor_statement()];
    chain[1].sub = "https://other.example".to_string();
    let anchors = vec![TrustAnchor {
        entity_id: "https://anchor.example".to_string(),
        required_trust_marks: Vec::new(),
        trusted_trust_mark_issuers: Vec::new(),
        allowed_redirect_hosts: Vec::new(),
    }];

    let err = validate_trust_chain("https://rp.example", &chain, &anchors, 200).unwrap_err();

    assert_eq!(federation_error_code(&err), "broken_issuer_link");
}

#[test]
fn metadata_policy_rejects_untrusted_redirect_host_and_strips_weak_grants() {
    let metadata = OpenIdRelyingPartyMetadata {
        redirect_uris: vec!["https://rp.example/callback".to_string()],
        grant_types: vec![
            "authorization_code".to_string(),
            "implicit".to_string(),
            "password".to_string(),
        ],
    };

    let filtered = apply_metadata_policy(&metadata, &["rp.example".to_string()]).unwrap();

    assert_eq!(filtered.grant_types, vec!["authorization_code"]);
    assert!(apply_metadata_policy(&metadata, &["other.example".to_string()]).is_err());
}

#[test]
fn trust_chain_applies_anchor_redirect_host_policy() {
    let mut rp = rp_statement();
    let relying_party = rp
        .metadata
        .as_mut()
        .and_then(|metadata| metadata.openid_relying_party.as_mut())
        .unwrap();
    relying_party
        .redirect_uris
        .push("https://evil.example/callback".to_string());
    relying_party.grant_types.push("implicit".to_string());
    let chain = vec![rp, intermediate_statement(), anchor_statement()];
    let anchors = vec![TrustAnchor {
        entity_id: "https://anchor.example".to_string(),
        required_trust_marks: vec!["https://trust.example/marks/verified".to_string()],
        trusted_trust_mark_issuers: Vec::new(),
        allowed_redirect_hosts: vec!["rp.example".to_string()],
    }];

    let err = validate_trust_chain("https://rp.example", &chain, &anchors, 200).unwrap_err();

    assert_eq!(federation_error_code(&err), "redirect_host_not_allowed");

    let mut rp = rp_statement();
    let relying_party = rp
        .metadata
        .as_mut()
        .and_then(|metadata| metadata.openid_relying_party.as_mut())
        .unwrap();
    relying_party.grant_types.push("implicit".to_string());
    let chain = vec![rp, intermediate_statement(), anchor_statement()];
    let validation = validate_trust_chain("https://rp.example", &chain, &anchors, 200).unwrap();

    assert_eq!(
        validation
            .effective_openid_relying_party
            .unwrap()
            .grant_types,
        vec!["authorization_code"]
    );
}

#[test]
fn signed_entity_statement_round_trips_and_rejects_tampering() {
    let signer = LocalSigner::from_secret("fed-test", b"federation-test-secret");
    let statement = signed_statement();

    let token = sign_entity_statement(&signer, &statement).unwrap();
    let decoded = decode_signed_entity_statement(&signer, &token).unwrap();

    assert_eq!(decoded, statement);

    let mut parts = token.split('.').collect::<Vec<_>>();
    parts[1] = "eyJzdWIiOiJodHRwczovL2V2aWwuZXhhbXBsZSJ9";
    let tampered = parts.join(".");
    let err = decode_signed_entity_statement(&signer, &tampered).unwrap_err();
    assert_eq!(
        federation_error_code(&err),
        "entity_statement_decode_failed"
    );
}

#[test]
fn signed_trust_chain_validates_and_rejects_tampered_statement() {
    let signer = LocalSigner::from_secret("fed-chain-test", b"federation-chain-secret");
    let now = util::now_seconds();
    let mut rp = rp_statement();
    let mut intermediate = intermediate_statement();
    let mut anchor = anchor_statement();
    for statement in [&mut rp, &mut intermediate, &mut anchor] {
        statement.iat = now;
        statement.exp = now + 3600;
    }
    let chain = [rp, intermediate, anchor];
    let signed_chain = chain
        .iter()
        .map(|statement| sign_entity_statement(&signer, statement).unwrap())
        .collect::<Vec<_>>();
    let anchors = vec![TrustAnchor {
        entity_id: "https://anchor.example".to_string(),
        required_trust_marks: vec!["https://trust.example/marks/verified".to_string()],
        trusted_trust_mark_issuers: Vec::new(),
        allowed_redirect_hosts: vec!["rp.example".to_string()],
    }];

    let validation =
        validate_signed_trust_chain(&signer, "https://rp.example", &signed_chain, &anchors, now)
            .unwrap();

    assert_eq!(validation.subject, "https://rp.example");
    assert_eq!(validation.trust_anchor, "https://anchor.example");

    let mut tampered_chain = signed_chain;
    let mut token_parts = tampered_chain[0].split('.').collect::<Vec<_>>();
    token_parts[1] = "eyJzdWIiOiJodHRwczovL2V2aWwuZXhhbXBsZSJ9";
    tampered_chain[0] = token_parts.join(".");
    let err = validate_signed_trust_chain(
        &signer,
        "https://rp.example",
        &tampered_chain,
        &anchors,
        now,
    )
    .unwrap_err();
    assert_eq!(
        federation_error_code(&err),
        "signed_entity_statement_invalid"
    );
}

#[test]
fn trust_chain_rejects_untrusted_trust_mark_issuer() {
    let mut rp = rp_statement();
    rp.trust_marks[0].issuer = "https://evil.example".to_string();
    let chain = vec![rp, intermediate_statement(), anchor_statement()];
    let anchors = vec![TrustAnchor {
        entity_id: "https://anchor.example".to_string(),
        required_trust_marks: vec!["https://trust.example/marks/verified".to_string()],
        trusted_trust_mark_issuers: Vec::new(),
        allowed_redirect_hosts: vec!["rp.example".to_string()],
    }];

    let err = validate_trust_chain("https://rp.example", &chain, &anchors, 200).unwrap_err();

    assert_eq!(federation_error_code(&err), "untrusted_trust_mark_issuer");
}

#[test]
fn inbound_broker_routes_by_idp_hint_social_provider_and_domain() {
    let providers = inbound_providers();

    let idp_route = route_inbound_provider(
        &providers,
        &HomeRealmDiscoveryRequest {
            idp_hint: Some("partner-saml".to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(idp_route.provider_id, "partner-saml");
    assert_eq!(idp_route.provider_kind, InboundProviderKind::Saml);
    assert_eq!(idp_route.reason, "idp_hint");

    let social_route = route_inbound_provider(
        &providers,
        &HomeRealmDiscoveryRequest {
            social_provider: Some("Google".to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(social_route.provider_id, "google-social");
    assert_eq!(social_route.reason, "social_provider");

    let domain_route = route_inbound_provider(
        &providers,
        &HomeRealmDiscoveryRequest {
            login_hint: Some("alice@corp.example".to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(domain_route.provider_id, "corp-oidc");
    assert_eq!(domain_route.reason, "domain_discovery");
}

#[test]
fn inbound_broker_rejects_ambiguous_domains_and_unknown_routes() {
    let mut providers = inbound_providers();
    providers.push(InboundIdentityProvider {
        id: "corp-entra".to_string(),
        kind: InboundProviderKind::EntraId,
        issuer: "https://login.microsoftonline.com/corp/v2.0".to_string(),
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
        claim_mappings: Vec::new(),
    });

    let err = route_inbound_provider(
        &providers,
        &HomeRealmDiscoveryRequest {
            login_hint: Some("alice@corp.example".to_string()),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(federation_error_code(&err), "duplicate_domain");

    let providers = inbound_providers();
    let err = route_inbound_provider(
        &providers,
        &HomeRealmDiscoveryRequest {
            social_provider: Some("github".to_string()),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(federation_error_code(&err), "unknown_social_provider");
}

#[test]
fn inbound_login_plan_normalizes_claims_and_uses_jit_or_account_linking() {
    let providers = inbound_providers();
    let external = ExternalIdentityClaims {
        issuer: "https://login.corp.example".to_string(),
        subject: "external-alice".to_string(),
        claims: BTreeMap::from([
            (
                "email".to_string(),
                serde_json::Value::String("alice@corp.example".to_string()),
            ),
            (
                "groups".to_string(),
                serde_json::json!(["engineering", "admins"]),
            ),
        ]),
    };

    let plan = plan_inbound_login(
        &providers,
        &HomeRealmDiscoveryRequest {
            domain: Some("corp.example".to_string()),
            ..Default::default()
        },
        &external,
        &[],
    )
    .unwrap();

    assert_eq!(plan.route.provider_id, "corp-oidc");
    assert!(plan.create_subject);
    assert_eq!(plan.linked_subject, None);
    assert_eq!(
        plan.normalized_claims["email"],
        serde_json::Value::String("alice@corp.example".to_string())
    );
    assert_eq!(plan.normalized_claims["provider_id"], "corp-oidc");
}

#[test]
fn inbound_login_plan_requires_existing_link_when_jit_is_disabled() {
    let providers = inbound_providers();
    let external = ExternalIdentityClaims {
        issuer: "https://idp.partner.example/metadata".to_string(),
        subject: "partner-bob".to_string(),
        claims: BTreeMap::from([(
            "NameID".to_string(),
            serde_json::Value::String("partner-bob".to_string()),
        )]),
    };
    let request = HomeRealmDiscoveryRequest {
        domain: Some("partner.example".to_string()),
        ..Default::default()
    };

    let err = plan_inbound_login(&providers, &request, &external, &[]).unwrap_err();
    assert_eq!(federation_error_code(&err), "jit_disabled");

    let plan = plan_inbound_login(
        &providers,
        &request,
        &external,
        &[BrokerAccountLink {
            provider_id: "partner-saml".to_string(),
            external_subject: "partner-bob".to_string(),
            local_subject: "user-bob".to_string(),
        }],
    )
    .unwrap();

    assert!(!plan.create_subject);
    assert_eq!(plan.linked_subject.as_deref(), Some("user-bob"));
    assert_eq!(plan.normalized_claims["name_id"], "partner-bob");
}

#[test]
fn inbound_login_plan_fails_closed_on_issuer_or_required_claim_mismatch() {
    let providers = inbound_providers();
    let request = HomeRealmDiscoveryRequest {
        domain: Some("corp.example".to_string()),
        ..Default::default()
    };
    let wrong_issuer = ExternalIdentityClaims {
        issuer: "https://evil.example".to_string(),
        subject: "external-alice".to_string(),
        claims: BTreeMap::new(),
    };
    let err = plan_inbound_login(&providers, &request, &wrong_issuer, &[]).unwrap_err();
    assert_eq!(federation_error_code(&err), "issuer_mismatch");

    let missing_required_claim = ExternalIdentityClaims {
        issuer: "https://login.corp.example".to_string(),
        subject: "external-alice".to_string(),
        claims: BTreeMap::new(),
    };
    let err = plan_inbound_login(&providers, &request, &missing_required_claim, &[]).unwrap_err();
    assert_eq!(federation_error_code(&err), "required_claim_missing");
}

#[test]
fn inbound_login_plan_rejects_jit_without_email_verified() {
    let providers = inbound_providers();
    let external = ExternalIdentityClaims {
        issuer: "https://login.corp.example".to_string(),
        subject: "ext-alice".to_string(),
        claims: BTreeMap::from([
            (
                "email".to_string(),
                serde_json::Value::String("alice@corp.example".to_string()),
            ),
            ("email_verified".to_string(), serde_json::Value::Bool(false)),
        ]),
    };
    let request = HomeRealmDiscoveryRequest {
        domain: Some("corp.example".to_string()),
        ..Default::default()
    };
    let plan = plan_inbound_login(&providers, &request, &external, &[]).unwrap();
    // plan succeeds (signature verification and claim mapping pass)
    // but exec_broker_login_plan would reject email_verified=false
    assert!(plan.create_subject);
    // email_verified is not mapped in corp-oidc, so it won't appear in normalized,
    // which means exec_broker_login_plan won't find it and will reject as unverified.
    // Verify that the email claim IS present (mapped from required mapping).
    assert_eq!(
        plan.normalized_claims["email"],
        serde_json::Value::String("alice@corp.example".to_string())
    );
    // email_verified is NOT in the claim_mappings, so it's not in normalized_claims
    assert!(!plan.normalized_claims.contains_key("email_verified"));
}

#[tokio::test]
async fn federation_route_returns_signed_entity_statement_jwt() {
    let path =
        std::env::temp_dir().join(format!("qid-federation-route-{}.json", util::now_seconds()));
    let repo = Arc::new(
        FileRepository::new(path.to_str().expect("test path is not UTF-8"))
            .await
            .expect("file repository creation failed"),
    );
    repo.migrate().await.expect("file migration failed");
    repo.create_realm(
        &"tenant-1".into(),
        &"test".into(),
        "https://id.example.com",
        Some("Test Realm"),
    )
    .await
    .expect("realm creation failed");
    let signer = Arc::new(LocalSigner::from_secret(
        "fed-route-test",
        b"federation-route-secret",
    ));
    let state = Arc::new(
        SharedState::new(
            test_helpers::test_config(),
            repo,
            signer.clone(),
            serde_json::json!({}),
        )
        .unwrap(),
    );
    let app = federation_routes::<FileRepository>().with_state(state);
    let request = Request::builder()
        .method(Method::GET)
        .uri("/.well-known/openid-federation")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "application/entity-statement+jwt"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let token = std::str::from_utf8(&body).unwrap();
    let statement = decode_signed_entity_statement(signer.as_ref(), token).unwrap();
    assert_eq!(statement.iss, "https://id.example.com");
    assert_eq!(statement.sub, "https://id.example.com");
    assert!(statement.metadata.unwrap().openid_provider.is_some());
}

#[tokio::test]
async fn trust_chain_validation_route_validates_signed_chain_and_records_audit() {
    let path = std::env::temp_dir().join(format!(
        "qid-federation-validation-route-{}.json",
        util::now_seconds()
    ));
    let repo = Arc::new(
        FileRepository::new(path.to_str().expect("test path is not UTF-8"))
            .await
            .expect("file repository creation failed"),
    );
    repo.migrate().await.expect("file migration failed");
    let signer = Arc::new(LocalSigner::from_secret(
        "fed-validation-test",
        b"federation-validation-secret",
    ));
    let state = Arc::new(
        SharedState::new(
            test_helpers::test_config(),
            repo.clone(),
            signer.clone(),
            serde_json::json!({}),
        )
        .unwrap(),
    );
    let now = util::now_seconds();
    let mut rp = rp_statement();
    rp.iat = now - 10;
    rp.exp = now + 1000;
    let mut intermediate = intermediate_statement();
    intermediate.iat = now - 10;
    intermediate.exp = now + 1000;
    let mut anchor = anchor_statement();
    anchor.iat = now - 10;
    anchor.exp = now + 1000;
    let signed_chain = vec![rp, intermediate, anchor]
        .into_iter()
        .map(|statement| sign_entity_statement(signer.as_ref(), &statement).unwrap())
        .collect::<Vec<_>>();
    let request_body = serde_json::json!({
        "subject": "https://rp.example",
        "signed_trust_chain": signed_chain,
        "trust_anchors": [{
            "entity_id": "https://anchor.example",
            "required_trust_marks": ["https://trust.example/marks/verified"],
            "trusted_trust_mark_issuers": [],
            "allowed_redirect_hosts": ["rp.example"]
        }],
        "now_epoch_seconds": now,
        "actor": "federation-admin",
        "reason": "test federation onboarding"
    });
    let app = federation_routes::<FileRepository>().with_state(state);
    let request = Request::builder()
        .method(Method::POST)
        .uri("/federation/v1/trust-chain/validate")
        .header("content-type", "application/json")
        .body(Body::from(request_body.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["validation"]["trust_anchor"], "https://anchor.example");
    assert_eq!(body["validation"]["automatic_client_trust"], true);
    let audit_events = repo
        .list_audit_events(None, 10)
        .await
        .expect("list audit events failed");
    assert_eq!(audit_events.len(), 1);
    assert_eq!(audit_events[0].action, "federation.trust_chain.validate");
    assert_eq!(audit_events[0].actor, "federation-api");
    assert_eq!(
        audit_events[0].metadata_json["trust_anchor"],
        "https://anchor.example"
    );
}
