use qid_policy::{Decision, DecisionDetails, PolicyContext};
use qid_risk::RiskEvaluation;

const EDGE_PEP_REQUIRED_CAPABILITY_EFFECTS: &[&str] = &[
    "challenge",
    "inject_headers",
    "local_response",
    "override_upstream",
    "cache_bypass",
    "mirror_upstreams",
    "force_inspect",
    "force_tunnel",
    "rate_limit",
    "rate_limit_profile",
    "policy_tags",
];

pub(crate) fn build_explain_json(
    profile: qid_core::config::DeploymentProfile,
    realm_config: Option<&qid_core::config::RealmConfig>,
    ctx: &PolicyContext,
    result: &DecisionDetails,
    active_bundle_name: Option<&str>,
    risk_evaluation: Option<&RiskEvaluation>,
) -> serde_json::Value {
    let assertion_audience = realm_config.and_then(|realm| {
        let adapter_name = ctx.effective_pep_registration()?;
        realm
            .pep_registrations
            .registrations
            .iter()
            .find(|a| a.name == adapter_name)
            .and_then(|a| a.audience.clone())
    });
    let (positive_ttl_seconds, negative_ttl_seconds) = realm_config
        .and_then(|realm| {
            let adapter_name = ctx.effective_pep_registration()?;
            realm
                .pep_registrations
                .registrations
                .iter()
                .find(|a| a.name == adapter_name)
                .map(|a| {
                    (
                        a.decision.cache.positive_ttl_seconds,
                        a.decision.cache.negative_ttl_seconds,
                    )
                })
        })
        .unwrap_or((0, 0));
    let cacheability = serde_json::json!({
        "positive_ttl_seconds": positive_ttl_seconds,
        "negative_ttl_seconds": negative_ttl_seconds,
        "policy_revision": active_bundle_name,
        "cache_key_inputs": {
            "subject": ctx.subject_id,
            "resource_host": ctx.resource_host,
            "resource_action": ctx.resource_action,
            "pep_registration": ctx.effective_pep_registration(),
        },
    });
    let deployment_profile = explain_deployment_profile(profile, realm_config);
    let effective_token_policy = realm_config
        .map(|realm| {
            serde_json::json!({
                "access_token_format": realm.protocols.oauth.tokens.access_token_format,
                "access_token_ttl_seconds": realm.protocols.oauth.tokens.access_token_ttl_seconds,
                "refresh_token_ttl_seconds": realm.protocols.oauth.tokens.refresh_token_ttl_seconds,
                "id_token_ttl_seconds": realm.protocols.oauth.tokens.id_token_ttl_seconds,
                "default_scope": realm.protocols.oauth.default_scope,
                "introspection": {
                    "enabled": realm.protocols.oauth.introspection.enabled,
                    "jwt_response": realm.protocols.oauth.introspection.jwt_response,
                },
                "revocation_enabled": realm.protocols.oauth.revocation.enabled,
                "par_enabled": realm.protocols.oauth.par.enabled,
                "rar_enabled": realm.protocols.oauth.rar.enabled,
                "dpop_enabled": realm.protocols.oauth.dpop.enabled,
                "mtls_enabled": realm.protocols.oauth.mtls.enabled,
                "device_authorization_enabled": realm.protocols.oauth.device_authorization.enabled,
                "ciba_enabled": realm.protocols.oauth.ciba.enabled,
                "dynamic_client_registration_enabled": realm.protocols.oauth.dynamic_client_registration.enabled,
                "private_key_jwt_enabled": realm.protocols.oauth.private_key_jwt.enabled,
                "resource_servers": realm.protocols.oauth.resource_servers.iter().map(|server| {
                    serde_json::json!({
                        "audience": server.audience,
                        "resources": server.resources,
                        "scopes": server.scopes,
                        "introspection_client_ids": server.introspection_client_ids,
                        "high_risk": server.high_risk,
                        "sender_constraint_required": server.require_sender_constraint || server.high_risk,
                    })
                }).collect::<Vec<_>>(),
            })
        })
        .unwrap_or_else(|| serde_json::json!({ "available": false }));
    let effective_client_policy = realm_config
        .map(|realm| {
            serde_json::json!({
                "authorization_code_enabled": realm.protocols.oidc.authorization_code.enabled,
                "pkce_required": realm.protocols.oidc.authorization_code.pkce_required,
                "implicit_allowed": realm.protocols.oidc.implicit.enabled,
                "ropc_allowed": realm.protocols.oidc.ropc.enabled,
                "logout": {
                    "backchannel": realm.protocols.oidc.logout.backchannel,
                    "frontchannel": realm.protocols.oidc.logout.frontchannel,
                },
                "registered_redirect_uri_match": "exact",
                "client_auth_methods": [
                    "client_secret_basic",
                    "client_secret_post",
                    "none",
                    "private_key_jwt"
                ],
                "static_registry": "repository",
            })
        })
        .unwrap_or_else(|| serde_json::json!({ "available": false }));
    let required_auth = explain_required_auth(ctx, result, risk_evaluation);
    let claim_release_plan = serde_json::json!({
        "subject": ctx.subject_id,
        "resource_host": ctx.resource_host,
        "resource_action": ctx.resource_action,
        "groups": ctx.groups,
        "roles": ctx.roles,
        "entitlements": ctx.entitlements,
        "device_id": ctx.device_id,
        "posture": ctx.posture,
        "risk_score": ctx.risk_score,
        "minimize_pii": true,
        "released_claims": explain_released_claims(ctx, result),
    });
    let pep_actions = explain_pep_actions(result, risk_evaluation);
    let audit_fields = serde_json::json!({
        "realm": realm_config.map(|realm| realm.id.as_str()),
        "subject": ctx.subject_id,
        "resource_host": ctx.resource_host,
        "resource_action": ctx.resource_action,
        "pep_registration": ctx.effective_pep_registration(),
        "decision": pep_decision_name(&result.decision),
        "policy_id": result.policy_id,
        "active_policy_bundle": active_bundle_name,
        "matched_rules": result.matched_rules,
        "policy_tags": result.policy_tags,
        "risk_score": risk_evaluation.map(|risk| risk.score),
        "risk_outcome": risk_evaluation.map(|risk| serde_json::to_value(&risk.outcome).expect("risk outcome serialization")),
        "risk_labels": risk_evaluation.map(|risk| risk.labels.clone()),
        "audit_level": risk_evaluation.and_then(|risk| risk.audit_level.clone()),
    });

    serde_json::json!({
        "decision": result,
        "risk_evaluation": risk_evaluation,
        "deployment_profile": deployment_profile,
        "effective_client_policy": effective_client_policy,
        "effective_token_policy": effective_token_policy,
        "required_auth": required_auth,
        "claim_release_plan": claim_release_plan,
        "pep_actions": pep_actions,
        "cacheability": cacheability,
        "assertion_audience": assertion_audience,
        "policy_decision_trace": result.trace,
        "audit_fields": audit_fields,
    })
}

fn explain_deployment_profile(
    profile: qid_core::config::DeploymentProfile,
    realm_config: Option<&qid_core::config::RealmConfig>,
) -> serde_json::Value {
    let obligations = match profile {
        qid_core::config::DeploymentProfile::Oidc => serde_json::json!({
            "strict": true,
            "requires_oidc_authorization_code": true,
            "requires_pkce": true,
            "requires_pep_registration": false,
            "requires_passkeys": false,
            "requires_scim": false,
            "requires_par": false,
            "requires_rar": false,
            "requires_dpop": false,
            "requires_mtls": false,
            "requires_private_key_jwt": false,
            "requires_jarm": false,
            "requires_jwt_introspection": false,
            "requires_sender_constrained_resource_servers": false,
        }),
        qid_core::config::DeploymentProfile::EdgePep => serde_json::json!({
            "strict": true,
            "requires_http_message_signatures": true,
            "requires_pep_registration": true,
            "requires_fail_closed_pep_decision": true,
            "requires_capability_effects": EDGE_PEP_REQUIRED_CAPABILITY_EFFECTS,
            "requires_passkeys": false,
            "requires_scim": false,
            "requires_par": false,
            "requires_rar": false,
            "requires_dpop": false,
            "requires_mtls": true,
            "requires_private_key_jwt": false,
            "requires_jarm": false,
            "requires_jwt_introspection": false,
            "requires_sender_constrained_resource_servers": false,
        }),
        qid_core::config::DeploymentProfile::Enterprise => serde_json::json!({
            "strict": true,
            "requires_pep_registration": false,
            "requires_passkeys": true,
            "requires_scim": true,
            "requires_scim_cursor_secret": true,
            "requires_scim_event_callback_allowlist": true,
            "requires_saml": true,
            "requires_signed_saml_assertions": true,
            "requires_signed_saml_metadata": true,
            "requires_saml_service_provider": true,
            "requires_directory_sync": true,
            "requires_ldaps_directory_provider": true,
            "requires_par": false,
            "requires_rar": false,
            "requires_dpop": false,
            "requires_mtls": false,
            "requires_private_key_jwt": false,
            "requires_jarm": false,
            "requires_jwt_introspection": false,
            "requires_sender_constrained_resource_servers": false,
        }),
        qid_core::config::DeploymentProfile::Ciam => serde_json::json!({
            "strict": true,
            "requires_pep_registration": false,
            "requires_passkeys": true,
            "requires_scim": false,
            "requires_oidc_discovery": true,
            "requires_oidc_userinfo": true,
            "requires_oidc_authorization_code": true,
            "requires_pkce": true,
            "requires_fedcm": true,
            "requires_ciam_consent": true,
            "requires_ciam_progressive_profile": true,
            "requires_ciam_identity_proofing": true,
            "requires_ciam_privacy_dashboard": true,
            "requires_inbound_federation": true,
            "requires_inbound_oidc_or_social_provider": true,
            "requires_par": false,
            "requires_rar": false,
            "requires_dpop": false,
            "requires_mtls": false,
            "requires_private_key_jwt": false,
            "requires_jarm": false,
            "requires_jwt_introspection": false,
            "requires_sender_constrained_resource_servers": false,
        }),
        qid_core::config::DeploymentProfile::Fapi => serde_json::json!({
            "strict": true,
            "requires_http_message_signatures": true,
            "requires_pep_registration": false,
            "requires_passkeys": false,
            "requires_scim": false,
            "requires_par": true,
            "requires_rar": true,
            "requires_dpop": true,
            "requires_mtls": true,
            "requires_private_key_jwt": true,
            "requires_jarm": true,
            "requires_signed_request_object": true,
            "requires_jwt_introspection": true,
            "requires_sender_constrained_resource_servers": true,
        }),
        qid_core::config::DeploymentProfile::HighAssurance => serde_json::json!({
            "strict": true,
            "requires_http_message_signatures": true,
            "requires_pep_registration": false,
            "requires_passkeys": true,
            "requires_scim": false,
            "requires_par": true,
            "requires_rar": true,
            "requires_dpop": true,
            "requires_mtls": true,
            "requires_private_key_jwt": true,
            "requires_jarm": true,
            "requires_signed_request_object": true,
            "requires_jwt_introspection": true,
            "requires_sender_constrained_resource_servers": true,
            "requires_remote_kms_hsm_or_pkcs11_keyrings": true,
            "requires_admin_approval": true,
            "requires_admin_step_up": true,
            "requires_backup": true,
            "requires_passwordless_only": true,
        }),
        qid_core::config::DeploymentProfile::Vc => serde_json::json!({
            "strict": true,
            "requires_http_message_signatures": true,
            "requires_pep_registration": false,
            "requires_passkeys": false,
            "requires_scim": false,
            "requires_par": true,
            "requires_rar": true,
            "requires_dpop": true,
            "requires_mtls": true,
            "requires_private_key_jwt": true,
            "requires_jarm": true,
            "requires_signed_request_object": true,
            "requires_jwt_introspection": true,
            "requires_sender_constrained_resource_servers": true,
            "requires_oid4vci": true,
            "requires_oid4vp": true,
            "requires_haip": true,
            "requires_vc_data_model_2_0": true,
            "requires_jose_cose": true,
            "requires_vc_status_list": true,
            "requires_holder_binding": true,
        }),
        qid_core::config::DeploymentProfile::Workload => serde_json::json!({
            "strict": true,
            "requires_pep_registration": false,
            "requires_passkeys": false,
            "requires_scim": false,
            "requires_par": false,
            "requires_rar": false,
            "requires_dpop": false,
            "requires_mtls": true,
            "requires_private_key_jwt": true,
            "requires_jarm": false,
            "requires_jwt_introspection": false,
            "requires_sender_constrained_resource_servers": false,
        }),
        qid_core::config::DeploymentProfile::NetworkAaa => serde_json::json!({
            "strict": true,
            "requires_radius": true,
            "requires_radius_tls": true,
            "requires_eap": true,
            "requires_eap_tls": true,
            "requires_capport": true,
            "requires_coa": true,
            "requires_accounting": true,
            "requires_directory_authority": true,
            "requires_mtls": true,
            "requires_shared_secret": true,
            "requires_radius_authentication_bind": true,
            "requires_radius_tls_bind": true,
            "requires_accounting_bind": true,
            "requires_coa_bind": true,
            "requires_radius_tls_certificate_path": true,
            "requires_radius_tls_private_key_path": true,
            "requires_radius_tls_client_ca_path": true,
            "requires_enabled_directory_authority": true,
        }),
    };
    let realm_status = realm_config.map(|realm| {
        serde_json::json!({
            "realm": realm.id,
            "pep_registrations": realm.pep_registrations.registrations.len(),
            "all_pep_decision_fail_closed": realm.pep_registrations.registrations.iter().all(|adapter| adapter.decision.fail_policy == "deny"),
            "passkeys_enabled": realm.authentication.passkeys.enabled,
            "scim_enabled": realm.protocols.scim.enabled,
            "par_enabled": realm.protocols.oauth.par.enabled,
            "rar_enabled": realm.protocols.oauth.rar.enabled,
            "dpop_enabled": realm.protocols.oauth.dpop.enabled,
            "mtls_enabled": realm.protocols.oauth.mtls.enabled,
            "private_key_jwt_enabled": realm.protocols.oauth.private_key_jwt.enabled,
            "jwt_introspection_enabled": realm.protocols.oauth.introspection.jwt_response,
            "sender_constrained_resource_servers": realm.protocols.oauth.resource_servers.iter().all(|server| server.require_sender_constraint || server.high_risk),
        })
    });
    serde_json::json!({
        "name": profile.as_str(),
        "obligations": obligations,
        "realm_status": realm_status,
    })
}

fn explain_required_auth(
    ctx: &PolicyContext,
    result: &DecisionDetails,
    risk_evaluation: Option<&RiskEvaluation>,
) -> serde_json::Value {
    let risk_requires_auth = risk_evaluation.is_some_and(|risk| risk.required_acr.is_some());
    let step_up_required = matches!(result.decision, Decision::StepUp) || risk_requires_auth;
    let amr = risk_evaluation
        .map(|risk| risk.required_amr.clone())
        .filter(|amr| !amr.is_empty())
        .unwrap_or_else(|| {
            if matches!(result.decision, Decision::StepUp) {
                vec!["webauthn".to_string(), "totp".to_string()]
            } else {
                Vec::new()
            }
        });
    serde_json::json!({
        "acr": risk_evaluation
            .and_then(|risk| risk.required_acr.clone())
            .or_else(|| ctx.acr.clone()),
        "amr": amr,
        "auth_age_seconds": ctx.auth_age_seconds,
        "step_up_required": step_up_required,
    })
}

fn explain_pep_actions(
    result: &DecisionDetails,
    risk_evaluation: Option<&RiskEvaluation>,
) -> serde_json::Value {
    let local_response = matches!(
        result.decision,
        Decision::Deny | Decision::LocalResponse | Decision::ApprovalRequired
    )
    .then(|| {
        let error_msg = match result.decision {
            Decision::ApprovalRequired => "approval_required",
            _ => "access_denied",
        };
        serde_json::json!({
            "status": 403,
            "content_type": "application/json",
            "body": {
                "error": error_msg,
                "decision_id": result.policy_id,
            },
        })
    });
    let force_inspect = result
        .pep
        .force_inspect
        .or_else(|| risk_evaluation.map(|risk| risk.pep_force_inspect));
    let force_tunnel = result
        .pep
        .force_tunnel
        .or_else(|| risk_evaluation.map(|risk| risk.pep_force_tunnel));
    let cache_bypass = result.pep.cache_bypass.or_else(|| {
        risk_evaluation.map(|risk| {
            matches!(
                risk.outcome,
                qid_risk::RiskOutcome::Deny | qid_risk::RiskOutcome::ForceInspect
            )
        })
    });
    let rate_limit_profile = result
        .rate_limit_profile
        .clone()
        .or_else(|| risk_evaluation.and_then(|risk| risk.rate_limit_profile.clone()));
    let mut policy_tags = result.policy_tags.clone();
    if let Some(risk) = risk_evaluation {
        policy_tags.extend(risk.labels.iter().map(|label| format!("risk:{label}")));
    }
    dedupe_explain_strings(&mut policy_tags);
    serde_json::json!({
        "decision": pep_decision_name(&result.decision),
        "status": match result.decision {
            Decision::Deny | Decision::LocalResponse | Decision::ApprovalRequired => Some(403),
            Decision::StepUp | Decision::ConsentRequired => Some(302),
            Decision::Allow | Decision::AuditOnly | Decision::Quarantine => None,
            Decision::Conditional => Some(299),
        },
        "ttl_ms": pep_decision_ttl_ms(&result.decision),
        "request_add": result.inject_headers.as_ref().map(|_| serde_json::json!({
            "x-qid-decision-id": [result.policy_id.clone()],
        })),
        "request_set": result.inject_headers,
        "request_remove": null,
        "response_set": null,
        "response_add": null,
        "response_remove": null,
        "local_response": local_response,
        "force_inspect": force_inspect,
        "force_tunnel": force_tunnel,
        "cache_bypass": cache_bypass,
        "mirror_upstreams": result.pep.mirror_upstreams,
        "override_upstream": result.pep.override_upstream,
        "timeout_override_ms": result.pep.timeout_override_ms,
        "rate_limit_profile": rate_limit_profile,
        "policy_tags": policy_tags,
    })
}

fn dedupe_explain_strings(values: &mut Vec<String>) {
    let mut seen = std::collections::BTreeSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn explain_released_claims(ctx: &PolicyContext, result: &DecisionDetails) -> Vec<&'static str> {
    let mut claims = vec!["sub", "policy_tags"];
    if matches!(
        result.decision,
        Decision::Allow
            | Decision::StepUp
            | Decision::AuditOnly
            | Decision::Quarantine
            | Decision::Conditional
    ) {
        if !ctx.groups.is_empty() {
            claims.push("groups");
        }
        if !ctx.roles.is_empty() {
            claims.push("roles");
        }
        if !ctx.entitlements.is_empty() {
            claims.push("entitlements");
        }
        if ctx.device_id.is_some() {
            claims.push("device");
        }
        if ctx.acr.is_some() || ctx.auth_age_seconds.is_some() {
            claims.push("auth");
        }
        if ctx.risk_score.is_some() {
            claims.push("risk");
        }
    }
    claims
}

fn pep_decision_name(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow | Decision::AuditOnly => "allow",
        Decision::Deny => "deny",
        Decision::StepUp | Decision::ConsentRequired => "challenge",
        Decision::LocalResponse => "local_response",
        Decision::ApprovalRequired => "approval_required",
        Decision::Quarantine => "quarantine",
        Decision::Conditional => "conditional",
    }
}

fn pep_decision_ttl_ms(decision: &Decision) -> u64 {
    match decision {
        Decision::Allow | Decision::AuditOnly | Decision::Quarantine => 30_000,
        _ => 5_000,
    }
}
