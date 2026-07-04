use super::*;

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

fn push_fapi_profile_checks(checks: &mut Vec<CheckItem>, config: &QidConfig, profile_name: &str) {
    checks.push(if config.server.http_message_signatures.enabled {
        check_ok(
            format!("profile.{profile_name}.http_message_signatures"),
            "HTTP Message Signatures enabled",
        )
    } else {
        check_error(
            format!("profile.{profile_name}.http_message_signatures"),
            "requires HTTP Message Signatures",
        )
    });
    for realm in &config.realms {
        let oauth = &realm.protocols.oauth;
        for (enabled, feature) in [
            (oauth.par.enabled, "par"),
            (oauth.rar.enabled, "rar"),
            (oauth.dpop.enabled, "dpop"),
            (oauth.mtls.enabled, "mtls"),
            (oauth.private_key_jwt.enabled, "private_key_jwt"),
            (oauth.jarm.enabled, "jarm"),
        ] {
            let name = format!("profile.{profile_name}.{feature}.realm.{}", realm.id);
            checks.push(if enabled {
                check_ok(&name, format!("{feature} enabled"))
            } else {
                check_error(&name, format!("requires {feature}"))
            });
        }
        let par_required = format!(
            "profile.{profile_name}.require_pushed_authorization_requests.realm.{}",
            realm.id
        );
        checks.push(if oauth.require_pushed_authorization_requests {
            check_ok(&par_required, "pushed authorization requests required")
        } else {
            check_error(
                &par_required,
                "requires require_pushed_authorization_requests",
            )
        });
        let jar = format!(
            "profile.{profile_name}.signed_request_object.realm.{}",
            realm.id
        );
        checks.push(
            if realm
                .protocols
                .oidc
                .authorization_code
                .require_signed_request_object
            {
                check_ok(&jar, "signed request objects required")
            } else {
                check_error(&jar, "requires signed request objects")
            },
        );
        let jwt_intro = format!(
            "profile.{profile_name}.jwt_introspection.realm.{}",
            realm.id
        );
        checks.push(if oauth.introspection.jwt_response {
            check_ok(&jwt_intro, "JWT introspection enabled")
        } else {
            check_error(&jwt_intro, "requires JWT introspection response")
        });
        let sender_constrained = format!(
            "profile.{profile_name}.sender_constrained_resource_servers.realm.{}",
            realm.id
        );
        let has_sender_constrained_resource_servers = !oauth.resource_servers.is_empty()
            && oauth
                .resource_servers
                .iter()
                .all(|server| server.require_sender_constraint || server.high_risk);
        checks.push(if has_sender_constrained_resource_servers {
            check_ok(
                &sender_constrained,
                "sender-constrained resource servers configured",
            )
        } else {
            check_error(
                &sender_constrained,
                "requires sender-constrained OAuth resource servers",
            )
        });
    }
}

pub(crate) fn check_deployment_profile(
    config: &QidConfig,
    plan: &qid_core::plan::RuntimePlan,
) -> CheckItem {
    let realm_count = plan.realms.len();
    let message = format!(
        "deployment profile {} is compiled for {realm_count} realm(s)",
        config.profile.as_str()
    );
    check_ok(format!("profile.{}", config.profile.as_str()), message)
}

pub(crate) fn check_profile_obligations(config: &QidConfig) -> Vec<CheckItem> {
    let profile = config.profile;
    let mut checks = Vec::new();
    match profile {
        qid_core::config::DeploymentProfile::Oidc => {
            for realm in &config.realms {
                let auth_code = format!("profile.oidc.authorization_code.realm.{}", realm.id);
                checks.push(
                    if realm.protocols.oidc.enabled
                        && realm.protocols.oidc.authorization_code.enabled
                    {
                        check_ok(&auth_code, "OIDC authorization code enabled")
                    } else {
                        check_error(&auth_code, "requires OIDC authorization code")
                    },
                );
                let pkce = format!("profile.oidc.pkce.realm.{}", realm.id);
                checks.push(if realm.protocols.oidc.authorization_code.pkce_required {
                    check_ok(&pkce, "PKCE required")
                } else {
                    check_error(&pkce, "requires PKCE")
                });
            }
        }
        qid_core::config::DeploymentProfile::EdgePep => {
            checks.push(if config.server.http_message_signatures.enabled {
                check_ok(
                    "profile.edge-pep.http_message_signatures",
                    "HTTP Message Signatures enabled",
                )
            } else {
                check_error(
                    "profile.edge-pep.http_message_signatures",
                    "requires HTTP Message Signatures",
                )
            });
            let registration_count: usize = config
                .realms
                .iter()
                .filter(|realm| realm.pep_registrations.enabled)
                .flat_map(|r| r.pep_registrations.registrations.iter())
                .count();
            checks.push(if registration_count > 0 {
                check_ok(
                    "profile.edge-pep.registrations",
                    format!("{registration_count} PEP registration(s) configured"),
                )
            } else {
                check_error(
                    "profile.edge-pep.registrations",
                    "requires at least one PEP registration".to_string(),
                )
            });
            for realm in &config.realms {
                if realm.pep_registrations.enabled {
                    let mtls = format!("profile.edge-pep.mtls.realm.{}", realm.id);
                    checks.push(if realm.protocols.oauth.mtls.enabled {
                        check_ok(&mtls, "mTLS enabled")
                    } else {
                        check_error(&mtls, "requires mTLS")
                    });
                    for registration in &realm.pep_registrations.registrations {
                        let name = format!(
                            "profile.edge-pep.fail_policy.realm.{}.{}",
                            realm.id, registration.name
                        );
                        checks.push(if registration.decision.fail_policy == "deny" {
                            check_ok(&name, "fail_policy=deny")
                        } else {
                            check_error(
                                &name,
                                format!(
                                    "requires fail_policy=deny, got {}",
                                    registration.decision.fail_policy
                                ),
                            )
                        });
                        for capability in EDGE_PEP_REQUIRED_CAPABILITY_EFFECTS {
                            let capability_name = format!(
                                "profile.edge-pep.capability.realm.{}.{}.{}",
                                realm.id, registration.name, capability
                            );
                            checks.push(
                                if registration
                                    .capabilities
                                    .iter()
                                    .any(|configured| configured.effect == *capability)
                                {
                                    check_ok(
                                        &capability_name,
                                        format!("capability effect {capability} configured"),
                                    )
                                } else {
                                    check_error(
                                        &capability_name,
                                        format!("requires capability effect {capability}"),
                                    )
                                },
                            );
                        }
                    }
                }
            }
        }
        qid_core::config::DeploymentProfile::Enterprise => {
            for realm in &config.realms {
                let pk = format!("profile.enterprise.passkeys.realm.{}", realm.id);
                checks.push(if realm.authentication.passkeys.enabled {
                    check_ok(&pk, "passkeys enabled")
                } else {
                    check_error(&pk, "requires passkeys")
                });
                let scim = format!("profile.enterprise.scim.realm.{}", realm.id);
                checks.push(if realm.protocols.scim.enabled {
                    check_ok(&scim, "SCIM enabled")
                } else {
                    check_error(&scim, "requires SCIM")
                });
                let scim_cursor = format!("profile.enterprise.scim_cursor.realm.{}", realm.id);
                checks.push(
                    if realm
                        .protocols
                        .scim
                        .cursor_secret
                        .as_deref()
                        .is_some_and(|secret| secret.len() >= 32)
                    {
                        check_ok(&scim_cursor, "SCIM cursor secret configured")
                    } else {
                        check_error(&scim_cursor, "requires SCIM cursor_secret")
                    },
                );
                let scim_callbacks =
                    format!("profile.enterprise.scim_callbacks.realm.{}", realm.id);
                checks.push(
                    if !realm.protocols.scim.event_callback_allowed_hosts.is_empty() {
                        check_ok(&scim_callbacks, "SCIM callback host allowlist configured")
                    } else {
                        check_error(&scim_callbacks, "requires SCIM callback host allowlist")
                    },
                );
                let saml = format!("profile.enterprise.saml.realm.{}", realm.id);
                checks.push(
                    if realm.protocols.saml.enabled
                        && realm.protocols.saml.sign_assertions
                        && realm.protocols.saml.sign_metadata
                        && !realm.protocols.saml.service_providers.is_empty()
                    {
                        check_ok(&saml, "SAML signed assertions and metadata configured")
                    } else {
                        check_error(
                            &saml,
                            "requires SAML, signed assertions, XMLDSig metadata, and SPs",
                        )
                    },
                );
                let directory = format!("profile.enterprise.directory.realm.{}", realm.id);
                let has_enterprise_directory =
                    realm.protocols.directory.providers.iter().any(|provider| {
                        provider.enabled
                            && matches!(
                                provider.provider_type.as_str(),
                                "ldap" | "active-directory"
                            )
                            && provider.connection.url.starts_with("ldaps://")
                            && provider.connection.bind_dn.is_some()
                            && provider.connection.bind_password.is_some()
                            && provider.connection.base_dn.is_some()
                            && !provider.connection.tls_insecure_skip_verify
                    });
                checks.push(
                    if realm.protocols.directory.enabled && has_enterprise_directory {
                        check_ok(&directory, "LDAPS directory provider configured")
                    } else {
                        check_error(&directory, "requires an enabled LDAPS directory provider")
                    },
                );
            }
        }
        qid_core::config::DeploymentProfile::Ciam => {
            for realm in &config.realms {
                let oidc = format!("profile.ciam.oidc.realm.{}", realm.id);
                checks.push(
                    if realm.protocols.oidc.enabled
                        && realm.protocols.oidc.discovery
                        && realm.protocols.oidc.userinfo
                        && realm.protocols.oidc.authorization_code.enabled
                        && realm.protocols.oidc.authorization_code.pkce_required
                    {
                        check_ok(
                            &oidc,
                            "OIDC discovery, userinfo, authorization code, and PKCE configured",
                        )
                    } else {
                        check_error(
                            &oidc,
                            "requires OIDC discovery, userinfo, authorization code, and PKCE",
                        )
                    },
                );
                let passkeys = format!("profile.ciam.passkeys.realm.{}", realm.id);
                checks.push(if realm.authentication.passkeys.enabled {
                    check_ok(&passkeys, "passkeys enabled")
                } else {
                    check_error(&passkeys, "requires passkeys")
                });
                let fedcm = format!("profile.ciam.fedcm.realm.{}", realm.id);
                checks.push(if realm.protocols.fedcm.enabled {
                    check_ok(&fedcm, "FedCM enabled")
                } else {
                    check_error(&fedcm, "requires FedCM")
                });
                let ciam = &realm.protocols.ciam;
                for (enabled, feature) in [
                    (ciam.consent, "consent"),
                    (ciam.progressive_profile, "progressive_profile"),
                    (ciam.identity_proofing, "identity_proofing"),
                    (ciam.privacy_dashboard, "privacy_dashboard"),
                ] {
                    let name = format!("profile.ciam.{feature}.realm.{}", realm.id);
                    checks.push(if enabled {
                        check_ok(&name, format!("{feature} enabled"))
                    } else {
                        check_error(&name, format!("requires {feature}"))
                    });
                }
                let federation = format!("profile.ciam.federation.realm.{}", realm.id);
                let has_social_or_oidc =
                    realm
                        .protocols
                        .federation
                        .inbound_providers
                        .iter()
                        .any(|provider| {
                            provider.enabled
                                && matches!(provider.kind.as_str(), "oidc" | "social")
                                && provider
                                    .client_id
                                    .as_deref()
                                    .is_some_and(|value| !value.is_empty())
                                && provider
                                    .client_secret
                                    .as_deref()
                                    .is_some_and(|value| !value.is_empty())
                                && !provider.domains.is_empty()
                                && provider.account_linking
                                && provider.jit_provisioning
                                && (provider.kind == "oidc" || provider.social_provider.is_some())
                        });
                checks.push(if realm.protocols.federation.enabled && has_social_or_oidc {
                    check_ok(&federation, "inbound OIDC or social provider configured")
                } else {
                    check_error(
                        &federation,
                        "requires inbound OIDC or social provider with client credentials, domains, account linking, and JIT provisioning",
                    )
                });
            }
        }
        qid_core::config::DeploymentProfile::Fapi => {
            push_fapi_profile_checks(&mut checks, config, "fapi");
        }
        qid_core::config::DeploymentProfile::Vc => {
            push_fapi_profile_checks(&mut checks, config, "vc");
            for realm in &config.realms {
                let vc = &realm.protocols.vc;
                for (enabled, feature) in [
                    (vc.oid4vci, "OID4VCI"),
                    (vc.oid4vp, "OID4VP"),
                    (vc.haip, "HAIP"),
                    (vc.vc_data_model_2_0, "VC Data Model 2.0"),
                    (vc.jose_cose, "JOSE/COSE"),
                    (vc.status_list, "VC status list"),
                    (vc.holder_binding_required, "holder binding"),
                ] {
                    let name = format!("profile.vc.{feature}.realm.{}", realm.id);
                    checks.push(if enabled {
                        check_ok(&name, format!("{feature} configured"))
                    } else {
                        check_error(&name, format!("requires {feature}"))
                    });
                }
                let issuer_key = format!("profile.vc.issuer_key_ref.realm.{}", realm.id);
                checks.push(
                    if vc
                        .issuer_key_ref
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty())
                    {
                        check_ok(&issuer_key, "issuer key reference configured")
                    } else {
                        check_error(&issuer_key, "requires issuer_key_ref")
                    },
                );
            }
        }
        qid_core::config::DeploymentProfile::Workload => {
            for realm in &config.realms {
                let workload = &realm.protocols.workload;
                for (enabled, feature) in [
                    (workload.spiffe_workload_api, "SPIFFE Workload API"),
                    (workload.x509_svid, "X.509-SVID"),
                    (workload.jwt_svid, "JWT-SVID"),
                    (workload.short_lived_credentials, "short-lived credentials"),
                    (workload.rats_eat, "RATS/EAT"),
                    (workload.token_exchange, "OAuth token exchange"),
                ] {
                    let name = format!("profile.workload.{feature}.realm.{}", realm.id);
                    checks.push(if enabled {
                        check_ok(&name, format!("{feature} configured"))
                    } else {
                        check_error(&name, format!("requires {feature}"))
                    });
                }
                let ca_key = format!("profile.workload.workload_ca_key_ref.realm.{}", realm.id);
                checks.push(
                    if workload
                        .workload_ca_key_ref
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty())
                    {
                        check_ok(&ca_key, "workload CA key reference configured")
                    } else {
                        check_error(&ca_key, "requires workload_ca_key_ref")
                    },
                );
                let mtls = format!("profile.workload.mtls.realm.{}", realm.id);
                checks.push(if realm.protocols.oauth.mtls.enabled {
                    check_ok(&mtls, "mTLS enabled")
                } else {
                    check_error(&mtls, "requires mTLS")
                });
                let pkj = format!("profile.workload.private_key_jwt.realm.{}", realm.id);
                checks.push(if realm.protocols.oauth.private_key_jwt.enabled {
                    check_ok(&pkj, "private_key_jwt enabled")
                } else {
                    check_error(&pkj, "requires private_key_jwt")
                });
            }
        }
        qid_core::config::DeploymentProfile::HighAssurance => {
            push_fapi_profile_checks(&mut checks, config, "high-assurance");
            let kms = config
                .crypto
                .keyrings
                .iter()
                .all(|kr| matches!(kr.signer.r#type.as_str(), "kms" | "hsm" | "pkcs11"));
            checks.push(if !config.crypto.keyrings.is_empty() && kms {
                check_ok(
                    "profile.high-assurance.keyrings",
                    "KMS/HSM/PKCS#11 keyrings configured",
                )
            } else {
                check_error(
                    "profile.high-assurance.keyrings",
                    "requires KMS/HSM/PKCS#11 keyrings",
                )
            });
            checks.push(if config.admin.security.require_approval {
                check_ok(
                    "profile.high-assurance.admin_approval",
                    "admin approval required",
                )
            } else {
                check_error(
                    "profile.high-assurance.admin_approval",
                    "requires admin approval",
                )
            });
            checks.push(if config.admin.security.require_step_up {
                check_ok(
                    "profile.high-assurance.admin_step_up",
                    "admin step-up required",
                )
            } else {
                check_error(
                    "profile.high-assurance.admin_step_up",
                    "requires admin step-up",
                )
            });
            checks.push(if config.ops.backup.enabled {
                check_ok("profile.high-assurance.backup", "backup enabled")
            } else {
                check_error("profile.high-assurance.backup", "requires backup")
            });
            for realm in &config.realms {
                let pk = format!("profile.high-assurance.passkeys.realm.{}", realm.id);
                checks.push(if realm.authentication.passkeys.enabled {
                    check_ok(&pk, "passkeys enabled")
                } else {
                    check_error(&pk, "requires passkeys")
                });
                let mtls = format!("profile.high-assurance.mtls.realm.{}", realm.id);
                checks.push(if realm.protocols.oauth.mtls.enabled {
                    check_ok(&mtls, "mTLS enabled")
                } else {
                    check_error(&mtls, "requires mTLS")
                });
                let pl = format!("profile.high-assurance.passwordless.realm.{}", realm.id);
                checks.push(if realm.authentication.passwordless_only {
                    check_ok(&pl, "passwordless_only enabled")
                } else {
                    check_error(&pl, "requires passwordless_only")
                });
            }
        }
        qid_core::config::DeploymentProfile::NetworkAaa => {
            for realm in &config.realms {
                let network_aaa = &realm.protocols.network_aaa;
                for (enabled, feature) in [
                    (network_aaa.radius, "RADIUS"),
                    (network_aaa.radius_tls, "RADIUS/TLS"),
                    (network_aaa.eap, "EAP"),
                    (network_aaa.eap_tls, "EAP-TLS"),
                    (network_aaa.capport, "CAPPORT"),
                    (network_aaa.coa, "RADIUS CoA"),
                    (network_aaa.accounting, "RADIUS accounting"),
                    (network_aaa.directory_authority, "directory authority"),
                ] {
                    let name = format!("profile.network-aaa.{feature}.realm.{}", realm.id);
                    checks.push(if enabled {
                        check_ok(&name, format!("{feature} configured"))
                    } else {
                        check_error(&name, format!("requires {feature}"))
                    });
                }
                let mtls = format!("profile.network-aaa.mtls.realm.{}", realm.id);
                checks.push(if realm.protocols.oauth.mtls.enabled {
                    check_ok(&mtls, "mTLS enabled")
                } else {
                    check_error(&mtls, "requires mTLS")
                });
                let secret = format!("profile.network-aaa.shared_secret.realm.{}", realm.id);
                checks.push(
                    if network_aaa
                        .shared_secret
                        .as_deref()
                        .is_some_and(|value| value.len() >= 16)
                    {
                        check_ok(&secret, "RADIUS shared secret configured")
                    } else {
                        check_error(&secret, "requires shared_secret of at least 16 bytes")
                    },
                );
                for (value, field) in [
                    (
                        network_aaa.radius_authentication_bind.as_deref(),
                        "radius_authentication_bind",
                    ),
                    (network_aaa.radius_tls_bind.as_deref(), "radius_tls_bind"),
                    (network_aaa.accounting_bind.as_deref(), "accounting_bind"),
                    (network_aaa.coa_bind.as_deref(), "coa_bind"),
                ] {
                    let name = format!("profile.network-aaa.{field}.realm.{}", realm.id);
                    checks.push(
                        if value.is_some_and(|bind| bind.parse::<std::net::SocketAddr>().is_ok()) {
                            check_ok(&name, "listener bind address configured")
                        } else {
                            check_error(&name, format!("requires valid {field}"))
                        },
                    );
                }
                for (value, field) in [
                    (
                        network_aaa.radius_tls_certificate_path.as_deref(),
                        "radius_tls_certificate_path",
                    ),
                    (
                        network_aaa.radius_tls_private_key_path.as_deref(),
                        "radius_tls_private_key_path",
                    ),
                    (
                        network_aaa.radius_tls_client_ca_path.as_deref(),
                        "radius_tls_client_ca_path",
                    ),
                ] {
                    let name = format!("profile.network-aaa.{field}.realm.{}", realm.id);
                    checks.push(if value.is_some_and(|path| !path.trim().is_empty()) {
                        check_ok(&name, "TLS material path configured")
                    } else {
                        check_error(&name, format!("requires {field}"))
                    });
                }
                let directory = format!("profile.network-aaa.directory.realm.{}", realm.id);
                let has_directory_authority = realm.protocols.directory.enabled
                    && realm
                        .protocols
                        .directory
                        .providers
                        .iter()
                        .any(|provider| provider.enabled);
                checks.push(if has_directory_authority {
                    check_ok(&directory, "directory authority configured")
                } else {
                    check_error(&directory, "requires an enabled directory authority")
                });
            }
        }
    }
    checks
}
