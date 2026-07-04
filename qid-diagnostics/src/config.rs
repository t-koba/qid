use super::*;
use std::path::PathBuf;

pub(crate) fn check_issuer_alignment(
    config: &QidConfig,
    plan: &qid_core::plan::RuntimePlan,
) -> Vec<CheckItem> {
    plan.realms
        .iter()
        .map(|realm| {
            if realm.issuer.starts_with(&config.server.public_base_url) {
                check_ok(
                    format!("issuer.{}", realm.id),
                    format!("issuer {} is aligned with public_base_url", realm.issuer),
                )
            } else {
                check_warning(
                    format!("issuer.{}", realm.id),
                    format!(
                        "issuer {} does not start with public_base_url {}",
                        realm.issuer, config.server.public_base_url
                    ),
                )
            }
        })
        .collect()
}

pub(crate) fn check_weak_flows(config: &QidConfig) -> Vec<CheckItem> {
    config
        .realms
        .iter()
        .flat_map(|realm| {
            let high_risk_audiences: Vec<&str> = realm
                .protocols
                .oauth
                .resource_servers
                .iter()
                .filter(|rs| rs.high_risk)
                .map(|rs| rs.audience.as_str())
                .collect();
            let has_high_risk = !high_risk_audiences.is_empty();

            let mut items: Vec<CheckItem> = vec![
                (
                    format!("weak_flow.{}.implicit", realm.id),
                    realm.protocols.oidc.implicit.enabled,
                    "implicit flow",
                ),
                (
                    format!("weak_flow.{}.ropc", realm.id),
                    realm.protocols.oidc.ropc.enabled,
                    "ROPC flow",
                ),
            ]
            .into_iter()
            .map(|(name, enabled, label)| {
                if enabled {
                    check_error(name, format!("{label} is enabled"))
                } else {
                    check_ok(name, format!("{label} is disabled"))
                }
            })
            .collect();

            if has_high_risk {
                let mfa = &realm.authentication.mfa;
                let strong_mfa = mfa.totp.enabled
                    || realm.authentication.passkeys.enabled
                    || mfa
                        .allowed
                        .iter()
                        .any(|m| m != "sms" && m != "phone");
                let weak_mfa_name = format!("weak_mfa.{}", realm.id);
                if mfa.sms.enabled && !strong_mfa {
                    items.push(check_error(
                        weak_mfa_name,
                        format!(
                            "high-risk audiences {:?} enabled but MFA is SMS-only; require TOTP or passkeys",
                            high_risk_audiences
                        ),
                    ));
                } else if !mfa.sms.enabled && !strong_mfa {
                    items.push(check_error(
                        weak_mfa_name,
                        format!(
                            "high-risk audiences {:?} enabled but no MFA configured",
                            high_risk_audiences
                        ),
                    ));
                } else {
                    items.push(check_ok(
                        weak_mfa_name,
                        format!(
                            "high-risk audiences {:?} have strong MFA configured",
                            high_risk_audiences
                        ),
                    ));
                }
            }

            items
        })
        .collect()
}

pub(crate) fn check_policy_bundles(config: &QidConfig, config_path: &Path) -> Vec<CheckItem> {
    config
        .realms
        .iter()
        .flat_map(|realm| {
            if realm.policy.bundles.is_empty() {
                return vec![check_warning(
                    format!("policy_bundle.{}", realm.id),
                    format!(
                        "realm {} has no configured policy bundle; default_decision={}",
                        realm.id, realm.policy.default_decision
                    ),
                )];
            }
            realm
                .policy
                .bundles
                .iter()
                .map(|bundle| {
                    if bundle.mode != "enforce" && bundle.mode != "dry_run" {
                        return check_error(
                            format!("policy_bundle.{}.{}", realm.id, bundle.name),
                            format!("unsupported policy bundle mode: {}", bundle.mode),
                        );
                    }
                    match policy_bundle_source_status(config_path, &bundle.source) {
                        PolicyBundleSourceStatus::Readable(path) => {
                            let content = match std::fs::read_to_string(&path) {
                                Ok(c) => c,
                                Err(e) => {
                                    return check_error(
                                        format!("policy_bundle.{}.{}", realm.id, bundle.name),
                                        format!("policy bundle source found but unreadable: {e}"),
                                    );
                                }
                            };
                            let compile_check = try_compile_policy_bundle(&path, &content);
                            match compile_check {
                                Ok(msg) => check_ok(
                                    format!("policy_bundle.{}.{}", realm.id, bundle.name),
                                    format!(
                                        "policy bundle source is readable: {}; {msg}",
                                        path.display()
                                    ),
                                ),
                                Err(e) => check_error(
                                    format!("policy_bundle.{}.{}", realm.id, bundle.name),
                                    format!(
                                        "policy bundle source is readable: {}; {e}",
                                        path.display()
                                    ),
                                ),
                            }
                        }
                        PolicyBundleSourceStatus::Missing(path) => check_warning(
                            format!("policy_bundle.{}.{}", realm.id, bundle.name),
                            format!("policy bundle source is missing: {}", path.display()),
                        ),
                        PolicyBundleSourceStatus::External(source) => check_ok(
                            format!("policy_bundle.{}.{}", realm.id, bundle.name),
                            format!("policy bundle source is external: {source}"),
                        ),
                        PolicyBundleSourceStatus::Unsupported(source) => check_warning(
                            format!("policy_bundle.{}.{}", realm.id, bundle.name),
                            format!("policy bundle source scheme is not recognized: {source}"),
                        ),
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

pub(crate) enum PolicyBundleSourceStatus {
    Readable(PathBuf),
    Missing(PathBuf),
    External(String),
    Unsupported(String),
}

pub(crate) fn policy_bundle_source_status(
    config_path: &Path,
    source: &str,
) -> PolicyBundleSourceStatus {
    if source.starts_with("https://") || source.starts_with("http://") {
        PolicyBundleSourceStatus::External(source.to_string())
    } else if let Some(raw_path) = source.strip_prefix("file://") {
        resolved_policy_source_status(config_path, PathBuf::from(raw_path))
    } else {
        resolved_policy_source_status(config_path, PathBuf::from(source))
    }
}

pub(crate) fn resolved_policy_source_status(
    config_path: &Path,
    path: PathBuf,
) -> PolicyBundleSourceStatus {
    if path.components().next().is_none() {
        return PolicyBundleSourceStatus::Unsupported(String::new());
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::Prefix(_)))
    {
        return PolicyBundleSourceStatus::Unsupported(path.display().to_string());
    }
    let resolved = if path.is_absolute() {
        path
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(path)
    };
    if resolved.is_file() {
        PolicyBundleSourceStatus::Readable(resolved)
    } else {
        PolicyBundleSourceStatus::Missing(resolved)
    }
}

/// Try to compile/parse a policy bundle file to validate its contents.
/// Supports JSON-based native policy bundles.
fn try_compile_policy_bundle(path: &Path, content: &str) -> Result<String, String> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "json" => {
            let trimmed = content.trim();
            if trimmed.is_empty() {
                return Err("policy bundle file is empty".to_string());
            }
            serde_json::from_str::<serde_json::Value>(trimmed)
                .map_err(|e| format!("policy bundle is not valid JSON: {e}"))?;
            Ok("JSON policy parsed successfully".to_string())
        }
        "rego" | "r" | "yaml" | "yml" => {
            if content.trim().is_empty() {
                return Err("policy bundle file is empty".to_string());
            }
            // For Rego, basic syntactic check: must contain "package" keyword
            if ext == "rego" && !content.contains("package ") {
                return Err("Rego policy file does not contain 'package' declaration".to_string());
            }
            Ok(format!("{ext} bundle content is non-empty"))
        }
        _ => {
            // Unknown extension: just verify non-empty
            if content.trim().is_empty() {
                Err("policy bundle file is empty".to_string())
            } else {
                Ok("bundle content is non-empty".to_string())
            }
        }
    }
}

pub(crate) fn check_pep_registrations(config: &QidConfig) -> Vec<CheckItem> {
    let mut checks = Vec::new();
    let mut audiences = std::collections::BTreeSet::new();
    for realm in &config.realms {
        if realm.pep_registrations.enabled && realm.pep_registrations.registrations.is_empty() {
            checks.push(check_warning(
                format!("pep_registration.{}", realm.id),
                "PEP registrations are enabled but no registrations are configured".to_string(),
            ));
        }
        for registration in &realm.pep_registrations.registrations {
            let Some(audience) = registration.audience.clone() else {
                checks.push(check_error(
                    format!("pep_registration.{}.{}", realm.id, registration.name),
                    "PEP registration must declare audience".to_string(),
                ));
                continue;
            };
            if audiences.insert(audience.clone()) {
                let ttl_ok = if registration.assertion.ttl_seconds > 300 {
                    checks.push(check_error(
                        format!(
                            "pep_registration.{}.{}.assertion_ttl",
                            realm.id, registration.name
                        ),
                        format!(
                            "assertion ttl_seconds={} exceeds maximum of 300",
                            registration.assertion.ttl_seconds
                        ),
                    ));
                    false
                } else {
                    true
                };
                if ttl_ok {
                    checks.push(check_ok(
                        format!("pep_registration.{}.{}", realm.id, registration.name),
                        format!(
                            "PEP registration audience={audience}, fail_policy={}, assertion_ttl={}",
                            registration.decision.fail_policy, registration.assertion.ttl_seconds
                        ),
                    ));
                }
            } else {
                checks.push(check_error(
                    format!("pep_registration.{}.{}", realm.id, registration.name),
                    format!("duplicate PEP registration audience: {audience}"),
                ));
            }
        }
    }
    if checks.is_empty() {
        checks.push(CheckItem {
            name: "pep_registration".to_string(),
            status: CheckStatus::NotApplicable,
            message: "no PEP registrations configured".to_string(),
        });
    }
    checks
}

pub(crate) fn check_resource_servers(config: &QidConfig) -> Vec<CheckItem> {
    let mut checks = Vec::new();
    for realm in &config.realms {
        if realm.protocols.oauth.resource_servers.is_empty() {
            checks.push(CheckItem {
                name: format!("resource_server.{}", realm.id),
                status: CheckStatus::NotApplicable,
                message: "no OAuth resource servers configured".to_string(),
            });
            continue;
        }
        for server in &realm.protocols.oauth.resource_servers {
            if server.scopes.is_empty() {
                checks.push(check_warning(
                    format!("resource_server.{}.{}", realm.id, server.audience),
                    format!(
                        "resource server {} has no scope allowlist; any requested scope can be issued",
                        server.audience
                    ),
                ));
                continue;
            }
            if server.resources.is_empty() {
                checks.push(check_warning(
                    format!("resource_server.{}.{}", realm.id, server.audience),
                    format!(
                        "resource server {} has no resource indicators; only audience requests can target it",
                        server.audience
                    ),
                ));
                continue;
            }
            if server.introspection_client_ids.is_empty() {
                checks.push(check_warning(
                    format!("resource_server.{}.{}", realm.id, server.audience),
                    format!(
                        "resource server {} has no introspection client allowlist; introspection will fail closed",
                        server.audience
                    ),
                ));
                continue;
            }
            if server.high_risk && !server.require_sender_constraint {
                checks.push(check_warning(
                    format!("resource_server.{}.{}", realm.id, server.audience),
                    format!(
                        "resource server {} is high_risk; token issuance still enforces sender constraint, but config should set require_sender_constraint=true explicitly",
                        server.audience
                    ),
                ));
                continue;
            }
            checks.push(check_ok(
                format!("resource_server.{}.{}", realm.id, server.audience),
                format!(
                    "resource server {} declares {} resource indicators, {} scopes, sender_constraint_required={}",
                    server.audience,
                    server.resources.len(),
                    server.scopes.len(),
                    server.require_sender_constraint || server.high_risk
                ),
            ));
        }
    }
    checks
}

pub(crate) fn check_keyrings(config: &QidConfig) -> Vec<CheckItem> {
    if config.crypto.keyrings.is_empty() {
        return vec![check_warning(
            "keyring",
            "no explicit keyring configured; qidd will use local default signing key".to_string(),
        )];
    }
    let mut checks = config
        .crypto
        .keyrings
        .iter()
        .map(|keyring| {
            let scope = keyring
                .realm_id
                .as_deref()
                .map(|realm_id| format!("realm={realm_id}"))
                .unwrap_or_else(|| "realm=global".to_string());
            let purposes = if keyring.purposes.is_empty() {
                "purposes=unspecified".to_string()
            } else {
                format!("purposes={}", keyring.purposes.join(","))
            };
            if keyring.signer.r#type == "local" {
                check_ok(
                    format!("keyring.{}", keyring.name),
                    format!(
                        "local signer configured with {scope} {purposes} rotation overlap={}d max_age={}d",
                        keyring.rotation.overlap_days, keyring.rotation.max_age_days
                    ),
                )
            } else if keyring.signer.public_jwk.is_some() {
                check_ok(
                    format!("keyring.{}", keyring.name),
                    format!(
                        "remote signer {} configured with pinned public_jwk {scope} {purposes}",
                        keyring.signer.r#type
                    ),
                )
            } else {
                check_error(
                    format!("keyring.{}", keyring.name),
                    format!(
                        "remote signer {} is missing public_jwk",
                        keyring.signer.r#type
                    ),
                )
            }
        })
        .collect::<Vec<_>>();
    checks.extend(check_pep_assertion_keyrings(config));
    checks.extend(super::network::check_remote_signer_configuration(config));
    checks
}

pub(crate) fn check_pep_assertion_keyrings(config: &QidConfig) -> Vec<CheckItem> {
    config
        .realms
        .iter()
        .filter(|realm| {
            realm.pep_registrations.enabled || !realm.pep_registrations.registrations.is_empty()
        })
        .map(|realm| {
            let dedicated = config.crypto.keyrings.iter().find(|keyring| {
                keyring.realm_id.as_deref() == Some(realm.id.as_str())
                    && keyring.purposes.len() == 1
                    && is_pep_assertion_purpose(&keyring.purposes[0])
            });
            if let Some(keyring) = dedicated {
                check_ok(
                    format!("keyring.{}.pep_assertion", realm.id),
                    format!(
                        "realm {} uses dedicated PEP assertion keyring {} with signer {}",
                        realm.id, keyring.name, keyring.signer.r#type
                    ),
                )
            } else {
                let shared = config.crypto.keyrings.iter().find(|keyring| {
                    keyring.realm_id.as_deref() == Some(realm.id.as_str())
                        && keyring
                            .purposes
                            .iter()
                            .any(|purpose| is_pep_assertion_purpose(purpose))
                });
                match shared {
                    Some(keyring) => check_error(
                        format!("keyring.{}.pep_assertion", realm.id),
                        format!(
                            "PEP assertion keyring {} for realm {} must be dedicated; purposes={}",
                            keyring.name,
                            realm.id,
                            keyring.purposes.join(",")
                        ),
                    ),
                    None => check_error(
                        format!("keyring.{}.pep_assertion", realm.id),
                        format!(
                            "realm {} has PEP registrations but no dedicated pep_assertion keyring",
                            realm.id
                        ),
                    ),
                }
            }
        })
        .collect()
}

pub(crate) fn is_pep_assertion_purpose(purpose: &str) -> bool {
    matches!(purpose, "pep_assertion")
}

pub(crate) fn check_redirect_uri_surface(config: &QidConfig) -> CheckItem {
    let static_clients: usize = config.realms.iter().map(|realm| realm.clients.len()).sum();
    if static_clients == 0 {
        return check_warning(
            "redirect_uri",
            "no static clients are declared in qid.yaml; repository clients must be audited separately"
                .to_string(),
        );
    }
    let redirect_count: usize = config
        .realms
        .iter()
        .flat_map(|realm| &realm.clients)
        .map(|client| client.redirect_uris.len())
        .sum();
    check_ok(
        "redirect_uri",
        format!(
            "{static_clients} static clients declare {redirect_count} exact redirect URIs; wildcard and weak redirect schemes are rejected by config validation"
        ),
    )
}

pub(crate) fn check_saml_metadata(config: &QidConfig) -> Vec<CheckItem> {
    let mut checks = Vec::new();
    for realm in &config.realms {
        if !realm.protocols.saml.enabled {
            continue;
        }
        for sp in &realm.protocols.saml.service_providers {
            let base = format!("saml.sp.{}.realm.{}", sp.entity_id, realm.id);
            let signing =
                check_saml_certificates(&format!("{base}.signing"), &sp.signing_certificates);
            checks.extend(signing);
            let encryption =
                check_saml_certificates(&format!("{base}.encryption"), &sp.encryption_certificates);
            checks.extend(encryption);
        }
    }
    if checks.is_empty() {
        checks.push(check_ok(
            "saml",
            "SAML not configured or no service providers",
        ));
    }
    checks
}

fn check_saml_certificates(name: &str, certs: &[String]) -> Vec<CheckItem> {
    if certs.is_empty() {
        return vec![check_ok(name, "no certificates configured (optional)")];
    }
    certs
        .iter()
        .enumerate()
        .map(|(i, pem_str)| {
            let cert_name = format!("{name}[{i}]");
            let pem_bytes = pem_str.as_bytes();
            let pem = match x509_parser::pem::Pem::read(std::io::Cursor::new(pem_bytes)) {
                Ok((pem, _)) => pem,
                Err(e) => {
                    return check_error(
                        cert_name,
                        format!("invalid PEM certificate: {e}"),
                    );
                }
            };
            let cert = match pem.parse_x509() {
                Ok(c) => c,
                Err(e) => {
                    return check_error(
                        cert_name,
                        format!("invalid X.509 certificate: {e}"),
                    );
                }
            };
            let validity = cert.validity();
            let not_before = validity.not_before.to_string();
            let not_after = validity.not_after.to_string();
            let subject = cert.subject().to_string();
            let issuer = cert.issuer().to_string();
            let now = x509_parser::time::ASN1Time::now();
            let expired = now > validity.not_after;
            let not_yet_valid = now < validity.not_before;
            if expired {
                check_error(
                    cert_name,
                    format!(
                        "certificate expired at {not_after}, subject={subject}, issuer={issuer}"
                    ),
                )
            } else if not_yet_valid {
                check_warning(
                    cert_name,
                    format!(
                        "certificate not yet valid until {not_before}, subject={subject}, issuer={issuer}"
                    ),
                )
            } else {
                check_ok(
                    cert_name,
                    format!(
                        "valid certificate, subject={subject}, issuer={issuer}, not_before={not_before}, not_after={not_after}"
                    ),
                )
            }
        })
        .collect()
}

pub(crate) fn check_scim_schemas(config: &QidConfig) -> Vec<CheckItem> {
    let mut checks = Vec::new();
    for realm in &config.realms {
        let name = format!("scim.realm.{}", realm.id);
        if !realm.protocols.scim.enabled {
            continue;
        }
        checks.push(check_ok(
            &name,
            "SCIM protocol enabled, base_path configured",
        ));
        for schema in &realm.protocols.scim.custom_schemas {
            let schema_name = format!("scim.schema.{}.realm.{}", schema.id, realm.id);
            if schema.name.trim().is_empty() {
                checks.push(check_error(
                    &schema_name,
                    format!("SCIM custom schema {} has empty name", schema.id),
                ));
                continue;
            }
            if !schema.id.starts_with("urn:") {
                checks.push(check_error(
                    &schema_name,
                    format!("SCIM custom schema id is not a valid URN: {}", schema.id),
                ));
                continue;
            }
            let valid_types = [
                "string",
                "boolean",
                "decimal",
                "integer",
                "dateTime",
                "binary",
                "reference",
                "complex",
            ];
            for attr in &schema.attributes {
                let attr_name = format!("{schema_name}.{}", attr.name);
                if attr.name.trim().is_empty() {
                    checks.push(check_error(
                        &attr_name,
                        format!(
                            "SCIM custom schema {} has attribute with empty name",
                            schema.id
                        ),
                    ));
                } else if !valid_types.contains(&attr.r#type.as_str()) {
                    checks.push(check_error(
                        &attr_name,
                        format!(
                            "SCIM custom schema {} attribute {} has invalid type: {}",
                            schema.id, attr.name, attr.r#type
                        ),
                    ));
                } else {
                    checks.push(check_ok(
                        &attr_name,
                        format!(
                            "SCIM custom schema {} attribute {} type={}",
                            schema.id, attr.name, attr.r#type
                        ),
                    ));
                }
            }
        }
    }
    if checks.is_empty() {
        checks.push(check_ok("scim", "SCIM not configured"));
    }
    checks
}
