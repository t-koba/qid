use crate::models::{ClientType, TokenFormat};
use figment::{
    Figment,
    providers::{Env, Format, Toml, Yaml},
};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::error::{QidError, QidResult};

/// Top-level configuration for qid.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QidConfig {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub profile: DeploymentProfile,
    pub server: ServerConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub crypto: CryptoConfig,
    #[serde(default)]
    pub realms: Vec<RealmConfig>,
    #[serde(default)]
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub ops: OpsConfig,
}

impl QidConfig {
    /// Load configuration from a file path.
    ///
    /// Supported formats: TOML, YAML.
    pub fn from_file(path: &str) -> QidResult<Self> {
        Self::from_files([PathBuf::from(path)])
    }

    /// Load configuration from one or more file paths.
    ///
    /// Earlier files and includes provide defaults; later files override them.
    pub fn from_files<I, P>(paths: I) -> QidResult<Self>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut ordered_paths = Vec::new();
        let mut visiting = HashSet::new();
        let mut visited = HashSet::new();
        for path in paths {
            collect_config_paths(
                path.as_ref(),
                &mut ordered_paths,
                &mut visiting,
                &mut visited,
            )?;
        }
        if ordered_paths.is_empty() {
            return Err(QidError::Config {
                message: "at least one config file must be provided".to_string(),
            });
        }

        let mut figment = Figment::new();
        for path in &ordered_paths {
            figment = merge_config_file(figment, path)?;
        }
        let figment = figment.merge(Env::prefixed("QID_").split("__"));

        let config: QidConfig = figment.extract().map_err(|e| QidError::Config {
            message: format!("failed to load config: {e}"),
        })?;

        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration.
    pub fn validate(&self) -> QidResult<()> {
        if self.realms.is_empty() {
            return Err(QidError::Config {
                message: "at least one realm must be configured".to_string(),
            });
        }

        let mut seen_ids = std::collections::HashSet::new();
        let mut seen_registration_audiences = std::collections::HashSet::new();
        for realm in &self.realms {
            if !seen_ids.insert(&realm.id) {
                return Err(QidError::Config {
                    message: format!("duplicate realm id: {}", realm.id),
                });
            }
            realm.validate()?;
            for registration in &realm.pep_registrations.registrations {
                let Some(audience) = registration.audience.as_ref() else {
                    return Err(QidError::Config {
                        message: format!(
                            "realm {} PEP registration {} must declare audience",
                            realm.id, registration.name
                        ),
                    });
                };
                if !seen_registration_audiences.insert(audience.clone()) {
                    return Err(QidError::Config {
                        message: format!("duplicate PEP registration audience: {audience}"),
                    });
                }
            }
        }
        self.server.validate()?;
        validate_multi_realm_issuer_routes(self)?;
        self.admin.validate()?;
        self.crypto.validate()?;
        self.ops.validate()?;
        self.profile.validate_config(self)?;
        validate_metrics_listen(&self.observability)?;

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct ConfigIncludeManifest {
    #[serde(default)]
    include: Vec<String>,
}

fn collect_config_paths(
    path: &Path,
    ordered_paths: &mut Vec<PathBuf>,
    visiting: &mut HashSet<PathBuf>,
    visited: &mut HashSet<PathBuf>,
) -> QidResult<()> {
    let canonical = std::fs::canonicalize(path).map_err(|error| QidError::Config {
        message: format!("failed to resolve config path {}: {error}", path.display()),
    })?;
    if visited.contains(&canonical) {
        return Ok(());
    }
    if !visiting.insert(canonical.clone()) {
        return Err(QidError::Config {
            message: format!("config include cycle detected at {}", canonical.display()),
        });
    }
    let manifest = load_include_manifest(&canonical)?;
    let base_dir = canonical.parent().unwrap_or_else(|| Path::new("."));
    for include in manifest.include {
        let include_path = PathBuf::from(&include);
        let resolved = if include_path.is_absolute() {
            include_path
        } else {
            base_dir.join(include_path)
        };
        collect_config_paths(&resolved, ordered_paths, visiting, visited)?;
    }
    visiting.remove(&canonical);
    visited.insert(canonical.clone());
    ordered_paths.push(canonical);
    Ok(())
}

fn load_include_manifest(path: &Path) -> QidResult<ConfigIncludeManifest> {
    let figment = merge_config_file(Figment::new(), path)?;
    figment.extract().map_err(|error| QidError::Config {
        message: format!(
            "failed to read config includes from {}: {error}",
            path.display()
        ),
    })
}

fn merge_config_file(figment: Figment, path: &Path) -> QidResult<Figment> {
    let Some(path_str) = path.to_str() else {
        return Err(QidError::Config {
            message: format!("config path is not valid UTF-8: {}", path.display()),
        });
    };
    if path_str.ends_with(".yaml") || path_str.ends_with(".yml") {
        Ok(figment.merge(Yaml::file(path_str)))
    } else if path_str.ends_with(".toml") {
        Ok(figment.merge(Toml::file(path_str)))
    } else {
        Err(QidError::Config {
            message: format!(
                "unsupported config file format: {path_str} (expected .yaml, .yml, or .toml)"
            ),
        })
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DeploymentProfile {
    #[default]
    Oidc,
    EdgePep,
    Enterprise,
    Fapi,
    Ciam,
    Workload,
    HighAssurance,
    NetworkAaa,
    Vc,
}

impl DeploymentProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::EdgePep => "edge-pep",
            Self::Enterprise => "enterprise",
            Self::Fapi => "fapi",
            Self::Ciam => "ciam",
            Self::Workload => "workload",
            Self::HighAssurance => "high-assurance",
            Self::NetworkAaa => "network-aaa",
            Self::Vc => "vc",
        }
    }

    fn validate_config(self, config: &QidConfig) -> QidResult<()> {
        match self {
            Self::Oidc => validate_oidc_profile(config),
            Self::EdgePep => validate_edge_pep_profile(config),
            Self::Fapi => validate_fapi_profile(config),
            Self::Workload => validate_workload_profile(config),
            Self::HighAssurance => {
                validate_fapi_profile(config)?;
                validate_high_assurance_profile(config)
            }
            Self::NetworkAaa => validate_network_aaa_profile(config),
            Self::Vc => validate_vc_profile(config),
            Self::Enterprise => validate_enterprise_profile(config),
            Self::Ciam => validate_ciam_profile(config),
        }
    }
}

fn validate_oidc_profile(config: &QidConfig) -> QidResult<()> {
    for realm in &config.realms {
        if !realm.protocols.oidc.enabled || !realm.protocols.oidc.authorization_code.enabled {
            return Err(QidError::Config {
                message: format!(
                    "profile oidc requires OIDC authorization code for realm {}",
                    realm.id
                ),
            });
        }
        if !realm.protocols.oidc.authorization_code.pkce_required {
            return Err(QidError::Config {
                message: format!("profile oidc requires PKCE for realm {}", realm.id),
            });
        }
    }
    Ok(())
}

fn validate_edge_pep_profile(config: &QidConfig) -> QidResult<()> {
    if !config.server.http_message_signatures.enabled {
        return Err(QidError::Config {
            message: "profile edge-pep requires HTTP Message Signatures".to_string(),
        });
    }
    let registration_count = config
        .realms
        .iter()
        .filter(|realm| realm.pep_registrations.enabled)
        .flat_map(|realm| realm.pep_registrations.registrations.iter())
        .count();
    if registration_count == 0 {
        return Err(QidError::Config {
            message: "profile edge-pep requires at least one PEP registration".to_string(),
        });
    }
    for realm in &config.realms {
        if realm.pep_registrations.enabled {
            if !realm.protocols.oauth.mtls.enabled {
                return Err(QidError::Config {
                    message: format!("profile edge-pep requires mTLS for realm {}", realm.id),
                });
            }
            for registration in &realm.pep_registrations.registrations {
                let required_capabilities = [
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
                for capability in required_capabilities {
                    if !registration
                        .capabilities
                        .iter()
                        .any(|configured| configured.effect == capability)
                    {
                        return Err(QidError::Config {
                            message: format!(
                                "profile edge-pep requires capability effect {capability} for realm {} PEP registration {}",
                                realm.id, registration.name
                            ),
                        });
                    }
                }
                if registration.decision.fail_policy != "deny" {
                    return Err(QidError::Config {
                        message: format!(
                            "profile edge-pep requires fail_policy=deny for realm {} PEP registration {}",
                            realm.id, registration.name
                        ),
                    });
                }
            }
        }
    }
    Ok(())
}

fn validate_enterprise_profile(config: &QidConfig) -> QidResult<()> {
    for realm in &config.realms {
        if !realm.authentication.passkeys.enabled {
            return Err(QidError::Config {
                message: format!(
                    "profile enterprise requires passkeys for realm {}",
                    realm.id
                ),
            });
        }
        if !realm.protocols.scim.enabled {
            return Err(QidError::Config {
                message: format!("profile enterprise requires SCIM for realm {}", realm.id),
            });
        }
        if realm
            .protocols
            .scim
            .cursor_secret
            .as_deref()
            .is_none_or(|secret| secret.len() < 32)
        {
            return Err(QidError::Config {
                message: format!(
                    "profile enterprise requires a SCIM cursor_secret of at least 32 bytes for realm {}",
                    realm.id
                ),
            });
        }
        if realm.protocols.scim.event_callback_allowed_hosts.is_empty() {
            return Err(QidError::Config {
                message: format!(
                    "profile enterprise requires SCIM EventSubscription callback host allowlist for realm {}",
                    realm.id
                ),
            });
        }
        if !realm.protocols.saml.enabled {
            return Err(QidError::Config {
                message: format!("profile enterprise requires SAML for realm {}", realm.id),
            });
        }
        if !realm.protocols.saml.sign_assertions || !realm.protocols.saml.sign_metadata {
            return Err(QidError::Config {
                message: format!(
                    "profile enterprise requires signed SAML assertions and XMLDSig metadata for realm {}",
                    realm.id
                ),
            });
        }
        if realm.protocols.saml.service_providers.is_empty() {
            return Err(QidError::Config {
                message: format!(
                    "profile enterprise requires at least one configured SAML service provider for realm {}",
                    realm.id
                ),
            });
        }
        if !realm.protocols.directory.enabled {
            return Err(QidError::Config {
                message: format!(
                    "profile enterprise requires directory sync for realm {}",
                    realm.id
                ),
            });
        }
        let has_enterprise_directory = realm.protocols.directory.providers.iter().any(|provider| {
            provider.enabled
                && matches!(provider.provider_type.as_str(), "ldap" | "active-directory")
                && provider.connection.url.starts_with("ldaps://")
                && provider.connection.bind_dn.is_some()
                && provider.connection.bind_password.is_some()
                && provider.connection.base_dn.is_some()
                && !provider.connection.tls_insecure_skip_verify
        });
        if !has_enterprise_directory {
            return Err(QidError::Config {
                message: format!(
                    "profile enterprise requires an enabled LDAPS directory provider with bind credentials and TLS verification for realm {}",
                    realm.id
                ),
            });
        }
    }
    Ok(())
}

fn validate_ciam_profile(config: &QidConfig) -> QidResult<()> {
    for realm in &config.realms {
        if !realm.protocols.oidc.enabled
            || !realm.protocols.oidc.discovery
            || !realm.protocols.oidc.userinfo
            || !realm.protocols.oidc.authorization_code.enabled
            || !realm.protocols.oidc.authorization_code.pkce_required
        {
            return Err(QidError::Config {
                message: format!(
                    "profile ciam requires OIDC discovery, userinfo, authorization code, and PKCE for realm {}",
                    realm.id
                ),
            });
        }
        if !realm.authentication.passkeys.enabled {
            return Err(QidError::Config {
                message: format!("profile ciam requires passkeys for realm {}", realm.id),
            });
        }
        if !realm.protocols.fedcm.enabled {
            return Err(QidError::Config {
                message: format!("profile ciam requires FedCM for realm {}", realm.id),
            });
        }
        let ciam = &realm.protocols.ciam;
        for (enabled, feature) in [
            (ciam.consent, "consent"),
            (ciam.progressive_profile, "progressive_profile"),
            (ciam.identity_proofing, "identity_proofing"),
            (ciam.privacy_dashboard, "privacy_dashboard"),
        ] {
            if !enabled {
                return Err(QidError::Config {
                    message: format!("profile ciam requires {feature} for realm {}", realm.id),
                });
            }
        }
        if !realm.protocols.federation.enabled {
            return Err(QidError::Config {
                message: format!(
                    "profile ciam requires inbound federation for realm {}",
                    realm.id
                ),
            });
        }
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
        if !has_social_or_oidc {
            return Err(QidError::Config {
                message: format!(
                    "profile ciam requires an enabled inbound OIDC or social provider with client credentials, domains, account linking, and JIT provisioning for realm {}",
                    realm.id
                ),
            });
        }
    }
    Ok(())
}

fn validate_fapi_profile(config: &QidConfig) -> QidResult<()> {
    if !config.server.http_message_signatures.enabled {
        return Err(QidError::Config {
            message: format!(
                "profile {} requires HTTP Message Signatures",
                config.profile.as_str()
            ),
        });
    }
    for realm in &config.realms {
        let oauth = &realm.protocols.oauth;
        for (enabled, feature) in [
            (oauth.par.enabled, "PAR"),
            (oauth.rar.enabled, "RAR"),
            (oauth.dpop.enabled, "DPoP"),
            (oauth.mtls.enabled, "mTLS"),
            (oauth.private_key_jwt.enabled, "private_key_jwt"),
            (oauth.jarm.enabled, "JARM"),
        ] {
            if !enabled {
                return Err(QidError::Config {
                    message: format!(
                        "profile {} requires {feature} for realm {}",
                        config.profile.as_str(),
                        realm.id
                    ),
                });
            }
        }
        if !oauth.require_pushed_authorization_requests {
            return Err(QidError::Config {
                message: format!(
                    "profile {} requires require_pushed_authorization_requests for realm {}",
                    config.profile.as_str(),
                    realm.id
                ),
            });
        }
        if !realm
            .protocols
            .oidc
            .authorization_code
            .require_signed_request_object
        {
            return Err(QidError::Config {
                message: format!(
                    "profile {} requires signed request objects for realm {}",
                    config.profile.as_str(),
                    realm.id
                ),
            });
        }
        if !oauth.introspection.jwt_response {
            return Err(QidError::Config {
                message: format!(
                    "profile {} requires JWT introspection response for realm {}",
                    config.profile.as_str(),
                    realm.id
                ),
            });
        }
        if oauth.resource_servers.is_empty()
            || oauth
                .resource_servers
                .iter()
                .any(|server| !server.require_sender_constraint && !server.high_risk)
        {
            return Err(QidError::Config {
                message: format!(
                    "profile {} requires sender-constrained OAuth resource servers for realm {}",
                    config.profile.as_str(),
                    realm.id
                ),
            });
        }
    }
    Ok(())
}

fn validate_vc_profile(config: &QidConfig) -> QidResult<()> {
    validate_fapi_profile(config)?;
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
            if !enabled {
                return Err(QidError::Config {
                    message: format!("profile vc requires {feature} for realm {}", realm.id),
                });
            }
        }
        if vc
            .issuer_key_ref
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(QidError::Config {
                message: format!("profile vc requires issuer_key_ref for realm {}", realm.id),
            });
        }
    }
    Ok(())
}

fn validate_workload_profile(config: &QidConfig) -> QidResult<()> {
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
            if !enabled {
                return Err(QidError::Config {
                    message: format!("profile workload requires {feature} for realm {}", realm.id),
                });
            }
        }
        if workload
            .workload_ca_key_ref
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(QidError::Config {
                message: format!(
                    "profile workload requires workload_ca_key_ref for realm {}",
                    realm.id
                ),
            });
        }
        if !realm.protocols.oauth.mtls.enabled {
            return Err(QidError::Config {
                message: format!("profile workload requires mTLS for realm {}", realm.id),
            });
        }
        if !realm.protocols.oauth.private_key_jwt.enabled {
            return Err(QidError::Config {
                message: format!(
                    "profile workload requires private_key_jwt for realm {}",
                    realm.id
                ),
            });
        }
    }
    Ok(())
}

fn validate_network_aaa_profile(config: &QidConfig) -> QidResult<()> {
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
            if !enabled {
                return Err(QidError::Config {
                    message: format!(
                        "profile network-aaa requires {feature} for realm {}",
                        realm.id
                    ),
                });
            }
        }
        if !realm.protocols.oauth.mtls.enabled {
            return Err(QidError::Config {
                message: format!("profile network-aaa requires mTLS for realm {}", realm.id),
            });
        }
        if network_aaa
            .shared_secret
            .as_deref()
            .is_none_or(|value| value.len() < 16)
        {
            return Err(QidError::Config {
                message: format!(
                    "profile network-aaa requires shared_secret of at least 16 bytes for realm {}",
                    realm.id
                ),
            });
        }
        for (value, field) in [
            (
                network_aaa.radius_authentication_bind.as_deref(),
                "radius_authentication_bind",
            ),
            (network_aaa.radius_tls_bind.as_deref(), "radius_tls_bind"),
            (network_aaa.accounting_bind.as_deref(), "accounting_bind"),
            (network_aaa.coa_bind.as_deref(), "coa_bind"),
        ] {
            if value.is_none_or(|bind| {
                bind.trim().is_empty() || bind.parse::<std::net::SocketAddr>().is_err()
            }) {
                return Err(QidError::Config {
                    message: format!(
                        "profile network-aaa requires valid {field} for realm {}",
                        realm.id
                    ),
                });
            }
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
            if value.is_none_or(|path| path.trim().is_empty()) {
                return Err(QidError::Config {
                    message: format!(
                        "profile network-aaa requires {field} for realm {}",
                        realm.id
                    ),
                });
            }
        }
        let has_directory_authority = realm.protocols.directory.enabled
            && realm
                .protocols
                .directory
                .providers
                .iter()
                .any(|provider| provider.enabled);
        if !has_directory_authority {
            return Err(QidError::Config {
                message: format!(
                    "profile network-aaa requires an enabled directory authority for realm {}",
                    realm.id
                ),
            });
        }
    }
    Ok(())
}

fn validate_high_assurance_profile(config: &QidConfig) -> QidResult<()> {
    if config.crypto.keyrings.is_empty()
        || !config
            .crypto
            .keyrings
            .iter()
            .all(|keyring| matches!(keyring.signer.r#type.as_str(), "kms" | "hsm" | "pkcs11"))
    {
        return Err(QidError::Config {
            message: "profile high-assurance requires remote KMS/HSM/PKCS#11 keyrings".to_string(),
        });
    }
    if !config.admin.security.require_approval || !config.admin.security.require_step_up {
        return Err(QidError::Config {
            message: "profile high-assurance requires admin approval and step-up".to_string(),
        });
    }
    if !config.ops.backup.enabled {
        return Err(QidError::Config {
            message: "profile high-assurance requires backup".to_string(),
        });
    }
    for realm in &config.realms {
        if !realm.authentication.passkeys.enabled {
            return Err(QidError::Config {
                message: format!(
                    "profile high-assurance requires passkeys for realm {}",
                    realm.id
                ),
            });
        }
        if !realm.protocols.oauth.mtls.enabled {
            return Err(QidError::Config {
                message: format!(
                    "profile high-assurance requires mTLS for realm {}",
                    realm.id
                ),
            });
        }
        if !realm.authentication.passwordless_only {
            return Err(QidError::Config {
                message: format!(
                    "profile high-assurance requires passwordless_only for realm {}",
                    realm.id
                ),
            });
        }
    }
    Ok(())
}

pub use runtime::*;

mod runtime;

pub use security::*;

mod security;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RealmConfig {
    pub id: String,
    pub issuer: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub clients: Vec<StaticClientConfig>,
    #[serde(default)]
    pub protocols: ProtocolConfig,
    #[serde(default)]
    pub authentication: AuthenticationConfig,
    #[serde(default)]
    pub sessions: SessionConfig,
    #[serde(default)]
    pub pep_registrations: PepRegistrationsConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
}

impl RealmConfig {
    fn validate(&self) -> QidResult<()> {
        if self.id.trim().is_empty() {
            return Err(QidError::Config {
                message: "realm id must not be empty".to_string(),
            });
        }
        if !is_url_safe_realm_id(&self.id) {
            return Err(QidError::Config {
                message: format!(
                    "realm {} id must contain only unreserved URL path segment characters [A-Za-z0-9._~-]",
                    self.id
                ),
            });
        }
        if self.issuer.trim().is_empty() {
            return Err(QidError::Config {
                message: format!("realm {} issuer must not be empty", self.id),
            });
        }
        if let Err(e) = url::Url::parse(&self.issuer) {
            return Err(QidError::Config {
                message: format!("realm {} issuer is not a valid URL: {e}", self.id),
            });
        }
        if self.protocols.oidc.implicit.enabled {
            return Err(QidError::Config {
                message: format!("realm {} enables forbidden implicit flow", self.id),
            });
        }
        if self.protocols.oidc.ropc.enabled {
            return Err(QidError::Config {
                message: format!("realm {} enables forbidden ROPC flow", self.id),
            });
        }
        if self.protocols.oidc.authorization_code.enabled
            && !self.protocols.oidc.authorization_code.pkce_required
        {
            return Err(QidError::Config {
                message: format!(
                    "realm {} must require PKCE for authorization code flow",
                    self.id
                ),
            });
        }
        let mut seen_resource_server_audiences = std::collections::HashSet::new();
        let mut seen_resource_indicators = std::collections::HashSet::new();
        for resource_server in &self.protocols.oauth.resource_servers {
            resource_server.validate(&self.id)?;
            if !seen_resource_server_audiences.insert(&resource_server.audience) {
                return Err(QidError::Config {
                    message: format!(
                        "realm {} has duplicate OAuth resource server audience: {}",
                        self.id, resource_server.audience
                    ),
                });
            }
            for resource in &resource_server.resources {
                if !seen_resource_indicators.insert(resource) {
                    return Err(QidError::Config {
                        message: format!(
                            "realm {} has duplicate OAuth resource indicator: {resource}",
                            self.id
                        ),
                    });
                }
            }
        }
        let mut seen_client_ids = std::collections::HashSet::new();
        for client in &self.clients {
            client.validate(&self.id)?;
            if !seen_client_ids.insert(&client.client_id) {
                return Err(QidError::Config {
                    message: format!(
                        "realm {} has duplicate static client_id: {}",
                        self.id, client.client_id
                    ),
                });
            }
        }
        if self.protocols.directory.enabled {
            let mut seen_provider_ids = std::collections::HashSet::new();
            for p in &self.protocols.directory.providers {
                if p.id.trim().is_empty() {
                    return Err(QidError::Config {
                        message: format!(
                            "realm {} directory provider id must not be empty",
                            self.id
                        ),
                    });
                }
                if !seen_provider_ids.insert(&p.id) {
                    return Err(QidError::Config {
                        message: format!(
                            "realm {} has duplicate directory provider id: {}",
                            self.id, p.id
                        ),
                    });
                }
                if p.connection.url.trim().is_empty() {
                    return Err(QidError::Config {
                        message: format!(
                            "realm {} directory provider {} connection.url is required",
                            self.id, p.id
                        ),
                    });
                }
                match p.provider_type.as_str() {
                    "ldap" | "active-directory" | "scim" | "hr_csv" | "hr_webhook" => {}
                    other => {
                        return Err(QidError::Config {
                            message: format!(
                                "realm {} directory provider {} has unsupported type: {other}",
                                self.id, p.id
                            ),
                        });
                    }
                }
            }
        }

        let mut seen_saml_sp_entity_ids = std::collections::HashSet::new();
        if self.protocols.saml.sign_metadata
            && self
                .protocols
                .saml
                .idp_signing_key_pem_path
                .as_deref()
                .is_none_or(|path| path.trim().is_empty())
        {
            return Err(QidError::Config {
                message: format!(
                    "realm {} SAML metadata signing requires idp_signing_key_pem_path for XMLDSig",
                    self.id
                ),
            });
        }
        if self.protocols.saml.sign_assertions
            && self
                .protocols
                .saml
                .idp_signing_key_pem_path
                .as_deref()
                .is_none_or(|path| path.trim().is_empty())
        {
            return Err(QidError::Config {
                message: format!(
                    "realm {} SAML assertion signing requires idp_signing_key_pem_path for XMLDSig",
                    self.id
                ),
            });
        }
        for sp in &self.protocols.saml.service_providers {
            if sp.entity_id.trim().is_empty() {
                return Err(QidError::Config {
                    message: format!("realm {} SAML SP entity_id must not be empty", self.id),
                });
            }
            if !seen_saml_sp_entity_ids.insert(&sp.entity_id) {
                return Err(QidError::Config {
                    message: format!(
                        "realm {} has duplicate SAML SP entity_id: {}",
                        self.id, sp.entity_id
                    ),
                });
            }
            if let Err(e) = url::Url::parse(&sp.entity_id) {
                return Err(QidError::Config {
                    message: format!(
                        "realm {} SAML SP entity_id is not a valid URL: {e}",
                        self.id
                    ),
                });
            }
            if let Err(e) = url::Url::parse(&sp.acs_url) {
                return Err(QidError::Config {
                    message: format!("realm {} SAML SP ACS URL is not valid: {e}", self.id),
                });
            }
            if let Some(slo_url) = &sp.slo_url
                && let Err(e) = url::Url::parse(slo_url)
            {
                return Err(QidError::Config {
                    message: format!("realm {} SAML SP SLO URL is not valid: {e}", self.id),
                });
            }
            if sp.signing_certificates.is_empty() {
                return Err(QidError::Config {
                    message: format!(
                        "realm {} SAML SP {} must include signing_certificates",
                        self.id, sp.entity_id
                    ),
                });
            }
            if sp.want_assertions_signed
                && self
                    .protocols
                    .saml
                    .idp_signing_key_pem_path
                    .as_deref()
                    .is_none_or(|path| path.trim().is_empty())
            {
                return Err(QidError::Config {
                    message: format!(
                        "realm {} SAML SP {} requires idp_signing_key_pem_path for XMLDSig",
                        self.id, sp.entity_id
                    ),
                });
            }
            if self.protocols.saml.encrypt_assertions.as_deref() == Some("required")
                && sp.encryption_certificates.is_empty()
            {
                return Err(QidError::Config {
                    message: format!(
                        "realm {} SAML SP {} must include encryption_certificates when encrypted assertions are required",
                        self.id, sp.entity_id
                    ),
                });
            }
        }
        for provider in &self.protocols.federation.inbound_providers {
            if provider.enabled
                && provider.kind.eq_ignore_ascii_case("saml")
                && provider.saml_signing_certificates.is_empty()
            {
                return Err(QidError::Config {
                    message: format!(
                        "realm {} inbound SAML provider {} must include saml_signing_certificates",
                        self.id, provider.id
                    ),
                });
            }
            if provider.kind.eq_ignore_ascii_case("saml") {
                for certificate in &provider.saml_signing_certificates {
                    if certificate.trim().is_empty() {
                        return Err(QidError::Config {
                            message: format!(
                                "realm {} inbound SAML provider {} has an empty signing certificate",
                                self.id, provider.id
                            ),
                        });
                    }
                }
            }
        }
        if self.protocols.scim.enabled {
            let Some(cursor_secret) = self.protocols.scim.cursor_secret.as_deref() else {
                return Err(QidError::Config {
                    message: format!(
                        "realm {} SCIM cursor_secret is required when SCIM is enabled",
                        self.id
                    ),
                });
            };
            if cursor_secret.len() < 32 {
                return Err(QidError::Config {
                    message: format!(
                        "realm {} SCIM cursor_secret must be at least 32 bytes",
                        self.id
                    ),
                });
            }
            for host in &self.protocols.scim.event_callback_allowed_hosts {
                validate_scim_event_callback_allowed_host(host, &self.id)?;
            }
            validate_scim_custom_schemas(&self.protocols.scim.custom_schemas, &self.id)?;
        }
        let mut seen_registration_names = std::collections::HashSet::new();
        for registration in &self.pep_registrations.registrations {
            if !seen_registration_names.insert(&registration.name) {
                return Err(QidError::Config {
                    message: format!(
                        "realm {} has duplicate PEP registration: {}",
                        self.id, registration.name
                    ),
                });
            }
            if registration.decision.fail_policy != "deny" {
                return Err(QidError::Config {
                    message: format!(
                        "realm {} PEP registration {} must fail closed with fail_policy=deny",
                        self.id, registration.name
                    ),
                });
            }
            if registration.assertion.ttl_seconds > 300 {
                return Err(QidError::Config {
                    message: format!(
                        "realm {} PEP registration {} assertion ttl_seconds must not exceed 300 (got {})",
                        self.id, registration.name, registration.assertion.ttl_seconds
                    ),
                });
            }
            if !matches!(registration.auth.active_method, PepAuthMethod::BearerJwt) {
                return Err(QidError::Config {
                    message: format!(
                        "realm {} PEP registration {} auth.active_method is not implemented",
                        self.id, registration.name
                    ),
                });
            }
            let mut seen_capabilities = std::collections::HashSet::new();
            for capability in &registration.capabilities {
                if capability.effect.trim().is_empty() {
                    return Err(QidError::Config {
                        message: format!(
                            "realm {} PEP registration {} capability effect must not be empty",
                            self.id, registration.name
                        ),
                    });
                }
                let key = (
                    capability.mode.as_deref().unwrap_or_default(),
                    capability.phase.as_deref().unwrap_or_default(),
                    capability.effect.as_str(),
                );
                if !seen_capabilities.insert(key) {
                    return Err(QidError::Config {
                        message: format!(
                            "realm {} PEP registration {} has duplicate capability effect {}",
                            self.id, registration.name, capability.effect
                        ),
                    });
                }
            }
        }
        if self.authentication.passwordless_only {
            if !self.authentication.passkeys.enabled {
                return Err(QidError::Config {
                    message: format!(
                        "realm {} passwordless_only requires passkeys to be enabled",
                        self.id
                    ),
                });
            }
        } else if !self.authentication.passkeys.enabled && !self.authentication.password.enabled {
            return Err(QidError::Config {
                message: format!(
                    "realm {} must enable at least one authentication method (passkeys or password)",
                    self.id
                ),
            });
        }
        Ok(())
    }
}

fn is_url_safe_realm_id(realm_id: &str) -> bool {
    realm_id.bytes().all(
        |byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'~' | b'-'),
    )
}

fn validate_multi_realm_issuer_routes(config: &QidConfig) -> QidResult<()> {
    if config.realms.len() < 2 {
        return Ok(());
    }
    let base = config.server.public_base_url.trim_end_matches('/');
    for realm in &config.realms {
        let expected = format!("{base}/realms/{}", realm.id);
        if realm.issuer.trim_end_matches('/') != expected {
            return Err(QidError::Config {
                message: format!(
                    "multi-realm issuer for realm {} must be {} to match realm-scoped discovery routes",
                    realm.id, expected
                ),
            });
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StaticClientConfig {
    pub client_id: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default = "default_public_client_type")]
    pub client_type: ClientType,
    #[serde(default = "default_token_endpoint_auth_method_for_static_client")]
    pub token_endpoint_auth_method: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub client_secret_hash: Option<String>,
    #[serde(default)]
    pub mtls_certificate_thumbprints: Vec<String>,
    #[serde(default = "crate::models::default_client_jwks")]
    pub jwks: serde_json::Value,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default = "default_static_client_grant_types")]
    pub grant_types: Vec<String>,
}

impl StaticClientConfig {
    fn validate(&self, realm_id: &str) -> QidResult<()> {
        if self.client_id.trim().is_empty() {
            return Err(QidError::Config {
                message: format!("realm {realm_id} static client_id must not be empty"),
            });
        }
        if self.grant_types.is_empty() {
            return Err(QidError::Config {
                message: format!(
                    "realm {realm_id} static client {} must declare grant_types",
                    self.client_id
                ),
            });
        }
        if self
            .grant_types
            .iter()
            .any(|grant| grant == "implicit" || grant == "password")
        {
            return Err(QidError::Config {
                message: format!(
                    "realm {realm_id} static client {} enables forbidden weak grant",
                    self.client_id
                ),
            });
        }
        validate_static_client_auth_method(realm_id, self)?;
        if self.client_type == ClientType::Public
            && self
                .grant_types
                .iter()
                .any(|grant| grant == "client_credentials")
        {
            return Err(QidError::Config {
                message: format!(
                    "realm {realm_id} public static client {} cannot use client_credentials",
                    self.client_id
                ),
            });
        }
        if self
            .grant_types
            .iter()
            .any(|grant| grant == "authorization_code")
            && self.redirect_uris.is_empty()
        {
            return Err(QidError::Config {
                message: format!(
                    "realm {realm_id} static client {} requires redirect_uris for authorization_code",
                    self.client_id
                ),
            });
        }
        let mut seen_redirects = std::collections::HashSet::new();
        for redirect_uri in &self.redirect_uris {
            validate_static_redirect_uri(realm_id, &self.client_id, redirect_uri)?;
            if !seen_redirects.insert(redirect_uri) {
                return Err(QidError::Config {
                    message: format!(
                        "realm {realm_id} static client {} has duplicate redirect_uri: {}",
                        self.client_id, redirect_uri
                    ),
                });
            }
        }
        Ok(())
    }
}

fn default_public_client_type() -> ClientType {
    ClientType::Public
}

fn default_token_endpoint_auth_method_for_static_client() -> String {
    "none".to_string()
}

fn default_static_client_grant_types() -> Vec<String> {
    vec!["authorization_code".to_string()]
}

fn validate_static_client_auth_method(
    realm_id: &str,
    client: &StaticClientConfig,
) -> QidResult<()> {
    let method = client.token_endpoint_auth_method.as_str();
    if client.client_secret.is_some() && client.client_secret_hash.is_some() {
        return Err(QidError::Config {
            message: format!(
                "realm {realm_id} static client {} must not declare both client_secret and client_secret_hash",
                client.client_id
            ),
        });
    }
    match client.client_type {
        ClientType::Public => {
            if method != "none" {
                return Err(QidError::Config {
                    message: format!(
                        "realm {realm_id} public static client {} must use token_endpoint_auth_method=none",
                        client.client_id
                    ),
                });
            }
            if client.client_secret.is_some() || client.client_secret_hash.is_some() {
                return Err(QidError::Config {
                    message: format!(
                        "realm {realm_id} public static client {} must not declare a client secret",
                        client.client_id
                    ),
                });
            }
        }
        ClientType::Confidential => match method {
            "client_secret_basic" | "client_secret_post" => {
                if client.client_secret.is_none() && client.client_secret_hash.is_none() {
                    return Err(QidError::Config {
                        message: format!(
                            "realm {realm_id} confidential static client {} must declare client_secret or client_secret_hash",
                            client.client_id
                        ),
                    });
                }
            }
            "private_key_jwt" => validate_static_client_jwks(realm_id, client)?,
            "tls_client_auth" | "self_signed_tls_client_auth" => {
                if client.mtls_certificate_thumbprints.is_empty() {
                    return Err(QidError::Config {
                        message: format!(
                            "realm {realm_id} mTLS static client {} must declare mtls_certificate_thumbprints",
                            client.client_id
                        ),
                    });
                }
            }
            "none" => {
                return Err(QidError::Config {
                    message: format!(
                        "realm {realm_id} confidential static client {} must not use token_endpoint_auth_method=none",
                        client.client_id
                    ),
                });
            }
            other => {
                return Err(QidError::Config {
                    message: format!(
                        "realm {realm_id} static client {} has unsupported token_endpoint_auth_method: {other}",
                        client.client_id
                    ),
                });
            }
        },
    }
    Ok(())
}

fn validate_static_client_jwks(realm_id: &str, client: &StaticClientConfig) -> QidResult<()> {
    let keys = client
        .jwks
        .get("keys")
        .and_then(|value| value.as_array())
        .ok_or_else(|| QidError::Config {
            message: format!(
                "realm {realm_id} private_key_jwt static client {} must declare jwks.keys",
                client.client_id
            ),
        })?;
    if keys.is_empty() {
        return Err(QidError::Config {
            message: format!(
                "realm {realm_id} private_key_jwt static client {} must declare at least one JWK",
                client.client_id
            ),
        });
    }
    for (idx, key) in keys.iter().enumerate() {
        let object = key.as_object().ok_or_else(|| QidError::Config {
            message: format!(
                "realm {realm_id} private_key_jwt static client {} jwks.keys[{idx}] must be an object",
                client.client_id
            ),
        })?;
        match object.get("kty").and_then(|value| value.as_str()) {
            Some("RSA" | "EC" | "OKP") => {}
            Some(other) => {
                return Err(QidError::Config {
                    message: format!(
                        "realm {realm_id} private_key_jwt static client {} jwks.keys[{idx}].kty is unsupported: {other}",
                        client.client_id
                    ),
                });
            }
            None => {
                return Err(QidError::Config {
                    message: format!(
                        "realm {realm_id} private_key_jwt static client {} jwks.keys[{idx}] missing kty",
                        client.client_id
                    ),
                });
            }
        }
    }
    Ok(())
}

fn validate_static_redirect_uri(
    realm_id: &str,
    client_id: &str,
    redirect_uri: &str,
) -> QidResult<()> {
    if redirect_uri.contains('*') {
        return Err(QidError::Config {
            message: format!(
                "realm {realm_id} static client {client_id} redirect_uri must not contain wildcards"
            ),
        });
    }
    let parsed = url::Url::parse(redirect_uri).map_err(|e| QidError::Config {
        message: format!(
            "realm {realm_id} static client {client_id} redirect_uri is not valid: {e}"
        ),
    })?;
    if parsed.fragment().is_some() {
        return Err(QidError::Config {
            message: format!(
                "realm {realm_id} static client {client_id} redirect_uri must not contain a fragment"
            ),
        });
    }
    let scheme = parsed.scheme();
    let host = parsed.host_str().unwrap_or_default();
    let localhost = matches!(host, "localhost" | "127.0.0.1" | "::1");
    if scheme != "https" && !(scheme == "http" && localhost) {
        return Err(QidError::Config {
            message: format!(
                "realm {realm_id} static client {client_id} redirect_uri must use https except localhost"
            ),
        });
    }
    Ok(())
}

pub use protocol::*;

mod protocol;

pub use auth::*;

mod auth;

fn validate_scim_custom_schemas(
    schemas: &[crate::config::CustomScimSchemaConfig],
    realm_id: &str,
) -> QidResult<()> {
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
    let mut seen_ids = std::collections::HashSet::new();
    for schema in schemas {
        if !seen_ids.insert(&schema.id) {
            return Err(QidError::Config {
                message: format!(
                    "realm {realm_id} SCIM custom schema has duplicate id: {}",
                    schema.id
                ),
            });
        }
        if !schema.id.starts_with("urn:") {
            return Err(QidError::Config {
                message: format!(
                    "realm {realm_id} SCIM custom schema id must be a valid URN: {}",
                    schema.id
                ),
            });
        }
        if schema.name.trim().is_empty() {
            return Err(QidError::Config {
                message: format!(
                    "realm {realm_id} SCIM custom schema {} has empty name",
                    schema.id
                ),
            });
        }
        let mut seen_attrs = std::collections::HashSet::new();
        for attr in &schema.attributes {
            if attr.name.trim().is_empty() {
                return Err(QidError::Config {
                    message: format!(
                        "realm {realm_id} SCIM custom schema {} has an attribute with empty name",
                        schema.id
                    ),
                });
            }
            if !seen_attrs.insert(&attr.name) {
                return Err(QidError::Config {
                    message: format!(
                        "realm {realm_id} SCIM custom schema {} has duplicate attribute name: {}",
                        schema.id, attr.name
                    ),
                });
            }
            if !valid_types.contains(&attr.r#type.as_str()) {
                return Err(QidError::Config {
                    message: format!(
                        "realm {realm_id} SCIM custom schema {} attribute {} has invalid type: {}",
                        schema.id, attr.name, attr.r#type
                    ),
                });
            }
        }
    }
    Ok(())
}

fn validate_scim_event_callback_allowed_host(host: &str, realm_id: &str) -> QidResult<()> {
    let normalized = host.trim().to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.contains('/')
        || normalized.contains(':')
        || normalized.contains('@')
        || normalized.contains('#')
        || normalized.contains('?')
    {
        return Err(QidError::Config {
            message: format!(
                "realm {realm_id} SCIM event_callback_allowed_hosts entries must be host names"
            ),
        });
    }
    let host = normalized.strip_prefix("*.").unwrap_or(&normalized);
    if host.is_empty() || host.contains('*') || host.eq_ignore_ascii_case("localhost") {
        return Err(QidError::Config {
            message: format!(
                "realm {realm_id} SCIM event_callback_allowed_hosts contains an unsafe host"
            ),
        });
    }
    if host.parse::<std::net::IpAddr>().is_ok_and(|ip| {
        ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_multicast()
            || match ip {
                std::net::IpAddr::V4(v4) => {
                    v4.is_private() || v4.is_link_local() || v4.is_broadcast()
                }
                std::net::IpAddr::V6(v6) => v6.is_unique_local() || v6.is_unicast_link_local(),
            }
    }) {
        return Err(QidError::Config {
            message: format!(
                "realm {realm_id} SCIM event_callback_allowed_hosts contains a non-routable host"
            ),
        });
    }
    Ok(())
}

/// Config validation helper: when `enabled` is true, `value` must be `Some` and non-empty.
/// Returns the field name in the error message for clear diagnostics.
pub fn require_when_enabled(
    enabled: bool,
    value: Option<&str>,
    field: &str,
    feature: &str,
) -> QidResult<()> {
    if enabled && value.is_none_or(|v| v.trim().is_empty()) {
        return Err(QidError::Config {
            message: format!("{field} is required when {feature} is enabled"),
        });
    }
    Ok(())
}

/// Validate metrics listen address: must be loopback or explicitly allowlisted.
fn validate_metrics_listen(obs: &ObservabilityConfig) -> QidResult<()> {
    match obs.metrics.listen.parse::<std::net::SocketAddr>() {
        Ok(addr) if addr.ip().is_unspecified() => Err(QidError::Config {
            message: format!(
                "metrics.listen {} must be a loopback address or explicitly allowlisted; \
                 binding to all interfaces exposes metrics to the network",
                obs.metrics.listen
            ),
        }),
        Ok(_) => Ok(()),
        Err(e) => Err(QidError::Config {
            message: format!("metrics.listen is not a valid socket address: {e}"),
        }),
    }
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

#[cfg(test)]
mod tests;
