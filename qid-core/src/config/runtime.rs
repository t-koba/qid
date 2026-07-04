use super::*;

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    #[serde(default)]
    pub security: AdminSecurityConfig,
}

impl AdminConfig {
    pub(crate) fn validate(&self) -> QidResult<()> {
        self.security.validate()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdminSecurityConfig {
    #[serde(default = "default_true")]
    pub require_reason: bool,
    #[serde(default = "default_true")]
    pub require_step_up: bool,
    #[serde(default = "default_admin_required_acr")]
    pub required_acr: String,
    #[serde(default = "default_admin_required_amr")]
    pub required_amr: Vec<String>,
    #[serde(default = "default_admin_max_elevation_seconds")]
    pub max_elevation_seconds: u64,
    #[serde(default = "default_false")]
    pub require_approval: bool,
    #[serde(default = "default_admin_max_approval_age_seconds")]
    pub max_approval_age_seconds: u64,
    #[serde(default = "default_true")]
    pub breakglass_enabled: bool,
}

impl Default for AdminSecurityConfig {
    fn default() -> Self {
        Self {
            require_reason: default_true(),
            require_step_up: default_true(),
            required_acr: default_admin_required_acr(),
            required_amr: default_admin_required_amr(),
            max_elevation_seconds: default_admin_max_elevation_seconds(),
            require_approval: default_false(),
            max_approval_age_seconds: default_admin_max_approval_age_seconds(),
            breakglass_enabled: default_true(),
        }
    }
}

impl AdminSecurityConfig {
    fn validate(&self) -> QidResult<()> {
        if self.require_step_up {
            if self.required_acr.trim().is_empty() {
                return Err(QidError::Config {
                    message:
                        "admin.security.required_acr must not be empty when step-up is required"
                            .to_string(),
                });
            }
            if self.required_amr.is_empty() {
                return Err(QidError::Config {
                    message:
                        "admin.security.required_amr must not be empty when step-up is required"
                            .to_string(),
                });
            }
            for method in &self.required_amr {
                if method.trim().is_empty() {
                    return Err(QidError::Config {
                        message: "admin.security.required_amr must not contain empty values"
                            .to_string(),
                    });
                }
            }
        }
        if self.max_elevation_seconds == 0 {
            return Err(QidError::Config {
                message: "admin.security.max_elevation_seconds must be greater than zero"
                    .to_string(),
            });
        }
        if self.require_approval && self.max_approval_age_seconds == 0 {
            return Err(QidError::Config {
                message: "admin.security.max_approval_age_seconds must be greater than zero when approval is required"
                    .to_string(),
            });
        }
        Ok(())
    }
}

pub fn default_admin_required_acr() -> String {
    "urn:qid:acr:phishing-resistant".to_string()
}

pub fn default_admin_required_amr() -> Vec<String> {
    vec![
        "hwk".to_string(),
        "webauthn".to_string(),
        "passkey".to_string(),
    ]
}

fn default_admin_max_elevation_seconds() -> u64 {
    900
}

fn default_admin_max_approval_age_seconds() -> u64 {
    3600
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OpsConfig {
    #[serde(default)]
    pub cache: OpsCacheConfig,
    #[serde(default)]
    pub cluster: OpsClusterConfig,
    #[serde(default)]
    pub backup: OpsBackupConfig,
    #[serde(default)]
    pub emergency: OpsEmergencyConfig,
}

impl OpsConfig {
    pub fn validate(&self) -> QidResult<()> {
        self.cache.validate()?;
        self.cluster.validate()?;
        self.backup.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OpsCacheConfig {
    #[serde(default = "default_ops_cache_kind")]
    pub kind: String,
    #[serde(default)]
    pub endpoints: Vec<String>,
    #[serde(default = "default_ops_cache_key_prefix")]
    pub key_prefix: String,
    #[serde(default = "default_ops_cache_ttl_seconds")]
    pub ttl_seconds: u64,
}

impl Default for OpsCacheConfig {
    fn default() -> Self {
        Self {
            kind: default_ops_cache_kind(),
            endpoints: Vec::new(),
            key_prefix: default_ops_cache_key_prefix(),
            ttl_seconds: default_ops_cache_ttl_seconds(),
        }
    }
}

impl OpsCacheConfig {
    fn validate(&self) -> QidResult<()> {
        match self.kind.as_str() {
            "disabled" => Ok(()),
            "redis" | "valkey" => {
                if self.endpoints.is_empty() {
                    return Err(QidError::Config {
                        message: format!("ops.cache.kind={} requires endpoints", self.kind),
                    });
                }
                if self.key_prefix.trim().is_empty() {
                    return Err(QidError::Config {
                        message: "ops.cache.key_prefix must not be empty".to_string(),
                    });
                }
                if self.ttl_seconds == 0 {
                    return Err(QidError::Config {
                        message: "ops.cache.ttl_seconds must be greater than zero".to_string(),
                    });
                }
                Ok(())
            }
            other => Err(QidError::Config {
                message: format!("unsupported ops.cache.kind: {other}"),
            }),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OpsClusterConfig {
    #[serde(default)]
    pub cluster_id: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default = "default_leader_lease_ttl_seconds")]
    pub leader_lease_ttl_seconds: u64,
    #[serde(default)]
    pub multi_region_active_active: bool,
}

impl Default for OpsClusterConfig {
    fn default() -> Self {
        Self {
            cluster_id: None,
            region: None,
            node_id: None,
            leader_lease_ttl_seconds: default_leader_lease_ttl_seconds(),
            multi_region_active_active: false,
        }
    }
}

impl OpsClusterConfig {
    fn validate(&self) -> QidResult<()> {
        if self.leader_lease_ttl_seconds == 0 {
            return Err(QidError::Config {
                message: "ops.cluster.leader_lease_ttl_seconds must be greater than zero"
                    .to_string(),
            });
        }
        if self.multi_region_active_active {
            for (name, value) in [
                ("cluster_id", &self.cluster_id),
                ("region", &self.region),
                ("node_id", &self.node_id),
            ] {
                if value.as_deref().unwrap_or_default().trim().is_empty() {
                    return Err(QidError::Config {
                        message: format!(
                            "ops.cluster.{name} is required when multi_region_active_active is enabled"
                        ),
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OpsBackupConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub object_store_uri: Option<String>,
    #[serde(default)]
    pub migration_version: Option<String>,
}

impl OpsBackupConfig {
    fn validate(&self) -> QidResult<()> {
        if self.enabled {
            if self
                .object_store_uri
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                return Err(QidError::Config {
                    message: "ops.backup.object_store_uri is required when backup is enabled"
                        .to_string(),
                });
            }
            if self
                .migration_version
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                return Err(QidError::Config {
                    message: "ops.backup.migration_version is required when backup is enabled"
                        .to_string(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OpsEmergencyConfig {
    #[serde(default)]
    pub read_only: bool,
}

pub(crate) fn default_ops_cache_kind() -> String {
    "disabled".to_string()
}

pub(crate) fn default_ops_cache_key_prefix() -> String {
    "qid".to_string()
}

pub(crate) fn default_ops_cache_ttl_seconds() -> u64 {
    60
}

fn default_leader_lease_ttl_seconds() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: String,
    pub public_base_url: String,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub http_message_signatures: HttpMessageSignaturesConfig,
    #[serde(default)]
    pub cors: CorsConfig,
    #[serde(default)]
    pub paths: ServerPaths,
}

impl ServerConfig {
    pub(crate) fn validate(&self) -> QidResult<()> {
        self.listen
            .parse::<std::net::SocketAddr>()
            .map_err(|e| QidError::Config {
                message: format!("server.listen must be a valid socket address: {e}"),
            })?;
        url::Url::parse(&self.public_base_url).map_err(|e| QidError::Config {
            message: format!("server.public_base_url must be a valid URL: {e}"),
        })?;
        self.cors.validate()?;
        self.http_message_signatures.validate()?;
        self.paths.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpMessageSignaturesConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub shared_secret: Option<String>,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub keys: Vec<HttpMessageSignatureKeyConfig>,
    #[serde(default = "default_http_message_signature_max_age_seconds")]
    pub max_age_seconds: u64,
    #[serde(default = "default_true")]
    pub require_content_digest: bool,
}

impl Default for HttpMessageSignaturesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            shared_secret: None,
            key_id: None,
            keys: Vec::new(),
            max_age_seconds: default_http_message_signature_max_age_seconds(),
            require_content_digest: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpMessageSignatureKeyConfig {
    pub key_id: String,
    pub shared_secret: String,
}

fn default_http_message_signature_max_age_seconds() -> u64 {
    300
}

fn default_true() -> bool {
    true
}

impl HttpMessageSignaturesConfig {
    pub(crate) fn validate(&self) -> QidResult<()> {
        if self.enabled {
            if self.shared_secret.is_none() && self.keys.is_empty() {
                return Err(QidError::Config {
                    message:
                        "server.http_message_signatures.shared_secret or keys is required when enabled"
                            .to_string(),
                });
            }
            if let Some(secret) = self.shared_secret.as_deref()
                && secret.len() < 32
            {
                return Err(QidError::Config {
                    message:
                        "server.http_message_signatures.shared_secret must be at least 32 bytes"
                            .to_string(),
                });
            }
            let mut key_ids = std::collections::HashSet::new();
            for key in &self.keys {
                if key.key_id.trim().is_empty() {
                    return Err(QidError::Config {
                        message: "server.http_message_signatures.keys.key_id must not be empty"
                            .to_string(),
                    });
                }
                if key.shared_secret.len() < 32 {
                    return Err(QidError::Config {
                        message:
                            "server.http_message_signatures.keys.shared_secret must be at least 32 bytes"
                                .to_string(),
                    });
                }
                if !key_ids.insert(key.key_id.as_str()) {
                    return Err(QidError::Config {
                        message: "server.http_message_signatures.keys.key_id values must be unique"
                            .to_string(),
                    });
                }
            }
            if self.max_age_seconds == 0 {
                return Err(QidError::Config {
                    message:
                        "server.http_message_signatures.max_age_seconds must be greater than zero"
                            .to_string(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CorsConfig {
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_cors_methods")]
    pub allowed_methods: Vec<String>,
    #[serde(default = "default_cors_headers")]
    pub allowed_headers: Vec<String>,
    #[serde(default)]
    pub allow_credentials: bool,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: Vec::new(),
            allowed_methods: default_cors_methods(),
            allowed_headers: default_cors_headers(),
            allow_credentials: false,
        }
    }
}

impl CorsConfig {
    fn validate(&self) -> QidResult<()> {
        if self.allowed_origins.iter().any(|origin| origin == "*") && self.allow_credentials {
            return Err(QidError::Config {
                message: "server.cors.allow_credentials cannot be used with wildcard origin"
                    .to_string(),
            });
        }
        for origin in &self.allowed_origins {
            if origin == "*" {
                continue;
            }
            let parsed = url::Url::parse(origin).map_err(|e| QidError::Config {
                message: format!("server.cors.allowed_origins contains invalid origin: {e}"),
            })?;
            if !matches!(parsed.scheme(), "https" | "http") || parsed.host_str().is_none() {
                return Err(QidError::Config {
                    message: "server.cors.allowed_origins must contain absolute HTTP origins"
                        .to_string(),
                });
            }
            if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
                return Err(QidError::Config {
                    message:
                        "server.cors.allowed_origins must not include path, query, or fragment"
                            .to_string(),
                });
            }
        }
        for method in &self.allowed_methods {
            if !is_http_token(method) {
                return Err(QidError::Config {
                    message: format!(
                        "server.cors.allowed_methods contains invalid method: {method}"
                    ),
                });
            }
        }
        for header in &self.allowed_headers {
            if header != "*" && !is_http_token(header) {
                return Err(QidError::Config {
                    message: format!(
                        "server.cors.allowed_headers contains invalid header: {header}"
                    ),
                });
            }
        }
        Ok(())
    }
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
                    | b'0'..=b'9'
                    | b'A'..=b'Z'
                    | b'a'..=b'z'
            )
        })
}

fn default_cors_methods() -> Vec<String> {
    vec![
        "GET".to_string(),
        "POST".to_string(),
        "PUT".to_string(),
        "DELETE".to_string(),
        "PATCH".to_string(),
        "OPTIONS".to_string(),
    ]
}

fn default_cors_headers() -> Vec<String> {
    vec![
        "authorization".to_string(),
        "content-type".to_string(),
        "dpop".to_string(),
    ]
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerPaths {
    #[serde(default = "default_health_path")]
    pub health: String,
    #[serde(default = "default_ready_path")]
    pub ready: String,
    #[serde(default = "default_jwks_path")]
    pub jwks: String,
    #[serde(default = "default_well_known_openid_configuration")]
    pub well_known_openid_configuration: String,
    #[serde(default = "default_well_known_oauth_authorization_server")]
    pub well_known_oauth_authorization_server: String,
    #[serde(default = "default_well_known_oauth_protected_resource")]
    pub well_known_oauth_protected_resource: String,
    #[serde(default = "default_authorize_path")]
    pub authorize: String,
    #[serde(default = "default_par_path")]
    pub par: String,
    #[serde(default = "default_device_authorization_path")]
    pub device_authorization: String,
    #[serde(default = "default_backchannel_authentication_path")]
    pub backchannel_authentication: String,
    #[serde(default = "default_dynamic_client_registration_path")]
    pub dynamic_client_registration: String,
    #[serde(default = "default_dynamic_client_registration_management_path")]
    pub dynamic_client_registration_management: String,
    #[serde(default = "default_userinfo_path")]
    pub userinfo: String,
    #[serde(default = "default_token_path")]
    pub token: String,
    #[serde(default = "default_introspect_path")]
    pub introspect: String,
    #[serde(default = "default_revoke_path")]
    pub revoke: String,
    #[serde(default = "default_pep_decision_path")]
    pub pep_decision: String,
    #[serde(default = "default_authzen_evaluation_path")]
    pub authzen_evaluation: String,
    #[serde(default = "default_assertion_path")]
    pub assertion: String,
    #[serde(default = "default_auth_password_path")]
    pub auth_password: String,
    #[serde(default = "default_auth_session_refresh_path")]
    pub auth_session_refresh: String,
    #[serde(default = "default_auth_session_revoke_path")]
    pub auth_session_revoke: String,
    #[serde(default = "default_logout_path")]
    pub logout: String,
    #[serde(default = "default_backchannel_logout_path")]
    pub backchannel_logout: String,
    #[serde(default = "default_frontchannel_logout_path")]
    pub frontchannel_logout: String,
    #[serde(default = "default_auth_webauthn_start_path")]
    pub auth_webauthn_start: String,
    #[serde(default = "default_auth_webauthn_finish_path")]
    pub auth_webauthn_finish: String,
    #[serde(default = "default_auth_webauthn_auth_start_path")]
    pub auth_webauthn_auth_start: String,
    #[serde(default = "default_auth_webauthn_auth_finish_path")]
    pub auth_webauthn_auth_finish: String,
    #[serde(default = "default_auth_webauthn_discoverable_start_path")]
    pub auth_webauthn_discoverable_start: String,
    #[serde(default = "default_auth_webauthn_discoverable_finish_path")]
    pub auth_webauthn_discoverable_finish: String,
    #[serde(default = "default_auth_email_magic_link_send_path")]
    pub auth_email_magic_link_send: String,
    #[serde(default = "default_auth_email_magic_link_verify_path")]
    pub auth_email_magic_link_verify: String,
}

impl Default for ServerPaths {
    fn default() -> Self {
        Self {
            health: default_health_path(),
            ready: default_ready_path(),
            jwks: default_jwks_path(),
            well_known_openid_configuration: default_well_known_openid_configuration(),
            well_known_oauth_authorization_server: default_well_known_oauth_authorization_server(),
            well_known_oauth_protected_resource: default_well_known_oauth_protected_resource(),
            authorize: default_authorize_path(),
            par: default_par_path(),
            device_authorization: default_device_authorization_path(),
            backchannel_authentication: default_backchannel_authentication_path(),
            dynamic_client_registration: default_dynamic_client_registration_path(),
            dynamic_client_registration_management:
                default_dynamic_client_registration_management_path(),
            userinfo: default_userinfo_path(),
            token: default_token_path(),
            introspect: default_introspect_path(),
            revoke: default_revoke_path(),
            pep_decision: default_pep_decision_path(),
            authzen_evaluation: default_authzen_evaluation_path(),
            assertion: default_assertion_path(),
            auth_password: default_auth_password_path(),
            auth_session_refresh: default_auth_session_refresh_path(),
            auth_session_revoke: default_auth_session_revoke_path(),
            logout: default_logout_path(),
            backchannel_logout: default_backchannel_logout_path(),
            frontchannel_logout: default_frontchannel_logout_path(),
            auth_webauthn_start: default_auth_webauthn_start_path(),
            auth_webauthn_finish: default_auth_webauthn_finish_path(),
            auth_webauthn_auth_start: default_auth_webauthn_auth_start_path(),
            auth_webauthn_auth_finish: default_auth_webauthn_auth_finish_path(),
            auth_webauthn_discoverable_start: default_auth_webauthn_discoverable_start_path(),
            auth_webauthn_discoverable_finish: default_auth_webauthn_discoverable_finish_path(),
            auth_email_magic_link_send: default_auth_email_magic_link_send_path(),
            auth_email_magic_link_verify: default_auth_email_magic_link_verify_path(),
        }
    }
}

impl ServerPaths {
    fn validate(&self) -> QidResult<()> {
        let mut seen = std::collections::HashSet::new();
        let paths: Vec<&str> = vec![
            &self.health,
            &self.ready,
            &self.jwks,
            &self.well_known_openid_configuration,
            &self.well_known_oauth_authorization_server,
            &self.well_known_oauth_protected_resource,
            &self.authorize,
            &self.par,
            &self.device_authorization,
            &self.backchannel_authentication,
            &self.dynamic_client_registration,
            &self.dynamic_client_registration_management,
            &self.userinfo,
            &self.token,
            &self.introspect,
            &self.revoke,
            &self.pep_decision,
            &self.authzen_evaluation,
            &self.assertion,
            &self.auth_password,
            &self.auth_session_refresh,
            &self.auth_session_revoke,
            &self.logout,
            &self.backchannel_logout,
            &self.frontchannel_logout,
            &self.auth_webauthn_start,
            &self.auth_webauthn_finish,
            &self.auth_webauthn_auth_start,
            &self.auth_webauthn_auth_finish,
            &self.auth_webauthn_discoverable_start,
            &self.auth_webauthn_discoverable_finish,
            &self.auth_email_magic_link_send,
            &self.auth_email_magic_link_verify,
        ];
        for p in &paths {
            if p.is_empty() {
                return Err(QidError::Config {
                    message: "server.paths value must not be empty".to_string(),
                });
            }
            if !p.starts_with('/') {
                return Err(QidError::Config {
                    message: format!("server.paths value must start with '/': {p}"),
                });
            }
            if !seen.insert(*p) {
                return Err(QidError::Config {
                    message: format!("server.paths contains duplicate value: {p}"),
                });
            }
        }
        Ok(())
    }
}

fn default_health_path() -> String {
    "/health".to_string()
}
fn default_ready_path() -> String {
    "/ready".to_string()
}
fn default_jwks_path() -> String {
    "/jwks".to_string()
}
fn default_well_known_openid_configuration() -> String {
    "/.well-known/openid-configuration".to_string()
}
fn default_well_known_oauth_authorization_server() -> String {
    "/.well-known/oauth-authorization-server".to_string()
}
fn default_well_known_oauth_protected_resource() -> String {
    "/.well-known/oauth-protected-resource".to_string()
}
fn default_authorize_path() -> String {
    "/oauth2/authorize".to_string()
}
fn default_par_path() -> String {
    "/oauth2/par".to_string()
}
fn default_device_authorization_path() -> String {
    "/oauth2/device_authorization".to_string()
}
fn default_backchannel_authentication_path() -> String {
    "/oauth2/backchannel-authentication".to_string()
}
fn default_dynamic_client_registration_path() -> String {
    "/oauth2/register".to_string()
}
fn default_dynamic_client_registration_management_path() -> String {
    "/oauth2/register/:client_id".to_string()
}
fn default_userinfo_path() -> String {
    "/oidc/userinfo".to_string()
}
fn default_token_path() -> String {
    "/oauth2/token".to_string()
}
fn default_introspect_path() -> String {
    "/oauth2/introspect".to_string()
}
fn default_revoke_path() -> String {
    "/oauth2/revoke".to_string()
}
fn default_pep_decision_path() -> String {
    "/pep/decision/v1/evaluate".to_string()
}
fn default_authzen_evaluation_path() -> String {
    "/access/v1/evaluation".to_string()
}
fn default_assertion_path() -> String {
    "/pep/:realm/assertion".to_string()
}
fn default_logout_path() -> String {
    "/oidc/logout".to_string()
}
fn default_backchannel_logout_path() -> String {
    "/oidc/logout/backchannel".to_string()
}
fn default_frontchannel_logout_path() -> String {
    "/oidc/logout/frontchannel".to_string()
}
fn default_auth_password_path() -> String {
    "/api/v1/:realm/auth/password".to_string()
}
fn default_auth_session_refresh_path() -> String {
    "/api/v1/:realm/auth/session/refresh".to_string()
}
fn default_auth_session_revoke_path() -> String {
    "/api/v1/:realm/auth/session/revoke".to_string()
}
fn default_auth_webauthn_start_path() -> String {
    "/api/v1/:realm/auth/webauthn/start".to_string()
}
fn default_auth_webauthn_finish_path() -> String {
    "/api/v1/:realm/auth/webauthn/finish".to_string()
}
fn default_auth_webauthn_auth_start_path() -> String {
    "/api/v1/:realm/auth/webauthn/auth/start".to_string()
}
fn default_auth_webauthn_auth_finish_path() -> String {
    "/api/v1/:realm/auth/webauthn/auth/finish".to_string()
}
fn default_auth_webauthn_discoverable_start_path() -> String {
    "/api/v1/:realm/auth/webauthn/discoverable/start".to_string()
}
fn default_auth_webauthn_discoverable_finish_path() -> String {
    "/api/v1/:realm/auth/webauthn/discoverable/finish".to_string()
}
fn default_auth_email_magic_link_send_path() -> String {
    "/api/v1/:realm/auth/email-magic-link/send".to_string()
}
fn default_auth_email_magic_link_verify_path() -> String {
    "/api/v1/:realm/auth/email-magic-link/verify".to_string()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert: String,
    pub key: String,
}
