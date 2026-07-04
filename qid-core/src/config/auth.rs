use super::*;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationConfig {
    #[serde(default)]
    pub passkeys: PasskeyConfig,
    #[serde(default)]
    pub password: PasswordConfig,
    #[serde(default)]
    pub mfa: MfaConfig,
    /// When true, password authentication is explicitly blocked.
    /// Passkeys must be enabled. Password config is ignored.
    #[serde(default = "default_false")]
    pub passwordless_only: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PasskeyConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_false")]
    pub preferred: bool,
    #[serde(default)]
    pub rp_id: Option<String>,
    #[serde(default)]
    pub rp_origin: Option<String>,
    #[serde(default = "default_passkey_rp_name")]
    pub rp_name: String,
    #[serde(default)]
    pub attestation: Option<String>,
}

impl Default for PasskeyConfig {
    fn default() -> Self {
        Self {
            enabled: default_false(),
            preferred: default_false(),
            rp_id: None,
            rp_origin: None,
            rp_name: default_passkey_rp_name(),
            attestation: None,
        }
    }
}

fn default_passkey_rp_name() -> String {
    "qid".to_string()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PasswordConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_password_hash")]
    pub hash: String,
    #[serde(default)]
    pub pepper_ref: Option<String>,
    #[serde(default = "default_max_failed_attempts")]
    pub max_failed_attempts: u32,
    #[serde(default = "default_lockout_duration_seconds")]
    pub lockout_duration_seconds: u64,
    /// Per-realm Argon2id cost calibration. INTEROP §3 requires that these
    /// factors be tuned to the deployment's CPU/memory budget rather than
    /// hard-coded to the upstream library defaults. Verification always
    /// honours the parameters embedded in the stored hash.
    #[serde(default)]
    pub argon2id: Argon2idCostConfig,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            hash: default_password_hash(),
            pepper_ref: None,
            max_failed_attempts: default_max_failed_attempts(),
            lockout_duration_seconds: default_lockout_duration_seconds(),
            argon2id: Argon2idCostConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Argon2idCostConfig {
    #[serde(default = "default_argon2id_memory_kib")]
    pub memory_kib: u32,
    #[serde(default = "default_argon2id_time_cost")]
    pub time_cost: u32,
    #[serde(default = "default_argon2id_parallelism")]
    pub parallelism: u32,
}

impl Default for Argon2idCostConfig {
    fn default() -> Self {
        Self {
            memory_kib: default_argon2id_memory_kib(),
            time_cost: default_argon2id_time_cost(),
            parallelism: default_argon2id_parallelism(),
        }
    }
}

fn default_argon2id_memory_kib() -> u32 {
    19_456
}

fn default_argon2id_time_cost() -> u32 {
    2
}

fn default_argon2id_parallelism() -> u32 {
    1
}

fn default_password_hash() -> String {
    "argon2id".to_string()
}

fn default_max_failed_attempts() -> u32 {
    5
}

fn default_lockout_duration_seconds() -> u64 {
    300
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MfaConfig {
    #[serde(default = "default_false")]
    pub required_for_admins: bool,
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default)]
    pub totp: TotpConfig,
    #[serde(default)]
    pub sms: MfaSmsConfig,
    #[serde(default)]
    pub client_certificate: ClientCertificateMfaConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientCertificateMfaConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_certificate_attributes: Vec<String>,
}

impl Default for ClientCertificateMfaConfig {
    fn default() -> Self {
        Self {
            enabled: default_false(),
            allowed_certificate_attributes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MfaSmsConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TotpConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_totp_digits")]
    pub digits: u32,
    #[serde(default = "default_totp_period")]
    pub period: u64,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            enabled: default_false(),
            digits: default_totp_digits(),
            period: default_totp_period(),
        }
    }
}

fn default_totp_digits() -> u32 {
    6
}
fn default_totp_period() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    #[serde(default)]
    pub browser: BrowserSessionConfig,
    #[serde(default)]
    pub refresh_tokens: RefreshTokenConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrowserSessionConfig {
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,
    #[serde(default = "default_same_site")]
    pub same_site: String,
    #[serde(default = "default_idle_timeout_minutes")]
    pub idle_timeout_minutes: u64,
    #[serde(default = "default_absolute_timeout_hours")]
    pub absolute_timeout_hours: u64,
}

impl Default for BrowserSessionConfig {
    fn default() -> Self {
        Self {
            cookie_name: default_cookie_name(),
            same_site: default_same_site(),
            idle_timeout_minutes: default_idle_timeout_minutes(),
            absolute_timeout_hours: default_absolute_timeout_hours(),
        }
    }
}

fn default_cookie_name() -> String {
    "__Host-qid".to_string()
}

fn default_same_site() -> String {
    "Lax".to_string()
}

fn default_idle_timeout_minutes() -> u64 {
    30
}

fn default_absolute_timeout_hours() -> u64 {
    12
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RefreshTokenConfig {
    #[serde(default = "default_true")]
    pub rotation: bool,
    #[serde(default)]
    pub reuse_detection: Option<String>,
}

impl Default for RefreshTokenConfig {
    fn default() -> Self {
        Self {
            rotation: default_true(),
            reuse_detection: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PepRegistrationsConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default)]
    pub registrations: Vec<PepRegistrationConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PepRegistrationConfig {
    pub name: String,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<PepCapabilityConfig>,
    #[serde(default)]
    pub assertion: ProxyAssertionConfig,
    #[serde(default)]
    pub decision: PepDecisionConfig,
    #[serde(default)]
    pub auth: PepRegistrationAuthConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PepCapabilityConfig {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub phase: Option<String>,
    pub effect: String,
    #[serde(default)]
    pub constraints: PepCapabilityConstraintsConfig,
    #[serde(default)]
    pub authority: PepAuthorityConfig,
    #[serde(default)]
    pub build_features: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PepCapabilityConstraintsConfig {
    #[serde(default)]
    pub max_items: Option<u64>,
    #[serde(default)]
    pub allowed_schemes: Vec<String>,
    #[serde(default)]
    pub header_policy: Option<String>,
    #[serde(default)]
    pub local_response_supported: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PepAuthorityConfig {
    #[serde(default)]
    pub can_allow: bool,
    #[serde(default)]
    pub can_deny: bool,
    #[serde(default)]
    pub can_override_route: bool,
    #[serde(default)]
    pub can_weaken_local_policy: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PepRegistrationAuthConfig {
    #[serde(default)]
    pub active_method: PepAuthMethod,
    #[serde(default = "default_true")]
    pub replay_protection: bool,
    #[serde(default = "default_pep_auth_token_max_age_seconds")]
    pub token_max_age_seconds: u64,
    #[serde(default = "default_pep_auth_clock_skew_seconds")]
    pub clock_skew_seconds: u64,
    #[serde(default = "default_pep_auth_key_rotation")]
    pub key_rotation: String,
    #[serde(default)]
    pub http_message_signatures: PepHttpMessageSignaturesConfig,
}

impl Default for PepRegistrationAuthConfig {
    fn default() -> Self {
        Self {
            active_method: PepAuthMethod::default(),
            replay_protection: default_true(),
            token_max_age_seconds: default_pep_auth_token_max_age_seconds(),
            clock_skew_seconds: default_pep_auth_clock_skew_seconds(),
            key_rotation: default_pep_auth_key_rotation(),
            http_message_signatures: PepHttpMessageSignaturesConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PepAuthMethod {
    #[default]
    BearerJwt,
    Mtls,
    HttpMessageSignatures,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PepHttpMessageSignaturesConfig {
    #[serde(default = "default_true")]
    pub content_digest_required: bool,
}

impl Default for PepHttpMessageSignaturesConfig {
    fn default() -> Self {
        Self {
            content_digest_required: default_true(),
        }
    }
}

fn default_pep_auth_token_max_age_seconds() -> u64 {
    300
}

fn default_pep_auth_clock_skew_seconds() -> u64 {
    30
}

fn default_pep_auth_key_rotation() -> String {
    "required".to_string()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProxyAssertionConfig {
    #[serde(default = "default_assertion_header")]
    pub header: String,
    #[serde(default = "default_assertion_ttl_seconds")]
    pub ttl_seconds: u64,
    #[serde(default = "default_assertion_alg")]
    pub alg: String,
}

impl Default for ProxyAssertionConfig {
    fn default() -> Self {
        Self {
            header: default_assertion_header(),
            ttl_seconds: default_assertion_ttl_seconds(),
            alg: default_assertion_alg(),
        }
    }
}

fn default_assertion_header() -> String {
    "x-qid-assertion".to_string()
}

fn default_assertion_ttl_seconds() -> u64 {
    60
}

fn default_assertion_alg() -> String {
    "ES256".to_string()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PepDecisionConfig {
    #[serde(default = "default_pep_decision_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_pep_decision_fail_policy")]
    pub fail_policy: String,
    #[serde(default)]
    pub cache: PepDecisionCacheConfig,
}

impl Default for PepDecisionConfig {
    fn default() -> Self {
        Self {
            endpoint: default_pep_decision_endpoint(),
            fail_policy: default_pep_decision_fail_policy(),
            cache: PepDecisionCacheConfig::default(),
        }
    }
}

fn default_pep_decision_endpoint() -> String {
    "/pep/decision/v1/evaluate".to_string()
}

fn default_pep_decision_fail_policy() -> String {
    "deny".to_string()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PepDecisionCacheConfig {
    #[serde(default = "default_positive_ttl_seconds")]
    pub positive_ttl_seconds: u64,
    #[serde(default = "default_negative_ttl_seconds")]
    pub negative_ttl_seconds: u64,
}

impl Default for PepDecisionCacheConfig {
    fn default() -> Self {
        Self {
            positive_ttl_seconds: default_positive_ttl_seconds(),
            negative_ttl_seconds: default_negative_ttl_seconds(),
        }
    }
}

fn default_positive_ttl_seconds() -> u64 {
    30
}

fn default_negative_ttl_seconds() -> u64 {
    5
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    #[serde(default)]
    pub bundles: Vec<PolicyBundleConfig>,
    #[serde(default = "default_policy_decision")]
    pub default_decision: String,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            bundles: Vec::new(),
            default_decision: default_policy_decision(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundleConfig {
    pub name: String,
    pub source: String,
    #[serde(default = "default_bundle_mode")]
    pub mode: String,
}

fn default_bundle_mode() -> String {
    "enforce".to_string()
}

fn default_policy_decision() -> String {
    "deny".to_string()
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub logs: LogConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub tracing: TracingConfig,
    #[serde(default)]
    pub audit: AuditConfig,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TracingConfig {
    #[serde(default)]
    pub otlp_endpoint_env: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default = "default_false")]
    pub redact_pii: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: default_log_format(),
            redact_pii: default_false(),
        }
    }
}

fn default_log_format() -> String {
    "json".to_string()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    #[serde(default = "default_metrics_listen")]
    pub listen: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            listen: default_metrics_listen(),
        }
    }
}

fn default_metrics_listen() -> String {
    "127.0.0.1:9464".to_string()
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    #[serde(default)]
    pub sink: Option<AuditSinkConfig>,
    #[serde(default)]
    pub include: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditSinkConfig {
    pub r#type: String,
    #[serde(default)]
    pub path: Option<String>,
}
