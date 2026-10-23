use super::*;

/// The only refresh-token reuse mode the product implements: presenting a
/// superseded token revokes the whole token family.
pub const REFRESH_REUSE_DETECTION_REVOKE_FAMILY: &str = "revoke_family";

/// The only password hash algorithm the product creates. Verification
/// accepts the algorithms an imported credential may carry, but a
/// credential the product creates is always Argon2id.
pub const PASSWORD_HASH_ALGORITHM: &str = "argon2id";

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationConfig {
    #[serde(default)]
    pub email_verification: EmailVerificationConfig,
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

/// Policy for delivered, session-bound email ownership challenges.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct EmailVerificationConfig {
    pub ttl_seconds: u64,
    pub max_attempts: u32,
}

impl Default for EmailVerificationConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: 600,
            max_attempts: 5,
        }
    }
}

impl EmailVerificationConfig {
    pub(crate) fn validate(&self) -> QidResult<()> {
        if !(1..=3600).contains(&self.ttl_seconds) || self.max_attempts == 0 {
            return Err(QidError::Config {
                message: "authentication.email_verification requires ttl_seconds in 1..=3600 and positive max_attempts".into(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PasskeyConfig {
    /// Absent: none attestation. Present: require operator-trusted packed enrollment.
    #[serde(default)]
    pub attestation: Option<PackedAttestationPolicy>,
    /// Advertise WebAuthn before password in OIDC login choices (advisory only).
    #[serde(default = "default_false")]
    pub preferred: bool,
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default)]
    pub rp_id: Option<String>,
    #[serde(default)]
    pub rp_origin: Option<String>,
    #[serde(default = "default_passkey_rp_name")]
    pub rp_name: String,
}

impl Default for PasskeyConfig {
    fn default() -> Self {
        Self {
            attestation: None,
            enabled: default_false(),
            preferred: default_false(),
            rp_id: None,
            rp_origin: None,
            rp_name: default_passkey_rp_name(),
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
    /// The algorithm the product creates credentials with. The product
    /// creates Argon2id hashes only, so any other value names a capability
    /// the product does not have and is a configuration error.
    #[serde(default = "default_password_hash")]
    pub hash: String,
    /// How many failed password logins lock the account.
    #[serde(default = "default_max_failed_attempts")]
    pub max_failed_attempts: u32,
    /// How long the account stays locked.
    #[serde(default = "default_lockout_duration_seconds")]
    pub lockout_duration_seconds: u64,
    /// How many failed password logins the realm accepts within the
    /// lockout window. A realm that has spent this budget refuses further
    /// password logins until the window passes, so neither a password
    /// spray nor a mass lockout runs without bound.
    #[serde(default = "default_max_failed_attempts_per_realm")]
    pub max_failed_attempts_per_realm: u32,
    /// Per-realm Argon2id cost calibration. INTEROP §3 requires that these
    /// factors be tuned to the deployment's CPU/memory budget rather than
    /// hard-coded to the upstream library defaults. Verification always
    /// honours the parameters embedded in the stored hash, and a credential
    /// whose parameters differ from this cost is rehashed with it at the
    /// next successful login.
    #[serde(default)]
    pub argon2id: Argon2idCostConfig,
    /// Optional external secret keys; omitted means unpeppered creation.
    #[serde(default)]
    pub pepper: Option<PasswordPepperConfig>,
}

/// Key IDs are 1–8 UTF-8 bytes (the native Argon2 keyid limit).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PasswordPepperConfig {
    pub active: String,
    pub keys: std::collections::BTreeMap<String, PasswordSecretSource>,
}

/// Exactly one source, never inline secret bytes. File contents are read verbatim.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged, deny_unknown_fields)]
pub enum PasswordSecretSource {
    Env { env: String },
    File { file: String },
}

impl PasswordPepperConfig {
    pub fn validate(&self) -> QidResult<()> {
        let valid = self.keys.contains_key(&self.active)
            && self.keys.iter().all(|(id, source)| {
                !id.is_empty()
                    && id.len() <= 8
                    && match source {
                        PasswordSecretSource::Env { env: name } => {
                            !name.is_empty() && !name.contains(['=', '\0'])
                        }
                        PasswordSecretSource::File { file: path } => {
                            !path.is_empty() && !path.contains('\0')
                        }
                    }
            });
        if !valid {
            return Err(QidError::Config {
                message: "invalid password pepper key IDs, active key or secret source".into(),
            });
        }
        Ok(())
    }
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            hash: default_password_hash(),
            max_failed_attempts: default_max_failed_attempts(),
            lockout_duration_seconds: default_lockout_duration_seconds(),
            max_failed_attempts_per_realm: default_max_failed_attempts_per_realm(),
            argon2id: Argon2idCostConfig::default(),
            pepper: None,
        }
    }
}

impl PasswordConfig {
    /// The password policy a realm states. Every setting here has an
    /// effect: the hash algorithm names the one the product creates, and
    /// the lockout limits are the ones the realm's password logins
    /// enforce.
    pub fn validate(&self, realm_id: &str) -> QidResult<()> {
        if let Some(pepper) = &self.pepper {
            pepper.validate()?;
        }
        if self.hash != PASSWORD_HASH_ALGORITHM {
            return Err(QidError::Config {
                message: format!(
                    "realm {realm_id} authentication.password.hash must be \
                     {PASSWORD_HASH_ALGORITHM} (got {})",
                    self.hash
                ),
            });
        }
        if self.max_failed_attempts == 0 {
            return Err(QidError::Config {
                message: format!(
                    "realm {realm_id} authentication.password.max_failed_attempts must be at least 1"
                ),
            });
        }
        if self.lockout_duration_seconds == 0 {
            return Err(QidError::Config {
                message: format!(
                    "realm {realm_id} authentication.password.lockout_duration_seconds must be \
                     at least 1"
                ),
            });
        }
        if self.max_failed_attempts_per_realm == 0 {
            return Err(QidError::Config {
                message: format!(
                    "realm {realm_id} authentication.password.max_failed_attempts_per_realm \
                     must be at least 1"
                ),
            });
        }
        if self.argon2id.time_cost == 0 {
            return Err(QidError::Config {
                message: format!(
                    "realm {realm_id} authentication.password.argon2id.time_cost must be at \
                     least 1"
                ),
            });
        }
        if self.argon2id.parallelism == 0 {
            return Err(QidError::Config {
                message: format!(
                    "realm {realm_id} authentication.password.argon2id.parallelism must be at \
                     least 1"
                ),
            });
        }
        if u64::from(self.argon2id.memory_kib) < 8 * u64::from(self.argon2id.parallelism) {
            return Err(QidError::Config {
                message: format!(
                    "realm {realm_id} authentication.password.argon2id.memory_kib must be at \
                     least 8 KiB per lane"
                ),
            });
        }
        Ok(())
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
    PASSWORD_HASH_ALGORITHM.to_string()
}

fn default_max_failed_attempts() -> u32 {
    5
}

fn default_lockout_duration_seconds() -> u64 {
    300
}

fn default_max_failed_attempts_per_realm() -> u32 {
    100
}

/// The realm's multi-factor settings. The only factor the realm
/// configuration names is TOTP, and a realm that does not enable it
/// refuses TOTP enrolment and challenges.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MfaConfig {
    #[serde(default)]
    pub totp: TotpConfig,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TotpConfig {
    /// Whether the realm offers the TOTP factor. A realm that leaves it
    /// disabled refuses TOTP enrolment and challenges.
    #[serde(default = "default_false")]
    pub enabled: bool,
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

impl RefreshTokenConfig {
    /// The refresh path always rotates the token on every use, and a
    /// superseded or concurrently redeemed token always revokes the whole
    /// family. A configured setting may only state that behaviour: rotation
    /// cannot be turned off, and a reuse-detection mode must be the one the
    /// product enforces.
    pub(crate) fn validate(&self, realm_id: &str) -> QidResult<()> {
        if !self.rotation {
            return Err(QidError::Config {
                message: format!(
                    "realm {realm_id} sessions.refresh_tokens.rotation cannot be disabled: \
                     the refresh path always rotates the token on every use"
                ),
            });
        }
        let Some(mode) = self.reuse_detection.as_deref() else {
            return Ok(());
        };
        if mode != REFRESH_REUSE_DETECTION_REVOKE_FAMILY {
            return Err(QidError::Config {
                message: format!(
                    "realm {realm_id} sessions.refresh_tokens.reuse_detection must be \
                     {REFRESH_REUSE_DETECTION_REVOKE_FAMILY} (got {mode})"
                ),
            });
        }
        Ok(())
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

impl PepRegistrationsConfig {
    /// The registrations the realm serves.
    ///
    /// `enabled` is the switch that decides whether the realm serves its PEP
    /// registrations at all: a realm that leaves the switch off serves none of
    /// them, so the decision, assertion and AuthZEN endpoints never
    /// authenticate a PEP of that realm, and the PAR and OAuth mTLS paths
    /// never accept its PEP metadata.
    pub fn served(&self) -> &[PepRegistrationConfig] {
        if self.enabled {
            &self.registrations
        } else {
            &[]
        }
    }
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
    pub effect: String,
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
}

impl Default for PepRegistrationAuthConfig {
    fn default() -> Self {
        Self {
            active_method: PepAuthMethod::default(),
            replay_protection: default_true(),
            token_max_age_seconds: default_pep_auth_token_max_age_seconds(),
            clock_skew_seconds: default_pep_auth_clock_skew_seconds(),
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

fn default_pep_auth_token_max_age_seconds() -> u64 {
    300
}

fn default_pep_auth_clock_skew_seconds() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProxyAssertionConfig {
    #[serde(default = "default_assertion_ttl_seconds")]
    pub ttl_seconds: u64,
}

impl Default for ProxyAssertionConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: default_assertion_ttl_seconds(),
        }
    }
}

fn default_assertion_ttl_seconds() -> u64 {
    60
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PepDecisionConfig {
    #[serde(default = "default_pep_decision_fail_policy")]
    pub fail_policy: String,
    #[serde(default)]
    pub cache: PepDecisionCacheConfig,
}

impl Default for PepDecisionConfig {
    fn default() -> Self {
        Self {
            fail_policy: default_pep_decision_fail_policy(),
            cache: PepDecisionCacheConfig::default(),
        }
    }
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

/// The class of a decision in the decision cache. A positive decision is one
/// the request proceeds on, a negative one the product refuses or defers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionCacheClass {
    Positive,
    Negative,
}

impl PepDecisionCacheConfig {
    /// The lifetime, in milliseconds, the decision cache keeps a decision of
    /// the given class: a positive decision for `positive_ttl_seconds`, a
    /// negative one for `negative_ttl_seconds`. A lifetime of zero means the
    /// decision is not cached at all.
    pub fn ttl_ms(&self, class: DecisionCacheClass) -> u64 {
        let seconds = match class {
            DecisionCacheClass::Positive => self.positive_ttl_seconds,
            DecisionCacheClass::Negative => self.negative_ttl_seconds,
        };
        seconds.saturating_mul(1000)
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
}

/// Optional OTLP/gRPC span export. No endpoint means no exporter.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct TracingConfig {
    pub endpoint: Option<String>,
    pub service_name: String,
    pub scheduled_delay_ms: u64,
    pub export_timeout_ms: u64,
    pub max_queue_size: usize,
    pub max_export_batch_size: usize,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            endpoint: None,
            service_name: "qidd".to_string(),
            scheduled_delay_ms: 5_000,
            export_timeout_ms: 3_000,
            max_queue_size: 2_048,
            max_export_batch_size: 512,
        }
    }
}

impl TracingConfig {
    /// Validate without including the endpoint (which may contain secrets) in errors.
    pub fn validate(&self) -> crate::error::QidResult<()> {
        let invalid = |message: &str| crate::error::QidError::Config {
            message: format!("observability.tracing: {message}"),
        };
        if let Some(endpoint) = &self.endpoint {
            let url = url::Url::parse(endpoint)
                .map_err(|_| invalid("endpoint must be an absolute HTTP or HTTPS URL"))?;
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return Err(invalid("endpoint must be an absolute HTTP or HTTPS URL"));
            }
            if !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(invalid(
                    "endpoint must not contain credentials, query or fragment",
                ));
            }
        }
        if self.service_name.trim().is_empty() {
            return Err(invalid("service_name must not be empty"));
        }
        if self.scheduled_delay_ms == 0 || self.export_timeout_ms == 0 {
            return Err(invalid(
                "scheduled_delay_ms and export_timeout_ms must be positive",
            ));
        }
        if self.max_queue_size == 0
            || self.max_export_batch_size == 0
            || self.max_export_batch_size > self.max_queue_size
        {
            return Err(invalid(
                "batch and queue sizes must be positive, with batch <= queue",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: default_log_format(),
        }
    }
}

impl LogConfig {
    /// Whether the daemon writes JSON logs. The format is validated when the
    /// configuration is loaded, so only `json` and `text` reach this point.
    pub fn json(&self) -> bool {
        self.format == "json"
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
