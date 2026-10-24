use crate::config::{
    BrowserSessionConfig, DeploymentProfile, EmailMagicLinkConfig, MfaConfig, PasskeyConfig,
    PasswordConfig, PepRegistrationsConfig, PolicyConfig, QidConfig, TokenTtlConfig,
};
use crate::error::{QidError, QidResult};

/// Compiled runtime plan derived from `QidConfig`.
///
/// The runtime plan normalizes and pre-validates configuration so that the
/// daemon does not need to re-interpret raw config at request time.
#[derive(Debug, Clone)]
pub struct RuntimePlan {
    pub profile: DeploymentProfile,
    pub listen: String,
    pub public_base_url: String,
    pub realms: Vec<RuntimeRealm>,
}

impl RuntimePlan {
    pub fn from_config(config: &QidConfig) -> QidResult<Self> {
        let realms = config
            .realms
            .iter()
            .map(RuntimeRealm::from_config)
            .collect::<Result<Vec<_>, _>>()?;

        if config.server.listen.trim().is_empty() {
            return Err(QidError::Config {
                message: "server.listen must not be empty".to_string(),
            });
        }

        Ok(Self {
            profile: config.profile,
            listen: config.server.listen.clone(),
            public_base_url: config.server.public_base_url.clone(),
            realms,
        })
    }

    pub fn realm(&self, id: &str) -> Option<&RuntimeRealm> {
        self.realms.iter().find(|r| r.id == id)
    }

    pub fn first_realm(&self) -> Option<&RuntimeRealm> {
        self.realms.first()
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeRealm {
    pub id: String,
    pub issuer: String,
    pub display_name: String,
    pub tenant_id: Option<String>,
    pub token_ttl: TokenTtlConfig,
    pub oauth_default_scope: String,
    pub oidc_default_scope: String,
    pub pkce_required: bool,
    pub browser_session: BrowserSessionConfig,
    pub passkeys: PasskeyConfig,
    pub email_magic_link: EmailMagicLinkConfig,
    pub pep_registrations: PepRegistrationsConfig,
    pub policy: PolicyConfig,
    pub passwordless_only: bool,
    /// The realm's password policy: whether password authentication is on,
    /// the lockout limits every password login enforces, and the Argon2id
    /// cost the product creates credentials with.
    pub password: PasswordConfig,
    /// The realm's multi-factor settings: the factors the realm offers.
    pub mfa: MfaConfig,
    pub saml_clock_skew_seconds: u64,
    pub vc_max_credential_lifetime_seconds: u64,
}

impl RuntimeRealm {
    /// Whether this realm accepts a password on any login path. A realm
    /// that disabled password authentication, or that is passwordless,
    /// refuses every password login.
    pub fn accepts_password_authentication(&self) -> bool {
        self.password.enabled && !self.passwordless_only
    }

    /// Whether this realm offers the TOTP factor. A realm that does not
    /// enable TOTP refuses TOTP enrolment and challenges.
    pub fn accepts_totp(&self) -> bool {
        self.mfa.totp.enabled
    }

    fn from_config(config: &crate::config::RealmConfig) -> QidResult<Self> {
        Ok(Self {
            id: config.id.clone(),
            issuer: config.issuer.clone(),
            display_name: config
                .display_name
                .clone()
                .unwrap_or_else(|| config.id.clone()),
            tenant_id: config.tenant_id.clone(),
            token_ttl: config.protocols.oauth.tokens.clone(),
            oauth_default_scope: config.protocols.oauth.default_scope.clone(),
            oidc_default_scope: config.protocols.oidc.default_scope.clone(),
            pkce_required: config.protocols.oidc.authorization_code.pkce_required,
            browser_session: config.sessions.browser.clone(),
            passkeys: config.authentication.passkeys.clone(),
            email_magic_link: config.authentication.email_magic_link.clone(),
            pep_registrations: config.pep_registrations.clone(),
            policy: config.policy.clone(),
            passwordless_only: config.authentication.passwordless_only,
            password: config.authentication.password.clone(),
            mfa: config.authentication.mfa.clone(),
            saml_clock_skew_seconds: config.protocols.saml.max_clock_skew_seconds,
            vc_max_credential_lifetime_seconds: config.protocols.vc.max_credential_lifetime_seconds,
        })
    }
}
