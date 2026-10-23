//! Authentication service.

use async_trait::async_trait;
use qid_core::config::PasswordConfig;
use qid_core::error::{QidError, QidResult};
use qid_core::models::{PasswordCredential, User};
use qid_core::state::PasswordCredentials;
use qid_core::tenant::RealmId;
use qid_core::throttle::FailureBudget;
use qid_crypto::{ARGON2ID_ALGORITHM, Argon2idParams, BreachedPasswordSet, CredentialContext};
use qid_storage::prelude::*;
use std::sync::Arc;

use crate::hibp::HibpClient;

/// Authentication result.
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub user: User,
    pub acr: String,
    pub amr: Vec<String>,
    /// Browser session the authentication happened in, if any. Carried into
    /// authorization codes and refresh families for logout linkage.
    pub session_id: Option<String>,
}

/// The password policy a realm enforces.
#[derive(Debug, Clone, Copy)]
pub struct PasswordPolicy {
    pub max_failed_attempts: u32,
    pub max_failed_attempts_per_realm: u32,
    pub lockout_duration_seconds: u64,
    pub argon2id: Argon2idParams,
    requires_resolved_credentials: bool,
}

impl PasswordPolicy {
    /// The policy the realm's password configuration states.
    pub fn from_config(config: &PasswordConfig) -> Self {
        Self {
            max_failed_attempts: config.max_failed_attempts,
            max_failed_attempts_per_realm: config.max_failed_attempts_per_realm,
            lockout_duration_seconds: config.lockout_duration_seconds,
            argon2id: Argon2idParams::from_cost(&config.argon2id),
            requires_resolved_credentials: config.pepper.is_some(),
        }
    }
}

/// Authenticator performs credential verification.
pub struct Authenticator<R: Repository> {
    repo: Arc<R>,
    breached_passwords: BreachedPasswordSet,
    hibp_client: Option<HibpClient>,
    policy: PasswordPolicy,
    failure_budget: Arc<FailureBudget>,
    credentials: Option<Arc<dyn PasswordCredentials>>,
}

impl<R: Repository> Authenticator<R> {
    pub fn new(repo: Arc<R>, policy: PasswordPolicy, failure_budget: Arc<FailureBudget>) -> Self {
        Self {
            repo,
            breached_passwords: BreachedPasswordSet::default(),
            hibp_client: None,
            credentials: (!policy.requires_resolved_credentials).then(|| {
                Arc::new(CredentialContext::unpeppered(policy.argon2id))
                    as Arc<dyn PasswordCredentials>
            }),
            policy,
            failure_budget,
        }
    }

    pub fn with_breached_passwords(
        repo: Arc<R>,
        breached_passwords: BreachedPasswordSet,
        policy: PasswordPolicy,
        failure_budget: Arc<FailureBudget>,
    ) -> Self {
        let mut authenticator = Self::new(repo, policy, failure_budget);
        authenticator.breached_passwords = breached_passwords;
        authenticator
    }

    /// Use the deployment's resolved realm owner for every credential operation.
    pub fn with_credentials(mut self, credentials: Arc<dyn PasswordCredentials>) -> Self {
        self.credentials = Some(credentials);
        self
    }

    pub fn with_hibp_client(mut self, client: HibpClient) -> Self {
        self.hibp_client = Some(client);
        self
    }

    /// Authenticate a user with email and password.
    pub async fn authenticate_password(
        &self,
        realm_id: &RealmId,
        email: &str,
        password: &str,
    ) -> QidResult<AuthResult> {
        let credentials = self.credentials.as_ref().ok_or_else(|| QidError::Config {
            message: "configured password pepper requires a resolved credential context".into(),
        })?;
        // The realm spends a bounded number of failed password logins per
        // window. A realm that has spent its budget refuses password
        // logins before any credential is verified, so neither a password
        // spray nor a mass lockout makes the daemon verify credentials or
        // lock accounts without bound.
        if self.failure_budget.exhausted(
            realm_id.as_str(),
            self.policy.max_failed_attempts_per_realm,
            self.policy.lockout_duration_seconds,
        ) {
            return Err(QidError::AttemptBudgetSpent {
                message: "too many failed password attempts for this realm".to_string(),
            });
        }
        let user = self
            .repo
            .get_user_by_email(realm_id, email)
            .await?
            .ok_or_else(|| QidError::Unauthorized {
                message: "invalid credentials".to_string(),
            })?;

        // Check persistent account lockout
        let now = qid_core::util::now_seconds();
        if let Some(locked_until) = user.locked_until {
            if locked_until > now {
                return Err(QidError::TooManyRequests {
                    message: "account is temporarily locked".to_string(),
                });
            }
            // Lockout has expired; reset the counter
            let mut updated = user.clone();
            updated.failed_login_attempts = 0;
            updated.locked_until = None;
            self.repo.update_user(&updated).await?;
        }
        // Capture current user state for potential failure update
        let mut user = user;

        if let Some(ref hibp) = self.hibp_client
            && hibp
                .check_password(password)
                .await
                .map_err(|e| QidError::Internal {
                    message: format!("breach check error: {e}"),
                })?
        {
            self.record_failed_attempt(realm_id, &mut user, now).await?;
            return Err(QidError::Unauthorized {
                message: "password is compromised".to_string(),
            });
        }

        let cred = match self.repo.get_password_credential(&user.id).await? {
            Some(c) => c,
            None => {
                self.record_failed_attempt(realm_id, &mut user, now).await?;
                return Err(QidError::Unauthorized {
                    message: "invalid credentials".to_string(),
                });
            }
        };

        let (valid, rehash_required) = if self.breached_passwords.contains_password(password) {
            (false, false)
        } else {
            credentials.verify(password, &cred)
        };
        if !valid {
            self.record_failed_attempt(realm_id, &mut user, now).await?;
            return Err(QidError::Unauthorized {
                message: "invalid credentials".to_string(),
            });
        }

        if rehash_required {
            let hash = credentials.hash(password)?;
            self.repo
                .store_password_credential(&PasswordCredential {
                    user_id: user.id.clone(),
                    hash,
                    algorithm: ARGON2ID_ALGORITHM.to_string(),
                })
                .await?;
        }

        // Successful authentication: reset failed attempts
        if user.failed_login_attempts > 0 || user.locked_until.is_some() {
            let mut updated = user.clone();
            updated.failed_login_attempts = 0;
            updated.locked_until = None;
            self.repo.update_user(&updated).await?;
        }

        Ok(AuthResult {
            user,
            acr: "urn:qid:acr:password".to_string(),
            amr: vec!["pwd".to_string()],
            session_id: None,
        })
    }

    async fn record_failed_attempt(
        &self,
        realm_id: &RealmId,
        user: &mut User,
        now: u64,
    ) -> QidResult<()> {
        user.failed_login_attempts += 1;
        if user.failed_login_attempts >= self.policy.max_failed_attempts {
            user.locked_until = Some(now + self.policy.lockout_duration_seconds);
        }
        self.failure_budget.record_failure(
            realm_id.as_str(),
            self.policy.max_failed_attempts_per_realm,
            self.policy.lockout_duration_seconds,
        );
        self.repo.update_user(user).await
    }
}

#[async_trait]
pub trait AuthenticatorExt: Send + Sync {
    async fn authenticate_password(
        &self,
        realm_id: &RealmId,
        email: &str,
        password: &str,
    ) -> QidResult<AuthResult>;
}

#[async_trait]
impl<R: Repository> AuthenticatorExt for Authenticator<R> {
    async fn authenticate_password(
        &self,
        realm_id: &RealmId,
        email: &str,
        password: &str,
    ) -> QidResult<AuthResult> {
        self.authenticate_password(realm_id, email, password).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qid_core::config::PasswordConfig;
    use qid_core::models::{PasswordCredential, User};
    use qid_core::util;
    use qid_crypto::{PBKDF2_SHA256_ALGORITHM, encode_pbkdf2_sha256_hash, hash_password};
    use qid_storage::FileRepository;
    use sha2::{Digest, Sha256};

    async fn repository_with_user(password_hash: String, algorithm: &str) -> Arc<FileRepository> {
        let path = std::env::temp_dir().join(format!(
            "qid-session-auth-{}-{}.json",
            algorithm,
            util::now_seconds()
        ));
        let repo = Arc::new(
            FileRepository::new(path.to_str().expect("test path is not UTF-8"))
                .await
                .expect("file repository creation failed"),
        );
        repo.migrate()
            .await
            .expect("file repository migration failed");
        repo.create_realm(
            &"tenant-1".into(),
            &"corp".into(),
            "https://login.example.com",
            Some("Test realm"),
        )
        .await
        .expect("realm creation failed");
        repo.create_user(&User {
            id: "user-1".to_string(),
            realm_id: "corp".to_string(),
            email: Some("alice@example.com".to_string()),
            email_verified: true,
            display_name: Some("Alice".to_string()),
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .expect("user creation failed");
        repo.store_password_credential(&PasswordCredential {
            user_id: "user-1".to_string(),
            hash: password_hash,
            algorithm: algorithm.to_string(),
        })
        .await
        .expect("password credential creation failed");
        repo
    }

    #[tokio::test]
    async fn password_auth_progressively_rehashes_imported_pbkdf2_credential() {
        let password = "legacy-password-123!";
        let legacy_hash =
            encode_pbkdf2_sha256_hash(password, b"0123456789abcdef", 100_000).unwrap();
        let repo = repository_with_user(legacy_hash, PBKDF2_SHA256_ALGORITHM).await;
        let authenticator = Authenticator::new(
            repo.clone(),
            PasswordPolicy::from_config(&PasswordConfig::default()),
            Arc::new(FailureBudget::new()),
        );

        let result = authenticator
            .authenticate_password(&RealmId::from("corp"), "alice@example.com", password)
            .await
            .expect("password authentication failed");

        assert_eq!(result.user.id, "user-1");
        let stored = repo
            .get_password_credential("user-1")
            .await
            .expect("password credential lookup failed")
            .expect("password credential missing");
        assert_eq!(stored.algorithm, ARGON2ID_ALGORITHM);
        assert!(stored.hash.starts_with("$argon2id$"));
    }

    #[tokio::test]
    async fn password_auth_rejects_breached_password_even_when_hash_matches() {
        let password = "known-breached-password";
        let repo = repository_with_user(hash_password(password).unwrap(), ARGON2ID_ALGORITHM).await;
        let digest = Sha256::digest(password.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let breached = BreachedPasswordSet::from_sha256_hex([digest]).unwrap();
        let authenticator = Authenticator::with_breached_passwords(
            repo,
            breached,
            PasswordPolicy::from_config(&PasswordConfig::default()),
            Arc::new(FailureBudget::new()),
        );

        let err = authenticator
            .authenticate_password(&RealmId::from("corp"), "alice@example.com", password)
            .await
            .unwrap_err();

        assert!(matches!(err, QidError::Unauthorized { .. }));
    }
}
