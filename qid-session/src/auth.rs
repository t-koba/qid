//! Authentication service.

use async_trait::async_trait;
use qid_core::error::{QidError, QidResult};
use qid_core::models::{PasswordCredential, User};
use qid_core::tenant::RealmId;
use qid_crypto::{
    ARGON2ID_ALGORITHM, BreachedPasswordSet, DenyPepperResolver, hash_password,
    verify_password_credential,
};
use qid_storage::prelude::*;
use std::sync::Arc;

use crate::hibp::HibpClient;

/// Authentication result.
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub user: User,
    pub acr: String,
    pub amr: Vec<String>,
}

/// Authenticator performs credential verification.
pub struct Authenticator<R: Repository> {
    repo: Arc<R>,
    breached_passwords: BreachedPasswordSet,
    hibp_client: Option<HibpClient>,
    max_failed_attempts: u32,
    lockout_duration_seconds: u64,
}

impl<R: Repository> Authenticator<R> {
    pub fn new(repo: Arc<R>) -> Self {
        Self {
            repo,
            breached_passwords: BreachedPasswordSet::default(),
            hibp_client: None,
            max_failed_attempts: 5,
            lockout_duration_seconds: 300,
        }
    }

    pub fn with_breached_passwords(repo: Arc<R>, breached_passwords: BreachedPasswordSet) -> Self {
        Self {
            repo,
            breached_passwords,
            hibp_client: None,
            max_failed_attempts: 5,
            lockout_duration_seconds: 300,
        }
    }

    pub fn with_hibp_client(mut self, client: HibpClient) -> Self {
        self.hibp_client = Some(client);
        self
    }

    pub fn with_lockout_config(
        mut self,
        max_failed_attempts: u32,
        lockout_duration_seconds: u64,
    ) -> Self {
        self.max_failed_attempts = max_failed_attempts;
        self.lockout_duration_seconds = lockout_duration_seconds;
        self
    }

    /// Authenticate a user with email and password.
    pub async fn authenticate_password(
        &self,
        realm_id: &RealmId,
        email: &str,
        password: &str,
    ) -> QidResult<AuthResult> {
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
            self.record_failed_attempt(&mut user, now).await?;
            return Err(QidError::Unauthorized {
                message: "password is compromised".to_string(),
            });
        }

        let cred = match self.repo.get_password_credential(&user.id).await? {
            Some(c) => c,
            None => {
                self.record_failed_attempt(&mut user, now).await?;
                return Err(QidError::Unauthorized {
                    message: "invalid credentials".to_string(),
                });
            }
        };

        let verification = verify_password_credential(
            password,
            &cred,
            &DenyPepperResolver,
            if self.breached_passwords.is_empty() {
                None
            } else {
                Some(&self.breached_passwords)
            },
        )
        .map_err(|e| QidError::Internal {
            message: format!("password verification error: {e}"),
        })?;

        if !verification.valid {
            self.record_failed_attempt(&mut user, now).await?;
            return Err(QidError::Unauthorized {
                message: "invalid credentials".to_string(),
            });
        }

        if verification.rehash_required {
            let hash = hash_password(password).map_err(|e| QidError::Internal {
                message: format!("password rehash error: {e}"),
            })?;
            self.repo
                .store_password_credential(&PasswordCredential {
                    user_id: user.id.clone(),
                    hash,
                    algorithm: ARGON2ID_ALGORITHM.to_string(),
                    pepper_ref: None,
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
        })
    }

    /// Authenticate a user via email magic link (after token verification).
    pub async fn authenticate_email_magic_link(&self, user: &User) -> QidResult<AuthResult> {
        Ok(AuthResult {
            user: user.clone(),
            acr: "urn:qid:acr:email_magic_link".to_string(),
            amr: vec!["email_magic_link".to_string()],
        })
    }

    /// Authenticate a user via client certificate MFA factor.
    ///
    /// Accepts a validated client certificate fingerprint (SHA-256 of DER)
    /// and matches it against the user's registered fingerprints.
    pub async fn authenticate_client_certificate_mfa(
        &self,
        user: &User,
        fingerprint: &str,
        registered_fingerprints: &[String],
    ) -> QidResult<AuthResult> {
        if !registered_fingerprints.iter().any(|f| f == fingerprint) {
            return Err(QidError::Unauthorized {
                message: "client certificate authentication failed".to_string(),
            });
        }
        Ok(AuthResult {
            user: user.clone(),
            acr: "urn:qid:acr:phishing-resistant".to_string(),
            amr: vec!["client_certificate".to_string()],
        })
    }

    async fn record_failed_attempt(&self, user: &mut User, now: u64) -> QidResult<()> {
        user.failed_login_attempts += 1;
        if user.failed_login_attempts >= self.max_failed_attempts {
            user.locked_until = Some(now + self.lockout_duration_seconds);
        }
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

    async fn authenticate_email_magic_link(&self, user: &User) -> QidResult<AuthResult>;

    async fn authenticate_client_certificate_mfa(
        &self,
        user: &User,
        fingerprint: &str,
        registered_fingerprints: &[String],
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

    async fn authenticate_email_magic_link(&self, user: &User) -> QidResult<AuthResult> {
        self.authenticate_email_magic_link(user).await
    }

    async fn authenticate_client_certificate_mfa(
        &self,
        user: &User,
        fingerprint: &str,
        registered_fingerprints: &[String],
    ) -> QidResult<AuthResult> {
        self.authenticate_client_certificate_mfa(user, fingerprint, registered_fingerprints)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            pepper_ref: None,
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
        let authenticator = Authenticator::new(repo.clone());

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
        let authenticator = Authenticator::with_breached_passwords(repo, breached);

        let err = authenticator
            .authenticate_password(&RealmId::from("corp"), "alice@example.com", password)
            .await
            .unwrap_err();

        assert!(matches!(err, QidError::Unauthorized { .. }));
    }
}
