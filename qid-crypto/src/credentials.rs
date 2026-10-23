//! Resolved realm password credentials. Sources are snapshotted, never hot-reloaded.
use std::{collections::BTreeMap, sync::Arc};

use argon2::{
    Algorithm, Argon2, KeyId, ParamsBuilder, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use qid_core::{
    config::{PasswordConfig, PasswordSecretSource, QidConfig},
    error::{QidError, QidResult},
    models::PasswordCredential,
    state::{PasswordCredentials, SharedState},
};
use zeroize::Zeroizing;

use crate::password::{
    ARGON2ID_ALGORITHM, Argon2idParams, hash_password_with_params, verify_password_credential,
};

/// One resolved owner for creation, verification and progressive migration.
/// Deliberately has no Debug/Serialize implementation: secret bytes stay private.
pub struct CredentialContext {
    cost: Argon2idParams,
    active: Option<String>,
    keys: BTreeMap<String, Zeroizing<Vec<u8>>>,
}

fn config_error() -> QidError {
    QidError::Config {
        message: "password pepper secret source unavailable, empty or invalid".into(),
    }
}

impl CredentialContext {
    pub fn resolve(config: &PasswordConfig) -> QidResult<Self> {
        Self::resolve_with(config, |source| match source {
            PasswordSecretSource::Env { env } => std::env::var(env)
                .map(|value| Zeroizing::new(value.into_bytes()))
                .map_err(|_| config_error()),
            PasswordSecretSource::File { file } => std::fs::read(file)
                .map(Zeroizing::new)
                .map_err(|_| config_error()),
        })
    }

    fn resolve_with(
        config: &PasswordConfig,
        mut read: impl FnMut(&PasswordSecretSource) -> QidResult<Zeroizing<Vec<u8>>>,
    ) -> QidResult<Self> {
        config.validate("credential context")?;
        argon2::Params::new(
            config.argon2id.memory_kib,
            config.argon2id.time_cost,
            config.argon2id.parallelism,
            Some(32),
        )
        .map_err(|_| config_error())?;
        let mut context = Self::unpeppered(Argon2idParams::from_cost(&config.argon2id));
        if let Some(pepper) = &config.pepper {
            for (id, source) in &pepper.keys {
                let secret = read(source).map_err(|_| config_error())?;
                if secret.is_empty() {
                    return Err(config_error());
                }
                // Validate the native library's secret-length constraint before writes.
                Argon2::new_with_secret(
                    &secret,
                    Algorithm::Argon2id,
                    Version::V0x13,
                    argon2::Params::default(),
                )
                .map_err(|_| config_error())?;
                context.keys.insert(id.clone(), secret);
            }
            context.active = Some(pepper.active.clone());
        }
        Ok(context)
    }

    /// Low-level unconfigured operations; tagged credentials still fail closed.
    pub fn unpeppered(cost: Argon2idParams) -> Self {
        Self {
            cost,
            active: None,
            keys: BTreeMap::new(),
        }
    }
}

impl PasswordCredentials for CredentialContext {
    fn hash(&self, plaintext: &str) -> QidResult<String> {
        let result = (|| -> anyhow::Result<String> {
            let Some(id) = &self.active else {
                return hash_password_with_params(plaintext, &self.cost);
            };
            let secret = self
                .keys
                .get(id)
                .ok_or_else(|| anyhow::anyhow!("missing active key"))?;
            let mut builder = ParamsBuilder::new();
            builder
                .m_cost(self.cost.memory_kib)
                .t_cost(self.cost.time_cost)
                .p_cost(self.cost.parallelism)
                .output_len(self.cost.output_len as usize)
                .keyid(
                    KeyId::try_from(id.as_bytes())
                        .map_err(|_| anyhow::anyhow!("invalid key ID"))?,
                );
            let argon = Argon2::new_with_secret(
                secret,
                Algorithm::Argon2id,
                Version::V0x13,
                builder
                    .build()
                    .map_err(|_| anyhow::anyhow!("invalid cost"))?,
            )
            .map_err(|_| anyhow::anyhow!("invalid secret"))?;
            let material = Zeroizing::new(plaintext.as_bytes().to_vec());
            Ok(argon
                .hash_password(&material, &SaltString::generate(&mut OsRng))
                .map_err(|_| anyhow::anyhow!("hashing failed"))?
                .to_string())
        })();
        result.map_err(|_| QidError::Internal {
            message: "password hashing failed".into(),
        })
    }

    fn verify(&self, plaintext: &str, credential: &PasswordCredential) -> (bool, bool) {
        // Parse the selector before dispatching algorithms; a tag can never fall back.
        let parsed = PasswordHash::new(&credential.hash).ok();
        let Some(selector) = parsed
            .as_ref()
            .and_then(|parsed| parsed.params.get("keyid"))
        else {
            let verification =
                verify_password_credential(plaintext, credential, None, Some(&self.cost));
            return (
                verification.valid,
                verification.valid && (verification.rehash_required || self.active.is_some()),
            );
        };
        let Some(parsed) = parsed.as_ref() else {
            return (false, false);
        };
        let mut buffer = [0; 8];
        let id = match selector
            .b64_decode(&mut buffer)
            .ok()
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
        {
            Some(id) if !id.is_empty() => id,
            _ => return (false, false),
        };
        let Some(secret) = self.keys.get(id) else {
            return (false, false);
        };
        if credential.algorithm != ARGON2ID_ALGORITHM
            || parsed.algorithm.as_str() != ARGON2ID_ALGORITHM
        {
            return (false, false);
        }
        let Ok(argon) = Argon2::new_with_secret(
            secret,
            Algorithm::Argon2id,
            Version::V0x13,
            argon2::Params::default(),
        ) else {
            return (false, false);
        };
        let material = Zeroizing::new(plaintext.as_bytes().to_vec());
        let valid = argon.verify_password(&material, parsed).is_ok();
        // No active key means no downgrade, even if a retained key somehow exists.
        let rehash = valid
            && self.active.as_ref().is_some_and(|active| {
                active != id
                    || crate::password::stored_argon2id_cost(&credential.hash)
                        != Some((
                            self.cost.memory_kib,
                            self.cost.time_cost,
                            self.cost.parallelism,
                        ))
            });
        (valid, rehash)
    }
}

/// Resolve every configured realm before serving. The state owns one context per realm.
pub fn resolve_password_contexts(
    config: &QidConfig,
) -> QidResult<BTreeMap<String, Arc<dyn PasswordCredentials>>> {
    config
        .realms
        .iter()
        .map(|realm| {
            Ok((
                realm.id.clone(),
                Arc::new(CredentialContext::resolve(&realm.authentication.password)?)
                    as Arc<dyn PasswordCredentials>,
            ))
        })
        .collect()
}

/// Never silently construct an unpeppered owner for a configured pepper.
pub fn realm_password_context<R>(
    state: &SharedState<R>,
    realm: &str,
) -> QidResult<Arc<dyn PasswordCredentials>> {
    if let Some(context) = state.password_credentials.get(realm) {
        return Ok(context.clone());
    }
    let config = &state.require_realm(realm)?.password;
    if config.pepper.is_some() {
        return Err(config_error());
    }
    Ok(Arc::new(CredentialContext::resolve(config)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PBKDF2_SHA256_ALGORITHM, encode_pbkdf2_sha256_hash, verify_password};
    use qid_core::config::{Argon2idCostConfig, PasswordPepperConfig};

    fn config(active: &str, ids: &[&str]) -> PasswordConfig {
        PasswordConfig {
            argon2id: Argon2idCostConfig {
                memory_kib: 8,
                time_cost: 1,
                parallelism: 1,
            },
            pepper: Some(PasswordPepperConfig {
                active: active.into(),
                keys: ids
                    .iter()
                    .map(|id| {
                        (
                            id.to_string(),
                            PasswordSecretSource::Env {
                                env: id.to_string(),
                            },
                        )
                    })
                    .collect(),
            }),
            ..Default::default()
        }
    }

    fn resolve(config: &PasswordConfig, bytes: &[u8]) -> CredentialContext {
        CredentialContext::resolve_with(config, |_| Ok(Zeroizing::new(bytes.to_vec()))).unwrap()
    }

    fn credential(hash: String) -> PasswordCredential {
        PasswordCredential {
            user_id: "test-user".into(),
            algorithm: ARGON2ID_ALGORITHM.into(),
            hash,
        }
    }

    #[test]
    fn native_tag_selects_exact_secret_without_fallback_or_disclosure() {
        let realm_config = config("key1", &["key1"]);
        let owner = resolve(&realm_config, b"test-only-pepper-bytes");
        let credential = credential(owner.hash("password").unwrap());
        assert!(credential.hash.contains("keyid=a2V5MQ"));
        assert!(!credential.hash.contains("test-only-pepper-bytes"));
        assert_eq!(owner.verify("password", &credential), (true, false));
        assert_eq!(owner.verify("wrong", &credential), (false, false));
        let cross_realm = resolve(&realm_config, b"different-realm-secret");
        assert_eq!(cross_realm.verify("password", &credential), (false, false));
        let absent_key = resolve(&config("key2", &["key2"]), b"test-only-pepper-bytes");
        assert_eq!(absent_key.verify("password", &credential), (false, false));
        let disabled = CredentialContext::unpeppered(Argon2idParams::new(8, 1, 1));
        assert_eq!(disabled.verify("password", &credential), (false, false));
        assert!(!verify_password("password", &credential.hash).unwrap());
        assert!(!verify_password_credential("password", &credential, None, None).valid);
        for value in ["!", "", "dG9vLWxvbmcta2V5", "a2V5Mg"] {
            let malformed = PasswordCredential {
                hash: credential
                    .hash
                    .replace("keyid=a2V5MQ", &format!("keyid={value}")),
                ..credential.clone()
            };
            assert_eq!(owner.verify("password", &malformed), (false, false));
            assert!(!verify_password_credential("password", &malformed, None, None).valid);
        }
    }

    #[test]
    fn retained_keys_and_untagged_imports_migrate_to_active_key_and_cost() {
        let old = resolve(&config("old", &["old"]), b"test-old");
        let rotated_config = config("new", &["old", "new"]);
        let rotated = CredentialContext::resolve_with(&rotated_config, |source| {
            let PasswordSecretSource::Env { env } = source else {
                unreachable!()
            };
            Ok(Zeroizing::new(if env == "old" {
                b"test-old".to_vec()
            } else {
                b"test-new".to_vec()
            }))
        })
        .unwrap();
        let old_credential = credential(old.hash("password").unwrap());
        assert_eq!(rotated.verify("password", &old_credential), (true, true));
        let current = credential(rotated.hash("password").unwrap());
        assert_eq!(rotated.verify("password", &current), (true, false));
        assert_eq!(old.verify("password", &current), (false, false));
        let unpeppered = CredentialContext::unpeppered(Argon2idParams::new(8, 1, 1));
        let legacy = credential(unpeppered.hash("password").unwrap());
        assert_eq!(unpeppered.verify("password", &legacy), (true, false));
        assert_eq!(rotated.verify("password", &legacy), (true, true));
        let imported = PasswordCredential {
            hash: encode_pbkdf2_sha256_hash("password", b"0123456789abcdef", 100_000).unwrap(),
            algorithm: PBKDF2_SHA256_ALGORITHM.into(),
            ..legacy
        };
        assert_eq!(rotated.verify("password", &imported), (true, true));
        let mut higher_cost = rotated_config.clone();
        higher_cost.argon2id.memory_kib = 16;
        let higher = resolve(&higher_cost, b"test-new");
        assert_eq!(higher.verify("password", &current), (true, true));
    }

    #[test]
    fn configured_sources_are_required_validated_and_errors_are_redacted() {
        let valid = config("key1", &["key1"]);
        assert!(
            CredentialContext::resolve_with(&valid, |_| Ok(Zeroizing::new(Vec::new()))).is_err()
        );
        let error = CredentialContext::resolve_with(&valid, |_| {
            Err(QidError::Config {
                message: "secret-test-canary".into(),
            })
        })
        .err()
        .unwrap();
        assert!(!format!("{error:?}").contains("secret-test-canary"));
        for invalid in [
            config("missing", &["key1"]),
            config("", &[""]),
            config("123456789", &["123456789"]),
        ] {
            assert!(
                CredentialContext::resolve_with(&invalid, |_| panic!(
                    "invalid config must not read sources"
                ))
                .is_err()
            );
        }
        let mut invalid = valid.clone();
        invalid.pepper.as_mut().unwrap().keys.insert(
            "key1".into(),
            PasswordSecretSource::Env {
                env: "bad=name".into(),
            },
        );
        assert!(invalid.validate("test").is_err());
        // No global environment mutation: a unique name cannot have been provisioned.
        let mut missing = valid;
        missing.pepper.as_mut().unwrap().keys.insert(
            "key1".into(),
            PasswordSecretSource::Env {
                env: format!("QID_TEST_ABSENT_{}", rand::random::<u64>()),
            },
        );
        assert!(CredentialContext::resolve(&missing).is_err());
    }

    #[test]
    fn file_sources_are_snapshotted_verbatim_and_zero_length_is_rejected() {
        let path = std::env::temp_dir().join(format!("qid-pepper-{}", rand::random::<u64>()));
        let mut config = config("key1", &["key1"]);
        config.pepper.as_mut().unwrap().keys.insert(
            "key1".into(),
            PasswordSecretSource::File {
                file: path.to_str().unwrap().into(),
            },
        );
        assert!(CredentialContext::resolve(&config).is_err());
        std::fs::write(&path, b"test-only-secret\n").unwrap();
        let snapshot = CredentialContext::resolve(&config).unwrap();
        let credential = credential(snapshot.hash("password").unwrap());
        std::fs::write(&path, b"test-only-secret").unwrap();
        assert_eq!(snapshot.verify("password", &credential), (true, false));
        assert_eq!(
            CredentialContext::resolve(&config)
                .unwrap()
                .verify("password", &credential),
            (false, false)
        );
        std::fs::write(&path, b"").unwrap();
        assert!(CredentialContext::resolve(&config).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
