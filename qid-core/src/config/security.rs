use super::*;

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    #[serde(default)]
    pub primary: PrimaryStorageConfig,
    #[serde(default)]
    pub cache: StorageCacheConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrimaryStorageConfig {
    #[serde(default = "default_storage_type")]
    pub r#type: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub url_env: Option<String>,
}

impl Default for PrimaryStorageConfig {
    fn default() -> Self {
        Self {
            r#type: default_storage_type(),
            url: None,
            url_env: None,
        }
    }
}

impl PrimaryStorageConfig {
    /// Resolve the effective storage URL from `url`, then `url_env`, then
    /// `default_url`.
    pub fn resolve_url_or(&self, default_url: impl Into<String>) -> String {
        self.url
            .clone()
            .or_else(|| {
                self.url_env
                    .as_deref()
                    .and_then(|env| std::env::var(env).ok())
            })
            .unwrap_or_else(|| default_url.into())
    }
}

fn default_storage_type() -> String {
    "sqlite".to_string()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StorageCacheConfig {
    #[serde(default = "default_ops_cache_kind")]
    pub kind: String,
    #[serde(default)]
    pub url_env: Option<String>,
    #[serde(default)]
    pub endpoints: Vec<String>,
    #[serde(default = "default_ops_cache_key_prefix")]
    pub key_prefix: String,
    #[serde(default = "default_ops_cache_ttl_seconds")]
    pub ttl_seconds: u64,
}

impl Default for StorageCacheConfig {
    fn default() -> Self {
        Self {
            kind: default_ops_cache_kind(),
            url_env: None,
            endpoints: Vec::new(),
            key_prefix: default_ops_cache_key_prefix(),
            ttl_seconds: default_ops_cache_ttl_seconds(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CryptoConfig {
    #[serde(default = "default_crypto_alg")]
    pub default_alg: String,
    #[serde(default)]
    pub keyrings: Vec<KeyringConfig>,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            default_alg: default_crypto_alg(),
            keyrings: Vec::new(),
        }
    }
}

impl CryptoConfig {
    pub(crate) fn validate(&self) -> QidResult<()> {
        if !matches!(self.default_alg.as_str(), "ES256" | "RS256" | "EdDSA") {
            return Err(QidError::Config {
                message: "crypto.default_alg must be ES256, RS256, or EdDSA".to_string(),
            });
        }

        let mut seen_keyrings = std::collections::HashSet::new();
        for keyring in &self.keyrings {
            keyring.validate()?;
            if !seen_keyrings.insert(&keyring.name) {
                return Err(QidError::Config {
                    message: format!("duplicate crypto keyring: {}", keyring.name),
                });
            }
        }
        Ok(())
    }
}

fn default_crypto_alg() -> String {
    "ES256".to_string()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyringConfig {
    pub name: String,
    #[serde(default)]
    pub realm_id: Option<String>,
    #[serde(default)]
    pub purposes: Vec<String>,
    #[serde(default)]
    pub signer: SignerConfig,
    #[serde(default)]
    pub rotation: RotationConfig,
}

impl KeyringConfig {
    fn validate(&self) -> QidResult<()> {
        if self.name.trim().is_empty() {
            return Err(QidError::Config {
                message: "crypto keyring name must not be empty".to_string(),
            });
        }
        if self
            .realm_id
            .as_deref()
            .is_some_and(|realm_id| realm_id.trim().is_empty())
        {
            return Err(QidError::Config {
                message: format!("crypto keyring {} realm_id must not be empty", self.name),
            });
        }
        let mut seen_purposes = std::collections::HashSet::new();
        for purpose in &self.purposes {
            if !matches!(
                purpose.as_str(),
                "oidc_token" | "saml_assertion" | "pep_assertion" | "audit_log" | "browser_session"
            ) && purpose
                .strip_prefix("other:")
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(QidError::Config {
                    message: format!(
                        "crypto keyring {} has unsupported purpose: {purpose}",
                        self.name
                    ),
                });
            }
            if !seen_purposes.insert(purpose) {
                return Err(QidError::Config {
                    message: format!(
                        "crypto keyring {} has duplicate purpose: {purpose}",
                        self.name
                    ),
                });
            }
        }
        self.signer.validate(&self.name)?;
        self.rotation.validate(&self.name)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignerConfig {
    #[serde(default = "default_signer_type")]
    pub r#type: String,
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub public_jwk: Option<serde_json::Value>,
}

impl Default for SignerConfig {
    fn default() -> Self {
        Self {
            r#type: default_signer_type(),
            uri: None,
            public_jwk: None,
        }
    }
}

impl SignerConfig {
    fn validate(&self, keyring_name: &str) -> QidResult<()> {
        match self.r#type.as_str() {
            "local" => {
                if self.uri.is_some() {
                    return Err(QidError::Config {
                        message: format!(
                            "crypto keyring {keyring_name} local signer must not set uri"
                        ),
                    });
                }
                if self.public_jwk.is_some() {
                    return Err(QidError::Config {
                        message: format!(
                            "crypto keyring {keyring_name} local signer must not set public_jwk"
                        ),
                    });
                }
                Ok(())
            }
            "kms" | "hsm" | "pkcs11" => {
                let uri = self.uri.as_deref().unwrap_or_default();
                if uri.trim().is_empty() {
                    return Err(QidError::Config {
                        message: format!(
                            "crypto keyring {keyring_name} signer {} requires uri",
                            self.r#type
                        ),
                    });
                }
                validate_signer_uri(keyring_name, self.r#type.as_str(), uri)?;
                validate_remote_signer_public_jwk(keyring_name, self.public_jwk.as_ref())
            }
            other => Err(QidError::Config {
                message: format!(
                    "crypto keyring {keyring_name} has unsupported signer type: {other}"
                ),
            }),
        }
    }
}

fn validate_remote_signer_public_jwk(
    keyring_name: &str,
    public_jwk: Option<&serde_json::Value>,
) -> QidResult<()> {
    let jwk = public_jwk.ok_or_else(|| QidError::Config {
        message: format!("crypto keyring {keyring_name} remote signer requires public_jwk"),
    })?;
    let object = jwk.as_object().ok_or_else(|| QidError::Config {
        message: format!("crypto keyring {keyring_name} public_jwk must be an object"),
    })?;
    for required in ["kty", "kid", "alg"] {
        if object
            .get(required)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim()
            .is_empty()
        {
            return Err(QidError::Config {
                message: format!(
                    "crypto keyring {keyring_name} public_jwk.{required} must not be empty"
                ),
            });
        }
    }
    if object
        .get("kid")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        != keyring_name
    {
        return Err(QidError::Config {
            message: format!(
                "crypto keyring {keyring_name} public_jwk.kid must match keyring name"
            ),
        });
    }
    match object
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
    {
        "RS256" => {
            require_jwk_member(keyring_name, object, "n")?;
            require_jwk_member(keyring_name, object, "e")?;
            validate_rsa_key_size(keyring_name, object)
        }
        "ES256" => {
            require_jwk_member(keyring_name, object, "crv")?;
            require_jwk_member(keyring_name, object, "x")?;
            require_jwk_member(keyring_name, object, "y")
        }
        "EdDSA" => {
            require_jwk_member(keyring_name, object, "crv")?;
            require_jwk_member(keyring_name, object, "x")
        }
        other => Err(QidError::Config {
            message: format!(
                "crypto keyring {keyring_name} public_jwk alg must be RS256, ES256, or EdDSA, got {other}"
            ),
        }),
    }
}

/// Reject RSA keys with modulus < 2048 bits (§17.2 weak RSA key rejection).
fn validate_rsa_key_size(
    keyring_name: &str,
    object: &serde_json::Map<String, serde_json::Value>,
) -> QidResult<()> {
    let n_str = object
        .get("n")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    use base64::Engine;
    let n_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(n_str)
        .map_err(|_| QidError::Config {
            message: format!("crypto keyring {keyring_name} public_jwk.n is not valid base64url"),
        })?;
    let bit_length = n_bytes.len() * 8;
    if bit_length < 2048 {
        return Err(QidError::Config {
            message: format!(
                "crypto keyring {keyring_name} RSA key is only {bit_length} bits; minimum is 2048"
            ),
        });
    }
    Ok(())
}

fn require_jwk_member(
    keyring_name: &str,
    object: &serde_json::Map<String, serde_json::Value>,
    member: &str,
) -> QidResult<()> {
    if object
        .get(member)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        return Err(QidError::Config {
            message: format!("crypto keyring {keyring_name} public_jwk.{member} must not be empty"),
        });
    }
    Ok(())
}

fn validate_signer_uri(keyring_name: &str, signer_type: &str, uri: &str) -> QidResult<()> {
    let expected_scheme = match signer_type {
        "kms" => "kms://",
        "hsm" => "hsm://",
        "pkcs11" => "pkcs11://",
        _ => {
            return Err(QidError::Config {
                message: format!(
                    "crypto keyring {keyring_name} has unexpected signer type for URI validation"
                ),
            });
        }
    };
    let cloud_kms_scheme = signer_type == "kms"
        && ["aws-kms://", "gcp-kms://", "azure-kms://"]
            .iter()
            .any(|scheme| uri.starts_with(scheme));
    if uri.starts_with(expected_scheme) || cloud_kms_scheme {
        return Ok(());
    }
    Err(QidError::Config {
        message: format!(
            "crypto keyring {keyring_name} signer {signer_type} uri must use {expected_scheme}"
        ),
    })
}

fn default_signer_type() -> String {
    "local".to_string()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RotationConfig {
    #[serde(default = "default_overlap_days")]
    pub overlap_days: u64,
    #[serde(default = "default_max_age_days")]
    pub max_age_days: u64,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            overlap_days: default_overlap_days(),
            max_age_days: default_max_age_days(),
        }
    }
}

impl RotationConfig {
    fn validate(&self, keyring_name: &str) -> QidResult<()> {
        if self.max_age_days == 0 {
            return Err(QidError::Config {
                message: format!(
                    "crypto keyring {keyring_name} rotation.max_age_days must be greater than zero"
                ),
            });
        }
        if self.overlap_days > self.max_age_days {
            return Err(QidError::Config {
                message: format!(
                    "crypto keyring {keyring_name} rotation.overlap_days must not exceed max_age_days"
                ),
            });
        }
        Ok(())
    }
}

fn default_overlap_days() -> u64 {
    14
}

fn default_max_age_days() -> u64 {
    90
}
