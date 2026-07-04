//! Password hashing utilities.

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use qid_core::models::PasswordCredential;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

pub const ARGON2ID_ALGORITHM: &str = "argon2id";
pub const PBKDF2_SHA256_ALGORITHM: &str = "pbkdf2-sha256";
pub const BCRYPT_ALGORITHM: &str = "bcrypt";
pub const SCRYPT_ALGORITHM: &str = "scrypt";
pub const LDAP_BIND_ALGORITHM: &str = "ldap-bind";

/// Per-realm Argon2id cost parameters.
///
/// INTEROP §3 mandates that password hashing cost factors be calibrated
/// per deployment. The defaults match the upstream `Argon2::default()`,
/// but operators can tighten (or relax) the cost factors per realm to
/// match the available CPU and memory budget.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Argon2idParams {
    /// Memory cost in KiB. Must be at least 8 * `parallelism`.
    pub memory_kib: u32,
    /// Time cost (iterations).
    pub time_cost: u32,
    /// Parallelism (lanes).
    pub parallelism: u32,
    /// Output length in bytes.
    pub output_len: u32,
}

impl Default for Argon2idParams {
    fn default() -> Self {
        Self {
            memory_kib: 19_456,
            time_cost: 2,
            parallelism: 1,
            output_len: 32,
        }
    }
}

impl Argon2idParams {
    pub fn new(memory_kib: u32, time_cost: u32, parallelism: u32) -> Self {
        Self {
            memory_kib,
            time_cost,
            parallelism,
            output_len: 32,
        }
    }

    fn build(&self) -> anyhow::Result<Argon2<'_>> {
        let params = Params::new(
            self.memory_kib,
            self.time_cost,
            self.parallelism,
            Some(self.output_len as usize),
        )
        .map_err(|e| anyhow::anyhow!("invalid Argon2id parameters: {e}"))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// Resolve password peppers stored outside the database.
pub trait PasswordPepperResolver {
    fn resolve(&self, pepper_ref: &str) -> anyhow::Result<Vec<u8>>;
}

/// Fails closed for deployments that have not wired a KMS/HSM pepper resolver.
#[derive(Debug, Clone, Copy)]
pub struct DenyPepperResolver;

impl PasswordPepperResolver for DenyPepperResolver {
    fn resolve(&self, pepper_ref: &str) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("password pepper resolver is not configured for {pepper_ref}")
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BreachedPasswordSet {
    #[serde(default)]
    sha256_hex: std::collections::BTreeSet<String>,
}

impl BreachedPasswordSet {
    pub fn from_sha256_hex<I, S>(digests: I) -> anyhow::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut sha256_hex = std::collections::BTreeSet::new();
        for digest in digests {
            let digest = digest.into();
            if !is_lower_hex_sha256(&digest) {
                anyhow::bail!("breached password digest must be lowercase SHA-256 hex");
            }
            sha256_hex.insert(digest);
        }
        Ok(Self { sha256_hex })
    }

    pub fn contains_password(&self, plaintext: &str) -> bool {
        self.sha256_hex.contains(&sha256_hex(plaintext.as_bytes()))
    }

    pub fn is_empty(&self) -> bool {
        self.sha256_hex.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordVerification {
    pub valid: bool,
    pub rehash_required: bool,
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportedPasswordRecord {
    pub user_id: String,
    pub algorithm: String,
    pub hash: String,
    #[serde(default)]
    pub pepper_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordImportMigrationPlan {
    pub total: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub progressive_rehash_required: usize,
    pub online_bind_required: usize,
    pub reasons: Vec<String>,
}

/// Hash a plaintext password using Argon2id.
pub fn hash_password(plaintext: &str) -> anyhow::Result<String> {
    hash_password_material(
        password_material(plaintext, None).as_slice(),
        &Argon2idParams::default(),
    )
}

/// Hash a plaintext password with an external pepper.
pub fn hash_password_with_pepper(plaintext: &str, pepper: &[u8]) -> anyhow::Result<String> {
    hash_password_material(
        password_material(plaintext, Some(pepper)).as_slice(),
        &Argon2idParams::default(),
    )
}

/// Hash a plaintext password using per-realm Argon2id parameters.
pub fn hash_password_with_params(
    plaintext: &str,
    params: &Argon2idParams,
) -> anyhow::Result<String> {
    hash_password_material(password_material(plaintext, None).as_slice(), params)
}

/// Hash a plaintext password with both an external pepper and per-realm parameters.
pub fn hash_password_with_pepper_and_params(
    plaintext: &str,
    pepper: &[u8],
    params: &Argon2idParams,
) -> anyhow::Result<String> {
    hash_password_material(
        password_material(plaintext, Some(pepper)).as_slice(),
        params,
    )
}

fn hash_password_material(material: &[u8], params: &Argon2idParams) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = params.build()?;
    let password_hash = argon2
        .hash_password(material, &salt)
        .map_err(|e| anyhow::anyhow!("failed to hash password: {e}"))?;
    Ok(password_hash.to_string())
}

/// Verify a plaintext password against an encoded Argon2id hash.
pub fn verify_password(plaintext: &str, encoded_hash: &str) -> anyhow::Result<bool> {
    verify_argon2id_material(password_material(plaintext, None).as_slice(), encoded_hash)
}

pub fn verify_password_credential(
    plaintext: &str,
    credential: &PasswordCredential,
    pepper_resolver: &impl PasswordPepperResolver,
    breached_passwords: Option<&BreachedPasswordSet>,
) -> anyhow::Result<PasswordVerification> {
    if breached_passwords.is_some_and(|breached| breached.contains_password(plaintext)) {
        return Ok(PasswordVerification {
            valid: false,
            rehash_required: false,
            algorithm: credential.algorithm.clone(),
        });
    }
    let pepper = credential
        .pepper_ref
        .as_deref()
        .map(|pepper_ref| pepper_resolver.resolve(pepper_ref))
        .transpose()?;
    let material = password_material(plaintext, pepper.as_deref());
    let algorithm = normalize_algorithm(&credential.algorithm);
    let valid = match algorithm.as_str() {
        ARGON2ID_ALGORITHM => verify_argon2id_material(&material, &credential.hash)?,
        PBKDF2_SHA256_ALGORITHM => verify_pbkdf2_sha256_material(&material, &credential.hash)?,
        LDAP_BIND_ALGORITHM => false,
        BCRYPT_ALGORITHM | SCRYPT_ALGORITHM => {
            anyhow::bail!(
                "password algorithm {} requires a dedicated verifier that is not configured",
                credential.algorithm
            );
        }
        _ => anyhow::bail!("unsupported password algorithm {}", credential.algorithm),
    };
    Ok(PasswordVerification {
        valid,
        rehash_required: valid && algorithm != ARGON2ID_ALGORITHM,
        algorithm,
    })
}

pub fn plan_password_import_migration(
    records: &[ImportedPasswordRecord],
) -> PasswordImportMigrationPlan {
    let mut plan = PasswordImportMigrationPlan {
        total: records.len(),
        accepted: 0,
        rejected: 0,
        progressive_rehash_required: 0,
        online_bind_required: 0,
        reasons: Vec::new(),
    };
    let mut seen = std::collections::BTreeSet::new();
    for record in records {
        if record.user_id.trim().is_empty() {
            plan.rejected += 1;
            plan.reasons.push("user_id_empty".to_string());
            continue;
        }
        if !seen.insert(record.user_id.clone()) {
            plan.rejected += 1;
            plan.reasons
                .push(format!("duplicate_user_id:{}", record.user_id));
            continue;
        }
        let algorithm = normalize_algorithm(&record.algorithm);
        match algorithm.as_str() {
            ARGON2ID_ALGORITHM => {
                if record.hash.trim().is_empty() {
                    plan.rejected += 1;
                    plan.reasons.push(format!("empty_hash:{}", record.user_id));
                } else {
                    plan.accepted += 1;
                }
            }
            PBKDF2_SHA256_ALGORITHM => match parse_pbkdf2_sha256_hash(&record.hash) {
                Ok(_) => {
                    plan.accepted += 1;
                    plan.progressive_rehash_required += 1;
                }
                Err(_) => {
                    plan.rejected += 1;
                    plan.reasons
                        .push(format!("invalid_pbkdf2_hash:{}", record.user_id));
                }
            },
            BCRYPT_ALGORITHM | SCRYPT_ALGORITHM => {
                if record.hash.trim().is_empty() {
                    plan.rejected += 1;
                    plan.reasons.push(format!("empty_hash:{}", record.user_id));
                } else {
                    plan.accepted += 1;
                    plan.progressive_rehash_required += 1;
                    plan.reasons.push(format!(
                        "external_verifier_required:{}:{}",
                        record.user_id, algorithm
                    ));
                }
            }
            LDAP_BIND_ALGORITHM => {
                plan.accepted += 1;
                plan.progressive_rehash_required += 1;
                plan.online_bind_required += 1;
            }
            _ => {
                plan.rejected += 1;
                plan.reasons
                    .push(format!("unsupported_algorithm:{}", record.user_id));
            }
        }
    }
    plan
}

pub fn encode_pbkdf2_sha256_hash(
    plaintext: &str,
    salt: &[u8],
    iterations: u32,
) -> anyhow::Result<String> {
    encode_pbkdf2_sha256_material(
        password_material(plaintext, None).as_slice(),
        salt,
        iterations,
    )
}

fn encode_pbkdf2_sha256_material(
    material: &[u8],
    salt: &[u8],
    iterations: u32,
) -> anyhow::Result<String> {
    if iterations < 100_000 {
        anyhow::bail!("PBKDF2 iterations must be at least 100000");
    }
    if salt.len() < 16 {
        anyhow::bail!("PBKDF2 salt must be at least 16 bytes");
    }
    let digest = pbkdf2_sha256(material, salt, iterations)?;
    Ok(format!(
        "$pbkdf2-sha256$i={iterations}${}${}",
        URL_SAFE_NO_PAD.encode(salt),
        URL_SAFE_NO_PAD.encode(digest)
    ))
}

fn verify_argon2id_material(material: &[u8], encoded_hash: &str) -> anyhow::Result<bool> {
    let parsed_hash = PasswordHash::new(encoded_hash)
        .map_err(|e| anyhow::anyhow!("invalid password hash: {e}"))?;
    let argon2 = Argon2::default();
    Ok(argon2.verify_password(material, &parsed_hash).is_ok())
}

fn verify_pbkdf2_sha256_material(material: &[u8], encoded_hash: &str) -> anyhow::Result<bool> {
    let parsed = parse_pbkdf2_sha256_hash(encoded_hash)?;
    let digest = pbkdf2_sha256(material, &parsed.salt, parsed.iterations)?;
    Ok(qid_core::util::constant_time_eq(&digest, &parsed.digest))
}

struct Pbkdf2Sha256Hash {
    iterations: u32,
    salt: Vec<u8>,
    digest: Vec<u8>,
}

fn parse_pbkdf2_sha256_hash(encoded_hash: &str) -> anyhow::Result<Pbkdf2Sha256Hash> {
    let parts = encoded_hash.split('$').collect::<Vec<_>>();
    if parts.len() != 5 || !parts[0].is_empty() || parts[1] != PBKDF2_SHA256_ALGORITHM {
        anyhow::bail!("invalid PBKDF2 hash format");
    }
    let iterations = parts[2]
        .strip_prefix("i=")
        .ok_or_else(|| anyhow::anyhow!("invalid PBKDF2 iteration field"))?
        .parse::<u32>()
        .map_err(|e| anyhow::anyhow!("invalid PBKDF2 iteration count: {e}"))?;
    if iterations < 100_000 {
        anyhow::bail!("PBKDF2 iterations must be at least 100000");
    }
    let salt = URL_SAFE_NO_PAD
        .decode(parts[3])
        .map_err(|e| anyhow::anyhow!("invalid PBKDF2 salt: {e}"))?;
    if salt.len() < 16 {
        anyhow::bail!("PBKDF2 salt must be at least 16 bytes");
    }
    let digest = URL_SAFE_NO_PAD
        .decode(parts[4])
        .map_err(|e| anyhow::anyhow!("invalid PBKDF2 digest: {e}"))?;
    if digest.len() != 32 {
        anyhow::bail!("PBKDF2 digest must be 32 bytes");
    }
    Ok(Pbkdf2Sha256Hash {
        iterations,
        salt,
        digest,
    })
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> anyhow::Result<Vec<u8>> {
    let mut block_input = Vec::with_capacity(salt.len() + 4);
    block_input.extend_from_slice(salt);
    block_input.extend_from_slice(&1_u32.to_be_bytes());
    let mut mac = HmacSha256::new_from_slice(password)
        .map_err(|e| anyhow::anyhow!("invalid PBKDF2 password material: {e}"))?;
    mac.update(&block_input);
    let mut u = mac.finalize().into_bytes().to_vec();
    let mut output = u.clone();
    for _ in 1..iterations {
        let mut mac = HmacSha256::new_from_slice(password)
            .map_err(|e| anyhow::anyhow!("invalid PBKDF2 password material: {e}"))?;
        mac.update(&u);
        u = mac.finalize().into_bytes().to_vec();
        for (out, byte) in output.iter_mut().zip(&u) {
            *out ^= *byte;
        }
    }
    Ok(output)
}

fn password_material(plaintext: &str, pepper: Option<&[u8]>) -> Zeroizing<Vec<u8>> {
    let mut material = plaintext.as_bytes().to_vec();
    if let Some(pepper) = pepper {
        material.push(0);
        material.extend_from_slice(pepper);
    }
    Zeroizing::new(material)
}

fn normalize_algorithm(algorithm: &str) -> String {
    algorithm.trim().to_ascii_lowercase().replace('_', "-")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_and_verify() {
        let password = "my-secure-password-123!";
        let hash = hash_password(password).expect("hashing failed");
        assert!(!hash.is_empty());
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password(password, &hash).expect("verify failed"));
        assert!(!verify_password("wrong-password", &hash).expect("verify failed"));
    }

    #[test]
    fn password_credential_verifies_pbkdf2_and_requires_rehash() {
        let password = "legacy-password-123!";
        let hash = encode_pbkdf2_sha256_hash(password, b"0123456789abcdef", 100_000).unwrap();
        let credential = PasswordCredential {
            user_id: "user-1".to_string(),
            hash,
            algorithm: PBKDF2_SHA256_ALGORITHM.to_string(),
            pepper_ref: None,
        };

        let verified =
            verify_password_credential(password, &credential, &DenyPepperResolver, None).unwrap();

        assert!(verified.valid);
        assert!(verified.rehash_required);
        assert_eq!(verified.algorithm, PBKDF2_SHA256_ALGORITHM);
        assert!(
            !verify_password_credential("wrong", &credential, &DenyPepperResolver, None)
                .unwrap()
                .valid
        );
    }

    #[test]
    fn breached_password_set_rejects_known_password_before_hash_verification() {
        let password = "breached-password";
        let credential = PasswordCredential {
            user_id: "user-1".to_string(),
            hash: hash_password(password).unwrap(),
            algorithm: ARGON2ID_ALGORITHM.to_string(),
            pepper_ref: None,
        };
        let breached = BreachedPasswordSet::from_sha256_hex([sha256_hex(password.as_bytes())])
            .expect("breach set");

        let verified =
            verify_password_credential(password, &credential, &DenyPepperResolver, Some(&breached))
                .unwrap();

        assert!(!verified.valid);
        assert!(!verified.rehash_required);
    }

    #[test]
    fn peppered_password_requires_resolver_and_verifies_with_secret() {
        struct StaticResolver;
        impl PasswordPepperResolver for StaticResolver {
            fn resolve(&self, pepper_ref: &str) -> anyhow::Result<Vec<u8>> {
                assert_eq!(pepper_ref, "kms://alias/qid-password-pepper");
                Ok(b"tenant-pepper".to_vec())
            }
        }
        let password = "peppered-password";
        let credential = PasswordCredential {
            user_id: "user-1".to_string(),
            hash: hash_password_with_pepper(password, b"tenant-pepper").unwrap(),
            algorithm: ARGON2ID_ALGORITHM.to_string(),
            pepper_ref: Some("kms://alias/qid-password-pepper".to_string()),
        };

        assert!(
            verify_password_credential(password, &credential, &DenyPepperResolver, None).is_err()
        );
        let verified =
            verify_password_credential(password, &credential, &StaticResolver, None).unwrap();

        assert!(verified.valid);
        assert!(!verified.rehash_required);
    }

    #[test]
    fn password_import_plan_accepts_supported_legacy_shapes_and_flags_online_bind() {
        let pbkdf2_hash =
            encode_pbkdf2_sha256_hash("legacy", b"0123456789abcdef", 100_000).unwrap();
        let records = vec![
            ImportedPasswordRecord {
                user_id: "argon".to_string(),
                algorithm: ARGON2ID_ALGORITHM.to_string(),
                hash: "$argon2id$present".to_string(),
                pepper_ref: None,
            },
            ImportedPasswordRecord {
                user_id: "pbkdf2".to_string(),
                algorithm: PBKDF2_SHA256_ALGORITHM.to_string(),
                hash: pbkdf2_hash,
                pepper_ref: None,
            },
            ImportedPasswordRecord {
                user_id: "bcrypt".to_string(),
                algorithm: BCRYPT_ALGORITHM.to_string(),
                hash: "$2b$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                pepper_ref: None,
            },
            ImportedPasswordRecord {
                user_id: "ldap".to_string(),
                algorithm: LDAP_BIND_ALGORITHM.to_string(),
                hash: String::new(),
                pepper_ref: None,
            },
        ];

        let plan = plan_password_import_migration(&records);

        assert_eq!(plan.total, 4);
        assert_eq!(plan.accepted, 4);
        assert_eq!(plan.rejected, 0);
        assert_eq!(plan.progressive_rehash_required, 3);
        assert_eq!(plan.online_bind_required, 1);
        assert!(
            plan.reasons
                .iter()
                .any(|reason| reason == "external_verifier_required:bcrypt:bcrypt")
        );
    }
}
