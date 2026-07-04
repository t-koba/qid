use anyhow::Context;
use qid_core::config::QidConfig;
use qid_ops::{
    BackupObject, CacheBackendConfig, CacheBackendKind, KeyPurpose, KeyRotationRequirement,
    KeyringInventoryRecord, RestoreObjectStore, verify_backup_manifest,
};
use std::path::PathBuf;

pub(crate) fn parse_backup_object(raw: &str) -> anyhow::Result<BackupObject> {
    let mut parts = raw.splitn(3, ':');
    let path = parts
        .next()
        .filter(|part| !part.trim().is_empty())
        .context("backup object path must not be empty")?;
    let sha256 = parts
        .next()
        .filter(|part| !part.trim().is_empty())
        .context("backup object sha256 must not be empty")?;
    let bytes = parts
        .next()
        .context("backup object bytes must be present")?
        .parse::<u64>()
        .context("backup object bytes must be an integer")?;
    Ok(BackupObject {
        path: path.to_string(),
        sha256: sha256.to_string(),
        bytes,
    })
}

pub(crate) fn parse_keyring_inventory_record(raw: &str) -> anyhow::Result<KeyringInventoryRecord> {
    let fields = split_csv_fields(raw);
    if !(fields.len() == 8 || fields.len() == 9) {
        anyhow::bail!(
            "key inventory must have 8 or 9 fields: realm,keyring,kid,purpose,signer_type,created,not_before,retire_after[,revoked]"
        );
    }
    Ok(KeyringInventoryRecord {
        realm_id: non_empty_field(&fields, 0, "realm")?.to_string(),
        keyring_name: non_empty_field(&fields, 1, "keyring")?.to_string(),
        kid: non_empty_field(&fields, 2, "kid")?.to_string(),
        purpose: parse_key_purpose(non_empty_field(&fields, 3, "purpose")?)?,
        signer_type: non_empty_field(&fields, 4, "signer_type")?.to_string(),
        created_at_epoch: parse_u64_field(&fields, 5, "created")?,
        not_before_epoch: parse_u64_field(&fields, 6, "not_before")?,
        retire_after_epoch: parse_u64_field(&fields, 7, "retire_after")?,
        revoked: fields
            .get(8)
            .map(|value| parse_bool_field(value, "revoked"))
            .transpose()?
            .unwrap_or(false),
    })
}

pub(crate) fn parse_key_rotation_requirement(raw: &str) -> anyhow::Result<KeyRotationRequirement> {
    let fields = split_csv_fields(raw);
    if fields.len() != 6 {
        anyhow::bail!(
            "key rotation requirement must have 6 fields: realm,purpose,max_age_days,overlap_days,require_remote,require_dedicated"
        );
    }
    Ok(KeyRotationRequirement {
        realm_id: non_empty_field(&fields, 0, "realm")?.to_string(),
        purpose: parse_key_purpose(non_empty_field(&fields, 1, "purpose")?)?,
        max_age_days: parse_u64_field(&fields, 2, "max_age_days")?,
        overlap_days: parse_u64_field(&fields, 3, "overlap_days")?,
        require_remote_signer: parse_bool_field(
            non_empty_field(&fields, 4, "require_remote")?,
            "require_remote",
        )?,
        require_dedicated_keyring: parse_bool_field(
            non_empty_field(&fields, 5, "require_dedicated")?,
            "require_dedicated",
        )?,
    })
}

fn split_csv_fields(raw: &str) -> Vec<String> {
    raw.split(',').map(|part| part.trim().to_string()).collect()
}

fn non_empty_field<'a>(fields: &'a [String], index: usize, name: &str) -> anyhow::Result<&'a str> {
    fields
        .get(index)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("{name} must not be empty"))
}

fn parse_u64_field(fields: &[String], index: usize, name: &str) -> anyhow::Result<u64> {
    non_empty_field(fields, index, name)?
        .parse::<u64>()
        .with_context(|| format!("{name} must be an unsigned integer"))
}

fn parse_bool_field(value: &str, name: &str) -> anyhow::Result<bool> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => anyhow::bail!("{name} must be true or false"),
    }
}

pub(crate) fn parse_key_purpose(value: &str) -> anyhow::Result<KeyPurpose> {
    Ok(match value {
        "oidc_token" => KeyPurpose::OidcToken,
        "saml_assertion" => KeyPurpose::SamlAssertion,
        "pep_assertion" => KeyPurpose::PepAssertion,
        "audit_log" => KeyPurpose::AuditLog,
        "browser_session" => KeyPurpose::BrowserSession,
        other if other.starts_with("other:") && other.len() > "other:".len() => {
            KeyPurpose::Other(other["other:".len()..].to_string())
        }
        other => anyhow::bail!("unsupported key purpose: {other}"),
    })
}

pub(crate) fn cache_backend_config_from_qid(
    config: &QidConfig,
) -> anyhow::Result<CacheBackendConfig> {
    let cache = &config.storage.cache;
    let endpoints = if cache.endpoints.is_empty() {
        if let Some(env) = &cache.url_env {
            std::env::var(env).map(|url| vec![url]).unwrap_or_default()
        } else {
            Vec::new()
        }
    } else {
        cache.endpoints.clone()
    };
    Ok(CacheBackendConfig {
        kind: match cache.kind.as_str() {
            "disabled" => CacheBackendKind::Disabled,
            "redis" => CacheBackendKind::Redis,
            "valkey" => CacheBackendKind::Valkey,
            other => anyhow::bail!("unsupported cache.kind: {other}"),
        },
        endpoints,
        key_prefix: cache.key_prefix.clone(),
        ttl_seconds: cache.ttl_seconds,
    })
}

pub(crate) fn read_backup_manifest(
    path: &std::path::Path,
) -> anyhow::Result<qid_ops::BackupManifest> {
    let raw_manifest = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let manifest: qid_ops::BackupManifest =
        serde_json::from_str(&raw_manifest).context("invalid backup manifest JSON")?;
    if !verify_backup_manifest(&manifest) {
        anyhow::bail!("backup manifest hash verification failed");
    }
    Ok(manifest)
}

pub(crate) struct LocalRestoreStore {
    source_dir: PathBuf,
    target_dir: PathBuf,
}

impl LocalRestoreStore {
    pub(crate) fn new(source_dir: PathBuf, target_dir: PathBuf) -> Self {
        Self {
            source_dir,
            target_dir,
        }
    }
}

impl RestoreObjectStore for LocalRestoreStore {
    fn read_backup_object(&self, path: &str) -> Result<Vec<u8>, qid_core::QidError> {
        let safe_path = safe_join(&self.source_dir, path)
            .map_err(|msg| qid_core::QidError::BadRequest { message: msg })?;
        std::fs::read(&safe_path).map_err(|e| qid_core::QidError::Internal {
            message: format!("failed to read source object: {e}"),
        })
    }

    fn write_restore_object(
        &mut self,
        path: &str,
        body: &[u8],
        allow_overwrite: bool,
    ) -> Result<String, qid_core::QidError> {
        let output_path = safe_join(&self.target_dir, path)
            .map_err(|msg| qid_core::QidError::BadRequest { message: msg })?;
        if !allow_overwrite && output_path.exists() {
            return Err(qid_core::QidError::BadRequest {
                message: "target object already exists".to_string(),
            });
        }
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| qid_core::QidError::Internal {
                message: format!("failed to create restore directory: {e}"),
            })?;
        }
        std::fs::write(&output_path, body).map_err(|e| qid_core::QidError::Internal {
            message: format!("failed to write restore object: {e}"),
        })?;
        Ok(output_path.display().to_string())
    }
}

fn safe_join(base: &std::path::Path, relative: &str) -> Result<PathBuf, String> {
    let relative_path = std::path::Path::new(relative);
    if relative_path.is_absolute() {
        return Err("path must be relative".to_string());
    }
    for component in relative_path.components() {
        match component {
            std::path::Component::Normal(_) => {}
            _ => return Err("path contains unsafe components".to_string()),
        }
    }
    Ok(base.join(relative_path))
}
