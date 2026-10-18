//! Shared local policy-bundle source handling for startup and diagnostics.
//!
//! `qidd` consumes local native JSON bundles at startup; an external
//! deployment process must materialize any remote bundle before startup.
//! Diagnostics reuse the same resolution and validation semantics so both
//! surfaces agree on which file a configured source refers to and whether
//! its content is a valid native bundle.
use std::path::{Path, PathBuf};

/// Resolve a configured bundle source to a filesystem path.
///
/// Bare relative paths and relative `file://` paths resolve against the
/// directory containing the config file. Absolute paths are preserved.
/// `http(s)` sources are rejected with the same unsupported-at-startup
/// meaning used by `qidd`.
pub fn resolve_policy_bundle_path(config_path: &Path, source: &str) -> Result<PathBuf, String> {
    if source.starts_with("http://") || source.starts_with("https://") {
        return Err(format!(
            "remote policy bundle sources are not supported at startup: {source}"
        ));
    }
    let raw = source.strip_prefix("file://").unwrap_or(source);
    if raw.is_empty() {
        return Err("policy bundle source path is empty".to_string());
    }
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(path))
    }
}

/// Parse native bundle content into JSON, validating the native schema.
///
/// Matches `qidd` startup: content must be JSON deserializable into
/// [`crate::PolicyBundle`]. Returns the parsed JSON value on success.
pub fn parse_native_policy_bundle(content: &str) -> Result<serde_json::Value, String> {
    if content.trim().is_empty() {
        return Err("policy bundle file is empty".to_string());
    }
    let value: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| format!("policy bundle is not valid JSON: {e}"))?;
    serde_json::from_value::<crate::PolicyBundle>(value.clone())
        .map_err(|e| format!("invalid policy bundle: {e}"))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_bundle_json() -> String {
        serde_json::json!({
            "version": "1",
            "default_decision": "deny",
            "rules": [{
                "name": "allow-read",
                "type": "allow",
                "action": "read",
                "resource_host": "*"
            }]
        })
        .to_string()
    }

    #[test]
    fn resolves_relative_file_and_bare_paths_from_config_dir() {
        let config_dir = std::env::temp_dir().join("qid-policy-source-test");
        let config = config_dir.join("qid.yaml");
        let expected = config_dir.join("policies/bundle.json");
        assert_eq!(
            resolve_policy_bundle_path(&config, "policies/bundle.json").expect("bare"),
            expected
        );
        assert_eq!(
            resolve_policy_bundle_path(&config, "file://policies/bundle.json").expect("file"),
            expected
        );
        assert_eq!(
            resolve_policy_bundle_path(&config, "file://./policies/bundle.json").expect("dot"),
            expected
        );
    }

    #[test]
    fn preserves_absolute_paths_and_rejects_remote_or_empty_sources() {
        let config_dir = std::env::temp_dir().join("qid-policy-source-test");
        let config = config_dir.join("qid.yaml");
        let absolute = std::env::temp_dir().join("qid-policy-bundle.json");
        assert_eq!(
            resolve_policy_bundle_path(&config, absolute.to_str().expect("absolute path"))
                .expect("abs"),
            absolute
        );
        let file_uri = format!("file://{}", absolute.display());
        assert_eq!(
            resolve_policy_bundle_path(&config, &file_uri).expect("file abs"),
            absolute
        );
        let err = resolve_policy_bundle_path(&config, "https://example.com/bundle.json")
            .expect_err("remote");
        assert!(err.contains("not supported at startup"), "{err}");
        let err = resolve_policy_bundle_path(&config, "file://").expect_err("empty file URI");
        assert!(err.contains("source path is empty"), "{err}");
    }

    #[test]
    fn parses_valid_native_bundle_and_rejects_other_content() {
        assert!(parse_native_policy_bundle(&minimal_bundle_json()).is_ok());
        assert!(parse_native_policy_bundle("{}").is_err());
        assert!(parse_native_policy_bundle("not json").is_err());
    }
}
