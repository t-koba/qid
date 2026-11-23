use qid_core::config::{PrimaryStorageConfig, QidConfig, StorageCacheConfig};
use qid_core::error::QidError;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

fn primary(url: Option<&str>, url_env: Option<&str>) -> PrimaryStorageConfig {
    PrimaryStorageConfig {
        r#type: "postgres".to_string(),
        url: url.map(str::to_string),
        url_env: url_env.map(str::to_string),
    }
}

// Config loading merges every `QID_` variable into the config tree, so tests
// that set environment variables must not overlap with a config load.
static ENV_LOCK: Mutex<()> = Mutex::new(());

struct EnvGuard {
    name: &'static str,
    _lock: MutexGuard<'static, ()>,
}

impl EnvGuard {
    fn set(name: &'static str, value: impl AsRef<OsStr>) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        unsafe { std::env::set_var(name, value) };
        Self { name, _lock: lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        unsafe { std::env::remove_var(self.name) };
    }
}

struct TempConfigDir(PathBuf);

#[allow(clippy::expect_used)] // Fixture setup failures are test failures.
impl TempConfigDir {
    fn with_url_env(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("qid-storage-url-{}", ulid::Ulid::new()));
        std::fs::create_dir(&dir).expect("create temp config dir");
        let yaml = format!(
            "server:\n  listen: '127.0.0.1:8443'\n  public_base_url: 'https://id.example.com'\n\
             storage:\n  primary:\n    type: postgres\n    url_env: {name}\n\
             realms:\n  - id: corp\n    issuer: 'https://id.example.com/realms/corp'\n"
        );
        std::fs::write(dir.join("config.yaml"), yaml).expect("write temp config");
        Self(dir)
    }

    fn config_path(&self) -> String {
        self.0
            .join("config.yaml")
            .to_str()
            .expect("temp path utf-8")
            .to_string()
    }
}

impl Drop for TempConfigDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn explicit_url_is_used_without_an_environment_source() {
    let config = primary(Some("postgres://explicit"), None);
    assert_eq!(
        config.resolve_url_or("sqlite:fallback.db").unwrap(),
        "postgres://explicit"
    );
}

#[test]
fn explicit_url_takes_precedence_over_url_env() {
    const NAME: &str = "QID_TEST_STORAGE_URL_IGNORED";
    let _guard = EnvGuard::set(NAME, "postgres://env-host/db");
    let config = primary(Some("postgres://explicit"), Some(NAME));
    assert_eq!(
        config.resolve_url_or("sqlite:fallback.db").unwrap(),
        "postgres://explicit"
    );
}

#[test]
fn blank_url_is_rejected() {
    let config = primary(Some("  "), None);
    let err = config.resolve_url_or("sqlite:fallback.db").unwrap_err();
    assert!(matches!(err, QidError::Config { .. }));
    assert!(err.message().contains("url must not be blank"));
}

#[test]
fn blank_url_is_rejected_even_with_a_valid_url_env() {
    const NAME: &str = "QID_TEST_STORAGE_URL_BLANK_WITH_EXPLICIT";
    let _guard = EnvGuard::set(NAME, "postgres://env-host/db");
    let config = primary(Some(" \t "), Some(NAME));
    let err = config.resolve_url_or("sqlite:fallback.db").unwrap_err();
    assert!(matches!(err, QidError::Config { .. }));
    assert!(err.message().contains("url must not be blank"));
}

#[test]
fn missing_env_is_rejected_and_names_the_variable() {
    const NAME: &str = "QID_TEST_STORAGE_URL_MISSING";
    unsafe { std::env::remove_var(NAME) };
    let config = primary(None, Some(NAME));
    let err = config.resolve_url_or("sqlite:fallback.db").unwrap_err();
    assert!(matches!(err, QidError::Config { .. }));
    assert!(err.message().contains(NAME));
    assert!(err.message().contains("not set"));
    assert!(!err.message().contains("fallback.db"));
}

#[test]
fn blank_env_is_rejected() {
    const NAME: &str = "QID_TEST_STORAGE_URL_BLANK";
    let _guard = EnvGuard::set(NAME, "  \t ");
    let config = primary(None, Some(NAME));
    let err = config.resolve_url_or("sqlite:fallback.db").unwrap_err();
    assert!(matches!(err, QidError::Config { .. }));
    assert!(err.message().contains(NAME));
    assert!(err.message().contains("blank"));
}

#[test]
fn valid_env_value_is_returned() {
    const NAME: &str = "QID_TEST_STORAGE_URL_VALID";
    let _guard = EnvGuard::set(NAME, "postgres://env-host/db");
    let config = primary(None, Some(NAME));
    assert_eq!(
        config.resolve_url_or("sqlite:fallback.db").unwrap(),
        "postgres://env-host/db"
    );
}

#[cfg(unix)]
#[test]
fn non_unicode_env_is_rejected_without_its_value() {
    use std::os::unix::ffi::OsStringExt;

    const NAME: &str = "QID_TEST_STORAGE_URL_NON_UNICODE";
    let _guard = EnvGuard::set(NAME, std::ffi::OsString::from_vec(vec![0xff, 0xfe]));
    let config = primary(None, Some(NAME));
    let err = config.resolve_url_or("sqlite:fallback.db").unwrap_err();
    assert!(matches!(err, QidError::Config { .. }));
    assert!(err.message().contains(NAME));
    assert!(err.message().contains("Unicode"));
    assert!(!err.message().contains('\u{fffd}'));
}

#[cfg(windows)]
#[test]
fn non_unicode_env_is_rejected_without_its_value() {
    use std::os::windows::ffi::OsStringExt;

    const NAME: &str = "QID_TEST_STORAGE_URL_NON_UNICODE";
    let _guard = EnvGuard::set(NAME, std::ffi::OsString::from_wide(&[0xd800, 0x0041]));
    let config = primary(None, Some(NAME));
    let err = config.resolve_url_or("sqlite:fallback.db").unwrap_err();
    assert!(matches!(err, QidError::Config { .. }));
    assert!(err.message().contains(NAME));
    assert!(err.message().contains("Unicode"));
}

#[test]
fn no_url_source_uses_the_supplied_default() {
    let config = primary(None, None);
    assert_eq!(
        config.resolve_url_or("sqlite:fallback.db").unwrap(),
        "sqlite:fallback.db"
    );
}

#[test]
fn config_file_url_env_resolves_from_an_unreserved_variable() {
    const NAME: &str = "STORAGE_URL_REGRESSION_CONFIG_SOURCE";
    let dir = TempConfigDir::with_url_env(NAME);
    let _guard = EnvGuard::set(NAME, "offline-sample://valid");
    let config = QidConfig::from_file(&dir.config_path()).unwrap();
    assert_eq!(config.storage.primary.url_env.as_deref(), Some(NAME));
    assert_eq!(
        config
            .storage
            .primary
            .resolve_url_or("sqlite:fallback.db")
            .unwrap(),
        "offline-sample://valid"
    );
}

#[test]
fn qid_prefixed_url_env_is_rejected_by_config_loading() {
    const NAME: &str = "QID_STORAGE_URL_REGRESSION_RESERVED";
    let dir = TempConfigDir::with_url_env(NAME);
    let _guard = EnvGuard::set(NAME, "offline-sample://valid");
    let err = QidConfig::from_file(&dir.config_path()).unwrap_err();
    assert!(matches!(err, QidError::Config { .. }));
    let message = err.message();
    assert!(message.contains("unknown field"), "{message}");
    assert!(
        message.contains("storage_url_regression_reserved"),
        "{message}"
    );
}

fn cache(url_env: Option<&str>, endpoints: &[&str]) -> StorageCacheConfig {
    StorageCacheConfig {
        kind: "valkey".to_string(),
        url_env: url_env.map(str::to_string),
        endpoints: endpoints.iter().map(|value| value.to_string()).collect(),
        key_prefix: "qid".to_string(),
        ttl_seconds: 60,
    }
}

#[test]
fn cache_explicit_endpoints_take_precedence_over_url_env() {
    const NAME: &str = "QID_TEST_CACHE_URL_IGNORED";
    let _guard = EnvGuard::set(NAME, "redis://env-cache:6379");
    let config = cache(Some(NAME), &["redis://explicit-cache:6379"]);
    assert_eq!(
        config.resolve_endpoints().unwrap(),
        vec!["redis://explicit-cache:6379"]
    );
}

#[test]
fn cache_missing_url_env_is_rejected_and_names_the_variable() {
    const NAME: &str = "QID_TEST_CACHE_URL_MISSING";
    let _lock = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    unsafe { std::env::remove_var(NAME) };
    let config = cache(Some(NAME), &[]);
    let err = config.resolve_endpoints().unwrap_err();
    assert!(matches!(err, QidError::Config { .. }));
    assert!(err.message().contains(NAME));
    assert!(err.message().contains("not set"));
}

#[test]
fn cache_blank_url_env_is_rejected() {
    const NAME: &str = "QID_TEST_CACHE_URL_BLANK";
    let _guard = EnvGuard::set(NAME, " \t ");
    let config = cache(Some(NAME), &[]);
    let err = config.resolve_endpoints().unwrap_err();
    assert!(matches!(err, QidError::Config { .. }));
    assert!(err.message().contains(NAME));
    assert!(err.message().contains("blank"));
}

#[test]
fn cache_url_env_supplies_a_single_endpoint() {
    const NAME: &str = "QID_TEST_CACHE_URL_VALID";
    let _guard = EnvGuard::set(NAME, " redis://env-cache:6379 ");
    let config = cache(Some(NAME), &[]);
    assert_eq!(
        config.resolve_endpoints().unwrap(),
        vec!["redis://env-cache:6379"]
    );
}

#[test]
fn cache_without_a_url_source_has_no_endpoints() {
    assert!(cache(None, &[]).resolve_endpoints().unwrap().is_empty());
}
