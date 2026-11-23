use qid_core::config::PrimaryStorageConfig;
use qid_core::error::QidError;
use std::ffi::OsStr;

fn primary(url: Option<&str>, url_env: Option<&str>) -> PrimaryStorageConfig {
    PrimaryStorageConfig {
        r#type: "postgres".to_string(),
        url: url.map(str::to_string),
        url_env: url_env.map(str::to_string),
    }
}

struct EnvGuard(&'static str);

impl EnvGuard {
    fn set(name: &'static str, value: impl AsRef<OsStr>) -> Self {
        unsafe { std::env::set_var(name, value) };
        Self(name)
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        unsafe { std::env::remove_var(self.0) };
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
fn url_and_url_env_together_are_rejected() {
    let config = primary(
        Some("postgres://explicit"),
        Some("QID_TEST_STORAGE_URL_AMBIGUOUS"),
    );
    let err = config.resolve_url_or("sqlite:fallback.db").unwrap_err();
    assert!(matches!(err, QidError::Config { .. }));
    assert!(err.message().contains("both url and url_env"));
}

#[test]
fn blank_url_is_rejected() {
    let config = primary(Some("  "), None);
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
