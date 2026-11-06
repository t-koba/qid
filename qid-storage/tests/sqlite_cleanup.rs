//! Deterministic retry-policy tests; no Windows locks or real sleeps required.
#[path = "support/sqlite_cleanup.rs"]
mod sqlite_cleanup;

use sqlite_cleanup::{parse_millis, retry};
use std::cell::Cell;
use std::io;
use std::time::Duration;

#[test]
fn transient_sharing_violation_then_success() {
    let elapsed = Cell::new(Duration::ZERO);
    let mut attempts = 0;
    let result = retry(
        || {
            attempts += 1;
            if attempts == 1 {
                Err(io::Error::from_raw_os_error(32))
            } else {
                Ok("removed")
            }
        },
        true,
        Duration::from_millis(10),
        Duration::from_millis(2),
        || elapsed.get(),
        |delay| elapsed.set(elapsed.get() + delay),
    )
    .unwrap();
    assert_eq!(result, "removed");
    assert_eq!(attempts, 2);
    assert_eq!(elapsed.get(), Duration::from_millis(2));
}

#[test]
fn persistent_lock_exhausts_deadline_and_preserves_final_error() {
    let elapsed = Cell::new(Duration::ZERO);
    let mut attempts = 0;
    let error = retry(
        || {
            attempts += 1;
            Err::<(), _>(io::Error::from_raw_os_error(32))
        },
        true,
        Duration::from_millis(5),
        Duration::from_millis(2),
        || elapsed.get(),
        |delay| elapsed.set(elapsed.get() + delay),
    )
    .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(32));
    assert_eq!(attempts, 4);
    assert_eq!(elapsed.get(), Duration::from_millis(5));
}

#[test]
fn nonretryable_errors_and_disabled_retries_return_without_sleep() {
    for (windows, timeout, code) in [
        (true, 10, 5),   // Not a sharing violation.
        (false, 10, 32), // Even OS error 32 must not retry on other platforms.
        (true, 0, 32),   // Zero disables retry.
    ] {
        let mut attempts = 0;
        let error = retry(
            || {
                attempts += 1;
                Err::<(), _>(io::Error::from_raw_os_error(code))
            },
            windows,
            Duration::from_millis(timeout),
            Duration::from_millis(2),
            || Duration::ZERO,
            |_| panic!("must not sleep"),
        )
        .unwrap_err();
        assert_eq!(attempts, 1);
        assert_eq!(error.raw_os_error(), Some(code));
    }
}

#[test]
fn invalid_timeout_is_clear_and_zero_is_accepted() {
    let name = "QID_TEST_SQLITE_CLEANUP_RETRY_TIMEOUT_MS";
    for value in ["", "-1", "1.5", "forever", "18446744073709551616"] {
        let error = parse_millis(name, value).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains(name));
    }
    assert_eq!(parse_millis(name, "0").unwrap(), Duration::ZERO);
    assert_eq!(parse_millis(name, "1000").unwrap(), Duration::from_secs(1));
}
