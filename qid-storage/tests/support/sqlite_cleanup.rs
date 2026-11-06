//! Filesystem cleanup only: callers must close SQLite repositories first.
//!
//! On Windows only, sharing violations (OS error 32) are retried for at most
//! QID_TEST_SQLITE_CLEANUP_RETRY_TIMEOUT_MS (default 1000; zero disables retry).
//! QID_TEST_SQLITE_CLEANUP_RETRY_INTERVAL_MS controls polling (default 10, nonzero).
//! Both settings are unsigned integer milliseconds; invalid settings return
//! InvalidInput. Other errors are returned immediately, and exhaustion returns
//! the final filesystem error unchanged. No lock owner is assumed.
#![allow(dead_code)]

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub(super) fn parse_millis(name: &str, value: &str) -> io::Result<Duration> {
    value
        .parse::<u64>()
        .map(Duration::from_millis)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} must be unsigned integer milliseconds"),
            )
        })
}

fn setting(name: &str, default: &str) -> io::Result<Duration> {
    match std::env::var(name) {
        Ok(value) => parse_millis(name, &value),
        Err(std::env::VarError::NotPresent) => parse_millis(name, default),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be Unicode unsigned integer milliseconds"),
        )),
    }
}

// Clock and sleep are injected so deadline/error tests need no Windows handles
// or wall-clock timing. The boolean is cfg!(windows) outside those tests.
pub(super) fn retry<T>(
    mut operation: impl FnMut() -> io::Result<T>,
    windows: bool,
    timeout: Duration,
    interval: Duration,
    mut elapsed: impl FnMut() -> Duration,
    mut sleep: impl FnMut(Duration),
) -> io::Result<T> {
    loop {
        match operation() {
            Err(error) if windows && error.raw_os_error() == Some(32) => {
                let remaining = timeout.saturating_sub(elapsed());
                if remaining.is_zero() {
                    return Err(error);
                }
                sleep(interval.min(remaining));
            }
            result => return result,
        }
    }
}

fn cleanup<T>(operation: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let timeout = setting("QID_TEST_SQLITE_CLEANUP_RETRY_TIMEOUT_MS", "1000")?;
    let interval = setting("QID_TEST_SQLITE_CLEANUP_RETRY_INTERVAL_MS", "10")?;
    if interval.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "QID_TEST_SQLITE_CLEANUP_RETRY_INTERVAL_MS must be nonzero",
        ));
    }
    let start = Instant::now();
    retry(
        operation,
        cfg!(windows),
        timeout,
        interval,
        || start.elapsed(),
        std::thread::sleep,
    )
}

pub fn remove_dir_all(path: &Path) -> io::Result<()> {
    cleanup(|| std::fs::remove_dir_all(path))
}

pub fn remove_sqlite_database_files(path: &Path) -> io::Result<()> {
    cleanup(|| remove_sqlite_database_files_once(path))
}

/// Nonretrying best-effort cleanup for Drop, where pool closure cannot be awaited.
pub fn remove_sqlite_database_files_once(path: &Path) -> io::Result<()> {
    for suffix in ["-wal", "-shm", "-journal", ""] {
        let mut candidate = path.as_os_str().to_os_string();
        candidate.push(suffix);
        match std::fs::remove_file(PathBuf::from(candidate)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
