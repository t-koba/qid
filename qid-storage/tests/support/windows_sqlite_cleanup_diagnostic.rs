use std::path::Path;

// Temporary instrumentation used only by the manually dispatched diagnostic.
#[cfg(windows)]
pub(crate) fn capture(path: &Path) -> bool {
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    match std::env::var("QID_SQLITE_CLEANUP_DIAGNOSTIC") {
        Err(std::env::VarError::NotPresent) => return true,
        Ok(value) if value == "1" => {}
        _ => return false,
    }
    let Some(deadline) = std::env::var("QID_SQLITE_CLEANUP_DIAGNOSTIC_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .and_then(|seconds| Instant::now().checked_add(Duration::from_secs(seconds)))
    else {
        return false;
    };
    let Ok(mut child) = Command::new("pwsh")
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-File"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/windows_sqlite_cleanup.ps1"
        ))
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        // PowerShell startup/parser/native errors may contain private paths.
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                // The helper creates no descendants or output files. Kill and
                // reap it before attempting deletion.
                let _ = child.kill();
                let _ = child.wait();
                eprintln!("ERROR: Windows cleanup diagnostic timed out or could not be collected");
                return false;
            }
        }
    }
}
