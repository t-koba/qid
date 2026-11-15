use std::path::Path;

#[cfg(windows)]
fn wait_for_child(
    child: &mut std::process::Child,
    timeout: std::time::Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = std::time::Instant::now().checked_add(timeout)?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            _ => return None,
        }
    }
}

#[cfg(windows)]
fn terminate_process_tree(pid: u32) -> bool {
    use std::process::{Command, Stdio};

    let Some(system_root) = std::env::var_os("SystemRoot") else {
        return false;
    };
    let taskkill = std::path::PathBuf::from(system_root)
        .join("System32")
        .join("taskkill.exe");
    let pid = pid.to_string();
    let Ok(mut killer) = Command::new(taskkill)
        .args(["/PID", pid.as_str(), "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    if let Some(status) = wait_for_child(&mut killer, std::time::Duration::from_secs(2)) {
        return status.success();
    }
    let _ = killer.kill();
    let _ = wait_for_child(&mut killer, std::time::Duration::from_secs(1));
    false
}

#[cfg(windows)]
fn terminate_tree_and_reap(child: &mut std::process::Child) -> bool {
    let tree_terminated = terminate_process_tree(child.id());
    let first_reap = wait_for_child(child, std::time::Duration::from_secs(1)).is_some();
    if !first_reap {
        let _ = child.kill();
    }
    let reaped = first_reap || wait_for_child(child, std::time::Duration::from_secs(1)).is_some();
    tree_terminated && reaped
}

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
    let unavailable = || {
        if matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("test_14.db" | "test_15.db")
        ) {
            eprintln!("HANDLE unavailable (helper could not be collected).");
        }
        false
    };
    let Some(deadline) = std::env::var("QID_SQLITE_CLEANUP_DIAGNOSTIC_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .and_then(|seconds| Instant::now().checked_add(Duration::from_secs(seconds)))
    else {
        return unavailable();
    };
    let Ok(mut child) = Command::new("pwsh")
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-File"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/windows_sqlite_cleanup.ps1"
        ))
        .arg(path)
        .arg("-TestProcessId")
        .arg(std::process::id().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        // PowerShell startup/parser/native errors may contain private paths.
        .stderr(Stdio::null())
        .spawn()
    else {
        return unavailable();
    };
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                // Killing only pwsh can orphan Handle. Terminate the whole tree
                // and reap pwsh before the test attempts its original deletion.
                if !terminate_tree_and_reap(&mut child) {
                    eprintln!(
                        "ERROR: Windows cleanup diagnostic process tree was not confirmed stopped"
                    );
                    return unavailable();
                }
                eprintln!("ERROR: Windows cleanup diagnostic timed out or could not be collected");
                return unavailable();
            }
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::{terminate_process_tree, terminate_tree_and_reap};
    use std::{
        fs,
        fs::OpenOptions,
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    struct ProcessTree {
        parent: Option<Child>,
        child_pid_path: PathBuf,
    }

    impl ProcessTree {
        fn spawn(
            parent_script: &Path,
            child_script: &Path,
            lock_path: &Path,
            ready_path: &Path,
            child_pid_path: &Path,
        ) -> Self {
            let child = Command::new("pwsh")
                .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-File"])
                .arg(parent_script)
                .env("QID_TEST_CHILD_SCRIPT", child_script)
                .env("QID_TEST_LOCK_PATH", lock_path)
                .env("QID_TEST_READY_PATH", ready_path)
                .env("QID_TEST_CHILD_PID_PATH", child_pid_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("PowerShell test parent starts");
            Self {
                parent: Some(child),
                child_pid_path: child_pid_path.to_path_buf(),
            }
        }

        fn child(&mut self) -> &mut Child {
            self.parent.as_mut().expect("test process tree is active")
        }

        fn terminate_and_reap(&mut self) -> bool {
            self.parent.as_mut().is_some_and(terminate_tree_and_reap)
        }

        fn disarm(&mut self) {
            self.parent.take();
        }
    }

    impl Drop for ProcessTree {
        fn drop(&mut self) {
            if let Some(pid) = fs::read_to_string(&self.child_pid_path)
                .ok()
                .and_then(|value| value.trim().parse::<u32>().ok())
            {
                let _ = terminate_process_tree(pid);
            }
            if let Some(mut parent) = self.parent.take() {
                let _ = terminate_tree_and_reap(&mut parent);
            }
        }
    }

    #[test]
    fn timeout_termination_stops_descendant_before_file_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let child_script = directory.path().join("child.ps1");
        let parent_script = directory.path().join("parent.ps1");
        let lock_path = directory.path().join("locked.db");
        let ready_path = directory.path().join("child-ready");
        let child_pid_path = directory.path().join("child.pid");
        fs::write(
            &child_script,
            r#"$lock = [System.IO.File]::Open($env:QID_TEST_LOCK_PATH, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
[System.IO.File]::WriteAllText($env:QID_TEST_READY_PATH, 'ready')
Start-Sleep -Seconds 30
"#,
        )
        .unwrap();
        fs::write(
            &parent_script,
            r#"$arguments = "-NoLogo -NoProfile -NonInteractive -File `"$env:QID_TEST_CHILD_SCRIPT`""
$child = Start-Process -FilePath 'pwsh' -ArgumentList $arguments -WindowStyle Hidden -PassThru
[System.IO.File]::WriteAllText($env:QID_TEST_CHILD_PID_PATH, [string]$child.Id)
Start-Sleep -Seconds 30
"#,
        )
        .unwrap();

        let mut tree = ProcessTree::spawn(
            &parent_script,
            &child_script,
            &lock_path,
            &ready_path,
            &child_pid_path,
        );
        let ready_deadline = Instant::now() + Duration::from_secs(10);
        while !ready_path.exists() && Instant::now() < ready_deadline {
            if tree.child().try_wait().unwrap().is_some() {
                panic!("PowerShell test parent exited before its descendant locked the file");
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            ready_path.exists(),
            "descendant did not acquire the file lock"
        );
        assert!(
            fs::remove_file(&lock_path).is_err(),
            "test descendant must hold the file against deletion"
        );

        assert!(tree.terminate_and_reap(), "process-tree termination failed");
        let lock = OpenOptions::new()
            .write(true)
            .open(&lock_path)
            .expect("descendant must release the file before tree termination returns");
        drop(lock);
        fs::remove_file(&lock_path).unwrap();
        tree.disarm();
    }
}
