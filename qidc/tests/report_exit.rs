#![allow(clippy::expect_used)]
//! The CLI's JSON reports carry a process contract: authoritative failures
//! must be visible to callers as a nonzero exit, not only inside stdout.
use qid_ops::{BackupObject, build_backup_manifest};
use std::process::{Command, Output};

fn write_config(dir: &std::path::Path, storage_url: &str) -> std::path::PathBuf {
    let config_path = dir.join("qid.yaml");
    let config = serde_json::json!({
        "server": {
            "listen": "127.0.0.1:0",
            "public_base_url": "https://id.example.com"
        },
        "storage": {
            "primary": {
                "type": "file",
                "url": storage_url
            }
        },
        "realms": [{
            "id": "corp",
            "issuer": "https://id.example.com/realms/corp"
        }]
    });
    std::fs::write(&config_path, config.to_string()).expect("qidc report exit fixture");
    config_path
}

fn write_manifest(dir: &std::path::Path) -> std::path::PathBuf {
    let manifest = build_backup_manifest(
        "source",
        "1",
        1,
        vec![BackupObject {
            path: "realms.json".to_string(),
            sha256: "00".repeat(32),
            bytes: 2,
        }],
    )
    .expect("qidc report exit fixture");
    let manifest_path = dir.join("manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string(&manifest).expect("qidc report exit fixture"),
    )
    .expect("qidc report exit fixture");
    manifest_path
}

fn invoke(args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_qidc"));
    command.args(args);
    command.output().expect("qidc report exit fixture")
}

fn report(output: &Output) -> serde_json::Value {
    serde_json::from_str(&String::from_utf8_lossy(&output.stdout))
        .expect("qidc report exit fixture")
}

#[test]
fn error_check_report_exits_nonzero() {
    let dir = std::env::temp_dir().join(format!("qidc-check-error-{}", ulid::Ulid::new()));
    std::fs::create_dir(&dir).expect("qidc report exit fixture");
    let store_dir = dir.join("store-dir");
    std::fs::create_dir(&store_dir).expect("qidc report exit fixture");
    let config = write_config(&dir, store_dir.to_str().expect("qidc report exit fixture"));
    let output = invoke(&[
        "--config",
        config.to_str().expect("qidc report exit fixture"),
        "check",
    ]);
    assert_eq!(report(&output)["status"], "error");
    assert!(!output.status.success());
}

#[test]
fn ok_check_report_exits_zero() {
    let dir = std::env::temp_dir().join(format!("qidc-check-ok-{}", ulid::Ulid::new()));
    std::fs::create_dir(&dir).expect("qidc report exit fixture");
    let config = write_config(
        &dir,
        dir.join("store.json")
            .to_str()
            .expect("qidc report exit fixture"),
    );
    let output = invoke(&[
        "--config",
        config.to_str().expect("qidc report exit fixture"),
        "check",
    ]);
    assert_ne!(report(&output)["status"], "error");
    assert!(output.status.success());
}

#[test]
fn rejected_restore_plan_exits_nonzero() {
    let dir = std::env::temp_dir().join(format!("qidc-plan-reject-{}", ulid::Ulid::new()));
    std::fs::create_dir(&dir).expect("qidc report exit fixture");
    let config = write_config(
        &dir,
        dir.join("store.json")
            .to_str()
            .expect("qidc report exit fixture"),
    );
    let manifest = write_manifest(&dir);
    let output = invoke(&[
        "--config",
        config.to_str().expect("qidc report exit fixture"),
        "ops",
        "restore-plan",
        "--manifest",
        manifest.to_str().expect("qidc report exit fixture"),
        "--target-cluster-id",
        "source",
        "--current-migration-version",
        "1",
        "--read-only",
    ]);
    assert_eq!(report(&output)["status"], "rejected");
    assert!(!output.status.success());
}

#[test]
fn ready_restore_plan_exits_zero() {
    let dir = std::env::temp_dir().join(format!("qidc-plan-ready-{}", ulid::Ulid::new()));
    std::fs::create_dir(&dir).expect("qidc report exit fixture");
    let config = write_config(
        &dir,
        dir.join("store.json")
            .to_str()
            .expect("qidc report exit fixture"),
    );
    let manifest = write_manifest(&dir);
    let output = invoke(&[
        "--config",
        config.to_str().expect("qidc report exit fixture"),
        "ops",
        "restore-plan",
        "--manifest",
        manifest.to_str().expect("qidc report exit fixture"),
        "--target-cluster-id",
        "target",
        "--current-migration-version",
        "1",
        "--read-only",
    ]);
    assert_eq!(report(&output)["status"], "ready");
    assert!(output.status.success());
}

#[test]
fn rejected_restore_execution_exits_nonzero() {
    let dir = std::env::temp_dir().join(format!("qidc-exec-reject-{}", ulid::Ulid::new()));
    std::fs::create_dir(&dir).expect("qidc report exit fixture");
    let config = write_config(
        &dir,
        dir.join("store.json")
            .to_str()
            .expect("qidc report exit fixture"),
    );
    let manifest = write_manifest(&dir);
    let output = invoke(&[
        "--config",
        config.to_str().expect("qidc report exit fixture"),
        "ops",
        "restore-execute",
        "--manifest",
        manifest.to_str().expect("qidc report exit fixture"),
        "--target-cluster-id",
        "source",
        "--current-migration-version",
        "1",
        "--read-only",
        "--source-dir",
        dir.join("source")
            .to_str()
            .expect("qidc report exit fixture"),
        "--target-dir",
        dir.join("target")
            .to_str()
            .expect("qidc report exit fixture"),
    ]);
    assert_eq!(report(&output)["status"], "rejected");
    assert!(!output.status.success());
}
