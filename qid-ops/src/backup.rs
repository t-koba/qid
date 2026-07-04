use crate::{bad_request, sha256_hex};
use qid_core::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ulid::Ulid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupObject {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupManifest {
    pub schema_version: String,
    pub backup_id: String,
    pub generated_at_epoch: u64,
    pub source_cluster_id: String,
    pub migration_version: String,
    pub objects: Vec<BackupObject>,
    pub manifest_hash: String,
}

pub fn build_backup_manifest(
    source_cluster_id: &str,
    migration_version: &str,
    generated_at_epoch: u64,
    objects: Vec<BackupObject>,
) -> QidResult<BackupManifest> {
    if source_cluster_id.trim().is_empty() {
        return Err(bad_request("Backup source cluster id must not be empty"));
    }
    if migration_version.trim().is_empty() {
        return Err(bad_request("Backup migration version must not be empty"));
    }
    if objects.is_empty() {
        return Err(bad_request("Backup manifest requires at least one object"));
    }
    let backup_id = Ulid::new().to_string();
    let manifest_hash = backup_manifest_hash(
        "1",
        &backup_id,
        generated_at_epoch,
        source_cluster_id,
        migration_version,
        &objects,
    );
    Ok(BackupManifest {
        schema_version: "1".to_string(),
        backup_id,
        generated_at_epoch,
        source_cluster_id: source_cluster_id.to_string(),
        migration_version: migration_version.to_string(),
        objects,
        manifest_hash,
    })
}

pub fn verify_backup_manifest(manifest: &BackupManifest) -> bool {
    if manifest.schema_version != "1" || manifest.objects.is_empty() {
        return false;
    }
    backup_manifest_hash(
        &manifest.schema_version,
        &manifest.backup_id,
        manifest.generated_at_epoch,
        &manifest.source_cluster_id,
        &manifest.migration_version,
        &manifest.objects,
    ) == manifest.manifest_hash
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestorePlan {
    pub status: RestorePlanStatus,
    pub backup_id: String,
    pub source_cluster_id: String,
    pub target_cluster_id: String,
    pub object_count: usize,
    pub requires_migration: bool,
    pub read_only_required: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RestorePlanStatus {
    Ready,
    Rejected,
}

pub fn plan_restore(
    manifest: &BackupManifest,
    target_cluster_id: &str,
    current_migration_version: &str,
    read_only_enabled: bool,
) -> RestorePlan {
    let mut reasons = Vec::new();
    if !verify_backup_manifest(manifest) {
        reasons.push("invalid_backup_manifest".to_string());
    }
    if target_cluster_id.trim().is_empty() {
        reasons.push("empty_target_cluster_id".to_string());
    }
    if manifest.source_cluster_id == target_cluster_id {
        reasons.push("same_source_and_target_cluster".to_string());
    }
    let requires_migration = manifest.migration_version != current_migration_version;
    if requires_migration {
        reasons.push("migration_required".to_string());
    }
    if !read_only_enabled {
        reasons.push("read_only_mode_required".to_string());
    }
    let read_only_required = true;
    let status = if reasons.iter().any(|reason| {
        reason == "invalid_backup_manifest"
            || reason == "empty_target_cluster_id"
            || reason == "same_source_and_target_cluster"
            || reason == "read_only_mode_required"
    }) {
        RestorePlanStatus::Rejected
    } else {
        RestorePlanStatus::Ready
    };

    RestorePlan {
        status,
        backup_id: manifest.backup_id.clone(),
        source_cluster_id: manifest.source_cluster_id.clone(),
        target_cluster_id: target_cluster_id.to_string(),
        object_count: manifest.objects.len(),
        requires_migration,
        read_only_required,
        reasons,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoreExecutionConfig {
    pub target_cluster_id: String,
    pub current_migration_version: String,
    pub read_only_enabled: bool,
    pub allow_overwrite: bool,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoreExecutionReport {
    pub status: RestoreExecutionStatus,
    pub plan: RestorePlan,
    pub restored_objects: Vec<RestoredObject>,
    pub reasons: Vec<String>,
    pub rollback: RestoreRollbackPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoreRollbackPlan {
    pub status: RestoreRollbackStatus,
    pub required: bool,
    pub actions: Vec<RestoreRollbackAction>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RestoreRollbackStatus {
    NotRequired,
    Ready,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoreRollbackAction {
    pub action: String,
    pub path: String,
    pub location: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RestoreExecutionStatus {
    Restored,
    DryRunVerified,
    Rejected,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoredObject {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub location: String,
}

pub trait RestoreObjectStore {
    fn read_backup_object(&self, path: &str) -> Result<Vec<u8>, qid_core::QidError>;
    fn write_restore_object(
        &mut self,
        path: &str,
        body: &[u8],
        allow_overwrite: bool,
    ) -> Result<String, qid_core::QidError>;
}

pub fn run_restore_execution<T: RestoreObjectStore>(
    store: &mut T,
    manifest: &BackupManifest,
    config: RestoreExecutionConfig,
) -> QidResult<RestoreExecutionReport> {
    let plan = plan_restore(
        manifest,
        &config.target_cluster_id,
        &config.current_migration_version,
        config.read_only_enabled,
    );
    if plan.status != RestorePlanStatus::Ready {
        return Ok(RestoreExecutionReport {
            status: RestoreExecutionStatus::Rejected,
            reasons: plan.reasons.clone(),
            plan,
            restored_objects: Vec::new(),
            rollback: RestoreRollbackPlan::not_required(),
        });
    }

    let mut restored_objects = Vec::new();
    for object in &manifest.objects {
        validate_backup_object_path(&object.path)?;
        let body = store
            .read_backup_object(&object.path)
            .map_err(|message| QidError::Storage {
                message: format!("failed to read backup object {}: {message}", object.path),
            })?;
        if body.len() as u64 != object.bytes {
            return Ok(failed_restore_report(
                plan,
                restored_objects,
                vec![format!("object_size_mismatch:{}", object.path)],
            ));
        }
        let actual_sha256 = sha256_hex(&body);
        if actual_sha256 != object.sha256 {
            return Ok(failed_restore_report(
                plan,
                restored_objects,
                vec![format!("object_hash_mismatch:{}", object.path)],
            ));
        }
        let restore_path = format!("{}/{}", manifest.backup_id, object.path);
        let location = if config.dry_run {
            format!("dry-run://restore/{restore_path}")
        } else {
            match store.write_restore_object(&restore_path, &body, config.allow_overwrite) {
                Ok(location) => location,
                Err(err) => {
                    return Ok(failed_restore_report(
                        plan,
                        restored_objects,
                        vec![format!(
                            "object_write_failed:{restore_path}:{}",
                            err.message()
                        )],
                    ));
                }
            }
        };
        restored_objects.push(RestoredObject {
            path: restore_path,
            bytes: object.bytes,
            sha256: object.sha256.clone(),
            location,
        });
    }

    Ok(RestoreExecutionReport {
        status: if config.dry_run {
            RestoreExecutionStatus::DryRunVerified
        } else {
            RestoreExecutionStatus::Restored
        },
        reasons: Vec::new(),
        plan,
        restored_objects,
        rollback: RestoreRollbackPlan::not_required(),
    })
}

fn failed_restore_report(
    plan: RestorePlan,
    restored_objects: Vec<RestoredObject>,
    reasons: Vec<String>,
) -> RestoreExecutionReport {
    let rollback = rollback_plan_for_partial_restore(&restored_objects, reasons.clone());
    RestoreExecutionReport {
        status: RestoreExecutionStatus::Failed,
        plan,
        restored_objects,
        reasons,
        rollback,
    }
}

pub fn plan_restore_rollback(report: &RestoreExecutionReport) -> RestoreRollbackPlan {
    if report.status != RestoreExecutionStatus::Failed || report.restored_objects.is_empty() {
        return RestoreRollbackPlan {
            status: RestoreRollbackStatus::NotRequired,
            required: false,
            actions: Vec::new(),
            reasons: Vec::new(),
        };
    }

    rollback_plan_for_partial_restore(&report.restored_objects, report.reasons.clone())
}

impl RestoreRollbackPlan {
    fn not_required() -> Self {
        Self {
            status: RestoreRollbackStatus::NotRequired,
            required: false,
            actions: Vec::new(),
            reasons: Vec::new(),
        }
    }
}

fn rollback_plan_for_partial_restore(
    restored_objects: &[RestoredObject],
    reasons: Vec<String>,
) -> RestoreRollbackPlan {
    if restored_objects.is_empty() {
        return RestoreRollbackPlan::not_required();
    }
    let actions = restored_objects
        .iter()
        .rev()
        .map(|object| RestoreRollbackAction {
            action: "delete_restored_object".to_string(),
            path: object.path.clone(),
            location: object.location.clone(),
            sha256: object.sha256.clone(),
            bytes: object.bytes,
        })
        .collect();
    RestoreRollbackPlan {
        status: RestoreRollbackStatus::Ready,
        required: true,
        actions,
        reasons,
    }
}

fn backup_manifest_hash(
    schema_version: &str,
    backup_id: &str,
    generated_at_epoch: u64,
    source_cluster_id: &str,
    migration_version: &str,
    objects: &[BackupObject],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(schema_version.as_bytes());
    hasher.update(b"\n");
    hasher.update(backup_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(generated_at_epoch.to_string().as_bytes());
    hasher.update(b"\n");
    hasher.update(source_cluster_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(migration_version.as_bytes());
    hasher.update(b"\n");
    for object in objects {
        hasher.update(object.path.as_bytes());
        hasher.update(b"\0");
        hasher.update(object.sha256.as_bytes());
        hasher.update(b"\0");
        hasher.update(object.bytes.to_string().as_bytes());
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

fn validate_backup_object_path(path: &str) -> QidResult<()> {
    if path.trim().is_empty() {
        return Err(bad_request("Backup object path must not be empty"));
    }
    if path.starts_with('/') || path.contains('\\') {
        return Err(bad_request("Backup object path must be relative"));
    }
    if path
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(bad_request(
            "Backup object path must not contain empty, current, or parent components",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256_hex;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MemoryRestoreStore {
        backup: BTreeMap<String, Vec<u8>>,
        restored: BTreeMap<String, Vec<u8>>,
        fail_write_paths: Vec<String>,
    }

    impl RestoreObjectStore for MemoryRestoreStore {
        fn read_backup_object(&self, path: &str) -> Result<Vec<u8>, qid_core::QidError> {
            self.backup
                .get(path)
                .cloned()
                .ok_or_else(|| qid_core::QidError::NotFound {
                    resource: format!("backup object {path}"),
                })
        }

        fn write_restore_object(
            &mut self,
            path: &str,
            body: &[u8],
            allow_overwrite: bool,
        ) -> Result<String, qid_core::QidError> {
            if self.fail_write_paths.iter().any(|blocked| blocked == path) {
                return Err(qid_core::QidError::BadRequest {
                    message: "configured write failure".to_string(),
                });
            }
            if !allow_overwrite && self.restored.contains_key(path) {
                return Err(qid_core::QidError::BadRequest {
                    message: format!("restore object already exists: {path}"),
                });
            }
            self.restored.insert(path.to_string(), body.to_vec());
            Ok(format!("memory://restore/{path}"))
        }
    }

    #[test]
    fn backup_manifest_verifies_and_restore_requires_read_only_mode() {
        let manifest = build_backup_manifest(
            "cluster-a",
            "20250618000007",
            100,
            vec![BackupObject {
                path: "db/main.sqlite".to_string(),
                sha256: "abc123".to_string(),
                bytes: 42,
            }],
        )
        .unwrap();

        assert!(verify_backup_manifest(&manifest));

        let rejected = plan_restore(&manifest, "cluster-b", "20250618000007", false);
        assert_eq!(rejected.status, RestorePlanStatus::Rejected);
        assert!(
            rejected
                .reasons
                .contains(&"read_only_mode_required".to_string())
        );

        let ready = plan_restore(&manifest, "cluster-b", "20250618000007", true);
        assert_eq!(ready.status, RestorePlanStatus::Ready);
    }

    #[test]
    fn restore_execution_verifies_hash_and_writes_objects() {
        let body = b"backup body".to_vec();
        let object = BackupObject {
            path: "db/main.sqlite".to_string(),
            sha256: sha256_hex(&body),
            bytes: body.len() as u64,
        };
        let manifest =
            build_backup_manifest("cluster-a", "20250618000007", 100, vec![object.clone()])
                .unwrap();
        let mut store = MemoryRestoreStore::default();
        store.backup.insert(object.path.clone(), body.clone());

        let report = run_restore_execution(
            &mut store,
            &manifest,
            RestoreExecutionConfig {
                target_cluster_id: "cluster-b".to_string(),
                current_migration_version: "20250618000007".to_string(),
                read_only_enabled: true,
                allow_overwrite: false,
                dry_run: false,
            },
        )
        .unwrap();

        assert_eq!(report.status, RestoreExecutionStatus::Restored);
        assert_eq!(report.restored_objects.len(), 1);
        assert_eq!(
            store
                .restored
                .get(&format!("{}/db/main.sqlite", manifest.backup_id))
                .unwrap(),
            &body
        );
    }

    #[test]
    fn restore_execution_dry_run_verifies_without_writing_objects() {
        let body = b"backup body".to_vec();
        let object = BackupObject {
            path: "db/main.sqlite".to_string(),
            sha256: sha256_hex(&body),
            bytes: body.len() as u64,
        };
        let manifest =
            build_backup_manifest("cluster-a", "20250618000007", 100, vec![object.clone()])
                .unwrap();
        let mut store = MemoryRestoreStore::default();
        store.backup.insert(object.path.clone(), body);

        let report = run_restore_execution(
            &mut store,
            &manifest,
            RestoreExecutionConfig {
                target_cluster_id: "cluster-b".to_string(),
                current_migration_version: "20250618000007".to_string(),
                read_only_enabled: true,
                allow_overwrite: false,
                dry_run: true,
            },
        )
        .unwrap();

        assert_eq!(report.status, RestoreExecutionStatus::DryRunVerified);
        assert_eq!(report.restored_objects.len(), 1);
        assert!(
            report.restored_objects[0]
                .location
                .starts_with("dry-run://")
        );
        assert!(store.restored.is_empty());
    }

    #[test]
    fn restore_failure_reports_partial_objects_for_rollback_plan() {
        let first = b"first backup body".to_vec();
        let second = b"second backup body".to_vec();
        let first_object = BackupObject {
            path: "db/first.sqlite".to_string(),
            sha256: sha256_hex(&first),
            bytes: first.len() as u64,
        };
        let second_object = BackupObject {
            path: "db/second.sqlite".to_string(),
            sha256: sha256_hex(&second),
            bytes: second.len() as u64,
        };
        let manifest = build_backup_manifest(
            "cluster-a",
            "20250618000007",
            100,
            vec![first_object.clone(), second_object.clone()],
        )
        .unwrap();
        let mut store = MemoryRestoreStore::default();
        store.backup.insert(first_object.path.clone(), first);
        store.backup.insert(second_object.path.clone(), second);
        let blocked_path = format!("{}/db/second.sqlite", manifest.backup_id);
        store.fail_write_paths.push(blocked_path.clone());

        let report = run_restore_execution(
            &mut store,
            &manifest,
            RestoreExecutionConfig {
                target_cluster_id: "cluster-b".to_string(),
                current_migration_version: "20250618000007".to_string(),
                read_only_enabled: true,
                allow_overwrite: false,
                dry_run: false,
            },
        )
        .unwrap();

        assert_eq!(report.status, RestoreExecutionStatus::Failed);
        assert_eq!(report.restored_objects.len(), 1);
        assert_eq!(report.reasons.len(), 1,);
        assert!(report.reasons[0].contains("object_write_failed"));
        assert!(report.reasons[0].contains("configured write failure"));
        let rollback = plan_restore_rollback(&report);
        assert_eq!(rollback.status, RestoreRollbackStatus::Ready);
        assert!(rollback.required);
        assert_eq!(rollback.actions.len(), 1);
        assert_eq!(report.rollback, rollback);
        assert_eq!(rollback.actions[0].action, "delete_restored_object");
        assert_eq!(
            rollback.actions[0].path,
            format!("{}/db/first.sqlite", manifest.backup_id)
        );
    }

    #[test]
    fn restore_execution_rejects_unsafe_object_path_and_hash_mismatch() {
        let manifest = build_backup_manifest(
            "cluster-a",
            "20250618000007",
            100,
            vec![BackupObject {
                path: "../db/main.sqlite".to_string(),
                sha256: sha256_hex(b"backup body"),
                bytes: 11,
            }],
        )
        .unwrap();
        let mut store = MemoryRestoreStore::default();
        let err = run_restore_execution(
            &mut store,
            &manifest,
            RestoreExecutionConfig {
                target_cluster_id: "cluster-b".to_string(),
                current_migration_version: "20250618000007".to_string(),
                read_only_enabled: true,
                allow_overwrite: false,
                dry_run: false,
            },
        )
        .unwrap_err();
        assert!(err.message().contains("parent components"));

        let object = BackupObject {
            path: "db/main.sqlite".to_string(),
            sha256: sha256_hex(b"expected"),
            bytes: 6,
        };
        let manifest =
            build_backup_manifest("cluster-a", "20250618000007", 100, vec![object]).unwrap();
        store
            .backup
            .insert("db/main.sqlite".to_string(), b"actual".to_vec());
        let report = run_restore_execution(
            &mut store,
            &manifest,
            RestoreExecutionConfig {
                target_cluster_id: "cluster-b".to_string(),
                current_migration_version: "20250618000007".to_string(),
                read_only_enabled: true,
                allow_overwrite: false,
                dry_run: false,
            },
        )
        .unwrap();
        assert_eq!(report.status, RestoreExecutionStatus::Failed);
        assert_eq!(report.reasons, vec!["object_hash_mismatch:db/main.sqlite"]);
    }
}
