//! Background workers for qid asynchronous operations.
#![forbid(unsafe_code)]

pub mod audit;
pub mod key_rotation;
pub mod notification;
pub mod smtp_transport;
pub mod sync;

pub use audit::*;
pub use key_rotation::*;
pub use notification::*;
pub use sync::*;

use sha2::{Digest, Sha256};

pub(crate) fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(hex_nibble(byte >> 4));
        out.push(hex_nibble(byte & 0x0f));
    }
    out
}

fn hex_nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + value - 10) as char,
        _ => '0',
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qid_core::models::{AuditEvent, AuditRetentionConfig};
    use qid_crypto::{KeyProtector, PassphraseProtector, parse_encrypted_key};
    use qid_ops::{
        KeyPurpose, KeyRotationAction, KeyRotationActionKind, KeyRotationPlan,
        KeyRotationPlanStatus, KeyRotationRequirement, KeyringInventoryRecord,
    };
    use qid_storage::{
        AuditRepository, FileRepository, SiemDeliveryRepository, SiemDeliveryStatus, SqlRepository,
    };
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU16, Ordering};

    static DB_SEQ: AtomicU16 = AtomicU16::new(0);

    fn db_url() -> String {
        let dir = std::env::temp_dir().join("qid_worker_test");
        std::fs::create_dir_all(&dir).ok();
        static CLEANED: OnceLock<()> = OnceLock::new();
        CLEANED.get_or_init(|| {
            for e in std::fs::read_dir(&dir).ok().into_iter().flatten().flatten() {
                let name = e.file_name();
                let s = name.to_string_lossy();
                if s.starts_with("test_") && s.ends_with(".db") {
                    std::fs::remove_file(e.path()).ok();
                }
            }
        });
        let n = DB_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("test_{n}.db"));
        format!("sqlite:{}", path.display())
    }

    async fn repo() -> SqlRepository {
        let repo = SqlRepository::connect(&db_url()).await.unwrap();
        repo.migrate().await.unwrap();
        repo
    }

    async fn seed_audit_event(repo: &SqlRepository, id: &str, created_at: u64) {
        repo.append_audit_event(&AuditEvent {
            id: id.to_string(),
            realm_id: Some("corp".to_string()),
            actor: "admin@example.com".to_string(),
            action: "audit.test".to_string(),
            target_type: "audit".to_string(),
            target_id: id.to_string(),
            reason: "test".to_string(),
            metadata_json: serde_json::json!({}),
            created_at,
            previous_hash: None,
            event_hash: None,
        })
        .await
        .unwrap();
    }

    struct CapturingTransport {
        response: AuditSiemHttpResponse,
        requests: RefCell<Vec<AuditSiemHttpRequest>>,
    }

    impl CapturingTransport {
        fn new(status: u16) -> Self {
            Self {
                response: AuditSiemHttpResponse {
                    status,
                    body: Vec::new(),
                },
                requests: RefCell::new(Vec::new()),
            }
        }
    }

    impl SiemWebhookTransport for CapturingTransport {
        fn send(&self, request: AuditSiemHttpRequest) -> Result<AuditSiemHttpResponse, String> {
            self.requests.borrow_mut().push(request);
            Ok(self.response.clone())
        }
    }

    struct InMemoryNotificationTransport {
        response: Result<NotificationResponse, String>,
        requests: RefCell<Vec<NotificationRequest>>,
    }

    impl InMemoryNotificationTransport {
        fn new(status: u16) -> Self {
            Self {
                response: Ok(NotificationResponse {
                    status,
                    provider_message_id: Some("msg-1".to_string()),
                }),
                requests: RefCell::new(Vec::new()),
            }
        }
    }

    impl NotificationTransport for InMemoryNotificationTransport {
        fn send(&self, request: NotificationRequest) -> Result<NotificationResponse, String> {
            self.requests.borrow_mut().push(request);
            self.response.clone()
        }
    }

    struct InMemoryWormArchive {
        objects: RefCell<BTreeMap<String, AuditWormObject>>,
    }

    impl InMemoryWormArchive {
        fn new() -> Self {
            Self {
                objects: RefCell::new(BTreeMap::new()),
            }
        }
    }

    impl WormArchiveTransport for InMemoryWormArchive {
        fn put_once(&self, object: AuditWormObject) -> Result<AuditWormPutResult, String> {
            let mut objects = self.objects.borrow_mut();
            if objects.contains_key(&object.key) {
                return Err(format!("object already exists: {}", object.key));
            }
            let key = object.key.clone();
            objects.insert(key.clone(), object);
            Ok(AuditWormPutResult {
                key: key.clone(),
                version_id: Some("v1".to_string()),
                location: format!("memory://{key}"),
            })
        }
    }

    #[tokio::test]
    async fn key_rotation_planning_job_records_rejected_plan_audit_event() {
        let repo = repo().await;
        let report = run_key_rotation_planning_job(
            &repo,
            KeyRotationPlanningJobConfig {
                inventory: vec![
                    KeyringInventoryRecord {
                        realm_id: "corp".to_string(),
                        keyring_name: "corp-shared".to_string(),
                        kid: "shared-1".to_string(),
                        purpose: qid_ops::KeyPurpose::PepAssertion,
                        signer_type: "local".to_string(),
                        created_at_epoch: 100,
                        not_before_epoch: 100,
                        retire_after_epoch: 10_000,
                        revoked: false,
                    },
                    KeyringInventoryRecord {
                        realm_id: "corp".to_string(),
                        keyring_name: "corp-shared".to_string(),
                        kid: "shared-2".to_string(),
                        purpose: qid_ops::KeyPurpose::OidcToken,
                        signer_type: "local".to_string(),
                        created_at_epoch: 100,
                        not_before_epoch: 100,
                        retire_after_epoch: 10_000,
                        revoked: false,
                    },
                ],
                requirements: vec![KeyRotationRequirement {
                    realm_id: "corp".to_string(),
                    purpose: qid_ops::KeyPurpose::PepAssertion,
                    max_age_days: 90,
                    overlap_days: 14,
                    require_remote_signer: true,
                    require_dedicated_keyring: true,
                }],
                now_epoch: 1_000,
                actor: "qid-worker".to_string(),
                reason: "scheduled key rotation planning".to_string(),
                record_audit_event: true,
            },
        )
        .await
        .expect("key rotation planning");

        assert_eq!(report.status, KeyRotationPlanningJobStatus::Rejected);
        assert_eq!(report.rejected_count, 1);
        assert!(report.audit_event_id.is_some());

        let events = repo
            .list_audit_events(Some(&"corp".into()), 10)
            .await
            .expect("audit events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "key_rotation.plan");
        assert_eq!(events[0].metadata_json["rejected_count"], 1);
    }

    #[tokio::test]
    async fn key_rotation_execution_job_writes_encrypted_successor_key_and_audit_event() {
        let dir = std::env::temp_dir().join(format!("qid_worker_rotation_{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&dir).expect("create rotation test directory");
        let store_path = dir.join("store.json");
        let repo = FileRepository::new(store_path.to_str().expect("store path is not UTF-8"))
            .await
            .expect("file repository");
        repo.migrate().await.expect("file migration");
        let output_dir = dir.join("keys");

        let report = run_key_rotation_execution_job(
            &repo,
            KeyRotationExecutionJobConfig {
                plan: KeyRotationPlan {
                    status: KeyRotationPlanStatus::ActionRequired,
                    realm_id: "corp".to_string(),
                    purpose: KeyPurpose::OidcToken,
                    active_kid: Some("old".to_string()),
                    successor_kid: None,
                    actions: vec![KeyRotationAction {
                        action: KeyRotationActionKind::GenerateSuccessor,
                        keyring_name: "corp-main".to_string(),
                        kid: Some("next".to_string()),
                        reason: "rotation_overlap_window_open".to_string(),
                    }],
                    reasons: Vec::new(),
                },
                output_dir: output_dir.clone(),
                algorithm: "ES256".to_string(),
                key_passphrase: b"test-passphrase".to_vec(),
                now_epoch: 123,
                actor: "qid-worker".to_string(),
                reason: "scheduled key rotation execution".to_string(),
                record_audit_event: true,
                force: false,
            },
        )
        .await
        .expect("key rotation execution");

        assert_eq!(report.status, KeyRotationExecutionJobStatus::Executed);
        assert_eq!(report.executed.len(), 1);
        assert!(report.unsupported.is_empty());
        let executed = &report.executed[0];
        assert_eq!(executed.kid, "next");
        assert!(executed.encrypted_key_path.exists());
        assert!(executed.public_key_path.exists());
        assert!(executed.public_jwk_path.exists());

        let encrypted_json =
            std::fs::read_to_string(&executed.encrypted_key_path).expect("encrypted key file");
        assert!(!encrypted_json.contains("PRIVATE KEY"));
        let encrypted = parse_encrypted_key(&encrypted_json).expect("parse encrypted key");
        assert_eq!(encrypted.kid, "next");
        assert_eq!(encrypted.alg, "ES256");
        let protector =
            PassphraseProtector::new(b"test-passphrase".to_vec()).expect("key protector");
        let private_pem = protector.unseal(&encrypted).expect("decrypt encrypted key");
        assert!(private_pem.contains("PRIVATE KEY"));

        let public_jwk =
            std::fs::read_to_string(&executed.public_jwk_path).expect("public jwk file");
        assert!(public_jwk.contains("\"kid\": \"next\""));
        let events = repo
            .list_audit_events(Some(&"corp".into()), 10)
            .await
            .expect("audit events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "key_rotation.execute");
        assert_eq!(events[0].metadata_json["status"], "executed");
        assert_eq!(events[0].metadata_json["executed"][0]["kid"], "next");

        drop(private_pem);
        drop(repo);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn retention_job_records_evaluation_event() {
        let repo = repo().await;
        seed_audit_event(&repo, "old", 10).await;
        seed_audit_event(&repo, "new", 200).await;
        repo.set_audit_retention_config(&AuditRetentionConfig {
            realm_id: Some("corp".to_string()),
            retention_days: 0,
            legal_hold: false,
            updated_by: "admin@example.com".to_string(),
            reason: "ticket-1".to_string(),
            updated_at: 199,
        })
        .await
        .unwrap();

        let report = run_audit_retention_job(
            &repo,
            AuditRetentionJobConfig {
                realm_id: Some("corp".to_string()),
                actor: "worker".to_string(),
                reason: "scheduled retention evaluation".to_string(),
                now_epoch: 200,
                record_audit_event: true,
            },
        )
        .await
        .unwrap();

        assert_eq!(report.status, AuditRetentionJobStatus::Evaluated);
        assert_eq!(
            report.plan.as_ref().unwrap().expired_event_ids,
            vec!["old".to_string()]
        );
        assert!(report.audit_event_id.is_some());
        let events = repo
            .list_audit_events(Some(&"corp".into()), 10)
            .await
            .unwrap();
        assert_eq!(events.len(), 3);
        assert!(
            repo.verify_audit_chain(Some(&"corp".into()))
                .await
                .unwrap()
                .valid
        );
    }

    #[tokio::test]
    async fn retention_job_skips_when_policy_is_missing() {
        let repo = repo().await;
        seed_audit_event(&repo, "event", 100).await;

        let report = run_audit_retention_job(
            &repo,
            AuditRetentionJobConfig {
                realm_id: Some("corp".to_string()),
                actor: "worker".to_string(),
                reason: "scheduled retention evaluation".to_string(),
                now_epoch: 200,
                record_audit_event: true,
            },
        )
        .await
        .unwrap();

        assert_eq!(report.status, AuditRetentionJobStatus::SkippedNoPolicy);
        assert!(report.audit_event_id.is_none());
        assert_eq!(
            repo.list_audit_events(Some(&"corp".into()), 10)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn siem_delivery_posts_payload_and_records_audit_event() {
        let repo = repo().await;
        seed_audit_event(&repo, "event-1", 100).await;
        let transport = CapturingTransport::new(202);

        let report = run_audit_siem_delivery_job(
            &repo,
            &transport,
            AuditSiemDeliveryConfig {
                realm_id: Some("corp".to_string()),
                endpoint_url: "https://siem.example.com/audit".to_string(),
                limit: 10,
                now_epoch: 200,
                traceparent: Some(
                    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00".to_string(),
                ),
                audit_correlation_id: Some("corr-1".to_string()),
                include_metadata: true,
                actor: "worker".to_string(),
                reason: "scheduled siem delivery".to_string(),
                record_audit_event: true,
                completed_attempts: 0,
                retry_policy: AuditSiemRetryPolicy::default(),
            },
        )
        .await
        .unwrap();

        assert_eq!(report.status, AuditSiemDeliveryStatus::Delivered);
        assert_eq!(report.event_count, 1);
        assert_eq!(report.http_status, Some(202));
        assert!(report.audit_event_id.is_some());
        let request = {
            let requests = transport.requests.borrow();
            assert_eq!(requests.len(), 1);
            requests[0].clone()
        };
        assert_eq!(request.method, "POST");
        assert_eq!(request.headers["content-type"], "application/json");
        assert_eq!(request.headers["x-qid-audit-correlation-id"], "corr-1");
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["schema_version"], "qid.audit.webhook.v1");
        assert_eq!(body["event_count"], 1);
        assert_eq!(body["events"][0]["id"], "event-1");
        assert_eq!(
            repo.list_audit_events(Some(&"corp".into()), 10)
                .await
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn siem_delivery_marks_retryable_failure() {
        let repo = repo().await;
        seed_audit_event(&repo, "event-1", 100).await;
        let transport = CapturingTransport::new(503);

        let report = run_audit_siem_delivery_job(
            &repo,
            &transport,
            AuditSiemDeliveryConfig {
                realm_id: Some("corp".to_string()),
                endpoint_url: "https://siem.example.com/audit".to_string(),
                limit: 10,
                now_epoch: 200,
                traceparent: None,
                audit_correlation_id: None,
                include_metadata: false,
                actor: "worker".to_string(),
                reason: "scheduled siem delivery".to_string(),
                record_audit_event: false,
                completed_attempts: 1,
                retry_policy: AuditSiemRetryPolicy {
                    max_attempts: 3,
                    base_delay_ms: 1_000,
                    max_delay_ms: 10_000,
                },
            },
        )
        .await
        .unwrap();

        assert_eq!(report.status, AuditSiemDeliveryStatus::FailedRetryable);
        let delivery_id = report.delivery_id.as_ref().expect("delivery id");
        let queued = repo
            .get_siem_delivery(delivery_id)
            .await
            .expect("SIEM delivery lookup")
            .expect("SIEM delivery queued");
        assert_eq!(queued.status, SiemDeliveryStatus::Pending);
        assert_eq!(queued.attempts, 2);
        assert_eq!(queued.next_retry_at, Some(202));
        assert_eq!(
            report.retry,
            AuditSiemRetryDecision {
                retry: true,
                attempt: 2,
                delay_ms: Some(2_000),
                first_error: None,
            }
        );
    }

    #[tokio::test]
    async fn siem_delivery_marks_dead_after_retry_budget_is_exhausted() {
        let repo = repo().await;
        seed_audit_event(&repo, "event-1", 100).await;
        let transport = CapturingTransport::new(503);

        let report = run_audit_siem_delivery_job(
            &repo,
            &transport,
            AuditSiemDeliveryConfig {
                realm_id: Some("corp".to_string()),
                endpoint_url: "https://siem.example.com/audit".to_string(),
                limit: 10,
                now_epoch: 200,
                traceparent: None,
                audit_correlation_id: None,
                include_metadata: false,
                actor: "worker".to_string(),
                reason: "scheduled siem delivery".to_string(),
                record_audit_event: false,
                completed_attempts: 2,
                retry_policy: AuditSiemRetryPolicy {
                    max_attempts: 3,
                    base_delay_ms: 1_000,
                    max_delay_ms: 10_000,
                },
            },
        )
        .await
        .unwrap();

        assert_eq!(report.status, AuditSiemDeliveryStatus::FailedPermanent);
        let queued = repo
            .get_siem_delivery(report.delivery_id.as_ref().expect("delivery id"))
            .await
            .expect("SIEM delivery lookup")
            .expect("SIEM delivery queued");
        assert_eq!(queued.status, SiemDeliveryStatus::Dead);
        assert_eq!(queued.attempts, 3);
        assert_eq!(queued.next_retry_at, None);
    }

    #[tokio::test]
    async fn siem_redrive_sends_persistent_payload_and_marks_delivered() {
        let repo = repo().await;
        seed_audit_event(&repo, "event-1", 100).await;
        let failing_transport = CapturingTransport::new(503);
        let failed = run_audit_siem_delivery_job(
            &repo,
            &failing_transport,
            AuditSiemDeliveryConfig {
                realm_id: Some("corp".to_string()),
                endpoint_url: "https://siem.example.com/audit".to_string(),
                limit: 10,
                now_epoch: 200,
                traceparent: None,
                audit_correlation_id: None,
                include_metadata: false,
                actor: "worker".to_string(),
                reason: "scheduled siem delivery".to_string(),
                record_audit_event: false,
                completed_attempts: 2,
                retry_policy: AuditSiemRetryPolicy {
                    max_attempts: 3,
                    base_delay_ms: 1_000,
                    max_delay_ms: 10_000,
                },
            },
        )
        .await
        .unwrap();
        let delivery_id = failed.delivery_id.expect("delivery id");

        let successful_transport = CapturingTransport::new(202);
        let redriven = run_audit_siem_redrive_job(
            &repo,
            &successful_transport,
            AuditSiemRedriveConfig {
                delivery_id: delivery_id.clone(),
                now_epoch: 300,
                actor: "worker".to_string(),
                reason: "scheduled siem redrive".to_string(),
                record_audit_event: false,
                retry_policy: AuditSiemRetryPolicy::default(),
            },
        )
        .await
        .unwrap();

        assert_eq!(redriven.status, AuditSiemDeliveryStatus::Delivered);
        let queued = repo
            .get_siem_delivery(&delivery_id)
            .await
            .expect("SIEM delivery lookup")
            .expect("SIEM delivery queued");
        assert_eq!(queued.status, SiemDeliveryStatus::Delivered);
        assert_eq!(queued.attempts, 4);
        assert_eq!(queued.next_retry_at, None);
        let requests = successful_transport.requests.borrow();
        assert_eq!(requests.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body["events"][0]["id"], "event-1");
    }

    #[tokio::test]
    async fn notification_delivery_sends_email_and_records_redacted_audit_event() {
        let repo = repo().await;
        let transport = InMemoryNotificationTransport::new(202);

        let report = run_notification_delivery_job(
            &repo,
            &transport,
            NotificationDeliveryConfig {
                realm_id: Some("corp".to_string()),
                channel: NotificationChannel::Email,
                provider: "smtp://mail.example.com".to_string(),
                recipient: "alice@example.com".to_string(),
                subject: Some("Verify your email".to_string()),
                body: "Use code 123456".to_string(),
                template_id: Some("email.verify".to_string()),
                data_json: serde_json::json!({"code": "123456"}),
                now_epoch: 300,
                actor: "worker".to_string(),
                reason: "scheduled email delivery".to_string(),
                record_audit_event: true,
                completed_attempts: 0,
                retry_policy: NotificationRetryPolicy::default(),
            },
        )
        .await
        .expect("notification delivery");

        assert_eq!(report.status, NotificationDeliveryStatus::Delivered);
        assert_eq!(report.provider_status, Some(202));
        assert_eq!(report.provider_message_id.as_deref(), Some("msg-1"));
        assert!(report.audit_event_id.is_some());
        let request = {
            let requests = transport.requests.borrow();
            assert_eq!(requests.len(), 1);
            requests[0].clone()
        };
        assert_eq!(request.channel, NotificationChannel::Email);
        assert_eq!(request.recipient, "alice@example.com");
        assert_eq!(request.template_id.as_deref(), Some("email.verify"));

        let events = repo
            .list_audit_events(Some(&"corp".into()), 10)
            .await
            .expect("audit events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "notification.deliver");
        assert_eq!(events[0].target_id, report.recipient_hash);
        assert_eq!(events[0].metadata_json["channel"], "email");
        assert_eq!(
            events[0].metadata_json["recipient_sha256"],
            report.recipient_hash
        );
        assert!(
            !events[0]
                .metadata_json
                .to_string()
                .contains("alice@example.com")
        );
        assert!(!events[0].metadata_json.to_string().contains("Use code"));
    }

    #[tokio::test]
    async fn notification_delivery_push_retry_and_validation_fail_closed() {
        let repo = repo().await;
        let transport = InMemoryNotificationTransport::new(503);

        let report = run_notification_delivery_job(
            &repo,
            &transport,
            NotificationDeliveryConfig {
                realm_id: Some("corp".to_string()),
                channel: NotificationChannel::Push,
                provider: "apns://team/app".to_string(),
                recipient: "device-token-1".to_string(),
                subject: None,
                body: "Approve sign-in".to_string(),
                template_id: Some("push.approve".to_string()),
                data_json: serde_json::json!({"challenge": "chal-1"}),
                now_epoch: 300,
                actor: "worker".to_string(),
                reason: "scheduled push delivery".to_string(),
                record_audit_event: false,
                completed_attempts: 1,
                retry_policy: NotificationRetryPolicy {
                    max_attempts: 3,
                    base_delay_ms: 500,
                    max_delay_ms: 5_000,
                },
            },
        )
        .await
        .expect("notification delivery");

        assert_eq!(report.status, NotificationDeliveryStatus::FailedRetryable);
        assert_eq!(
            report.retry,
            NotificationRetryDecision {
                retry: true,
                attempt: 2,
                delay_ms: Some(1_000),
                first_error: None,
            }
        );

        let err = run_notification_delivery_job(
            &repo,
            &transport,
            NotificationDeliveryConfig {
                realm_id: Some("corp".to_string()),
                channel: NotificationChannel::Email,
                provider: "smtp://mail.example.com".to_string(),
                recipient: "not-an-email".to_string(),
                subject: None,
                body: "Hello".to_string(),
                template_id: None,
                data_json: serde_json::json!({}),
                now_epoch: 300,
                actor: "worker".to_string(),
                reason: "invalid email delivery".to_string(),
                record_audit_event: true,
                completed_attempts: 0,
                retry_policy: NotificationRetryPolicy::default(),
            },
        )
        .await
        .expect_err("invalid email recipient must fail closed");
        assert!(err.message().contains("email address"));
    }

    #[tokio::test]
    async fn worm_archive_writes_body_manifest_and_audit_event() {
        let repo = repo().await;
        seed_audit_event(&repo, "event-1", 100).await;
        seed_audit_event(&repo, "event-2", 200).await;
        let archive = InMemoryWormArchive::new();

        let report = run_audit_worm_archive_job(
            &repo,
            &archive,
            AuditWormArchiveConfig {
                realm_id: Some("corp".to_string()),
                limit: 10,
                now_epoch: 300,
                include_metadata: true,
                actor: "worker".to_string(),
                reason: "scheduled archive".to_string(),
                record_audit_event: true,
            },
        )
        .await
        .unwrap();

        assert_eq!(report.status, AuditWormArchiveStatus::Archived);
        assert_eq!(report.event_count, 2);
        assert!(report.audit_event_id.is_some());
        let manifest = report.manifest.as_ref().unwrap();
        assert_eq!(manifest.schema_version, "qid.audit.evidence.v1");
        assert_eq!(manifest.event_count, 2);
        assert_eq!(manifest.first_event_id.as_deref(), Some("event-1"));
        assert_eq!(manifest.last_event_id.as_deref(), Some("event-2"));
        let (body_object, manifest_object) = {
            let objects = archive.objects.borrow();
            assert_eq!(objects.len(), 2);
            let body_key = report.body_object.as_ref().unwrap().key.clone();
            let manifest_key = report.manifest_object.as_ref().unwrap().key.clone();
            (objects[&body_key].clone(), objects[&manifest_key].clone())
        };
        assert_eq!(body_object.content_type, "application/x-ndjson");
        assert_eq!(manifest_object.content_type, "application/json");
        let manifest_body: serde_json::Value =
            serde_json::from_slice(&manifest_object.body).unwrap();
        assert_eq!(manifest_body["body_sha256"], manifest.body_sha256);
        let verification = verify_audit_evidence_archive(manifest, &body_object.body);
        assert!(verification.valid);
        assert_eq!(verification.event_count, 2);
        assert_eq!(verification.first_event_id.as_deref(), Some("event-1"));
        assert_eq!(verification.last_event_id.as_deref(), Some("event-2"));
        assert_eq!(
            verification.first_event_hash.as_deref(),
            manifest.first_event_hash.as_deref()
        );
        assert_eq!(
            verification.last_event_hash.as_deref(),
            manifest.last_event_hash.as_deref()
        );

        let mut tampered_body = body_object.body.clone();
        tampered_body.extend_from_slice(b"\n");
        let tampered = verify_audit_evidence_archive(manifest, &tampered_body);
        assert!(!tampered.valid);
        assert_eq!(tampered.error.as_deref(), Some("body_sha256 mismatch"));

        let mut lines = std::str::from_utf8(&body_object.body)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        lines[0]["previous_hash"] = serde_json::json!("broken-link");
        let relinked_body = lines
            .into_iter()
            .map(|value| serde_json::to_string(&value).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let mut relinked_manifest = manifest.clone();
        relinked_manifest.body_sha256 = hex_sha256(relinked_body.as_bytes());
        let relinked = verify_audit_evidence_archive(&relinked_manifest, relinked_body.as_bytes());
        assert!(!relinked.valid);
        assert_eq!(
            relinked.error.as_deref(),
            Some("audit export chain is not contiguous")
        );
        assert!(
            repo.verify_audit_chain(Some(&"corp".into()))
                .await
                .unwrap()
                .valid
        );
    }

    #[tokio::test]
    async fn worm_archive_report_builds_compliance_evidence_pack() {
        let repo = repo().await;
        seed_audit_event(&repo, "event-1", 100).await;
        seed_audit_event(&repo, "event-2", 200).await;
        let archive = InMemoryWormArchive::new();

        let mut report = run_audit_worm_archive_job(
            &repo,
            &archive,
            AuditWormArchiveConfig {
                realm_id: Some("corp".to_string()),
                limit: 10,
                now_epoch: 300,
                include_metadata: true,
                actor: "worker".to_string(),
                reason: "scheduled archive".to_string(),
                record_audit_event: false,
            },
        )
        .await
        .unwrap();
        report.body_object.as_mut().unwrap().location =
            "file:///var/lib/qid/evidence/corp/audit.jsonl".to_string();

        let pack = compliance_evidence_pack_from_audit_archive(
            "tenant-saas",
            vec!["SOC2-CC6.1".to_string(), "ISO27001-A.5.15".to_string()],
            100,
            301,
            &report,
        )
        .unwrap();

        assert_eq!(pack.tenant_id, "tenant-saas");
        assert!(pack.id.starts_with("audit-evidence-tenant-saas-300-"));
        assert_eq!(
            pack.object_uri,
            "file:///var/lib/qid/evidence/corp/audit.jsonl"
        );
        assert_eq!(
            pack.sha256_hex,
            report.manifest.as_ref().unwrap().body_sha256
        );
        assert_eq!(pack.generated_at, 300);

        let skipped = AuditWormArchiveReport {
            status: AuditWormArchiveStatus::SkippedNoEvents,
            realm_id: Some("corp".to_string()),
            event_count: 0,
            manifest: None,
            body_object: None,
            manifest_object: None,
            audit_event_id: None,
        };
        assert!(
            compliance_evidence_pack_from_audit_archive(
                "tenant-saas",
                vec!["SOC2-CC6.1".to_string()],
                100,
                301,
                &skipped,
            )
            .is_err()
        );

        report.body_object.as_mut().unwrap().location =
            "memory://audit/corp/300/body.jsonl".to_string();
        assert!(
            compliance_evidence_pack_from_audit_archive(
                "tenant-saas",
                vec!["SOC2-CC6.1".to_string()],
                100,
                301,
                &report,
            )
            .is_err()
        );
    }

    #[test]
    fn worm_archive_rejects_overwrite() {
        let archive = InMemoryWormArchive::new();
        let object = AuditWormObject {
            key: "audit/corp/object.jsonl".to_string(),
            content_type: "application/x-ndjson".to_string(),
            body: b"event\n".to_vec(),
            metadata: BTreeMap::new(),
        };
        assert!(archive.put_once(object.clone()).is_ok());
        assert!(archive.put_once(object).is_err());
    }

    #[tokio::test]
    async fn retention_execution_requires_archive_before_ready() {
        let repo = repo().await;
        seed_audit_event(&repo, "old", 10).await;
        seed_audit_event(&repo, "new", 200).await;
        repo.set_audit_retention_config(&AuditRetentionConfig {
            realm_id: Some("corp".to_string()),
            retention_days: 0,
            legal_hold: false,
            updated_by: "admin@example.com".to_string(),
            reason: "ticket-2".to_string(),
            updated_at: 199,
        })
        .await
        .unwrap();
        let archive = InMemoryWormArchive::new();

        let report = run_audit_retention_execution_job(
            &repo,
            &archive,
            AuditRetentionExecutionConfig {
                realm_id: Some("corp".to_string()),
                now_epoch: 200,
                actor: "worker".to_string(),
                reason: "scheduled retention execution".to_string(),
                archive_required: true,
                include_metadata_in_archive: true,
                record_audit_event: true,
            },
        )
        .await
        .unwrap();

        assert_eq!(report.status, AuditRetentionExecutionStatus::Ready);
        assert_eq!(report.purge_event_ids, vec!["old".to_string()]);
        assert!(report.archive_report.is_some());
        assert!(report.audit_event_id.is_some());
        assert!(
            repo.verify_audit_chain(Some(&"corp".into()))
                .await
                .unwrap()
                .valid
        );
        assert_eq!(archive.objects.borrow().len(), 2);
    }

    #[tokio::test]
    async fn retention_execution_skips_legal_hold() {
        let repo = repo().await;
        seed_audit_event(&repo, "old", 10).await;
        repo.set_audit_retention_config(&AuditRetentionConfig {
            realm_id: Some("corp".to_string()),
            retention_days: 0,
            legal_hold: true,
            updated_by: "admin@example.com".to_string(),
            reason: "legal-hold".to_string(),
            updated_at: 199,
        })
        .await
        .unwrap();
        let archive = InMemoryWormArchive::new();

        let report = run_audit_retention_execution_job(
            &repo,
            &archive,
            AuditRetentionExecutionConfig {
                realm_id: Some("corp".to_string()),
                now_epoch: 200,
                actor: "worker".to_string(),
                reason: "scheduled retention execution".to_string(),
                archive_required: true,
                include_metadata_in_archive: true,
                record_audit_event: true,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            report.status,
            AuditRetentionExecutionStatus::SkippedLegalHold
        );
        assert!(report.purge_event_ids.is_empty());
        assert!(report.archive_report.is_none());
        assert!(report.audit_event_id.is_none());
        assert!(archive.objects.borrow().is_empty());
    }
}
