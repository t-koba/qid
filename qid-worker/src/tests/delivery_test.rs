use super::*;

impl CapturingTransport {
    fn dry_run() -> Self {
        Self {
            response: AuditSiemHttpResponse {
                status: 0,
                sent: false,
            },
            requests: Mutex::new(Vec::new()),
        }
    }
}

#[tokio::test]
async fn siem_redrive_dry_run_leaves_delivery_pending() {
    let repo = repo().await;
    seed_audit_event(&repo, "event-1", 100).await;
    let failed = run_audit_siem_delivery_job(
        &repo,
        &CapturingTransport::new(503),
        AuditSiemDeliveryConfig {
            realm_id: Some("corp".to_string()),
            endpoint_url: "https://siem.example.com/audit".to_string(),
            limit: 10,
            now_epoch: 200,
            traceparent: None,
            audit_correlation_id: None,
            include_metadata: false,
            actor: "worker".to_string(),
            reason: "initial delivery".to_string(),
            record_audit_event: false,
            completed_attempts: 0,
            retry_policy: AuditSiemRetryPolicy {
                max_attempts: 1,
                base_delay_ms: 1000,
                max_delay_ms: 1000,
            },
        },
    )
    .await
    .unwrap();
    let delivery_id = failed.delivery_id.expect("delivery id");
    assert_eq!(failed.status, AuditSiemDeliveryStatus::FailedPermanent);

    let report = run_audit_siem_redrive_job(
        &repo,
        &CapturingTransport::dry_run(),
        AuditSiemRedriveConfig {
            delivery_id: delivery_id.clone(),
            now_epoch: 300,
            actor: "worker".to_string(),
            reason: "dry run".to_string(),
            record_audit_event: false,
            retry_policy: AuditSiemRetryPolicy::default(),
        },
    )
    .await
    .unwrap();
    assert_eq!(report.status, AuditSiemDeliveryStatus::SkippedDryRun);
    let queued = repo.get_siem_delivery(&delivery_id).await.unwrap().unwrap();
    assert_eq!(queued.status, SiemDeliveryStatus::Pending);
    assert_eq!(queued.next_retry_at, Some(300));
    assert_eq!(queued.attempts, 1);
}
