use super::*;
use qid_core::{
    models::{AuditEvent, AuditRetentionConfig, ScimUser},
    tenant::RealmId,
};
use qid_storage::prelude::*;

fn temp_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("qid-worker-cli-{name}-{}", ulid::Ulid::new()))
}

fn write_config(dir: &Path) -> (PathBuf, PathBuf) {
    let store = dir.join("qid-store.json");
    let config = dir.join("qid.yaml");
    let store_url =
        serde_json::to_string(&store.to_string_lossy()).expect("store path should serialize");
    std::fs::write(
        &config,
        format!(
            r#"
server:
  listen: "127.0.0.1:0"
  public_base_url: "https://id.example.com"
storage:
  primary:
    url: {store_url}
realms:
  - id: corp
    issuer: "https://id.example.com/realms/corp"
"#
        ),
    )
    .expect("config file");
    (config, store)
}

#[tokio::test]
async fn push_cleanup_command_is_bounded_and_independent_of_audit() {
    use clap::Parser;
    for limit in ["0", "1001"] {
        assert!(Args::try_parse_from(["qid-worker", "push-cleanup", "--limit", limit]).is_err());
    }
    let dir = temp_dir("push-cleanup");
    std::fs::create_dir_all(&dir).unwrap();
    let (config, store) = write_config(&dir);
    let repo = AnyRepository::connect(store.to_str().unwrap())
        .await
        .unwrap();
    append_audit_event(&repo, "must-remain", 1).await;
    drop(repo);
    let args = Args::try_parse_from([
        "qid-worker",
        "--config",
        config.to_str().unwrap(),
        "push-cleanup",
    ])
    .unwrap();
    let result = run(args).await.unwrap();
    assert_eq!(result["command"], "push_cleanup");
    assert_eq!(result["deleted"], 0);
    let repo = AnyRepository::connect(store.to_str().unwrap())
        .await
        .unwrap();
    assert!(
        repo.list_audit_events(None, 10)
            .await
            .unwrap()
            .iter()
            .any(|event| event.id == "must-remain")
    );
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn directory_sync_dry_run_is_rejected_without_changing_users_or_audit() {
    let dir = temp_dir("directory-sync-dry-run");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let (config, store) = write_config(&dir);
    let initial_user = ScimUser {
        id: "user-before-dry-run".to_string(),
        realm_id: "corp".to_string(),
        external_id: Some("uid=existing,dc=example,dc=com".to_string()),
        user_name: "before@example.com".to_string(),
        name_json: serde_json::json!({"givenName": "Before"}),
        emails_json: serde_json::json!([{"value": "before@example.com"}]),
        enterprise_json: serde_json::json!({}),
        directory_provider_id: None,
        deprovisioned_at: None,
        active: true,
    };
    let repo = AnyRepository::connect(store.to_str().expect("store path"))
        .await
        .expect("repository");
    repo.create_scim_user(&initial_user)
        .await
        .expect("seed user");
    drop(repo);

    let result = run(Args {
        config,
        command: Command::DirectorySync {
            realm: "corp".to_string(),
            provider_id: "missing-provider".to_string(),
            actor: "qid-worker".to_string(),
            reason: "dry-run safety regression".to_string(),
            now: Some(100),
            record_audit_event: true,
            dry_run: true,
        },
    })
    .await;
    let error = result.expect_err("dry-run must be rejected before directory lookup");
    assert!(
        error
            .to_string()
            .contains("directory sync dry-run is not supported")
    );

    let refreshed = AnyRepository::connect(store.to_str().expect("store path"))
        .await
        .expect("repository");
    let users = refreshed
        .list_scim_users(&RealmId::from("corp".to_string()))
        .await
        .expect("SCIM users");
    assert_eq!(
        serde_json::to_value(users).expect("serialize SCIM users"),
        serde_json::to_value(vec![initial_user]).expect("serialize initial user")
    );
    assert!(
        refreshed
            .list_audit_events(Some(&RealmId::from("corp".to_string())), 10)
            .await
            .expect("audit events")
            .is_empty()
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn directory_sync_honors_realm_level_kill_switch_before_connect() {
    let dir = temp_dir("directory-sync-disabled");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let (config, store) = write_config(&dir);
    let base_config = std::fs::read_to_string(&config).expect("base config");
    let disabled_directory_config = base_config.replace(
            "    issuer: \"https://id.example.com/realms/corp\"\n",
            "    issuer: \"https://id.example.com/realms/corp\"\n    protocols:\n      directory:\n        enabled: false\n        providers:\n          - id: corp-ldap\n            type: ldap\n            enabled: true\n            connection:\n              url: \"ldap://dir.invalid\"\n",
        );
    std::fs::write(&config, disabled_directory_config).expect("disabled directory config");

    let initial_user = ScimUser {
        id: "user-before-disabled-sync".to_string(),
        realm_id: "corp".to_string(),
        external_id: Some("uid=keep,dc=example,dc=com".to_string()),
        user_name: "keep@example.com".to_string(),
        name_json: serde_json::json!({"givenName": "Keep"}),
        emails_json: serde_json::json!([{"value": "keep@example.com"}]),
        enterprise_json: serde_json::json!({}),
        directory_provider_id: Some("corp-ldap".to_string()),
        deprovisioned_at: None,
        active: true,
    };
    let repo = AnyRepository::connect(store.to_str().expect("store path"))
        .await
        .expect("repository");
    repo.create_scim_user(&initial_user)
        .await
        .expect("seed user");
    drop(repo);

    let result = run(Args {
        config,
        command: Command::DirectorySync {
            realm: "corp".to_string(),
            provider_id: "corp-ldap".to_string(),
            actor: "qid-worker".to_string(),
            reason: "disabled kill-switch regression".to_string(),
            now: Some(100),
            record_audit_event: true,
            dry_run: false,
        },
    })
    .await
    .expect("disabled directory sync should report instead of failing");
    assert_eq!(result["command"], "directory_sync");
    assert_eq!(result["report"]["status"], "skipped_disabled");
    assert_eq!(result["report"]["provider_id"], "corp-ldap");
    assert!(result["report"]["audit_event_id"].is_null());

    let refreshed = AnyRepository::connect(store.to_str().expect("store path"))
        .await
        .expect("repository");
    let users = refreshed
        .list_scim_users(&RealmId::from("corp".to_string()))
        .await
        .expect("SCIM users");
    assert_eq!(
        serde_json::to_value(users).expect("serialize SCIM users"),
        serde_json::to_value(vec![initial_user]).expect("serialize initial user")
    );
    assert!(
        refreshed
            .list_audit_events(Some(&RealmId::from("corp".to_string())), 10)
            .await
            .expect("audit events")
            .is_empty()
    );
    std::fs::remove_dir_all(&dir).ok();
}

async fn append_audit_event(repo: &AnyRepository, id: &str, created_at: u64) {
    repo.append_audit_event(&AuditEvent {
        id: id.to_string(),
        realm_id: Some("corp".to_string()),
        actor: "admin@example.com".to_string(),
        action: "audit.test".to_string(),
        target_type: "audit".to_string(),
        target_id: id.to_string(),
        reason: "test".to_string(),
        metadata_json: serde_json::json!({ "id": id }),
        created_at,
        previous_hash: None,
        event_hash: None,
    })
    .await
    .expect("audit event");
}

#[tokio::test]
async fn retention_evaluate_command_uses_real_storage() {
    let dir = temp_dir("retention");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let (config, store) = write_config(&dir);
    let repo = AnyRepository::connect(store.to_str().expect("store path"))
        .await
        .expect("repository");
    append_audit_event(&repo, "old", 10).await;
    append_audit_event(&repo, "new", 200).await;
    repo.set_audit_retention_config(&AuditRetentionConfig {
        realm_id: Some("corp".to_string()),
        retention_days: 0,
        legal_hold: false,
        updated_by: "admin@example.com".to_string(),
        reason: "ticket-1".to_string(),
        updated_at: 199,
    })
    .await
    .expect("retention config");
    drop(repo);

    let result = run(Args {
        config,
        command: Command::RetentionEvaluate {
            realm: Some("corp".to_string()),
            actor: "qid-worker".to_string(),
            reason: "scheduled retention evaluation".to_string(),
            now: Some(200),
            record_audit_event: true,
        },
    })
    .await
    .expect("retention evaluate");

    assert_eq!(result["command"], "audit_retention_evaluate");
    assert_eq!(result["report"]["status"], "evaluated");
    assert_eq!(result["report"]["plan"]["expired_event_ids"][0], "old");
    let refreshed = AnyRepository::connect(store.to_str().expect("store path"))
        .await
        .expect("repository");
    assert_eq!(
        refreshed
            .list_audit_events(Some(&RealmId::from("corp".to_string())), 10)
            .await
            .expect("audit events")
            .len(),
        3
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn worm_archive_command_writes_append_only_files() {
    let dir = temp_dir("archive");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let (config, store) = write_config(&dir);
    let repo = AnyRepository::connect(store.to_str().expect("store path"))
        .await
        .expect("repository");
    append_audit_event(&repo, "event-1", 100).await;
    drop(repo);
    let archive_dir = dir.join("archive");
    std::fs::create_dir_all(&archive_dir).expect("create archive dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&archive_dir, std::fs::Permissions::from_mode(0o700))
            .expect("set archive dir permissions");
    }

    let result = run(Args {
        config,
        command: Command::WormArchive {
            realm: Some("corp".to_string()),
            archive_dir: archive_dir.clone(),
            limit: 10,
            actor: "qid-worker".to_string(),
            reason: "scheduled audit archive".to_string(),
            now: Some(300),
            include_metadata: true,
            record_audit_event: true,
            tsa_url: None,
            tsa_ca: Vec::new(),
            tsa_timeout_seconds: 10,
        },
    })
    .await
    .expect("worm archive");

    assert_eq!(result["command"], "audit_worm_archive");
    assert_eq!(result["report"]["status"], "archived");
    let body_location = result["report"]["body_object"]["location"]
        .as_str()
        .expect("body location");
    let body_path = body_location
        .strip_prefix("file://")
        .expect("file location");
    assert!(Path::new(body_path).exists());
    assert!(archive_dir.exists());
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn siem_deliver_command_captures_request_without_network() {
    let dir = temp_dir("siem");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let (config, store) = write_config(&dir);
    let repo = AnyRepository::connect(store.to_str().expect("store path"))
        .await
        .expect("repository");
    append_audit_event(&repo, "event-1", 100).await;
    drop(repo);
    let request_output = dir.join("siem-request.json");

    let result = run(Args {
        config,
        command: Command::SiemDeliver {
            realm: Some("corp".to_string()),
            endpoint_url: "https://siem.example.com/audit".to_string(),
            request_output: Some(request_output.clone()),
            dry_run: true,
            timeout_seconds: 10,
            limit: 10,
            now: Some(200),
            traceparent: None,
            audit_correlation_id: Some("corr-1".to_string()),
            include_metadata: true,
            actor: "qid-worker".to_string(),
            reason: "scheduled siem delivery".to_string(),
            record_audit_event: false,
            completed_attempts: 0,
            max_attempts: 5,
            base_delay_ms: 1000,
            max_delay_ms: 60000,
        },
    })
    .await
    .expect("siem deliver");

    assert_eq!(result["command"], "audit_siem_deliver");
    assert_eq!(result["report"]["status"], "skipped_dry_run");
    let repo = AnyRepository::connect(store.to_str().expect("store path"))
        .await
        .expect("repository");
    let delivery_id = result["report"]["delivery_id"]
        .as_str()
        .expect("delivery id");
    let queued = repo
        .get_siem_delivery(delivery_id)
        .await
        .expect("queue lookup")
        .expect("queue row");
    assert_eq!(
        queued.status,
        qid_storage::prelude::SiemDeliveryStatus::Pending
    );
    assert_eq!(queued.attempts, 0);
    let captured: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(request_output).expect("captured request"))
            .expect("captured request JSON");
    assert_eq!(captured["method"], "POST");
    assert_eq!(captured["body"]["event_count"], 1);
    assert_eq!(captured["body"]["events"][0]["id"], "event-1");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn notification_deliver_command_writes_request_and_audit() {
    let dir = temp_dir("notification");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let (config, store) = write_config(&dir);
    let request_output = dir.join("notification-request.json");

    let result = run(Args {
        config,
        command: Command::NotificationDeliver {
            realm: Some("corp".to_string()),
            channel: "email".to_string(),
            provider: "https://mail.example.com/send".to_string(),
            recipient: "alice@example.com".to_string(),
            subject: Some("Verify your email".to_string()),
            body: "Use code 123456".to_string(),
            template_id: Some("email.verify".to_string()),
            data_json: r#"{"code":"123456"}"#.to_string(),
            request_output: Some(request_output.clone()),
            dry_run: true,
            timeout_seconds: 10,
            now: Some(300),
            actor: "qid-worker".to_string(),
            reason: "scheduled notification delivery".to_string(),
            record_audit_event: true,
            completed_attempts: 0,
            max_attempts: 5,
            base_delay_ms: 1000,
            max_delay_ms: 60000,
        },
    })
    .await
    .expect("notification deliver");

    assert_eq!(result["command"], "notification_deliver");
    assert_eq!(result["report"]["status"], "skipped_dry_run");
    assert_eq!(result["report"]["channel"], "email");
    let captured: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(request_output).expect("captured request"))
            .expect("captured request JSON");
    assert_eq!(captured["body"]["channel"], "email");
    assert_eq!(captured["body"]["recipient"], "alice@example.com");
    assert_eq!(captured["body"]["template_id"], "email.verify");

    let refreshed = AnyRepository::connect(store.to_str().expect("store path"))
        .await
        .expect("repository");
    let events = refreshed
        .list_audit_events(Some(&RealmId::from("corp".to_string())), 10)
        .await
        .expect("audit events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "notification.deliver");
    assert_eq!(
        events[0].target_id,
        result["report"]["recipient_hash"]
            .as_str()
            .expect("recipient hash")
    );
    assert!(
        !events[0]
            .metadata_json
            .to_string()
            .contains("alice@example.com")
    );
    assert!(!events[0].metadata_json.to_string().contains("Use code"));
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn key_rotation_plan_command_uses_real_storage_and_records_audit() {
    let dir = temp_dir("key-rotation");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let (config, store) = write_config(&dir);

    let result = run(Args {
        config,
        command: Command::KeyRotationPlan {
            inventory: vec![
                "corp,corp-shared,shared-1,pep_assertion,local,100,100,10000".to_string(),
                "corp,corp-shared,shared-2,oidc_token,local,100,100,10000".to_string(),
            ],
            requirement: vec!["corp,pep_assertion,90,14,true,true".to_string()],
            actor: "qid-worker".to_string(),
            reason: "scheduled key rotation planning".to_string(),
            now: Some(1_000),
            record_audit_event: true,
        },
    })
    .await
    .expect("key rotation plan");

    assert_eq!(result["command"], "key_rotation_plan");
    assert_eq!(result["report"]["status"], "rejected");
    assert_eq!(result["report"]["rejected_count"], 1);
    assert_eq!(
        result["report"]["plans"][0]["reasons"][0],
        "dedicated_keyring_required:corp-shared"
    );
    let refreshed = AnyRepository::connect(store.to_str().expect("store path"))
        .await
        .expect("repository");
    let events = refreshed
        .list_audit_events(Some(&RealmId::from("corp".to_string())), 10)
        .await
        .expect("audit events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "key_rotation.plan");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn key_rotation_execute_command_writes_successor_key_and_records_audit() {
    let dir = temp_dir("key-rotation-execute");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let (config, store) = write_config(&dir);
    let plan_json = dir.join("plan.json");
    std::fs::write(
        &plan_json,
        serde_json::to_string(&KeyRotationPlan {
            status: qid_ops::KeyRotationPlanStatus::ActionRequired,
            realm_id: "corp".to_string(),
            purpose: qid_ops::KeyPurpose::OidcToken,
            active_kid: Some("old".to_string()),
            successor_kid: None,
            actions: vec![qid_ops::KeyRotationAction {
                action: qid_ops::KeyRotationActionKind::GenerateSuccessor,
                keyring_name: "corp-main".to_string(),
                kid: Some("next".to_string()),
                reason: "rotation_overlap_window_open".to_string(),
            }],
            reasons: Vec::new(),
        })
        .expect("serialize plan"),
    )
    .expect("write plan");
    let passphrase_file = dir.join("passphrase");
    std::fs::write(&passphrase_file, "test-passphrase\n").expect("write passphrase");
    let output_dir = dir.join("keys");

    let result = run(Args {
        config,
        command: Command::KeyRotationExecute {
            plan_json,
            output_dir: output_dir.clone(),
            algorithm: "ES256".to_string(),
            passphrase_file: Some(passphrase_file),
            actor: "qid-worker".to_string(),
            reason: "scheduled key rotation execution".to_string(),
            now: Some(123),
            record_audit_event: true,
            force: false,
        },
    })
    .await
    .expect("key rotation execute");

    assert_eq!(result["command"], "key_rotation_execute");
    assert_eq!(result["report"]["status"], "executed");
    let encrypted_path = output_dir.join("signing-key-corp-main-ES256-next.pem.enc");
    let public_key_path = output_dir.join("signing-key-corp-main-ES256-next.pub.pem");
    let public_jwk_path = output_dir.join("signing-key-corp-main-ES256-next.jwk.json");
    assert!(encrypted_path.exists());
    assert!(public_key_path.exists());
    assert!(public_jwk_path.exists());
    assert!(
        !std::fs::read_to_string(&encrypted_path)
            .expect("encrypted key")
            .contains("PRIVATE KEY")
    );
    let refreshed = AnyRepository::connect(store.to_str().expect("store path"))
        .await
        .expect("repository");
    let events = refreshed
        .list_audit_events(Some(&RealmId::from("corp".to_string())), 10)
        .await
        .expect("audit events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "key_rotation.execute");
    assert_eq!(events[0].metadata_json["executed"][0]["kid"], "next");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn scim_outbound_cli_defaults_to_dry_run_and_keeps_credentials_out_of_reports() {
    use clap::Parser;
    let dir = temp_dir("scim-outbound");
    std::fs::create_dir_all(&dir).unwrap();
    let (config, _) = write_config(&dir);
    let token_file = dir.join("token");
    std::fs::write(&token_file, "fixture-token\n").unwrap();
    let base = [
        "qid-worker",
        "--config",
        config.to_str().unwrap(),
        "scim-outbound-sync",
        "--realm",
        "corp",
        "--endpoint",
        "https://scim.invalid/v2",
        "--token-file",
        token_file.to_str().unwrap(),
    ];
    let parsed = Args::try_parse_from(base).unwrap();
    match &parsed.command {
        Command::ScimOutboundSync {
            apply,
            orphan_action,
            page_size,
            max_resources,
            ..
        } => {
            assert!(!apply);
            assert!(matches!(orphan_action, ScimOrphanAction::None));
            assert_eq!((*page_size, *max_resources), (100, 10_000));
        }
        _ => panic!("wrong command"),
    }
    // Empty registry performs no HTTP writes or reads, but still produces its audit/report.
    let result = run(parsed).await.unwrap();
    assert_eq!(result["report"]["dry_run"], true);
    assert_eq!(result["report"]["failed"], 0);
    assert!(
        !serde_json::to_string(&result)
            .unwrap()
            .contains("fixture-token")
    );
    let apply =
        Args::try_parse_from(
            base.into_iter()
                .chain(["--apply", "--orphan-action", "delete"]),
        )
        .unwrap();
    assert!(matches!(
        apply.command,
        Command::ScimOutboundSync {
            apply: true,
            orphan_action: ScimOrphanAction::Delete,
            ..
        }
    ));
    for args in [
        ["--page-size", "0"],
        ["--max-resources", "0"],
        ["--orphan-action", "unknown"],
    ] {
        assert!(Args::try_parse_from(base.into_iter().chain(args)).is_err());
    }
    assert!(Args::try_parse_from(["qid-worker", "scim-outbound-sync", "--realm", "corp"]).is_err());
    for endpoint in [
        "http://scim.invalid/v2",
        "https://user:password@scim.invalid/v2",
        "https://scim.invalid/v2?token=value",
        "https://scim.invalid/v2#fragment",
    ] {
        assert!(scim_token(endpoint, &token_file).is_err());
    }
    for token in ["", "two tokens", "value\r\ninjected"] {
        std::fs::write(&token_file, token).unwrap();
        let error = scim_token("https://scim.invalid/v2", &token_file)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "invalid SCIM token file");
    }
    std::fs::remove_file(&token_file).unwrap();
    assert_eq!(
        scim_token("https://scim.invalid/v2", &token_file)
            .unwrap_err()
            .to_string(),
        "cannot read SCIM token file"
    );
    std::fs::remove_dir_all(dir).unwrap();
}
