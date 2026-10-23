use qid_core::{error::QidError, models::ScimUser};
use qid_storage::{
    AnyRepository, HrBatch, HrReceipt, HrSummary, HrUserChange, RealmRepository, ScimRepository,
};

fn user(id: &str) -> ScimUser {
    ScimUser {
        id: id.into(),
        realm_id: "corp".into(),
        external_id: Some(id.into()),
        user_name: id.into(),
        name_json: serde_json::json!({}),
        emails_json: serde_json::json!([]),
        enterprise_json: serde_json::json!({}),
        directory_provider_id: None,
        deprovisioned_at: None,
        active: true,
    }
}
fn batch(sequence: u64, digest: &str, users: Vec<ScimUser>) -> HrBatch {
    HrBatch {
        realm_id: "corp".into(),
        provider_id: "hr".into(),
        receipt: HrReceipt {
            sequence,
            digest: digest.into(),
            summary: HrSummary {
                created: users.len() as u32,
                ..Default::default()
            },
        },
        changes: Some(
            users
                .into_iter()
                .map(|user| HrUserChange {
                    expected: None,
                    user,
                })
                .collect(),
        ),
    }
}
async fn exercise(repo: &AnyRepository) {
    repo.create_realm(
        &"tenant".into(),
        &"corp".into(),
        "https://id.example.com/corp",
        None,
    )
    .await
    .unwrap();
    let first = batch(1, "first", vec![user("a"), user("b")]);
    let gap = batch(2, "gap", vec![]);
    assert!(matches!(
        repo.apply_hr_batch(&gap).await,
        Err(QidError::Conflict { .. })
    ));
    // Serialization must choose one commit and one replay, not two creates.
    let (a, b) = tokio::join!(repo.apply_hr_batch(&first), repo.apply_hr_batch(&first));
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_ne!(a.replayed, b.replayed);
    assert_eq!(a.summary, b.summary);
    let mut rejected = first.clone();
    rejected.changes = None;
    assert!(repo.apply_hr_batch(&rejected).await.unwrap().replayed);
    rejected.receipt.sequence = 2;
    assert!(matches!(
        repo.apply_hr_batch(&rejected).await,
        Err(QidError::Conflict { .. })
    ));
    assert_eq!(
        repo.get_hr_receipt("corp", "hr")
            .await
            .unwrap()
            .unwrap()
            .sequence,
        1
    );
    let mut changed = first.clone();
    changed.receipt.digest = "different".into();
    assert!(repo.apply_hr_batch(&changed).await.is_err());
    let mut leaver = first.clone();
    leaver.receipt.sequence = 2;
    leaver.receipt.digest = "leaver".into();
    for c in leaver.changes.as_mut().unwrap() {
        c.expected = Some(c.user.clone());
        c.user.active = false;
        c.user.deprovisioned_at = Some(100);
    }
    leaver.receipt.summary = HrSummary {
        deprovisioned: 2,
        ..Default::default()
    };
    repo.apply_hr_batch(&leaver).await.unwrap();
    assert!(matches!(
        repo.apply_hr_batch(&first).await,
        Err(QidError::Conflict { .. })
    ));
    assert!(
        !repo.get_scim_user("a").await.unwrap().unwrap().active,
        "old joiner cannot reactivate after leaver"
    );
    // Same sequence with distinct bodies concurrently: exactly one success.
    let third = batch(3, "third-a", vec![user("c")]);
    let mut third_b = third.clone();
    third_b.receipt.digest = "third-b".into();
    let (a, b) = tokio::join!(repo.apply_hr_batch(&third), repo.apply_hr_batch(&third_b));
    assert_ne!(a.is_ok(), b.is_ok());
    // Next sequence and a gap race; the gap must fail in either lock order.
    let fourth = batch(4, "fourth", vec![]);
    let sixth = batch(6, "sixth", vec![user("must-not-exist")]);
    let (a, b) = tokio::join!(repo.apply_hr_batch(&fourth), repo.apply_hr_batch(&sixth));
    a.unwrap();
    assert!(matches!(b, Err(QidError::Conflict { .. })));
    let (a, b) = tokio::join!(repo.apply_hr_batch(&first), repo.apply_hr_batch(&fourth));
    assert!(matches!(a, Err(QidError::Conflict { .. })));
    assert!(b.unwrap().replayed);
    assert!(
        repo.get_scim_user("must-not-exist")
            .await
            .unwrap()
            .is_none()
    );
    // A stale expected target must abort the entire batch, including an earlier create.
    let mut fifth = batch(5, "fifth", vec![user("prefix")]);
    fifth.changes.as_mut().unwrap().push(HrUserChange {
        expected: Some(user("a")),
        user: user("a"),
    });
    assert!(matches!(
        repo.apply_hr_batch(&fifth).await,
        Err(QidError::Conflict { .. })
    ));
    assert!(repo.get_scim_user("prefix").await.unwrap().is_none());
    assert_eq!(
        repo.get_hr_receipt("corp", "hr")
            .await
            .unwrap()
            .unwrap()
            .sequence,
        4
    );
    // An ambiguous external ID introduced after planning invalidates every change.
    let mut ambiguous = user("duplicate");
    ambiguous.external_id = Some("a".into());
    repo.create_scim_user(&ambiguous).await.unwrap();
    fifth.changes.as_mut().unwrap()[1].expected = repo.get_scim_user("a").await.unwrap();
    assert!(repo.apply_hr_batch(&fifth).await.is_err());
    assert!(repo.get_scim_user("prefix").await.unwrap().is_none());
    // Provider and realm components are separate keys, not concatenated identities.
    let mut independent = batch(1, "other", vec![]);
    independent.provider_id = "other".into();
    repo.apply_hr_batch(&independent).await.unwrap();
    assert_eq!(
        repo.get_hr_receipt("corp", "other")
            .await
            .unwrap()
            .unwrap()
            .sequence,
        1
    );
    repo.delete_realm(&"corp".into()).await.unwrap();
    assert!(repo.get_hr_receipt("corp", "hr").await.unwrap().is_none());
}

#[test]
fn invalid_persisted_hr_receipt_sequences_fail_closed() {
    let invalid = HrReceipt {
        sequence: 0,
        digest: String::new(),
        summary: HrSummary::default(),
    };
    let incoming = batch(1, "valid", vec![]).receipt;
    assert!(matches!(
        qid_storage::hr_order(Some(&invalid), &incoming),
        Err(qid_core::error::QidError::Internal { .. })
    ));
}

#[tokio::test]
async fn ordered_hr_batches_are_atomic_and_durable_on_file_and_sql() {
    for sql in [false, true] {
        let dir = std::env::temp_dir().join(format!("qid-hr-contract-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store");
        let url = if sql {
            format!("sqlite:{}", path.display())
        } else {
            path.to_str().unwrap().into()
        };
        let repo = AnyRepository::connect(&url).await.unwrap();
        exercise(&repo).await;
        // `exercise` verifies realm deletion also removes its receipt. Recreate
        // the realm before testing a fresh durable receipt.
        repo.create_realm(
            &"tenant".into(),
            &"corp".into(),
            "https://id.example.com/corp",
            None,
        )
        .await
        .unwrap();
        // Persist a final empty batch and reopen to test the actual durable receipt.
        repo.apply_hr_batch(&batch(1, "durable", vec![]))
            .await
            .unwrap();
        match repo {
            AnyRepository::Sql(r) => r.close().await,
            AnyRepository::File(r) => drop(r),
        }
        // File handle must be dropped to release process lock.
        let reopened = AnyRepository::connect(&url).await.unwrap();
        assert_eq!(
            reopened
                .get_hr_receipt("corp", "hr")
                .await
                .unwrap()
                .unwrap()
                .digest,
            "durable"
        );
        assert!(
            reopened
                .apply_hr_batch(&batch(1, "durable", vec![]))
                .await
                .unwrap()
                .replayed
        );
        match reopened {
            AnyRepository::Sql(r) => r.close().await,
            AnyRepository::File(r) => drop(r),
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[tokio::test]
async fn sql_failure_after_a_prefix_write_rolls_back_users_and_receipt() {
    let dir = std::env::temp_dir().join(format!("qid-hr-sql-failure-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite:{}", dir.join("db").display());
    let repo = AnyRepository::connect(&url).await.unwrap();
    repo.create_realm(
        &"tenant".into(),
        &"corp".into(),
        "https://id.example.com/corp",
        None,
    )
    .await
    .unwrap();
    let pool = sqlx::SqlitePool::connect(&url).await.unwrap();
    sqlx::query("CREATE TRIGGER fail_hr BEFORE INSERT ON scim_users WHEN NEW.id = 'second' BEGIN SELECT RAISE(ABORT, 'injected'); END").execute(&pool).await.unwrap();
    let request = batch(1, "failure", vec![user("first"), user("second")]);
    assert!(repo.apply_hr_batch(&request).await.is_err());
    assert!(
        repo.list_scim_users(&"corp".into())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(repo.get_hr_receipt("corp", "hr").await.unwrap().is_none());
    sqlx::query("DROP TRIGGER fail_hr")
        .execute(&pool)
        .await
        .unwrap();
    repo.apply_hr_batch(&request).await.unwrap();
    pool.close().await;
    match repo {
        AnyRepository::Sql(r) => r.close().await,
        AnyRepository::File(r) => drop(r),
    }
    std::fs::remove_dir_all(dir).unwrap();
}
