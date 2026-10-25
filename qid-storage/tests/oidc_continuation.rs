use qid_core::{
    error::QidError,
    models::{OIDC_CONTINUATION_CONTEXT_MAX_BYTES, OidcAuthorizationContinuation},
    tenant::RealmId,
};
use qid_storage::{AnyRepository, OidcContinuationRepository};

fn record(id: &str) -> OidcAuthorizationContinuation {
    OidcAuthorizationContinuation {
        id: id.into(), realm_id: "realm".into(), user_id: "user".into(), client_id: "client".into(),
        context_json: r#"{ "version":1,"request":{"redirect_uri":"https://client.example/cb","state":"private-state","nonce":"private-nonce","response_mode":"form_post","code_challenge":"pkce","par_resolved":true}}"#.into(),
        browser_binding_sha256: [7; 32], created_at: 100, expires_at: 200,
    }
}

async fn consume(
    repo: &impl OidcContinuationRepository,
    c: &OidcAuthorizationContinuation,
    now: u64,
) -> Option<OidcAuthorizationContinuation> {
    repo.consume_oidc_continuation(
        &RealmId(c.realm_id.clone()),
        &c.user_id,
        &c.client_id,
        &c.id,
        &c.browser_binding_sha256,
        now,
    )
    .await
    .unwrap()
}

async fn contract(repo: &AnyRepository) {
    let c = record("transaction");
    repo.create_oidc_continuation(&c, 100).await.unwrap();
    for changed in [
        c.clone(),
        OidcAuthorizationContinuation {
            context_json: r#"{"substitute":true}"#.into(),
            ..c.clone()
        },
        OidcAuthorizationContinuation {
            realm_id: "other-realm".into(),
            user_id: "other-user".into(),
            client_id: "other-client".into(),
            ..c.clone()
        },
    ] {
        assert!(matches!(
            repo.create_oidc_continuation(&changed, 100).await,
            Err(QidError::Conflict { .. })
        ));
    }
    for changed in [
        OidcAuthorizationContinuation {
            id: "missing".into(),
            ..c.clone()
        },
        OidcAuthorizationContinuation {
            realm_id: "other".into(),
            ..c.clone()
        },
        OidcAuthorizationContinuation {
            user_id: "other".into(),
            ..c.clone()
        },
        OidcAuthorizationContinuation {
            client_id: "other".into(),
            ..c.clone()
        },
        OidcAuthorizationContinuation {
            browser_binding_sha256: [8; 32],
            ..c.clone()
        },
    ] {
        assert_eq!(consume(repo, &changed, 150).await, None);
    }
    // A second request has its own binding, not transferable from transaction one.
    let other = OidcAuthorizationContinuation {
        browser_binding_sha256: [9; 32],
        ..record("other-transaction")
    };
    repo.create_oidc_continuation(&other, 100).await.unwrap();
    let substitution = OidcAuthorizationContinuation {
        id: other.id.clone(),
        ..c.clone()
    };
    assert_eq!(consume(repo, &substitution, 150).await, None);
    assert_eq!(consume(repo, &c, 99).await, None);
    assert_eq!(consume(repo, &c, 200).await, None);
    assert_eq!(consume(repo, &c, 201).await, None);
    assert!(matches!(
        repo.consume_oidc_continuation(
            &RealmId("realm".into()),
            "user",
            "client",
            &c.id,
            &[7; 32],
            u64::MAX
        )
        .await,
        Err(QidError::BadRequest { .. })
    ));
    // Failed substitutions and clock checks never consume the original envelope.
    assert_eq!(consume(repo, &c, 100).await, Some(c.clone()));
    assert_eq!(consume(repo, &c, 100).await, None);
    assert!(matches!(
        repo.create_oidc_continuation(&c, 100).await,
        Err(QidError::Conflict { .. })
    ));
    assert_eq!(consume(repo, &other, 199).await, Some(other));

    // Bounded concurrent contenders exercise the single atomic consume operation.
    let race = record("consume-race");
    repo.create_oidc_continuation(&race, 100).await.unwrap();
    let (a, b, c, d) = tokio::join!(
        consume(repo, &race, 150),
        consume(repo, &race, 150),
        consume(repo, &race, 150),
        consume(repo, &race, 150)
    );
    let winners: Vec<_> = [a, b, c, d].into_iter().flatten().collect();
    assert_eq!(winners, vec![race]);
    let create_race = record("create-race");
    let (a, b) = tokio::join!(
        repo.create_oidc_continuation(&create_race, 100),
        repo.create_oidc_continuation(&create_race, 100)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(matches!(
        a.err().or(b.err()),
        Some(QidError::Conflict { .. })
    ));

    for json in [
        "",
        "not-json",
        "null",
        "[]",
        "{}",
        "1",
        "{\"v\":1} trailing",
    ] {
        let invalid = OidcAuthorizationContinuation {
            context_json: json.into(),
            ..record("invalid-context")
        };
        assert!(matches!(
            repo.create_oidc_continuation(&invalid, 100).await,
            Err(QidError::BadRequest { .. })
        ));
    }
    // UTF-8 bytes, not characters: exactly the limit is admitted, one byte over is not.
    let context = format!(
        "{{\"v\":\"{}\"}}",
        "é".repeat((OIDC_CONTINUATION_CONTEXT_MAX_BYTES - 8) / 2)
    );
    assert_eq!(context.len(), OIDC_CONTINUATION_CONTEXT_MAX_BYTES);
    let boundary = OidcAuthorizationContinuation {
        context_json: context,
        ..record("boundary")
    };
    repo.create_oidc_continuation(&boundary, 100).await.unwrap();
    assert_eq!(consume(repo, &boundary, 150).await, Some(boundary.clone()));
    let too_big = OidcAuthorizationContinuation {
        context_json: format!("{} ", boundary.context_json),
        ..record("too-big")
    };
    assert!(matches!(
        repo.create_oidc_continuation(&too_big, 100).await,
        Err(QidError::BadRequest { .. })
    ));
    let base = record("invalid-fields");
    for invalid in [
        OidcAuthorizationContinuation {
            id: "".into(),
            ..base.clone()
        },
        OidcAuthorizationContinuation {
            realm_id: "".into(),
            ..base.clone()
        },
        OidcAuthorizationContinuation {
            user_id: "".into(),
            ..base.clone()
        },
        OidcAuthorizationContinuation {
            client_id: "".into(),
            ..base.clone()
        },
        OidcAuthorizationContinuation {
            id: "x".repeat(257),
            ..base.clone()
        },
        OidcAuthorizationContinuation {
            user_id: "white space".into(),
            ..base.clone()
        },
        OidcAuthorizationContinuation {
            client_id: "control\n".into(),
            ..base.clone()
        },
        OidcAuthorizationContinuation {
            expires_at: 100,
            ..base.clone()
        },
        OidcAuthorizationContinuation {
            expires_at: 99,
            ..base.clone()
        },
        OidcAuthorizationContinuation {
            expires_at: u64::MAX,
            ..base.clone()
        },
        OidcAuthorizationContinuation {
            created_at: 99,
            ..base.clone()
        },
        OidcAuthorizationContinuation {
            created_at: 101,
            ..base.clone()
        },
    ] {
        assert!(matches!(
            repo.create_oidc_continuation(&invalid, 100).await,
            Err(QidError::BadRequest { .. })
        ));
    }
    // The rejected creations did not reserve the ID.
    repo.create_oidc_continuation(&base, 100).await.unwrap();
    assert_eq!(consume(repo, &base, 150).await, Some(base));
    // Signed SQL timestamp edge has identical semantics on the file backend.
    let edge = OidcAuthorizationContinuation {
        created_at: i64::MAX as u64 - 1,
        expires_at: i64::MAX as u64,
        ..record("clock-edge")
    };
    repo.create_oidc_continuation(&edge, edge.created_at)
        .await
        .unwrap();
    assert_eq!(consume(repo, &edge, edge.expires_at).await, None);
    assert_eq!(
        consume(repo, &edge, edge.created_at).await,
        Some(edge.clone())
    );
}

async fn cleanup_contract(repo: &AnyRepository) {
    let boundary = record("cleanup-boundary");
    let expired1 = record("cleanup-expired-1");
    let expired2 = record("cleanup-expired-2");
    let expired3 = record("cleanup-expired-3");
    let mut unexpired = record("cleanup-unexpired");
    unexpired.expires_at = 201;
    for c in [&boundary, &expired1, &expired2, &expired3, &unexpired] {
        repo.create_oidc_continuation(c, 100).await.unwrap();
    }

    assert_eq!(
        repo.cleanup_expired_oidc_continuations(199, 2)
            .await
            .unwrap(),
        0
    );
    assert_eq!(consume(repo, &boundary, 199).await, Some(boundary));
    assert_eq!(
        repo.cleanup_expired_oidc_continuations(200, 2)
            .await
            .unwrap(),
        2
    );
    assert_eq!(consume(repo, &expired1, 200).await, None);
    assert_eq!(
        repo.cleanup_expired_oidc_continuations(200, 2)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        repo.cleanup_expired_oidc_continuations(200, 2)
            .await
            .unwrap(),
        0
    );
    assert_eq!(consume(repo, &expired2, 200).await, None);
    assert_eq!(consume(repo, &unexpired, 200).await, Some(unexpired));
    assert!(matches!(
        repo.cleanup_expired_oidc_continuations(200, 0).await,
        Err(QidError::BadRequest { .. })
    ));
}

async fn close(repo: AnyRepository) {
    match repo {
        AnyRepository::Sql(repo) => repo.close().await,
        AnyRepository::File(repo) => drop(repo),
    }
}

async fn run(sql: bool) {
    let dir = std::env::temp_dir().join(format!("qid-oidc-continuation-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(if sql { "store.db" } else { "store.json" });
    let url = if sql {
        format!("sqlite:{}", path.display())
    } else {
        path.to_str().unwrap().into()
    };
    let repo = AnyRepository::connect(&url).await.unwrap();
    cleanup_contract(&repo).await;
    contract(&repo).await;
    let pending = record("restart-pending");
    repo.create_oidc_continuation(&pending, 100).await.unwrap();
    close(repo).await;
    let repo = AnyRepository::connect(&url).await.unwrap();
    assert_eq!(consume(&repo, &record("transaction"), 150).await, None);
    assert!(matches!(
        repo.create_oidc_continuation(&record("transaction"), 100)
            .await,
        Err(QidError::Conflict { .. })
    ));
    assert_eq!(consume(&repo, &pending, 150).await, Some(pending));
    close(repo).await;
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn file_continuation_contract() {
    run(false).await;
}
#[tokio::test]
async fn sql_continuation_contract() {
    run(true).await;
}

#[test]
fn continuation_shape_and_debug_redaction() {
    let c = record("redaction");
    let debug = format!("{c:?}");
    assert!(!debug.contains("private-state"));
    assert!(!debug.contains("private-nonce"));
    assert!(!debug.contains("browser_binding"));
    let mut json = serde_json::to_value(&c).unwrap();
    assert_eq!(
        serde_json::from_value::<OidcAuthorizationContinuation>(json.clone()).unwrap(),
        c
    );
    json["dpop_proof"] = "must-not-be-a-field".into();
    assert!(serde_json::from_value::<OidcAuthorizationContinuation>(json.clone()).is_err());
    json.as_object_mut().unwrap().remove("dpop_proof");
    json["browser_binding_sha256"] = serde_json::json!([1, 2]);
    assert!(serde_json::from_value::<OidcAuthorizationContinuation>(json).is_err());
}

#[tokio::test]
async fn file_write_failure_does_not_create_or_consume() {
    let dir = std::env::temp_dir().join(format!("qid-oidc-write-failure-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("store.json");
    let repo = AnyRepository::connect(path.to_str().unwrap())
        .await
        .unwrap();
    let c = record("retry-write");
    // A directory at the temporary-file path produces a bounded, portable write
    // error without permissions tricks or damage to the incumbent store.
    let tmp = path.with_extension("tmp");
    std::fs::create_dir(&tmp).unwrap();
    assert!(repo.create_oidc_continuation(&c, 100).await.is_err());
    std::fs::remove_dir(&tmp).unwrap();
    repo.create_oidc_continuation(&c, 100).await.unwrap();
    std::fs::create_dir(&tmp).unwrap();
    assert!(
        repo.consume_oidc_continuation(
            &RealmId(c.realm_id.clone()),
            &c.user_id,
            &c.client_id,
            &c.id,
            &c.browser_binding_sha256,
            150
        )
        .await
        .is_err()
    );
    std::fs::remove_dir(&tmp).unwrap();
    assert_eq!(consume(&repo, &c, 150).await, Some(c.clone()));
    close(repo).await;
    let repo = AnyRepository::connect(path.to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(consume(&repo, &c, 150).await, None);
    close(repo).await;
    std::fs::remove_dir_all(dir).unwrap();
}
