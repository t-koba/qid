thread_local! {
    static SERVICE_ACCOUNT_PROBE: std::cell::RefCell<Option<ServiceAccountProbe>> = const {
        std::cell::RefCell::new(None)
    };
}

struct ServiceAccountProbe {
    fallback_creates: usize,
    paused: bool,
    reached: Option<tokio::sync::oneshot::Sender<()>>,
    release: Option<tokio::sync::oneshot::Receiver<()>>,
}

struct ServiceAccountProbeGuard;

impl Drop for ServiceAccountProbeGuard {
    fn drop(&mut self) {
        SERVICE_ACCOUNT_PROBE.with(|probe| *probe.borrow_mut() = None);
    }
}

pub(super) struct ObservedServiceAccount<'a, R>(pub &'a R);

impl<R: ServiceAccountRepository> ObservedServiceAccount<'_, R> {
    pub async fn create_service_account(&self, sa: &ServiceAccount) -> QidResult<()> {
        let rendezvous = if sa.id.starts_with("service2:") {
            SERVICE_ACCOUNT_PROBE.with(|probe| {
                probe.borrow_mut().as_mut().and_then(|probe| {
                    probe.fallback_creates += 1;
                    if probe.paused {
                        None
                    } else {
                        probe.paused = true;
                        Some((probe.reached.take(), probe.release.take()))
                    }
                })
            })
        } else {
            None
        };
        if let Some((reached, release)) = rendezvous {
            if let Some(reached) = reached {
                let _ = reached.send(());
            }
            if let Some(release) = release {
                let _ = release.await;
            }
        }
        self.0.create_service_account(sa).await
    }
}

async fn service_account_race_setup() -> (
    Arc<SharedState<FileRepository>>,
    Arc<FileRepository>,
    Client,
    TokenRequest,
    String,
    String,
) {
    let client_id = "same-client";
    let mut config = test_helpers::test_config();
    let mut realm_b = config.realms[0].clone();
    realm_b.id = "realm-b".to_string();
    realm_b.issuer = "https://id.example.com/realms/realm-b".to_string();
    config.realms.push(realm_b);

    let (state, repo) = state_with_config(config).await;
    create_test_realm(&repo, "test", "https://id.example.com").await;
    create_test_realm(
        &repo,
        "realm-b",
        "https://id.example.com/realms/realm-b",
    )
    .await;

    let legacy = ServiceAccount {
        id: format!("service:{client_id}"),
        client_id: client_id.to_string(),
        realm_id: "test".to_string(),
        description: None,
        created_at: util::now_seconds(),
    };
    repo.create_service_account(&legacy).await.unwrap();

    let mut client = refresh_test_client(
        "realm-b-client",
        client_id,
        ClientType::Confidential,
        "client_secret_basic",
    );
    client.realm_id = "realm-b".to_string();
    client.grant_types = vec!["client_credentials".to_string()];
    repo.create_client(&client).await.unwrap();

    let req = TokenRequest {
        grant_type: "client_credentials".to_string(),
        client_id: Some(client_id.to_string()),
        scope: Some("api".to_string()),
        ..Default::default()
    };
    let fallback_id = format!("service2:{}:realm-b:{client_id}", "realm-b".len());
    (state, repo, client, req, legacy.id, fallback_id)
}

#[tokio::test]
async fn concurrent_service_account_fallback_conflict_reuses_winner() {
    let (state, repo, client, req, legacy_id, fallback_id) = service_account_race_setup().await;
    let (reached_tx, mut reached_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    SERVICE_ACCOUNT_PROBE.with(|probe| {
        assert!(probe.borrow().is_none());
        *probe.borrow_mut() = Some(ServiceAccountProbe {
            fallback_creates: 0,
            paused: false,
            reached: Some(reached_tx),
            release: Some(release_rx),
        });
    });
    let _probe_guard = ServiceAccountProbeGuard;

    let mut first = Box::pin(client_credentials_grant(&state, &req, &client, None));
    tokio::select! {
        result = &mut first => {
            let _ = result;
            panic!("first grant completed before reaching fallback create");
        }
        result = &mut reached_rx => result.expect("first grant must reach fallback create"),
    }

    // Let the competing grant create the fallback account and service user
    // before releasing the stale grant to its expected duplicate-ID Conflict.
    let winner = client_credentials_grant(&state, &req, &client, None).await;
    release_tx
        .send(())
        .expect("first grant must still be paused at fallback create");
    let loser = first.await;
    let winner = winner.expect("winner grant should succeed");
    let loser = loser.expect("loser should re-read and reuse the winner account");

    let probe = SERVICE_ACCOUNT_PROBE.with(|probe| probe.borrow_mut().take().unwrap());
    assert!(probe.paused);
    assert_eq!(probe.fallback_creates, 2);

    let winner_claims = state
        .signer
        .decode_signature_only(&winner.access_token)
        .unwrap()
        .claims;
    let loser_claims = state
        .signer
        .decode_signature_only(&loser.access_token)
        .unwrap()
        .claims;
    for claims in [winner_claims, loser_claims] {
        assert_eq!(claims.sub.as_deref(), Some(fallback_id.as_str()));
        assert_eq!(
            claims.iss.as_deref(),
            Some("https://id.example.com/realms/realm-b")
        );
    }
    assert_eq!(
        repo.get_service_account_by_client_id("test", "same-client")
            .await
            .unwrap()
            .unwrap()
            .id,
        legacy_id
    );
    assert_eq!(
        repo.list_service_accounts("realm-b").await.unwrap().len(),
        1
    );
}

#[tokio::test]
async fn unrelated_fallback_id_conflict_is_preserved() {
    let (state, repo, client, req, legacy_id, fallback_id) = service_account_race_setup().await;
    let unrelated = ServiceAccount {
        id: fallback_id.clone(),
        client_id: "unrelated-client".to_string(),
        realm_id: "test".to_string(),
        description: None,
        created_at: util::now_seconds(),
    };
    repo.create_service_account(&unrelated).await.unwrap();

    assert!(matches!(
        client_credentials_grant(&state, &req, &client, None).await,
        Err(QidError::Conflict { .. })
    ));
    assert!(repo
        .get_service_account_by_client_id("realm-b", "same-client")
        .await
        .unwrap()
        .is_none());
    let legacy = repo
        .get_service_account_by_client_id("test", "same-client")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(legacy.id, legacy_id);
    assert!(repo
        .list_service_accounts("test")
        .await
        .unwrap()
        .iter()
        .any(|account| account.id == fallback_id && account.client_id == "unrelated-client"));
}
