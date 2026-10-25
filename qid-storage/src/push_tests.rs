//! Storage tests deliberately supply verification outcomes, not signatures. The
//! service must perform cryptographic verification before requesting transitions.
use crate::{FileRepository, SqlRepository, prelude::*};
use qid_core::{QidError, models::*, tenant::RealmId};

fn registration(id: &str) -> PushRegistrationChallenge {
    PushRegistrationChallenge {
        authenticator: PushAuthenticator {
            id: id.into(),
            realm_id: "realm".into(),
            user_id: "owner".into(),
            destination: "private-provider-destination".into(),
            device_name: "Test Phone".into(),
            device_platform: "android".into(),
            public_jwk: PushPublicJwk::EC {
                crv: "P-256".into(),
                x: "public-x".into(),
                y: "public-y".into(),
            },
            created_at: 100,
            revoked_at: None,
        },
        nonce_verifier: "a".repeat(64),
        expires_at: 200,
        max_attempts: 2,
        attempt_count: 0,
    }
}
fn login(id: &str, auth: &str) -> PushLoginChallenge {
    PushLoginChallenge {
        id: id.into(),
        realm_id: "realm".into(),
        user_id: "owner".into(),
        authenticator_id: auth.into(),
        purpose: PushPurpose::PasswordLogin,
        nonce_verifier: "b".repeat(64),
        browser_binding_verifier: "c".repeat(64),
        resend_admitted_at: Vec::new(),
        created_at: 120,
        expires_at: 190,
        max_attempts: 2,
        attempt_count: 0,
        decision: None,
        decided_at: None,
        consumed_at: None,
    }
}
// Lifecycle fixtures use an explicit 10000-issuance / 86400-second budget.
// Quota tests below use small budgets and assert suppression directly.
async fn seed(repo: &impl FixtureRepository) {
    for r in ["realm", "other"] {
        repo.create_realm(
            &"tenant".into(),
            &r.into(),
            &format!("https://id.example.com/{r}"),
            None,
        )
        .await
        .unwrap();
    }
    for (u, r) in [("owner", "realm"), ("peer", "realm"), ("foreign", "other")] {
        repo.create_user(&User {
            id: u.into(),
            realm_id: r.into(),
            email: None,
            email_verified: false,
            display_name: None,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .unwrap();
    }
}
async fn active(repo: &impl FixtureRepository, id: &str) -> PushRegistrationChallenge {
    let c = registration(id);
    repo.fixture_registration(&c, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    assert!(repo.attempt_push_registration(&c, true, 110).await.unwrap());
    c
}
async fn stored_login(repo: &impl FixtureRepository, c: &PushLoginChallenge) -> PushLoginChallenge {
    repo.get_push_login(&c.realm_id.clone().into(), &c.user_id, &c.id)
        .await
        .unwrap()
        .unwrap()
}

async fn contract(repo: &impl FixtureRepository) {
    seed(repo).await;
    let realm: RealmId = "realm".into();
    // A global registration ID cannot be claimed by two account owners.
    let race_a = registration("owner-race");
    let mut race_b = race_a.clone();
    race_b.authenticator.user_id = "peer".into();
    let (a, b) = tokio::join!(
        repo.fixture_registration(&race_a, 10_000, 86_400),
        repo.fixture_registration(&race_b, 10_000, 86_400)
    );
    let owner_won = matches!(a, Ok(true));
    assert_ne!(owner_won, matches!(b, Ok(true)));
    for result in [a, b] {
        assert!(matches!(result, Ok(true) | Err(QidError::Conflict { .. })));
    }
    assert_eq!(
        repo.get_push_registration(&realm, "owner", "owner-race")
            .await
            .unwrap()
            .is_some(),
        owner_won
    );
    assert_eq!(
        repo.get_push_registration(&realm, "peer", "owner-race")
            .await
            .unwrap()
            .is_some(),
        !owner_won
    );
    let base = registration("device");
    // Shape validation refuses invalid initial state, raw secrets or no cap.
    for i in 0..7 {
        let mut c = base.clone();
        match i {
            0 => c.nonce_verifier = "raw nonce".into(),
            1 => c.max_attempts = 0,
            2 => c.attempt_count = 1,
            3 => c.authenticator.created_at = 0,
            4 => c.authenticator.revoked_at = Some(110),
            5 => c.expires_at = 100,
            _ => c.authenticator.destination.clear(),
        }
        assert!(matches!(
            repo.fixture_registration(&c, 10_000, 86_400)
                .await
                .map(|issued| assert!(issued)),
            Err(QidError::BadRequest { .. })
        ));
    }
    for (r, u) in [
        ("other", "owner"),
        ("realm", "foreign"),
        ("realm", "missing"),
    ] {
        let mut c = base.clone();
        c.authenticator.realm_id = r.into();
        c.authenticator.user_id = u.into();
        assert!(matches!(
            repo.fixture_registration(&c, 10_000, 86_400)
                .await
                .map(|issued| assert!(issued)),
            Err(QidError::Conflict { .. })
        ));
    }
    repo.fixture_registration(&base, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    assert!(
        repo.get_push_authenticator(&realm, "owner", "device")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.list_push_authenticators(&realm, "owner")
            .await
            .unwrap()
            .is_empty()
    );
    // Pending records are never login authority.
    assert!(
        repo.fixture_login(&login("pending", "device"), 10_000, 86_400)
            .await
            .map(|issued| assert!(issued))
            .is_err()
    );
    // A repeated ID cannot replace even the same owner's immutable binding.
    for i in 0..5 {
        let mut c = base.clone();
        match i {
            0 => c.authenticator.destination = "replacement".into(),
            1 => c.authenticator.user_id = "peer".into(),
            2 => c.authenticator.realm_id = "other".into(),
            3 => c.nonce_verifier = "d".repeat(64),
            _ => (),
        }
        assert!(matches!(
            repo.fixture_registration(&c, 10_000, 86_400)
                .await
                .map(|issued| assert!(issued)),
            Err(QidError::Conflict { .. })
        ));
    }
    for (r, u) in [("other", "owner"), ("realm", "peer")] {
        assert!(
            repo.get_push_registration(&r.into(), u, "device")
                .await
                .unwrap()
                .is_none()
        );
    }
    for i in 0..6 {
        let mut c = base.clone();
        match i {
            0 => c.authenticator.destination = "other-destination".into(),
            1 => c.authenticator.user_id = "peer".into(),
            2 => c.authenticator.realm_id = "other".into(),
            3 => c.nonce_verifier = "d".repeat(64),
            4 => {
                c.authenticator.public_jwk = PushPublicJwk::RSA {
                    n: "n".into(),
                    e: "e".into(),
                }
            }
            _ => c.max_attempts += 1,
        }
        assert!(!repo.attempt_push_registration(&c, true, 110).await.unwrap());
    }
    assert!(
        !repo
            .attempt_push_registration(&base, true, 99)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .attempt_push_registration(&base, true, 200)
            .await
            .unwrap()
    );
    // A bad signature counts, but cannot activate a registration.
    assert!(
        repo.attempt_push_registration(&base, false, 110)
            .await
            .unwrap()
    );
    assert!(
        repo.get_push_authenticator(&realm, "owner", "device")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repo.get_push_registration(&realm, "owner", "device")
            .await
            .unwrap()
            .unwrap()
            .attempt_count,
        1
    );
    let (a, b) = tokio::join!(
        repo.attempt_push_registration(&base, true, 111),
        repo.attempt_push_registration(&base, true, 111)
    );
    assert_ne!(a.unwrap(), b.unwrap());
    assert!(
        !repo
            .attempt_push_registration(&base, true, 112)
            .await
            .unwrap()
    );
    // Successful proof replaces the pending row; its verifier is no longer readable.
    assert!(
        repo.get_push_registration(&realm, "owner", "device")
            .await
            .unwrap()
            .is_none()
    );
    let auth = repo
        .get_push_authenticator(&realm, "owner", "device")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(auth.created_at, 111);
    assert_eq!(auth.destination, base.authenticator.destination);
    assert_eq!(auth.public_jwk, base.authenticator.public_jwk);
    for (r, u) in [("other", "owner"), ("realm", "peer")] {
        assert!(
            repo.get_push_authenticator(&r.into(), u, "device")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repo.list_push_authenticators(&r.into(), u)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            !repo
                .revoke_push_authenticator(&r.into(), u, "device", 130)
                .await
                .unwrap()
        );
    }
    // Expired proof remains pending, but never supplies login authority.
    let expired = registration("expired");
    repo.fixture_registration(&expired, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    assert!(
        !repo
            .attempt_push_registration(&expired, true, 200)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .attempt_push_registration(&expired, true, 201)
            .await
            .unwrap()
    );
    assert_eq!(
        repo.get_push_registration(&realm, "owner", "expired")
            .await
            .unwrap(),
        Some(expired)
    );
    assert!(
        repo.get_push_authenticator(&realm, "owner", "expired")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !repo
            .revoke_push_authenticator(&realm, "owner", "expired", 201)
            .await
            .unwrap()
    );
    assert!(
        repo.fixture_login(&login("expired-proof", "expired"), 10_000, 86_400)
            .await
            .map(|issued| assert!(issued))
            .is_err()
    );
    let exhausted = registration("exhausted");
    repo.fixture_registration(&exhausted, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    let (a, b) = tokio::join!(
        repo.attempt_push_registration(&exhausted, false, 110),
        repo.attempt_push_registration(&exhausted, false, 110)
    );
    assert!(a.unwrap() && b.unwrap());
    assert!(
        !repo
            .attempt_push_registration(&exhausted, true, 110)
            .await
            .unwrap()
    );
    assert_eq!(
        repo.get_push_registration(&realm, "owner", "exhausted")
            .await
            .unwrap()
            .unwrap()
            .attempt_count,
        2
    );
    assert!(
        repo.get_push_authenticator(&realm, "owner", "exhausted")
            .await
            .unwrap()
            .is_none()
    );

    let c = login("login", "device");
    for i in 0..8 {
        let mut invalid = c.clone();
        match i {
            0 => invalid.browser_binding_verifier = "raw browser secret".into(),
            1 => invalid.nonce_verifier.clear(),
            2 => invalid.id.clear(),
            3 => invalid.max_attempts = 0,
            4 => invalid.attempt_count = 1,
            5 => invalid.decision = Some(PushDecision::Approve),
            6 => invalid.decided_at = Some(130),
            _ => invalid.consumed_at = Some(140),
        }
        assert!(matches!(
            repo.fixture_login(&invalid, 10_000, 86_400)
                .await
                .map(|issued| assert!(issued)),
            Err(QidError::BadRequest { .. })
        ));
    }
    for i in 0..4 {
        let mut invalid = c.clone();
        match i {
            0 => invalid.realm_id = "other".into(),
            1 => invalid.user_id = "peer".into(),
            2 => invalid.authenticator_id = "missing".into(),
            _ => invalid.created_at = 110,
        }
        assert!(matches!(
            repo.fixture_login(&invalid, 10_000, 86_400)
                .await
                .map(|issued| assert!(issued)),
            Err(QidError::Conflict { .. })
        ));
    }
    repo.fixture_login(&c, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    assert!(
        repo.fixture_login(&c, 10_000, 86_400)
            .await
            .map(|issued| assert!(issued))
            .is_err()
    );
    for (r, u) in [("other", "owner"), ("realm", "peer")] {
        assert!(
            repo.get_push_login(&r.into(), u, "login")
                .await
                .unwrap()
                .is_none()
        );
    }
    for i in 0..9 {
        let mut wrong = c.clone();
        match i {
            0 => wrong.realm_id = "other".into(),
            1 => wrong.user_id = "peer".into(),
            2 => wrong.authenticator_id = "missing".into(),
            3 => wrong.nonce_verifier = "e".repeat(64),
            4 => wrong.browser_binding_verifier = "f".repeat(64),
            5 => wrong.max_attempts += 1,
            6 => wrong.expires_at += 1,
            7 => wrong.created_at += 1,
            _ => wrong.id = "missing".into(),
        }
        assert!(
            !repo
                .attempt_push_login(&wrong, Some(PushDecision::Approve), 130)
                .await
                .unwrap()
        );
        assert!(
            !repo
                .redeem_push_login(&wrong, &c.browser_binding_verifier, 140)
                .await
                .unwrap()
        );
    }
    assert_eq!(stored_login(repo, &c).await, c);
    assert!(
        !repo
            .redeem_push_login(&c, &c.browser_binding_verifier, 130)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .attempt_push_login(&c, Some(PushDecision::Approve), 119)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .attempt_push_login(&c, Some(PushDecision::Approve), 190)
            .await
            .unwrap()
    );
    assert!(repo.attempt_push_login(&c, None, 130).await.unwrap());
    assert_eq!(stored_login(repo, &c).await.decision, None);
    assert!(
        repo.attempt_push_login(&c, Some(PushDecision::Approve), 131)
            .await
            .unwrap()
    );
    assert_eq!(stored_login(repo, &c).await.attempt_count, 2);
    assert!(
        !repo
            .attempt_push_login(&c, Some(PushDecision::Deny), 132)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .redeem_push_login(&c, &"d".repeat(64), 140)
            .await
            .unwrap()
    );
    assert!(!repo.redeem_push_login(&c, "", 140).await.unwrap());
    assert!(
        !repo
            .redeem_push_login(&c, &c.browser_binding_verifier, 130)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .redeem_push_login(&c, &c.browser_binding_verifier, 190)
            .await
            .unwrap()
    );
    let (a, b) = tokio::join!(
        repo.redeem_push_login(&c, &c.browser_binding_verifier, 140),
        repo.redeem_push_login(&c, &c.browser_binding_verifier, 140)
    );
    assert_ne!(a.unwrap(), b.unwrap());
    assert_eq!(stored_login(repo, &c).await.consumed_at, Some(140));
    assert!(
        !repo
            .redeem_push_login(&c, &c.browser_binding_verifier, 141)
            .await
            .unwrap()
    );

    let denied = login("deny", "device");
    repo.fixture_login(&denied, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    assert!(
        repo.attempt_push_login(&denied, Some(PushDecision::Deny), 130)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .redeem_push_login(&denied, &denied.browser_binding_verifier, 140)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .attempt_push_login(&denied, Some(PushDecision::Approve), 140)
            .await
            .unwrap()
    );
    let race = login("decision-race", "device");
    repo.fixture_login(&race, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    let (a, b) = tokio::join!(
        repo.attempt_push_login(&race, Some(PushDecision::Approve), 130),
        repo.attempt_push_login(&race, Some(PushDecision::Deny), 130)
    );
    let approved = a.unwrap();
    assert_ne!(approved, b.unwrap());
    let result = stored_login(repo, &race).await;
    assert_eq!(result.attempt_count, 1);
    assert_eq!(
        result.decision,
        Some(if approved {
            PushDecision::Approve
        } else {
            PushDecision::Deny
        })
    );
    assert_eq!(
        repo.redeem_push_login(&race, &race.browser_binding_verifier, 140)
            .await
            .unwrap(),
        approved
    );
    let capped = login("bad-signature-race", "device");
    repo.fixture_login(&capped, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    let (a, b) = tokio::join!(
        repo.attempt_push_login(&capped, None, 130),
        repo.attempt_push_login(&capped, None, 130)
    );
    assert!(a.unwrap() && b.unwrap());
    assert!(
        !repo
            .attempt_push_login(&capped, Some(PushDecision::Approve), 140)
            .await
            .unwrap()
    );
    let result = stored_login(repo, &capped).await;
    assert_eq!(result.attempt_count, 2);
    assert_eq!(result.decision, None);

    // Revocation invalidates pending decisions and already approved challenges.
    let approved = login("revoked-approval", "device");
    let pending = login("revoked-pending", "device");
    repo.fixture_login(&approved, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    repo.fixture_login(&pending, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    assert!(
        repo.attempt_push_login(&approved, Some(PushDecision::Approve), 130)
            .await
            .unwrap()
    );
    assert!(
        repo.revoke_push_authenticator(&realm, "owner", "device", 135)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .revoke_push_authenticator(&realm, "owner", "device", 136)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .redeem_push_login(&approved, &approved.browser_binding_verifier, 140)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .attempt_push_login(&pending, Some(PushDecision::Approve), 140)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .attempt_push_registration(&base, true, 140)
            .await
            .unwrap()
    );
    assert!(
        repo.fixture_registration(&base, 10_000, 86_400)
            .await
            .map(|issued| assert!(issued))
            .is_err()
    );
    assert!(
        repo.fixture_login(&login("stale", "device"), 10_000, 86_400)
            .await
            .map(|issued| assert!(issued))
            .is_err()
    );
    assert_eq!(
        repo.list_push_authenticators(&realm, "owner")
            .await
            .unwrap()[0]
            .revoked_at,
        Some(135)
    );

    // Competing revocation and redemption serialize on the current authenticator.
    active(repo, "revocation-race").await;
    let c = login("revoke-race", "revocation-race");
    repo.fixture_login(&c, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    assert!(
        repo.attempt_push_login(&c, Some(PushDecision::Approve), 130)
            .await
            .unwrap()
    );
    let (revoked, redeemed) = tokio::join!(
        repo.revoke_push_authenticator(&realm, "owner", "revocation-race", 140),
        repo.redeem_push_login(&c, &c.browser_binding_verifier, 140)
    );
    assert!(revoked.unwrap());
    assert_eq!(
        stored_login(repo, &c).await.consumed_at.is_some(),
        redeemed.unwrap()
    );
    assert!(
        !repo
            .redeem_push_login(&c, &c.browser_binding_verifier, 141)
            .await
            .unwrap()
    );

    active(repo, "decision-revoke-race").await;
    let c = login("decision-revoke-race", "decision-revoke-race");
    repo.fixture_login(&c, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    let (revoked, decided) = tokio::join!(
        repo.revoke_push_authenticator(&realm, "owner", "decision-revoke-race", 140),
        repo.attempt_push_login(&c, Some(PushDecision::Approve), 140)
    );
    assert!(revoked.unwrap());
    assert_eq!(
        stored_login(repo, &c).await.decision.is_some(),
        decided.unwrap()
    );
    assert!(
        !repo
            .attempt_push_login(&c, Some(PushDecision::Approve), 141)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .redeem_push_login(&c, &c.browser_binding_verifier, 141)
            .await
            .unwrap()
    );

    // Creation must not reclaim an ID while its pending proof is activated.
    // Check both same-owner replacement and cross-owner/realm collisions.
    for (r, u) in [("realm", "owner"), ("realm", "peer"), ("other", "foreign")] {
        let id = format!("activation-create-{u}");
        let pending = registration(&id);
        repo.fixture_registration(&pending, 10_000, 86_400)
            .await
            .map(|issued| assert!(issued))
            .unwrap();
        let mut collision = pending.clone();
        collision.authenticator.realm_id = r.into();
        collision.authenticator.user_id = u.into();
        collision.authenticator.destination = "replacement-destination".into();
        collision.nonce_verifier = "d".repeat(64);
        let (activated, created) = tokio::join!(
            repo.attempt_push_registration(&pending, true, 150),
            repo.fixture_registration(&collision, 10_000, 86_400)
        );
        assert!(activated.unwrap());
        assert!(matches!(created, Err(QidError::Conflict { .. })));
        for (realm, user) in [(&realm, "owner"), (&r.into(), u)] {
            assert!(
                repo.get_push_registration(realm, user, &id)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        let mut expected = pending.authenticator.clone();
        expected.created_at = 150;
        assert_eq!(
            repo.get_push_authenticator(&realm, "owner", &id)
                .await
                .unwrap(),
            Some(expected.clone())
        );
        assert_eq!(
            repo.list_push_authenticators(&realm, "owner")
                .await
                .unwrap()
                .into_iter()
                .filter(|a| a.id == id)
                .collect::<Vec<_>>(),
            vec![expected]
        );
        for proof in [&pending, &collision] {
            assert!(
                !repo
                    .attempt_push_registration(proof, true, 151)
                    .await
                    .unwrap()
            );
            assert!(matches!(
                repo.fixture_registration(proof, 10_000, 86_400)
                    .await
                    .map(|issued| assert!(issued)),
                Err(QidError::Conflict { .. })
            ));
        }
    }

    // Activation and revocation use the same row/lock. Revocation either sees
    // pending state (false) or the enrolled row (true); proof can never replay.
    let racing = registration("activation-revoke-race");
    repo.fixture_registration(&racing, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    let (activated, revoked) = tokio::join!(
        repo.attempt_push_registration(&racing, true, 150),
        repo.revoke_push_authenticator(&realm, "owner", "activation-revoke-race", 150)
    );
    assert!(activated.unwrap());
    let row = repo
        .get_push_authenticator(&realm, "owner", "activation-revoke-race")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.revoked_at.is_some(), revoked.unwrap());
    assert!(
        !repo
            .attempt_push_registration(&racing, true, 151)
            .await
            .unwrap()
    );
    assert!(
        repo.get_push_registration(&realm, "owner", "activation-revoke-race")
            .await
            .unwrap()
            .is_none()
    );

    // Deletion cascades pending/enrolled lifecycles and logins, without factor authority.
    repo.delete_user("owner").await.unwrap();
    assert!(
        repo.get_push_registration(&realm, "owner", "device")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.get_push_authenticator(&realm, "owner", "device")
            .await
            .unwrap()
            .is_none()
    );
    for id in ["expired", "exhausted"] {
        assert!(
            repo.get_push_registration(&realm, "owner", id)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert!(
        repo.get_push_login(&realm, "owner", "login")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn file_push_contract() {
    let dir = std::env::temp_dir().join(format!("qid-push-{}", ulid::Ulid::new()));
    let repo = FileRepository::new(dir.join("store.json").to_str().unwrap())
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    contract(&repo).await;
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}
#[tokio::test]
async fn sql_push_contract() {
    let dir = std::env::temp_dir().join(format!("qid-push-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let repo = SqlRepository::connect(&format!("sqlite:{}", dir.join("store.db").display()))
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    contract(&repo).await;
    repo.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn push_debug_omits_sensitive_contents() {
    let r = registration("debug-device");
    let c = login("debug-login", "debug-device");
    let pending = PushAuthenticatorRecord::Pending(r.clone());
    let enrolled = PushAuthenticatorRecord::Enrolled(r.authenticator.clone());
    let debug = format!(
        "{:?} {:?} {:?} {:?} {:?}",
        r.authenticator, r, c, pending, enrolled
    );
    for secret in [
        &r.authenticator.destination,
        &r.nonce_verifier,
        &c.nonce_verifier,
        &c.browser_binding_verifier,
        "public-x",
    ] {
        assert!(!debug.contains(secret));
    }
}

fn assert_enrolled_payload(value: &serde_json::Value) {
    assert_eq!(value["state"], "enrolled");
    let record = value["record"].as_object().unwrap();
    assert_eq!(record.len(), 9); // exactly the PushAuthenticator fields, including device metadata
    for field in [
        "nonce_verifier",
        "expires_at",
        "max_attempts",
        "attempt_count",
        "completed_at",
        "authenticator",
    ] {
        assert!(!record.contains_key(field));
    }
}

async fn prepare_durable(repo: &impl FixtureRepository) {
    let mut r = registration("durable");
    r.authenticator.user_id = "peer".into();
    repo.fixture_registration(&r, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    assert!(repo.attempt_push_registration(&r, true, 110).await.unwrap());
    let mut c = login("durable-login", "durable");
    c.user_id = "peer".into();
    repo.fixture_login(&c, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    assert!(
        repo.attempt_push_login(&c, Some(PushDecision::Approve), 130)
            .await
            .unwrap()
    );
    assert!(
        repo.redeem_push_login(&c, &c.browser_binding_verifier, 140)
            .await
            .unwrap()
    );
    assert!(
        repo.revoke_push_authenticator(&"realm".into(), "peer", "durable", 150)
            .await
            .unwrap()
    );
}
async fn check_durable(repo: &impl FixtureRepository) {
    let realm = "realm".into();
    assert!(
        repo.get_push_registration(&realm, "peer", "durable")
            .await
            .unwrap()
            .is_none()
    );
    let mut r = registration("durable");
    r.authenticator.user_id = "peer".into();
    let a = repo
        .get_push_authenticator(&realm, "peer", "durable")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.created_at, 110);
    assert_eq!(a.revoked_at, Some(150));
    let c = repo
        .get_push_login(&realm, "peer", "durable-login")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(c.consumed_at, Some(140));
    assert!(!repo.attempt_push_registration(&r, true, 160).await.unwrap());
    assert!(
        !repo
            .redeem_push_login(&c, &c.browser_binding_verifier, 160)
            .await
            .unwrap()
    );
}

#[test]
fn file_push_immediate_durability_and_failure_rollback_in_interval_mode() {
    let dir = std::env::temp_dir().join(format!("qid-push-{}", ulid::Ulid::new()));
    let path = dir.join("store.json");
    let tmp = path.with_extension("tmp");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let repo = FileRepository::new_with_flush_mode(
            path.to_str().unwrap(),
            crate::FileFlushMode::Interval(std::time::Duration::from_secs(3600)),
        )
        .await
        .unwrap();
        repo.migrate().await.unwrap();
        seed(&repo).await;
        let r = registration("rollback");
        repo.fixture_registration(&r, 10_000, 86_400)
            .await
            .map(|issued| assert!(issued))
            .unwrap();
        let disk = std::fs::read(&path).unwrap();
        std::fs::create_dir(&tmp).unwrap();
        for verified in [false, true] {
            assert!(
                repo.attempt_push_registration(&r, verified, 110)
                    .await
                    .is_err()
            );
            assert_eq!(
                repo.get_push_registration(&"realm".into(), "owner", "rollback")
                    .await
                    .unwrap(),
                Some(r.clone())
            );
            assert!(
                repo.get_push_authenticator(&"realm".into(), "owner", "rollback")
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(std::fs::read(&path).unwrap(), disk);
        }
        std::fs::remove_dir(&tmp).unwrap();
        assert!(repo.attempt_push_registration(&r, true, 110).await.unwrap());
        let c = login("rollback-login", "rollback");
        repo.fixture_login(&c, 10_000, 86_400)
            .await
            .map(|issued| assert!(issued))
            .unwrap();
        let disk = std::fs::read(&path).unwrap();
        std::fs::create_dir(&tmp).unwrap();
        assert!(
            repo.attempt_push_login(&c, Some(PushDecision::Approve), 130)
                .await
                .is_err()
        );
        assert_eq!(stored_login(&repo, &c).await, c);
        assert_eq!(std::fs::read(&path).unwrap(), disk);
        std::fs::remove_dir(&tmp).unwrap();
        assert!(
            repo.attempt_push_login(&c, Some(PushDecision::Approve), 130)
                .await
                .unwrap()
        );
        let approved = stored_login(&repo, &c).await;
        let disk = std::fs::read(&path).unwrap();
        std::fs::create_dir(&tmp).unwrap();
        assert!(
            repo.redeem_push_login(&c, &c.browser_binding_verifier, 140)
                .await
                .is_err()
        );
        assert!(
            repo.revoke_push_authenticator(&"realm".into(), "owner", "rollback", 140)
                .await
                .is_err()
        );
        assert_eq!(stored_login(&repo, &c).await, approved);
        assert_eq!(
            repo.get_push_authenticator(&"realm".into(), "owner", "rollback")
                .await
                .unwrap()
                .unwrap()
                .revoked_at,
            None
        );
        assert_eq!(std::fs::read(&path).unwrap(), disk);
        std::fs::remove_dir(&tmp).unwrap();
        let disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(disk["push"].get("registrations").is_none());
        assert_enrolled_payload(&disk["push"]["authenticators"]["rollback"]);
        prepare_durable(&repo).await;
    });
    drop(runtime); // release the interval worker/file lock, including on Windows
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let reopened = FileRepository::new(path.to_str().unwrap()).await.unwrap();
        check_durable(&reopened).await;
    });
    drop(runtime);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn sql_push_activation_failure_rolls_back_and_state_survives_reopen() {
    let dir = std::env::temp_dir().join(format!("qid-push-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite:{}", dir.join("store.db").display());
    let repo = SqlRepository::connect(&url).await.unwrap();
    repo.migrate().await.unwrap();
    seed(&repo).await;
    let r = registration("rollback");
    repo.fixture_registration(&r, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    let pool = sqlx::AnyPool::connect(&url).await.unwrap();
    // Fail the lifecycle replacement. Pending proof state must remain unchanged.
    sqlx::query("CREATE TRIGGER fail_registration BEFORE UPDATE ON push_authenticators WHEN NEW.record_json <> OLD.record_json BEGIN SELECT RAISE(ABORT, 'injected error'); END").execute(&pool).await.unwrap();
    assert!(repo.attempt_push_registration(&r, true, 110).await.is_err());
    assert!(
        repo.get_push_authenticator(&"realm".into(), "owner", "rollback")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repo.get_push_registration(&"realm".into(), "owner", "rollback")
            .await
            .unwrap(),
        Some(r)
    );
    sqlx::query("DROP TRIGGER fail_registration")
        .execute(&pool)
        .await
        .unwrap();
    prepare_durable(&repo).await;
    let persisted: String =
        sqlx::query_scalar("SELECT record_json FROM push_authenticators WHERE id = 'durable'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_enrolled_payload(&serde_json::from_str(&persisted).unwrap());
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM push_authenticators WHERE id = 'durable'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rows, 1);
    let old_tables: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'push_registrations'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(old_tables, 0);
    pool.close().await;
    repo.close().await;
    let reopened = SqlRepository::connect(&url).await.unwrap();
    check_durable(&reopened).await;
    reopened.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn malformed_file_push_records_fail_closed() {
    let dir = std::env::temp_dir().join(format!("qid-push-corrupt-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("store.json");
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    repo.migrate().await.unwrap();
    seed(&repo).await;
    active(&repo, "device").await;
    let challenge = login("login", "device");
    repo.fixture_login(&challenge, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    let pending = registration("pending-corrupt");
    repo.fixture_registration(&pending, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    drop(repo);

    let mut store: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    store["push"]["authenticators"]["device"]["record"]["id"] = serde_json::json!("mismatched-id");
    store["push"]["logins"]["login"]["decision"] = serde_json::json!("approve");
    store["push"]["logins"]["login"]["decided_at"] = serde_json::json!(130);
    store["push"]["logins"]["login"]["attempt_count"] = serde_json::json!(0);
    store["push"]["authenticators"]["pending-corrupt"]["record"]["attempt_count"] =
        serde_json::json!(3);
    std::fs::write(&path, serde_json::to_vec(&store).unwrap()).unwrap();

    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    assert!(matches!(
        repo.get_push_authenticator(&"realm".into(), "owner", "device")
            .await,
        Err(QidError::Internal { .. })
    ));
    assert!(matches!(
        repo.get_push_login(&"realm".into(), "owner", "login").await,
        Err(QidError::Internal { .. })
    ));
    assert_corrupt_pending(&repo, &pending).await;
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn malformed_sql_push_records_fail_closed() {
    let dir = std::env::temp_dir().join(format!("qid-push-corrupt-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite:{}", dir.join("store.db").display());
    let repo = SqlRepository::connect(&url).await.unwrap();
    repo.migrate().await.unwrap();
    seed(&repo).await;
    active(&repo, "device").await;
    let challenge = login("login", "device");
    repo.fixture_login(&challenge, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    let pending = registration("pending-corrupt");
    repo.fixture_registration(&pending, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    let pool = sqlx::AnyPool::connect(&url).await.unwrap();

    let auth_json: String =
        sqlx::query_scalar("SELECT record_json FROM push_authenticators WHERE id = 'device'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut auth: serde_json::Value = serde_json::from_str(&auth_json).unwrap();
    auth["record"]["realm_id"] = serde_json::json!("other");
    sqlx::query("UPDATE push_authenticators SET record_json = $1 WHERE id = 'device'")
        .bind(auth.to_string())
        .execute(&pool)
        .await
        .unwrap();

    let login_json: String =
        sqlx::query_scalar("SELECT record_json FROM push_login_challenges WHERE id = 'login'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut login_record: serde_json::Value = serde_json::from_str(&login_json).unwrap();
    login_record["decision"] = serde_json::json!("approve");
    login_record["decided_at"] = serde_json::json!(130);
    login_record["attempt_count"] = serde_json::json!(0);
    sqlx::query("UPDATE push_login_challenges SET record_json = $1 WHERE id = 'login'")
        .bind(login_record.to_string())
        .execute(&pool)
        .await
        .unwrap();
    let mut bad_pending = pending.clone();
    bad_pending.attempt_count = 3;
    sqlx::query("UPDATE push_authenticators SET record_json = $1 WHERE id = 'pending-corrupt'")
        .bind(serde_json::to_string(&PushAuthenticatorRecord::Pending(bad_pending)).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    assert!(matches!(
        repo.get_push_authenticator(&"realm".into(), "owner", "device")
            .await,
        Err(QidError::Internal { .. })
    ));
    assert!(matches!(
        repo.get_push_login(&"realm".into(), "owner", "login").await,
        Err(QidError::Internal { .. })
    ));
    assert_corrupt_pending(&repo, &pending).await;
    repo.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}

async fn assert_corrupt_pending(
    repo: &impl FixtureRepository,
    pending: &PushRegistrationChallenge,
) {
    let realm = "realm".into();
    assert!(matches!(
        repo.get_push_registration(&realm, "owner", "pending-corrupt")
            .await,
        Err(QidError::Internal { .. })
    ));
    assert!(matches!(
        repo.get_push_authenticator(&realm, "owner", "pending-corrupt")
            .await,
        Err(QidError::Internal { .. })
    ));
    assert!(matches!(
        repo.list_push_authenticators(&realm, "owner").await,
        Err(QidError::Internal { .. })
    ));
    assert!(matches!(
        repo.attempt_push_registration(pending, true, 110).await,
        Err(QidError::Internal { .. })
    ));
    assert!(matches!(
        repo.revoke_push_authenticator(&realm, "owner", "pending-corrupt", 110)
            .await,
        Err(QidError::Internal { .. })
    ));
    assert!(matches!(
        repo.fixture_login(&login("corrupt-proof", "pending-corrupt"), 10_000, 86_400)
            .await
            .map(|issued| assert!(issued)),
        Err(QidError::Internal { .. })
    ));
}

fn quota_registration_in(
    realm: &str,
    id: &str,
    user: &str,
    created: u64,
    expires: u64,
) -> PushRegistrationChallenge {
    let mut c = registration(id);
    c.authenticator.realm_id = realm.into();
    c.authenticator.user_id = user.into();
    c.authenticator.created_at = created;
    c.expires_at = expires;
    c
}
fn quota_registration(
    id: &str,
    user: &str,
    created: u64,
    expires: u64,
) -> PushRegistrationChallenge {
    quota_registration_in("realm", id, user, created, expires)
}
fn quota_login_in(
    realm: &str,
    id: &str,
    auth: &str,
    user: &str,
    created: u64,
    expires: u64,
) -> PushLoginChallenge {
    let mut c = login(id, auth);
    c.realm_id = realm.into();
    c.user_id = user.into();
    c.created_at = created;
    c.expires_at = expires;
    c
}
fn quota_login(id: &str, auth: &str, user: &str, created: u64, expires: u64) -> PushLoginChallenge {
    quota_login_in("realm", id, auth, user, created, expires)
}
async fn enroll_in(repo: &impl FixtureRepository, realm: &str, id: &str, user: &str, created: u64) {
    let c = quota_registration_in(realm, id, user, created, created + 10_000);
    repo.fixture_registration(&c, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    assert!(
        repo.attempt_push_registration(&c, true, created + 10)
            .await
            .unwrap()
    );
}
async fn enroll(repo: &impl FixtureRepository, id: &str, user: &str, created: u64) {
    enroll_in(repo, "realm", id, user, created).await;
}

async fn quota_cleanup_contract(repo: &impl FixtureRepository) {
    seed(repo).await;
    let realm: RealmId = "realm".into();
    let other: RealmId = "other".into();
    let now = 200_000u64; // retention cutoff: 113_600

    // Cleanup runs first on an isolated owner so later quota windows stay exact.
    // Deletes only expired rows issued strictly before the cutoff.
    repo.fixture_registration(
        &quota_registration_in("other", "qc-old", "foreign", 1_000, 2_000),
        10_000,
        86_400,
    )
    .await
    .map(|issued| assert!(issued))
    .unwrap();
    repo.fixture_registration(
        &quota_registration_in("other", "qc-edge", "foreign", 113_600, 113_700),
        10_000,
        86_400,
    )
    .await
    .map(|issued| assert!(issued))
    .unwrap();
    let old_auth = quota_registration_in("other", "qc-enrolled", "foreign", 1_000, 50_000);
    repo.fixture_registration(&old_auth, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    assert!(
        repo.attempt_push_registration(&old_auth, true, 1_100)
            .await
            .unwrap()
    );
    assert!(
        repo.revoke_push_authenticator(&other, "foreign", "qc-enrolled", 1_200)
            .await
            .unwrap()
    );
    repo.fixture_registration(
        &quota_registration_in("other", "qc-fresh", "foreign", 199_000, 300_000),
        10_000,
        86_400,
    )
    .await
    .map(|issued| assert!(issued))
    .unwrap();
    enroll_in(repo, "other", "qc-dev", "foreign", 1_000).await;
    let ql1 = quota_login_in("other", "qc-login-1", "qc-dev", "foreign", 1_200, 1_300);
    repo.fixture_login(&ql1, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    let ql2 = quota_login_in("other", "qc-login-2", "qc-dev", "foreign", 1_400, 1_500);
    repo.fixture_login(&ql2, 10_000, 86_400)
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    assert!(
        repo.attempt_push_login(&ql2, Some(PushDecision::Approve), 1_450)
            .await
            .unwrap()
    );
    assert!(
        repo.redeem_push_login(&ql2, &ql2.browser_binding_verifier, 1_460)
            .await
            .unwrap()
    );
    assert_eq!(
        repo.cleanup_expired_push_records(now, 100).await.unwrap(),
        3
    );
    assert!(
        repo.get_push_registration(&other, "foreign", "qc-old")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.get_push_login(&other, "foreign", "qc-login-1")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.get_push_login(&other, "foreign", "qc-login-2")
            .await
            .unwrap()
            .is_none()
    );
    // Boundary issuance, enrolled/revoked rows, unexpired rows and the device
    // that authorized the deleted logins all survive.
    assert!(
        repo.get_push_registration(&other, "foreign", "qc-edge")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        repo.get_push_registration(&other, "foreign", "qc-fresh")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        repo.get_push_authenticator(&other, "foreign", "qc-enrolled")
            .await
            .unwrap()
            .unwrap()
            .revoked_at,
        Some(1_200)
    );
    assert!(
        repo.get_push_authenticator(&other, "foreign", "qc-dev")
            .await
            .unwrap()
            .is_some()
    );

    // Registration quota boundary: the third issuance in the window is suppressed
    // without writing, while IDs and accounts stay conflicts, never suppression.
    let r1 = quota_registration("qr-1", "owner", 10_000, 20_000);
    let r2 = quota_registration("qr-2", "owner", 10_010, 20_000);
    let r3 = quota_registration("qr-3", "owner", 10_020, 20_000);
    assert!(repo.fixture_registration(&r1, 2, 60).await.unwrap());
    assert!(repo.fixture_registration(&r2, 2, 60).await.unwrap());
    assert!(!repo.fixture_registration(&r3, 2, 60).await.unwrap());
    assert!(
        repo.get_push_registration(&realm, "owner", "qr-3")
            .await
            .unwrap()
            .is_none()
    );
    let mut dup = r1.clone();
    dup.authenticator.destination = "replacement".into();
    assert!(matches!(
        repo.fixture_registration(&dup, 2, 60).await,
        Err(QidError::Conflict { .. })
    ));
    assert!(matches!(
        repo.fixture_registration(
            &quota_registration("qr-ghost", "missing", 10_030, 20_000),
            2,
            60
        )
        .await,
        Err(QidError::Conflict { .. })
    ));
    // Owner isolation: another user has a separate budget.
    assert!(
        repo.fixture_registration(
            &quota_registration("qr-peer-1", "peer", 10_010, 20_000),
            1,
            60
        )
        .await
        .unwrap()
    );

    // A consumed issuance still counts against the budget while retained.
    enroll(repo, "qd-3", "owner", 4_900).await;
    let consumed = quota_login("ql-consumed", "qd-3", "owner", 5_000, 5_600);
    assert!(repo.fixture_login(&consumed, 1, 10_000).await.unwrap());
    assert!(
        repo.attempt_push_login(&consumed, Some(PushDecision::Approve), 5_400)
            .await
            .unwrap()
    );
    assert!(
        repo.redeem_push_login(&consumed, &consumed.browser_binding_verifier, 5_500)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .fixture_login(
                &quota_login("ql-after-consume", "qd-3", "owner", 5_500, 6_100),
                1,
                10_000
            )
            .await
            .unwrap()
    );

    // Login quota: one password success shares its budget across devices, and
    // registration issuance never consumes it.
    enroll(repo, "qd-1", "owner", 9_000).await;
    enroll(repo, "qd-2", "owner", 9_000).await;
    enroll(repo, "qp-1", "peer", 9_000).await;
    let l1 = quota_login("ql-1", "qd-1", "owner", 10_000, 10_600);
    assert!(repo.fixture_login(&l1, 1, 60).await.unwrap());
    assert!(
        !repo
            .fixture_login(&quota_login("ql-2", "qd-2", "owner", 10_010, 10_610), 1, 60)
            .await
            .unwrap()
    );
    assert!(
        repo.get_push_login(&realm, "owner", "ql-2")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.fixture_login(
            &quota_login("ql-peer-1", "qp-1", "peer", 10_010, 10_610),
            1,
            60
        )
        .await
        .unwrap()
    );
    // Purpose isolation: the peer login above does not consume the peer
    // registration budget, and vice versa.
    assert!(
        repo.fixture_registration(
            &quota_registration("qr-peer-2", "peer", 11_010, 20_000),
            1,
            60
        )
        .await
        .unwrap()
    );
    assert!(
        !repo
            .fixture_login(
                &quota_login("ql-peer-2", "qp-1", "peer", 10_020, 10_620),
                1,
                60
            )
            .await
            .unwrap()
    );

    // Expired undecided (delivery-failed) and denied issuance still counts.
    // The isolated owner has no other logins, so suppression is exact.
    enroll_in(repo, "other", "qf-4", "foreign", 90).await;
    assert!(
        repo.fixture_login(
            &quota_login_in("other", "ql-expired", "qf-4", "foreign", 100, 150),
            1,
            60
        )
        .await
        .unwrap()
    );
    assert!(
        !repo
            .fixture_login(
                &quota_login_in("other", "ql-after-expiry", "qf-4", "foreign", 200, 800),
                1,
                101
            )
            .await
            .unwrap()
    );
    enroll_in(repo, "other", "qf-5", "foreign", 290).await;
    let denied = quota_login_in("other", "ql-denied", "qf-5", "foreign", 300, 900);
    assert!(repo.fixture_login(&denied, 1, 60).await.unwrap());
    assert!(
        repo.attempt_push_login(&denied, Some(PushDecision::Deny), 400)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .fixture_login(
                &quota_login_in("other", "ql-after-deny", "qf-5", "foreign", 500, 1100),
                1,
                201
            )
            .await
            .unwrap()
    );

    // Admission race: exactly the budget is admitted, the rest is suppressed.
    let c0 = quota_registration("qrace-0", "owner", 30_000, 60_000);
    let c1 = quota_registration("qrace-1", "owner", 30_001, 60_000);
    let c2 = quota_registration("qrace-2", "owner", 30_002, 60_000);
    let c3 = quota_registration("qrace-3", "owner", 30_003, 60_000);
    let c4 = quota_registration("qrace-4", "owner", 30_004, 60_000);
    let (a, b, c, d, e) = tokio::join!(
        repo.fixture_registration(&c0, 2, 60),
        repo.fixture_registration(&c1, 2, 60),
        repo.fixture_registration(&c2, 2, 60),
        repo.fixture_registration(&c3, 2, 60),
        repo.fixture_registration(&c4, 2, 60)
    );
    assert_eq!(
        [a, b, c, d, e]
            .into_iter()
            .map(|r| r.unwrap())
            .filter(|admitted| *admitted)
            .count(),
        2
    );
    assert!(
        !repo
            .fixture_registration(
                &quota_registration("qrace-5", "owner", 30_005, 60_000),
                2,
                60
            )
            .await
            .unwrap()
    );

    // Activation preserves the original issuance time for quota accounting.
    let ra = quota_registration("qact-a", "owner", 50_000, 90_000);
    assert!(repo.fixture_registration(&ra, 1, 100).await.unwrap());
    assert!(
        repo.attempt_push_registration(&ra, true, 50_090)
            .await
            .unwrap()
    );
    assert!(
        repo.fixture_registration(
            &quota_registration("qact-b", "owner", 50_100, 90_000),
            1,
            100
        )
        .await
        .unwrap()
    );
    assert!(
        !repo
            .fixture_registration(
                &quota_registration("qact-c", "owner", 50_101, 90_000),
                1,
                100
            )
            .await
            .unwrap()
    );
    let pa = quota_registration("qact-peer-a", "peer", 60_000, 90_000);
    assert!(repo.fixture_registration(&pa, 1, 100).await.unwrap());
    assert!(
        repo.attempt_push_registration(&pa, true, 60_010)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .fixture_registration(
                &quota_registration("qact-peer-b", "peer", 60_020, 90_000),
                1,
                100
            )
            .await
            .unwrap()
    );

    // Cleanup/admission interaction: every retained countable row is deleted at
    // once, then the surviving window still suppresses until it slides.
    // Pending regs qr-1, qr-2, two race winners, qact-b, qr-peer-1, qr-peer-2
    // plus logins l1, ql-consumed, ql-peer-1, ql-expired and ql-denied: 12 rows.
    assert_eq!(
        repo.cleanup_expired_push_records(now, 100).await.unwrap(),
        12
    );
    let recent = quota_registration("qc-recent", "peer", 199_000, 300_000);
    assert!(repo.fixture_registration(&recent, 1, 86_400).await.unwrap());
    assert_eq!(
        repo.cleanup_expired_push_records(now, 100).await.unwrap(),
        0
    );
    assert!(
        !repo
            .fixture_registration(
                &quota_registration("qc-recent-x", "peer", 199_500, 300_000),
                1,
                86_400
            )
            .await
            .unwrap()
    );
    assert!(
        repo.fixture_registration(
            &quota_registration("qc-recent-y", "peer", 300_000, 400_000),
            1,
            86_400
        )
        .await
        .unwrap()
    );

    // The per-call bound deletes oldest-first across both tables.
    for i in 0..3 {
        repo.fixture_registration(
            &quota_registration(&format!("qc-bulk-{i}"), "owner", 2_000 + i, 3_000),
            10_000,
            86_400,
        )
        .await
        .map(|issued| assert!(issued))
        .unwrap();
    }
    assert_eq!(repo.cleanup_expired_push_records(now, 2).await.unwrap(), 2);
    assert_eq!(repo.cleanup_expired_push_records(now, 2).await.unwrap(), 1);
    assert_eq!(repo.cleanup_expired_push_records(now, 2).await.unwrap(), 0);

    // Invalid budgets and timestamps fail closed, never suppress.
    let bad = quota_registration("qc-bad", "owner", 10_000, 20_000);
    let bad_login = quota_login("qc-bad-login", "qd-1", "owner", 10_000, 10_600);
    for (max, window) in [(0, 60), (1, 0), (1, 86_401)] {
        assert!(matches!(
            repo.fixture_registration(&bad, max, window).await,
            Err(QidError::BadRequest { .. })
        ));
        assert!(matches!(
            repo.fixture_login(&bad_login, max, window).await,
            Err(QidError::BadRequest { .. })
        ));
    }
    let mut huge = bad.clone();
    huge.authenticator.created_at = u64::MAX;
    assert!(matches!(
        repo.fixture_registration(&huge, 1, 60).await,
        Err(QidError::BadRequest { .. })
    ));
    assert!(matches!(
        repo.cleanup_expired_push_records(now, 0).await,
        Err(QidError::BadRequest { .. })
    ));
    for limit in [1001, u32::MAX] {
        assert!(matches!(
            repo.cleanup_expired_push_records(now, limit).await,
            Err(QidError::BadRequest { .. })
        ));
    }
    assert!(matches!(
        repo.cleanup_expired_push_records(u64::MAX, 10).await,
        Err(QidError::BadRequest { .. })
    ));
}

#[tokio::test]
async fn file_push_quota_cleanup_contract() {
    let dir = std::env::temp_dir().join(format!("qid-push-quota-{}", ulid::Ulid::new()));
    let repo = FileRepository::new(dir.join("store.json").to_str().unwrap())
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    quota_cleanup_contract(&repo).await;
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}
#[tokio::test]
async fn sql_push_quota_cleanup_contract() {
    let dir = std::env::temp_dir().join(format!("qid-push-quota-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let repo = SqlRepository::connect(&format!("sqlite:{}", dir.join("store.db").display()))
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    quota_cleanup_contract(&repo).await;
    repo.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}

// Deterministic ordering of the two competing transitions: cleanup first makes
// proof impossible; activation first removes cleanup eligibility, even for an
// issuance old enough that an unchanged pending row would have been deleted.
async fn cleanup_activation_contract(repo: &impl FixtureRepository) {
    seed(repo).await;
    let realm = "realm".into();
    let now = 200_000;
    let deleted = quota_registration("cleanup-first", "owner", 1000, 2000);
    assert!(
        repo.fixture_registration(&deleted, 10, 86400)
            .await
            .unwrap()
    );
    assert_eq!(repo.cleanup_expired_push_records(now, 1).await.unwrap(), 1);
    assert!(
        !repo
            .attempt_push_registration(&deleted, true, 1500)
            .await
            .unwrap()
    );

    let activated = quota_registration("activate-first", "owner", 1000, 2000);
    assert!(
        repo.fixture_registration(&activated, 10, 86400)
            .await
            .unwrap()
    );
    assert!(
        repo.attempt_push_registration(&activated, true, 1500)
            .await
            .unwrap()
    );
    assert_eq!(repo.cleanup_expired_push_records(now, 1).await.unwrap(), 0);
    assert!(
        repo.get_push_authenticator(&realm, "owner", "activate-first")
            .await
            .unwrap()
            .is_some()
    );

    // Also exercise overlapping calls without relying on task scheduling or
    // sleeps. Whichever obtains the write lock first determines the only valid
    // outcome: deleted and unactivatable, or enrolled and undeletable.
    let racing = quota_registration("cleanup-race", "owner", 1000, 2000);
    assert!(repo.fixture_registration(&racing, 10, 86400).await.unwrap());
    let (activated, deleted) = tokio::join!(
        repo.attempt_push_registration(&racing, true, 1500),
        repo.cleanup_expired_push_records(now, 1),
    );
    let activated = activated.unwrap();
    assert_eq!(deleted.unwrap(), u64::from(!activated));
    assert_eq!(
        repo.get_push_authenticator(&realm, "owner", "cleanup-race")
            .await
            .unwrap()
            .is_some(),
        activated
    );

    // Original registration issuance and immutable login expiry each retain
    // equality at the retention cutoff. Live rows also remain. The live login
    // and boundary registration still suppress concurrent owner-wide issuance.
    for c in [
        quota_registration("old-live", "owner", 1000, 300_000),
        quota_registration("retention-edge", "owner", 113_600, 113_700),
    ] {
        assert!(repo.fixture_registration(&c, 10, 86400).await.unwrap());
    }
    for c in [
        quota_login(
            "old-live-login",
            "activate-first",
            "owner",
            now - 100,
            now + 100,
        ),
        quota_login(
            "retention-edge-login",
            "activate-first",
            "owner",
            113_500,
            113_600,
        ),
    ] {
        assert!(repo.fixture_login(&c, 10, 86400).await.unwrap());
    }
    assert_eq!(
        repo.cleanup_expired_push_records(now, 1000).await.unwrap(),
        0
    );
    assert!(
        !repo
            .fixture_registration(
                &quota_registration("edge-suppressed", "owner", now - 1, now + 100),
                1,
                86400
            )
            .await
            .unwrap()
    );
    assert!(
        !repo
            .fixture_login(
                &quota_login(
                    "edge-suppressed-login",
                    "activate-first",
                    "owner",
                    now - 1,
                    now + 100
                ),
                1,
                86400
            )
            .await
            .unwrap()
    );
    assert_eq!(
        repo.cleanup_expired_push_records(now + 1, 1000)
            .await
            .unwrap(),
        2
    );
    assert!(
        repo.get_push_registration(&realm, "owner", "old-live")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        repo.get_push_login(&realm, "owner", "old-live-login")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        repo.revoke_push_authenticator(&realm, "owner", "activate-first", 1600)
            .await
            .unwrap()
    );
    assert_eq!(
        repo.cleanup_expired_push_records(now, 1000).await.unwrap(),
        0
    );
    assert_eq!(
        repo.get_push_authenticator(&realm, "owner", "activate-first")
            .await
            .unwrap()
            .unwrap()
            .revoked_at,
        Some(1600)
    );
}

#[tokio::test]
async fn file_cleanup_activation_and_retention_guards() {
    let dir = std::env::temp_dir().join(format!("qid-push-guards-{}", ulid::Ulid::new()));
    let repo = FileRepository::new(dir.join("store.json").to_str().unwrap())
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    cleanup_activation_contract(&repo).await;
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn sql_cleanup_activation_and_retention_guards() {
    let dir = std::env::temp_dir().join(format!("qid-push-guards-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite:{}", dir.join("store.db").display());
    let repo = SqlRepository::connect(&url).await.unwrap();
    repo.migrate().await.unwrap();
    cleanup_activation_contract(&repo).await;
    repo.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn sql_push_expiry_metadata_mirrors_lifecycle_and_fails_closed() {
    let dir = std::env::temp_dir().join(format!("qid-push-metadata-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite:{}", dir.join("store.db").display());
    let repo = SqlRepository::connect(&url).await.unwrap();
    repo.migrate().await.unwrap();
    seed(&repo).await;
    let c = registration("metadata");
    assert!(repo.fixture_registration(&c, 1, 60).await.unwrap());
    let pool = sqlx::AnyPool::connect(&url).await.unwrap();
    let pending: Option<i64> = sqlx::query_scalar(
        "SELECT pending_expires_at FROM push_authenticators WHERE id = 'metadata'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pending, Some(c.expires_at as i64));
    sqlx::query("UPDATE push_authenticators SET pending_expires_at = pending_expires_at + 1 WHERE id = 'metadata'").execute(&pool).await.unwrap();
    assert!(matches!(
        repo.get_push_registration(&"realm".into(), "owner", "metadata")
            .await,
        Err(QidError::Internal { .. })
    ));
    sqlx::query("UPDATE push_authenticators SET pending_expires_at = $1 WHERE id = 'metadata'")
        .bind(c.expires_at as i64)
        .execute(&pool)
        .await
        .unwrap();
    assert!(repo.attempt_push_registration(&c, true, 110).await.unwrap());
    let pending: Option<i64> = sqlx::query_scalar(
        "SELECT pending_expires_at FROM push_authenticators WHERE id = 'metadata'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pending, None);
    let login = login("metadata-login", "metadata");
    assert!(repo.fixture_login(&login, 1, 60).await.unwrap());
    let expiry: i64 = sqlx::query_scalar(
        "SELECT expires_at FROM push_login_challenges WHERE id = 'metadata-login'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(expiry, login.expires_at as i64);
    sqlx::query(
        "UPDATE push_login_challenges SET expires_at = expires_at + 1 WHERE id = 'metadata-login'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        repo.get_push_login(&"realm".into(), "owner", "metadata-login")
            .await,
        Err(QidError::Internal { .. })
    ));
    pool.close().await;
    repo.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}

#[async_trait::async_trait]
trait FixtureRepository: Repository {
    async fn resend_at(
        &self,
        c: &PushLoginChallenge,
        nonce: &str,
        cooldown: u64,
        max: u32,
        window: u64,
        at: u64,
    ) -> qid_core::QidResult<bool> {
        self.fixture_resend(
            c,
            &c.browser_binding_verifier,
            nonce,
            max,
            window,
            cooldown,
            at,
        )
        .await
        .map(|row| row.is_some())
    }
    #[allow(clippy::too_many_arguments)]
    async fn fixture_resend(
        &self,
        c: &PushLoginChallenge,
        binding: &str,
        nonce: &str,
        max: u32,
        window: u64,
        cooldown: u64,
        at: u64,
    ) -> qid_core::QidResult<Option<PushLoginChallenge>>;

    async fn registration_at(
        &self,
        c: &PushRegistrationChallenge,
        max: u32,
        at: u64,
    ) -> qid_core::QidResult<bool>;
    async fn login_at(
        &self,
        c: &PushLoginChallenge,
        max: u32,
        at: u64,
    ) -> qid_core::QidResult<bool>;
    async fn fixture_registration(
        &self,
        c: &PushRegistrationChallenge,
        max: u32,
        window: u64,
    ) -> qid_core::QidResult<bool>;
    async fn fixture_login(
        &self,
        c: &PushLoginChallenge,
        max: u32,
        window: u64,
    ) -> qid_core::QidResult<bool>;
}
macro_rules! fixture_repo {
    ($repo:ty) => {
        #[async_trait::async_trait]
        impl FixtureRepository for $repo {
            async fn fixture_resend(
                &self,
                c: &PushLoginChallenge,
                binding: &str,
                nonce: &str,
                max: u32,
                window: u64,
                cooldown: u64,
                at: u64,
            ) -> qid_core::QidResult<Option<PushLoginChallenge>> {
                self.resend_push_login(
                    c,
                    binding,
                    nonce,
                    max,
                    window,
                    cooldown,
                    crate::push::AdmissionClock::at(at),
                )
                .await
            }

            async fn registration_at(
                &self,
                c: &PushRegistrationChallenge,
                max: u32,
                at: u64,
            ) -> qid_core::QidResult<bool> {
                self.issue_push_registration(c, max, 86400, crate::push::AdmissionClock::at(at))
                    .await
            }
            async fn login_at(
                &self,
                c: &PushLoginChallenge,
                max: u32,
                at: u64,
            ) -> qid_core::QidResult<bool> {
                self.issue_push_login(c, max, 86400, crate::push::AdmissionClock::at(at))
                    .await
            }
            async fn fixture_registration(
                &self,
                c: &PushRegistrationChallenge,
                max: u32,
                window: u64,
            ) -> qid_core::QidResult<bool> {
                let at = c.authenticator.created_at;
                self.issue_push_registration(c, max, window, crate::push::AdmissionClock::at(at))
                    .await
            }
            async fn fixture_login(
                &self,
                c: &PushLoginChallenge,
                max: u32,
                window: u64,
            ) -> qid_core::QidResult<bool> {
                let at = c.created_at;
                self.issue_push_login(c, max, window, crate::push::AdmissionClock::at(at))
                    .await
            }
        }
    };
}
fixture_repo!(FileRepository);
fixture_repo!(SqlRepository);

// A challenge was prepared at 199998, then waited behind cleanup until 200000.
// Under actual-admission semantics the old 113599 row is no longer in its
// window (which starts at 113601), so the first new issuance is allowed. It
// must be recorded at 200000, NOT at the stale creation time 199998: otherwise
// cleanup or the next rolling quota could forget it two seconds too early.
async fn delayed_admission_contract(repo: &impl FixtureRepository) {
    seed(repo).await;
    let old = quota_registration("delayed-old", "owner", 113599, 113700);
    assert!(repo.registration_at(&old, 1, 113599).await.unwrap());
    enroll(repo, "delayed-device", "peer", 100).await;
    let old_login = quota_login(
        "delayed-old-login",
        "delayed-device",
        "peer",
        113598,
        113599,
    );
    assert!(repo.login_at(&old_login, 1, 113598).await.unwrap());
    assert_eq!(
        repo.cleanup_expired_push_records(200000, 1000)
            .await
            .unwrap(),
        2
    );
    let new = quota_registration("delayed-new", "owner", 199998, 200100);
    let new_login = quota_login(
        "delayed-new-login",
        "delayed-device",
        "peer",
        199998,
        200100,
    );
    assert!(repo.registration_at(&new, 1, 200000).await.unwrap());
    assert!(repo.login_at(&new_login, 1, 200000).await.unwrap());
    assert_eq!(
        repo.get_push_registration(&"realm".into(), "owner", &new.authenticator.id)
            .await
            .unwrap(),
        Some(new.clone())
    );
    assert_eq!(stored_login(repo, &new_login).await, new_login);
    // These expired rows must survive cleanup with cutoff 199999 and 200000.
    for now in [286399, 286400] {
        assert_eq!(
            repo.cleanup_expired_push_records(now, 1000).await.unwrap(),
            0
        );
    }
    let next = quota_registration("delayed-next", "owner", 286398, 286500);
    let next_login = quota_login(
        "delayed-next-login",
        "delayed-device",
        "peer",
        286398,
        286500,
    );
    for at in [286398, 286399] {
        assert!(!repo.registration_at(&next, 1, at).await.unwrap());
        assert!(!repo.login_at(&next_login, 1, at).await.unwrap());
    }
    assert!(repo.registration_at(&next, 1, 286400).await.unwrap());
    assert!(repo.login_at(&next_login, 1, 286400).await.unwrap());
    assert_eq!(
        repo.cleanup_expired_push_records(286501, 1000)
            .await
            .unwrap(),
        2
    );
    // Neither future-created nor expired challenges can be admitted.
    let future = quota_registration("future", "owner", 400001, 400100);
    let expired = quota_registration("expired", "owner", 399900, 400000);
    assert!(repo.registration_at(&future, 100, 400000).await.is_err());
    assert!(repo.registration_at(&expired, 100, 400000).await.is_err());
    let future = quota_login("future-login", "delayed-device", "peer", 400001, 400100);
    let expired = quota_login("expired-login", "delayed-device", "peer", 399900, 400000);
    assert!(repo.login_at(&future, 100, 400000).await.is_err());
    assert!(repo.login_at(&expired, 100, 400000).await.is_err());
}
#[tokio::test]
async fn file_delayed_admission_cleanup_boundary() {
    let dir = std::env::temp_dir().join(format!("qid-delayed-{}", ulid::Ulid::new()));
    let repo = FileRepository::new(dir.join("store.json").to_str().unwrap())
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    delayed_admission_contract(&repo).await;
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}
#[tokio::test]
async fn sql_delayed_admission_cleanup_boundary() {
    let dir = std::env::temp_dir().join(format!("qid-delayed-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let repo = SqlRepository::connect(&format!("sqlite:{}", dir.join("store.db").display()))
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    delayed_admission_contract(&repo).await;
    repo.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}
#[tokio::test]
async fn file_cleanup_restores_only_removed_rows_on_write_failure() {
    let dir = std::env::temp_dir().join(format!("qid-cleanup-rollback-{}", ulid::Ulid::new()));
    let path = dir.join("store.json");
    let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
    repo.migrate().await.unwrap();
    seed(&repo).await;
    let r = quota_registration("old-pending", "owner", 100, 200);
    assert!(repo.registration_at(&r, 100, 100).await.unwrap());
    enroll(&repo, "device", "owner", 100).await;
    let c = quota_login("old-login", "device", "owner", 120, 200);
    assert!(repo.login_at(&c, 100, 120).await.unwrap());
    for limit in [1, 2] {
        let disk = std::fs::read(&path).unwrap();
        std::fs::create_dir(path.with_extension("tmp")).unwrap();
        assert!(
            repo.cleanup_expired_push_records(200000, limit)
                .await
                .is_err()
        );
        assert_eq!(
            repo.get_push_registration(&"realm".into(), "owner", "old-pending")
                .await
                .unwrap(),
            Some(r.clone())
        );
        assert_eq!(stored_login(&repo, &c).await, c);
        assert_eq!(std::fs::read(&path).unwrap(), disk);
        std::fs::remove_dir(path.with_extension("tmp")).unwrap();
    }
    assert_eq!(
        repo.cleanup_expired_push_records(200000, 2).await.unwrap(),
        2
    );
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}

// Admission time, not the earlier challenge creation time, bounds activation.
async fn registration_activation_clock_contract(repo: &impl FixtureRepository) {
    seed(repo).await;
    let pending = registration("activation-clock"); // created 100, expires 200
    assert!(repo.registration_at(&pending, 10, 150).await.unwrap());
    let realm = "realm".into();
    for verified in [true, false] {
        assert!(
            !repo
                .attempt_push_registration(&pending, verified, 140)
                .await
                .unwrap()
        );
        assert_eq!(
            repo.get_push_registration(&realm, "owner", &pending.authenticator.id)
                .await
                .unwrap(),
            Some(pending.clone())
        );
        assert!(
            repo.get_push_authenticator(&realm, "owner", &pending.authenticator.id)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert!(
        repo.attempt_push_registration(&pending, true, 150)
            .await
            .unwrap()
    );
    let mut enrolled = pending.authenticator;
    enrolled.created_at = 150;
    assert_eq!(
        repo.get_push_authenticator(&realm, "owner", &enrolled.id)
            .await
            .unwrap(),
        Some(enrolled)
    );
}
#[tokio::test]
async fn file_push_registration_activation_clock() {
    let dir = std::env::temp_dir().join(format!("qid-activation-clock-{}", ulid::Ulid::new()));
    let repo = FileRepository::new(dir.join("store.json").to_str().unwrap())
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    registration_activation_clock_contract(&repo).await;
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}
#[tokio::test]
async fn sql_push_registration_activation_clock() {
    let dir = std::env::temp_dir().join(format!("qid-activation-clock-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let repo = SqlRepository::connect(&format!("sqlite:{}", dir.join("store.db").display()))
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    registration_activation_clock_contract(&repo).await;
    repo.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}

async fn resend_contract(repo: &impl FixtureRepository) {
    seed(repo).await;
    enroll(repo, "resend-device", "owner", 100).await;
    let c = quota_login("resend-login", "resend-device", "owner", 1000, 1600);
    assert!(repo.login_at(&c, 3, 1002).await.unwrap());
    // Concurrent bad signatures must survive rotation; expected attempt state
    // is not an overwrite authority.
    assert!(repo.attempt_push_login(&c, None, 1005).await.unwrap());
    let n = "e".repeat(64);
    assert!(!repo.resend_at(&c, &n, 30, 3, 86400, 1031).await.unwrap());
    let admitted = repo
        .fixture_resend(&c, &c.browser_binding_verifier, &n, 3, 86400, 30, 1032)
        .await
        .unwrap()
        .expect("admitted snapshot");
    let mut current = stored_login(repo, &c).await;
    assert_eq!(admitted, current);
    let mut expected_new = c.clone();
    expected_new.attempt_count = 1;
    expected_new.nonce_verifier = n.clone();
    expected_new.resend_admitted_at.push(1032);
    assert_eq!(admitted, expected_new);
    // CAS covers history independently of the current nonce generation.
    let mut stale_history = current.clone();
    stale_history.resend_admitted_at.clear();
    assert!(
        !repo
            .attempt_push_login(&stale_history, Some(PushDecision::Approve), 1033)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .resend_at(&stale_history, &"f".repeat(64), 1, 100, 86400, 1033)
            .await
            .unwrap()
    );
    for binding in ["d".repeat(64), "not-a-verifier".into()] {
        assert!(
            repo.fixture_resend(&current, &binding, &"f".repeat(64), 100, 86400, 1, 1033)
                .await
                .unwrap()
                .is_none()
        );
    }
    for nonce in [
        current.nonce_verifier.clone(),
        "raw-nonce".into(),
        "A".repeat(64),
    ] {
        assert!(
            !repo
                .resend_at(&current, &nonce, 1, 100, 86400, 1033)
                .await
                .unwrap()
        );
    }
    for at in [999, 1001, 1031, 1032] {
        assert!(
            !repo
                .resend_at(&current, &"f".repeat(64), 1, 100, 86400, at)
                .await
                .unwrap()
        );
    }
    assert_eq!(stored_login(repo, &c).await, admitted);
    assert_eq!(current.attempt_count, 1);
    assert_eq!(current.resend_admitted_at, vec![1032]);
    assert_eq!(current.created_at, c.created_at);
    assert_eq!(current.expires_at, c.expires_at);
    assert_eq!(current.max_attempts, c.max_attempts);
    assert!(
        !repo
            .attempt_push_login(&c, Some(PushDecision::Approve), 1033)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .attempt_push_login(&c, Some(PushDecision::Deny), 1033)
            .await
            .unwrap()
    );
    let n2 = "f".repeat(64);
    let n3 = "a".repeat(64);
    let (a, b) = tokio::join!(
        repo.resend_at(&current, &n2, 30, 3, 86400, 1062),
        repo.resend_at(&current, &n3, 30, 3, 86400, 1062),
    );
    assert_eq!(u8::from(a.unwrap()) + u8::from(b.unwrap()), 1);
    current = stored_login(repo, &c).await;
    assert_eq!(current.resend_admitted_at, vec![1032, 1062]);
    assert_eq!(current.attempt_count, 1);
    // All three admissions count, irrespective of delivery or attempts.
    assert!(
        !repo
            .resend_at(&current, &n, 30, 3, 86400, 1092)
            .await
            .unwrap()
    );
    let next = quota_login("resend-next", "resend-device", "owner", 1063, 1600);
    assert!(!repo.login_at(&next, 3, 1063).await.unwrap());
    // In this short window only the resend counts; original issuance is older.
    assert!(!repo.fixture_login(&next, 1, 2).await.unwrap());
    assert!(!repo.resend_at(&current, &n, 1, 1, 2, 1063).await.unwrap());
    // A fresh initial issuance and a resend contend for the same last slot.
    let next = quota_login("resend-race", "resend-device", "owner", 1092, 1600);
    let (a, b) = tokio::join!(
        repo.login_at(&next, 4, 1092),
        repo.resend_at(&current, &n, 30, 4, 86400, 1092),
    );
    assert_eq!(u8::from(a.unwrap()) + u8::from(b.unwrap()), 1);
    current = stored_login(repo, &c).await;
    {
        let mut wrong = current.clone();
        // Each immutable/browser/owner mismatch must refuse without mutation.
        wrong.browser_binding_verifier = "e".repeat(64);
        assert!(
            !repo
                .resend_at(&wrong, &n2, 1, 100, 86400, 1200)
                .await
                .unwrap()
        );
    }
    for field in ["realm", "user", "authenticator", "id"] {
        let mut wrong = current.clone();
        match field {
            "realm" => wrong.realm_id = "other".into(),
            "user" => wrong.user_id = "peer".into(),
            "authenticator" => wrong.authenticator_id = "missing".into(),
            _ => wrong.id = "missing".into(),
        }
        assert!(
            !repo
                .resend_at(&wrong, &n2, 1, 100, 86400, 1200)
                .await
                .unwrap()
        );
    }
    assert!(
        !repo
            .resend_at(&current, &n2, 30, 100, 86400, 1600)
            .await
            .unwrap()
    );
    for cooldown in [0, 601] {
        assert!(
            !repo
                .resend_at(&current, &n2, cooldown, 100, 86400, 1200)
                .await
                .unwrap()
        );
    }
    assert!(
        repo.attempt_push_login(&current, Some(PushDecision::Approve), 1200)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .resend_at(&current, &n2, 1, 100, 86400, 1201)
            .await
            .unwrap()
    );
    assert!(
        repo.redeem_push_login(&current, &current.browser_binding_verifier, 1201)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .redeem_push_login(&current, &current.browser_binding_verifier, 1201)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .resend_at(&current, &n2, 1, 100, 86400, 1202)
            .await
            .unwrap()
    );

    let exhausted = quota_login("resend-exhausted", "resend-device", "owner", 2000, 2500);
    assert!(repo.login_at(&exhausted, 100, 2000).await.unwrap());
    let (attempted, resent) = tokio::join!(
        repo.attempt_push_login(&exhausted, None, 2001),
        repo.resend_at(&exhausted, &n, 1, 100, 86400, 2001),
    );
    assert!(resent.unwrap());
    let exhausted = stored_login(repo, &exhausted).await;
    assert_eq!(exhausted.attempt_count, u32::from(attempted.unwrap()));
    assert_eq!(exhausted.resend_admitted_at, vec![2001]);
    for _ in exhausted.attempt_count..exhausted.max_attempts {
        assert!(
            repo.attempt_push_login(&exhausted, None, 2001)
                .await
                .unwrap()
        );
    }
    assert!(
        !repo
            .resend_at(&exhausted, &n, 1, 100, 86400, 2002)
            .await
            .unwrap()
    );
    let denied = quota_login("resend-denied", "resend-device", "owner", 2600, 2900);
    assert!(repo.login_at(&denied, 100, 2600).await.unwrap());
    assert!(
        repo.attempt_push_login(&denied, Some(PushDecision::Deny), 2601)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .resend_at(&denied, &n, 1, 100, 86400, 2602)
            .await
            .unwrap()
    );
    let decided = stored_login(repo, &denied).await;
    assert!(
        !repo
            .resend_at(&decided, &n, 1, 100, 86400, 2602)
            .await
            .unwrap()
    );
    let revoked = quota_login("resend-revoked", "resend-device", "owner", 3000, 3500);
    assert!(repo.login_at(&revoked, 100, 3000).await.unwrap());
    assert!(
        repo.revoke_push_authenticator(&"realm".into(), "owner", "resend-device", 3001)
            .await
            .unwrap()
    );
    assert!(
        !repo
            .resend_at(&revoked, &n, 1, 100, 86400, 3002)
            .await
            .unwrap()
    );

    // Expiry, not initial issuance, is the conservative quota-evidence horizon.
    let has_race = repo
        .get_push_login(&"realm".into(), "owner", "resend-race")
        .await
        .unwrap()
        .is_some();
    assert_eq!(
        repo.cleanup_expired_push_records(86400 + 1600, 1000)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        repo.cleanup_expired_push_records(86400 + 1601, 1000)
            .await
            .unwrap(),
        1 + u64::from(has_race)
    );
    assert!(
        repo.get_push_login(&"realm".into(), "owner", &c.id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn file_push_resend_contract() {
    let dir = std::env::temp_dir().join(format!("qid-resend-{}", ulid::Ulid::new()));
    let repo = FileRepository::new(dir.join("store.json").to_str().unwrap())
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    resend_contract(&repo).await;
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}
#[tokio::test]
async fn sql_push_resend_contract() {
    let dir = std::env::temp_dir().join(format!("qid-resend-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let repo = SqlRepository::connect(&format!("sqlite:{}", dir.join("store.db").display()))
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    resend_contract(&repo).await;
    repo.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn push_resend_history_shape_is_bounded_and_fail_closed() {
    let c = login("shape", "device");
    for history in [
        vec![c.created_at - 1],
        vec![c.expires_at],
        vec![101, 101],
        vec![102, 101],
        vec![c.created_at + 1, c.created_at + 1],
        vec![c.created_at + 2, c.created_at + 1],
        vec![101; 600],
        (c.created_at..c.created_at + 601).collect(),
        vec![u64::MAX],
        vec![i64::MAX as u64 + 1],
    ] {
        let mut malformed = c.clone();
        malformed.resend_admitted_at = history;
        assert!(crate::push::validate_login_record(&malformed).is_err());
    }
    let mut c = c;
    let encoded = serde_json::to_value(&c).unwrap();
    let mut pre_resend = encoded.as_object().unwrap().clone();
    pre_resend.remove("resend_admitted_at");
    assert_eq!(
        serde_json::from_value::<PushLoginChallenge>(pre_resend.into()).unwrap(),
        c
    );
    c.resend_admitted_at = vec![c.created_at];
    assert!(crate::push::validate_login_record(&c).is_ok());
    assert!(crate::push::validate_login_issued(&c, c.created_at).is_err());
    c.expires_at = c.created_at + 600;
    c.resend_admitted_at = (c.created_at..c.expires_at).collect();
    assert_eq!(c.resend_admitted_at.len(), 600);
    assert!(crate::push::validate_login_record(&c).is_ok());
    c.resend_admitted_at = vec![c.created_at + 1];
    assert!(crate::push::validate_login_record(&c).is_ok());
    assert!(crate::push::validate_login_issued(&c, c.created_at + 1).is_err());
    assert!(crate::push::validate_login(&c).is_err());
    c.expires_at = c.created_at + 601;
    assert!(crate::push::validate_login_record(&c).is_err());
}

// Original issuance ages out before the resend. Cleanup must not erase the
// history that still suppresses both new challenges and further resends.
async fn resend_retention_contract(repo: &impl FixtureRepository) {
    seed(repo).await;
    enroll(repo, "retention-device", "owner", 100).await;
    for (id, issued) in [("retention-a", 1000), ("retention-b", 1001)] {
        let c = quota_login(id, "retention-device", "owner", issued, 1600);
        assert!(repo.login_at(&c, 100, issued).await.unwrap());
        assert!(
            repo.resend_at(&c, &"d".repeat(64), 1, 100, 86400, 1599)
                .await
                .unwrap()
        );
    }
    let now = 87401; // window starts at 1002: initial sends no longer count.
    assert_eq!(repo.cleanup_expired_push_records(now, 1).await.unwrap(), 0);
    let next = quota_login(
        "retention-next",
        "retention-device",
        "owner",
        now,
        now + 600,
    );
    assert!(!repo.login_at(&next, 2, now).await.unwrap());
    // Prove the count is exactly two resends, not zero or four sends.
    assert!(repo.login_at(&next, 3, now).await.unwrap());
    assert!(
        !repo
            .resend_at(&next, &"e".repeat(64), 1, 3, 86400, now + 1)
            .await
            .unwrap()
    );
    assert_eq!(
        repo.cleanup_expired_push_records(88000, 1).await.unwrap(),
        0
    );
    assert_eq!(
        repo.cleanup_expired_push_records(88001, 1).await.unwrap(),
        1
    );
    assert_eq!(
        repo.cleanup_expired_push_records(88001, 1).await.unwrap(),
        1
    );
    assert_eq!(
        repo.cleanup_expired_push_records(88001, 1).await.unwrap(),
        0
    );
    assert_eq!(stored_login(repo, &next).await, next);

    // The public API returns the exact committed snapshot, not a later read.
    let now = qid_core::util::now_seconds();
    let c = quota_login(
        "public-resend",
        "retention-device",
        "owner",
        now - 30,
        now + 300,
    );
    assert!(repo.login_at(&c, 100, now - 30).await.unwrap());
    let nonce = "e".repeat(64);
    let admitted = repo
        .try_resend_push_login(&c, &c.browser_binding_verifier, &nonce, 100, 86400, 1)
        .await
        .unwrap()
        .expect("public resend admitted");
    assert_eq!(admitted, stored_login(repo, &c).await);
    assert_eq!(admitted.nonce_verifier, nonce);
    assert_eq!(admitted.resend_admitted_at.len(), 1);
    assert!(admitted.resend_admitted_at[0] >= now);
    assert!(
        repo.try_resend_push_login(
            &c,
            &c.browser_binding_verifier,
            &"f".repeat(64),
            100,
            86400,
            1
        )
        .await
        .unwrap()
        .is_none()
    );
    assert!(
        repo.attempt_push_login(
            &admitted,
            Some(PushDecision::Approve),
            admitted.resend_admitted_at[0]
        )
        .await
        .unwrap()
    );
    assert!(
        repo.redeem_push_login(
            &admitted,
            &admitted.browser_binding_verifier,
            admitted.resend_admitted_at[0]
        )
        .await
        .unwrap()
    );
    assert!(
        !repo
            .redeem_push_login(
                &admitted,
                &admitted.browser_binding_verifier,
                admitted.resend_admitted_at[0]
            )
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn file_push_resend_retention_and_public_snapshot() {
    let dir = std::env::temp_dir().join(format!("qid-resend-retention-{}", ulid::Ulid::new()));
    let repo = FileRepository::new(dir.join("store.json").to_str().unwrap())
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    resend_retention_contract(&repo).await;
    drop(repo);
    std::fs::remove_dir_all(dir).unwrap();
}
#[tokio::test]
async fn sql_push_resend_retention_and_public_snapshot() {
    let dir = std::env::temp_dir().join(format!("qid-resend-retention-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    let repo = SqlRepository::connect(&format!("sqlite:{}", dir.join("store.db").display()))
        .await
        .unwrap();
    repo.migrate().await.unwrap();
    resend_retention_contract(&repo).await;
    repo.close().await;
    std::fs::remove_dir_all(dir).unwrap();
}
