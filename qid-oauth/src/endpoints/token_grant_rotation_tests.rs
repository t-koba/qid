// Observe the actual grant's storage write, without replacing the grant logic.
thread_local! {
    static ROTATION_PROBE: std::cell::RefCell<Option<RotationProbe>> = const {
        std::cell::RefCell::new(None)
    };
}

#[derive(Clone, Copy)]
enum RotationAction {
    Rotate,
    ReplaceRealm,
    Missing,
}

struct RotationProbe {
    action: RotationAction,
    calls: Vec<(String, String)>,
}

pub(super) struct ObservedRotation<'a, R>(pub &'a R);
impl<R: TokenRepository> ObservedRotation<'_, R> {
    pub async fn update_token_family_refresh_hash(
        &self,
        id: &str,
        realm_id: &str,
        expected_hash: &str,
        new_hash: &str,
        deadline: u64,
    ) -> QidResult<()> {
        let action = ROTATION_PROBE.with(|probe| {
            probe.borrow_mut().as_mut().map(|probe| {
                probe.calls.push((id.into(), realm_id.into()));
                probe.action
            })
        });
        match action {
            Some(RotationAction::ReplaceRealm) => {
                // Deterministically replace ownership after the grant's pre-read.
                let mut replacement = self.0.get_token_family(id).await?.unwrap();
                replacement.realm_id = "other".into();
                self.0.create_token_family(&replacement).await?;
            }
            Some(RotationAction::Missing) => {
                // Inject disappearance at the storage boundary; backend contracts
                // independently prove actual missing rows return this, not Conflict.
                return Err(QidError::NotFound {
                    resource: format!("token family {id}"),
                });
            }
            _ => {}
        }
        self.0
            .update_token_family_refresh_hash(id, realm_id, expected_hash, new_hash, deadline)
            .await
    }
}

#[tokio::test]
async fn refresh_rotation_observes_validated_client_realm_and_does_not_revoke_on_not_found() {
    for action in [
        RotationAction::Rotate,
        RotationAction::ReplaceRealm,
        RotationAction::Missing,
    ] {
        let now = util::now_seconds();
        let mut config = test_helpers::test_config();
        let mut second = config.realms[0].clone();
        second.id = "rotation-realm".into();
        config.realms.push(second);
        let (state, repo) = state_with_config(config).await;
        create_test_realm(&repo, "rotation-realm", "https://id.example.com").await;
        let mut client =
            refresh_test_client("rotation-client", "client", ClientType::Public, "none");
        client.realm_id = "rotation-realm".into();
        repo.create_client(&client).await.unwrap();
        let mut user = refresh_test_user("rotation-user");
        user.realm_id = client.realm_id.clone();
        repo.create_user(&user).await.unwrap();
        let mut expected = refresh_test_family(
            "rotation-family",
            &user.id,
            &client.client_id,
            "original-jti",
            &["api"],
            now,
            Some(now + 3600),
        );
        expected.realm_id = client.realm_id.clone();
        repo.create_token_family(&expected).await.unwrap();
        let token = signed_refresh(&state, &expected, "original-jti").await;
        ROTATION_PROBE.with(|probe| {
            assert!(probe.borrow().is_none());
            *probe.borrow_mut() = Some(RotationProbe {
                action,
                calls: vec![],
            });
        });
        let result = refresh_token_grant(&state, &refresh_req(token, None), &client, None).await;
        let probe = ROTATION_PROBE.with(|probe| probe.borrow_mut().take().unwrap());
        assert_eq!(
            probe.calls,
            vec![(expected.id.clone(), client.realm_id.clone())]
        );
        let stored = get_family(&repo, &expected.id).await;
        match action {
            RotationAction::Rotate => {
                let response = result.unwrap();
                assert!(!response.access_token.is_empty());
                assert!(response.refresh_token.is_some());
                assert_ne!(stored.current_refresh_hash, expected.current_refresh_hash);
                expected.current_refresh_hash = stored.current_refresh_hash.clone();
            }
            RotationAction::ReplaceRealm | RotationAction::Missing => {
                assert!(
                    matches!(result, Err(QidError::Unauthorized { ref message })
                    if message == "invalid refresh token"),
                    "{result:?}"
                );
                if matches!(action, RotationAction::ReplaceRealm) {
                    expected.realm_id = "other".into();
                }
                // The Missing case retains the same-realm family, so its full-row
                // comparison below also catches accidental reuse revocation.
            }
        }
        assert_eq!(
            serde_json::to_value(stored).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
    }
}
