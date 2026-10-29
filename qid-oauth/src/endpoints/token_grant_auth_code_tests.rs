// Observe the actual authorization-code grant's storage write, without
// replacing the grant logic.
thread_local! {
    static AUTH_CODE_PROBE: std::cell::RefCell<Option<AuthCodeProbe>> = const {
        std::cell::RefCell::new(None)
    };
}

#[derive(Clone, Copy)]
enum AuthCodeAction {
    Consume,
    ReplaceRealm,
    ReplaceClient,
    ReplaceUser,
    ReturnNotFound,
}

struct AuthCodeProbe {
    action: AuthCodeAction,
    calls: Vec<(String, String, String, String)>,
}

pub(super) struct ObservedAuthCode<'a, R>(pub &'a R);
impl<R: TokenRepository> ObservedAuthCode<'_, R> {
    pub async fn mark_authorization_code_used(&self, code: &AuthorizationCode) -> QidResult<()> {
        let action = AUTH_CODE_PROBE.with(|probe| {
            probe.borrow_mut().as_mut().map(|probe| {
                probe.calls.push((
                    code.code_hash.clone(),
                    code.realm_id.clone(),
                    code.client_id.clone(),
                    code.user_id.clone(),
                ));
                probe.action
            })
        });
        match action {
            Some(AuthCodeAction::ReplaceRealm) => {
                // Deterministically replace ownership after the grant's pre-read.
                let mut replacement =
                    self.0.get_authorization_code(&code.code_hash).await?.unwrap();
                replacement.realm_id = "other-realm".into();
                self.0.create_authorization_code(&replacement).await?;
            }
            Some(AuthCodeAction::ReplaceClient) => {
                // Deterministically replace ownership after the grant's pre-read.
                let mut replacement =
                    self.0.get_authorization_code(&code.code_hash).await?.unwrap();
                replacement.client_id = "other-client".into();
                self.0.create_authorization_code(&replacement).await?;
            }
            Some(AuthCodeAction::ReplaceUser) => {
                // Deterministically replace ownership after the grant's pre-read.
                let mut replacement =
                    self.0.get_authorization_code(&code.code_hash).await?.unwrap();
                replacement.user_id = "other-user".into();
                self.0.create_authorization_code(&replacement).await?;
            }
            Some(AuthCodeAction::ReturnNotFound) => {
                // Simulate the storage returning NotFound; the backend contract below
                // independently proves missing rows return NotFound, not Conflict.
                return Err(QidError::NotFound {
                    resource: format!("authorization code {}", code.code_hash),
                });
            }
            _ => {}
        }
        self.0.mark_authorization_code_used(code).await
    }
}

#[tokio::test]
async fn authorization_code_grant_observes_validated_owner_and_rejects_stale_writes() {
    for action in [
        AuthCodeAction::Consume,
        AuthCodeAction::ReplaceRealm,
        AuthCodeAction::ReplaceClient,
        AuthCodeAction::ReplaceUser,
        AuthCodeAction::ReturnNotFound,
    ] {
        let (state, repo) = setup_state().await;
        let now = util::now_seconds();
        let client =
            refresh_test_client("auth-code-id", "auth-code-client", ClientType::Public, "none");
        repo.create_client(&client).await.unwrap();
        let user = refresh_test_user("auth-code-user");
        repo.create_user(&user).await.unwrap();
        let code = "auth-code-value";
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let mut expected = AuthorizationCode {
            code_hash: util::sha256_base64url(code),
            client_id: client.client_id.clone(),
            user_id: user.id.clone(),
            realm_id: "test".to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            state: None,
            nonce: None,
            auth_time: None,
            acr: None,
            amr: Vec::new(),
            code_challenge: Some(util::sha256_base64url(verifier)),
            code_challenge_method: Some("S256".to_string()),
            scopes: vec!["openid".to_string()],
            resource: Vec::new(),
            authorization_details: None,
            expires_at: now + 3600,
            used: false,
            created_at: now,
            session_id: None,
        };
        repo.create_authorization_code(&expected).await.unwrap();
        AUTH_CODE_PROBE.with(|probe| {
            assert!(probe.borrow().is_none());
            *probe.borrow_mut() = Some(AuthCodeProbe {
                action,
                calls: vec![],
            });
        });
        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(code.to_string()),
            redirect_uri: Some("https://app.example.com/callback".to_string()),
            code_verifier: Some(verifier.to_string()),
            ..Default::default()
        };
        let result = authorization_code_grant(&state, &req, &client, None).await;
        let probe = AUTH_CODE_PROBE.with(|probe| probe.borrow_mut().take().unwrap());
        assert_eq!(
            probe.calls,
            vec![(
                expected.code_hash.clone(),
                "test".to_string(),
                "auth-code-client".to_string(),
                "auth-code-user".to_string(),
            )]
        );
        let stored = repo
            .get_authorization_code(&expected.code_hash)
            .await
            .unwrap()
            .unwrap();
        match action {
            AuthCodeAction::Consume => {
                let response = result.unwrap();
                assert!(!response.access_token.is_empty());
                assert!(response.refresh_token.is_some());
                expected.used = true;
            }
            AuthCodeAction::ReplaceRealm
            | AuthCodeAction::ReplaceClient
            | AuthCodeAction::ReplaceUser => {
                assert!(
                    matches!(result, Err(QidError::NotFound { .. })),
                    "stale owner must not issue tokens, got {result:?}"
                );
                match action {
                    AuthCodeAction::ReplaceRealm => expected.realm_id = "other-realm".into(),
                    AuthCodeAction::ReplaceClient => expected.client_id = "other-client".into(),
                    _ => expected.user_id = "other-user".into(),
                }
                // The foreign replacement keeps `used: false`: a stale owner
                // mismatch must not mark the changed row.
            }
            AuthCodeAction::ReturnNotFound => {
                assert!(
                    matches!(result, Err(QidError::NotFound { .. })),
                    "storage NotFound must not issue tokens, got {result:?}"
                );
            }
        }
        assert_eq!(
            serde_json::to_value(stored).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
    }
}
