//! OAuth 2.0 token grant handlers.

use qid_core::{
    error::{QidError, QidResult},
    models::{AccessToken, Client, ServiceAccount, User},
    pkce::verify_code_verifier,
    state::SharedState,
    tenant::RealmId,
};
use qid_observability::audit::AuditEvent;
use qid_storage::prelude::*;
use std::collections::HashMap;

use super::{
    TokenIssueClaims, TokenRequest, TokenResponse, access_token_type_for_cnf, format_access_token,
    generate_jti, issue_access_token, issue_id_token, issue_token_pair, sign_refresh_token,
    token_ttl,
};

pub async fn authorization_code_grant<R: Repository>(
    state: &SharedState<R>,
    req: &TokenRequest,
    client: &Client,
    cnf: Option<&serde_json::Value>,
) -> QidResult<TokenResponse> {
    let code = req.code.as_deref().ok_or_else(|| QidError::BadRequest {
        message: "code required".to_string(),
    })?;
    let redirect_uri = req
        .redirect_uri
        .as_deref()
        .ok_or_else(|| QidError::BadRequest {
            message: "redirect_uri required".to_string(),
        })?;

    let code_hash = qid_core::util::sha256_base64url(code);
    let auth_code = state
        .repo
        .get_authorization_code(&code_hash)
        .await?
        .ok_or_else(|| QidError::Unauthorized {
            message: "invalid code".to_string(),
        })?;

    if auth_code.used
        || auth_code.expires_at <= qid_core::util::now_seconds()
        || auth_code.redirect_uri != redirect_uri
        || auth_code.client_id != client.client_id
        || auth_code.realm_id != client.realm_id
    {
        return Err(QidError::Unauthorized {
            message: "invalid code".to_string(),
        });
    }

    if !verify_code_verifier(
        auth_code.code_challenge.as_deref(),
        auth_code.code_challenge_method.as_deref(),
        req.code_verifier.as_deref().unwrap_or(""),
    ) {
        return Err(QidError::Unauthorized {
            message: "invalid code_verifier".to_string(),
        });
    }

    state.repo.mark_authorization_code_used(&code_hash).await?;

    let user = state
        .repo
        .get_user_by_id(&auth_code.user_id)
        .await?
        .ok_or_else(|| QidError::NotFound {
            resource: "user".to_string(),
        })?;
    if user.realm_id != auth_code.realm_id {
        return Err(QidError::Unauthorized {
            message: "authorization code user realm mismatch".to_string(),
        });
    }

    let scopes = auth_code.scopes.clone();
    let realm = state
        .config
        .realms
        .iter()
        .find(|r| r.id == auth_code.realm_id)
        .ok_or_else(|| QidError::NotFound {
            resource: format!("realm {}", auth_code.realm_id),
        })?;
    let issuer = realm.issuer.clone();
    let audiences =
        qid_core::oauth::resolve_token_audience(realm, &[], &auth_code.resource, &scopes, cnf)?;
    let pair = issue_token_pair(
        state,
        &issuer,
        &user,
        &auth_code.client_id,
        &auth_code.realm_id,
        &scopes,
        TokenIssueClaims {
            audience: Some(&audiences),
            resource: Some(&auth_code.resource),
            authorization_details: auth_code.authorization_details.as_ref(),
            cnf,
            auth_time: auth_code.auth_time,
            acr: auth_code.acr.as_deref(),
            amr: Some(&auth_code.amr),
            nonce: auth_code.nonce.as_deref(),
            act: None,
            authorization_code: Some(code),
            access_token: None,
        },
    )
    .await?;

    let event = AuditEvent {
        r#type: "token.issued".to_string(),
        time: qid_core::util::now_seconds().to_string(),
        tenant: None,
        realm: Some(auth_code.realm_id.clone()),
        subject: Some(user.id.clone()),
        decision: Some("issued".to_string()),
        decision_id: None,
        extra: HashMap::new(),
    };
    tracing::info!(target: "audit", "{:?}", event);

    let client = state
        .repo
        .get_client_by_client_id(
            &RealmId::from(auth_code.realm_id.clone()),
            &auth_code.client_id,
        )
        .await?
        .ok_or_else(|| QidError::NotFound {
            resource: format!("client {}", auth_code.client_id),
        })?;
    let sub_override = if client.subject_type.as_deref() == Some("pairwise") {
        Some(qid_core::compute_pairwise_sub(
            &user.id,
            &qid_core::sector_identifier_for_client(&client),
            &issuer,
        ))
    } else {
        None
    };

    Ok(TokenResponse {
        access_token: pair.access_token.clone(),
        token_type: access_token_type_for_cnf(cnf).to_string(),
        expires_in: pair.expires_in,
        refresh_token: Some(pair.refresh_token),
        id_token: Some(issue_id_token(
            state,
            &issuer,
            &user,
            &auth_code.client_id,
            &auth_code.realm_id,
            &scopes,
            TokenIssueClaims {
                audience: None,
                resource: Some(&auth_code.resource),
                authorization_details: auth_code.authorization_details.as_ref(),
                cnf,
                auth_time: auth_code.auth_time,
                acr: auth_code.acr.as_deref(),
                amr: Some(&auth_code.amr),
                nonce: auth_code.nonce.as_deref(),
                act: None,
                authorization_code: Some(code),
                access_token: Some(&pair.access_token),
            },
            sub_override.as_deref(),
        )?),
        scope: Some(scopes.join(" ")),
        issued_token_type: None,
    })
}

pub async fn client_credentials_grant<R: Repository>(
    state: &SharedState<R>,
    req: &TokenRequest,
    effective_client_id: &str,
    cnf: Option<&serde_json::Value>,
) -> QidResult<TokenResponse> {
    let client_id = if !effective_client_id.is_empty() {
        effective_client_id
    } else {
        req.client_id
            .as_deref()
            .ok_or_else(|| QidError::BadRequest {
                message: "client_id required".to_string(),
            })?
    };

    let client = find_client_across_realms(state, client_id).await?;
    let realm_id = client.realm_id.clone();
    let realm_cfg = state
        .config
        .realms
        .iter()
        .find(|r| r.id == realm_id)
        .ok_or_else(|| QidError::NotFound {
            resource: format!("realm {realm_id}"),
        })?;
    let issuer = realm_cfg.issuer.clone();
    let default_scope = realm_cfg.protocols.oauth.default_scope.clone();

    let sa = match state
        .repo
        .get_service_account_by_client_id(&realm_id, client_id)
        .await?
    {
        Some(sa) => sa,
        None => {
            let sa = ServiceAccount {
                id: format!("service:{}", client_id),
                client_id: client_id.to_string(),
                realm_id: realm_id.clone(),
                description: None,
                created_at: qid_core::util::now_seconds(),
            };
            state.repo.create_service_account(&sa).await?;
            sa
        }
    };

    let service_user = User {
        id: sa.id.clone(),
        realm_id: sa.realm_id.clone(),
        email: None,
        email_verified: false,
        display_name: sa.description.clone(),
        failed_login_attempts: 0,
        locked_until: None,
        org: None,
    };

    // Persist the service user so FK constraints on access_tokens.user_id are satisfied.
    if state.repo.get_user_by_id(&service_user.id).await?.is_none() {
        state.repo.create_user(&service_user).await?;
    }

    let scopes = req
        .scope
        .as_deref()
        .map(|s| s.split(' ').map(String::from).collect())
        .unwrap_or_else(|| vec![default_scope]);
    let resources = req.resource.iter().cloned().collect::<Vec<_>>();
    if let Some(details) = &req.authorization_details {
        qid_core::oauth::validate_authorization_details(details)?;
    }
    let audiences = req
        .audience
        .as_deref()
        .map(|value| {
            value
                .split(' ')
                .filter(|part| !part.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let audiences =
        qid_core::oauth::resolve_token_audience(realm_cfg, &audiences, &resources, &scopes, cnf)?;

    let (access_token, expires_in) = issue_access_token(
        state,
        &issuer,
        &service_user,
        client_id,
        &realm_id,
        &scopes,
        TokenIssueClaims {
            audience: Some(&audiences),
            resource: Some(&resources),
            authorization_details: req.authorization_details.as_ref(),
            cnf,
            auth_time: Some(qid_core::util::now_seconds()),
            acr: None,
            amr: None,
            nonce: None,
            act: None,
            authorization_code: None,
            access_token: None,
        },
    )
    .await?;

    let event = AuditEvent {
        r#type: "token.issued".to_string(),
        time: qid_core::util::now_seconds().to_string(),
        tenant: None,
        realm: Some(realm_id.clone()),
        subject: Some(sa.id.clone()),
        decision: Some("issued".to_string()),
        decision_id: None,
        extra: HashMap::new(),
    };
    tracing::info!(target: "audit", "{:?}", event);

    Ok(TokenResponse {
        access_token,
        token_type: access_token_type_for_cnf(cnf).to_string(),
        expires_in,
        refresh_token: None,
        id_token: None,
        scope: Some(scopes.join(" ")),
        issued_token_type: None,
    })
}

pub async fn refresh_token_grant<R: Repository>(
    state: &SharedState<R>,
    req: &TokenRequest,
    cnf: Option<&serde_json::Value>,
) -> QidResult<TokenResponse> {
    let refresh_token = req
        .refresh_token
        .as_deref()
        .ok_or_else(|| QidError::BadRequest {
            message: "refresh_token required".to_string(),
        })?;

    let data = state
        .signer
        .decode_signature_only(refresh_token)
        .map_err(|e| QidError::Crypto {
            message: format!("failed to decode refresh token: {e}"),
        })?;
    let claims = data.claims;

    // RFC 9700 §4.13: refresh tokens MUST be bound to the issuer's intended
    // audience. The `aud` claim of a refresh token issued by qid carries the
    // client_id of the client that originally requested it. We re-validate
    // that binding here against the registered client.
    let refresh_aud = claims
        .aud
        .as_deref()
        .ok_or_else(|| QidError::Unauthorized {
            message: "refresh token missing aud claim".to_string(),
        })?;
    if !client_id_is_registered(state, refresh_aud).await? {
        return Err(QidError::Unauthorized {
            message: "refresh token audience is not a registered client".to_string(),
        });
    }

    let refresh_jti = claims.jti.ok_or_else(|| QidError::Crypto {
        message: "refresh token missing jti".to_string(),
    })?;

    let family_id = claims
        .extra
        .get("family_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| QidError::BadRequest {
            message: "refresh token missing family_id".to_string(),
        })?;

    let family = state
        .repo
        .get_token_family(family_id)
        .await?
        .ok_or_else(|| QidError::Unauthorized {
            message: "invalid refresh token".to_string(),
        })?;

    if family.revoked {
        return Err(QidError::Unauthorized {
            message: "refresh token family revoked".to_string(),
        });
    }

    let expected_hash = qid_core::util::sha256_base64url(&refresh_jti);
    if family.current_refresh_hash != expected_hash {
        // Token theft detected: revoke the entire family to contain the breach.
        metrics::counter!("qid_refresh_reuse_detected_total").increment(1);
        if let Err(revoke_err) = state.repo.revoke_token_family(&family.id).await {
            tracing::warn!(error = %revoke_err, family_id = %family.id, "revoke_token_family failed after refresh reuse detection");
        }
        return Err(QidError::Unauthorized {
            message: "invalid refresh token".to_string(),
        });
    }

    let user = state
        .repo
        .get_user_by_id(&family.user_id)
        .await?
        .ok_or_else(|| QidError::NotFound {
            resource: "user".to_string(),
        })?;
    if user.realm_id != family.realm_id {
        return Err(QidError::Unauthorized {
            message: "refresh token user realm mismatch".to_string(),
        });
    }

    let realm = state
        .realm(&family.realm_id)
        .ok_or_else(|| QidError::NotFound {
            resource: format!("realm {}", family.realm_id),
        })?;

    let issuer = realm.issuer.clone();
    let scopes = vec![realm.oauth_default_scope.clone()];

    // mTLS refresh token binding enforcement:
    // if the original token family had an x5t#S256 sender constraint,
    // the refresh request must present a matching x5t#S256.
    if let Some(sender) = &family.sender_constraint
        && sender.get("x5t#S256").is_some()
    {
        let has_matching_mtls = cnf
            .and_then(|c| c.get("x5t#S256"))
            .and_then(|v| v.as_str())
            .map(|x5t| {
                sender
                    .get("x5t#S256")
                    .and_then(|v| v.as_str())
                    .map(|orig| x5t == orig)
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        if !has_matching_mtls {
            return Err(QidError::Unauthorized {
                message: "mTLS certificate binding required for refresh token".to_string(),
            });
        }
    }

    let now = qid_core::util::now_seconds();
    let new_access_jti = generate_jti();
    let new_refresh_jti = generate_jti();
    let new_hash = qid_core::util::sha256_base64url(&new_refresh_jti);
    let family_audience = if family.audience.is_empty() {
        vec![family.client_id.clone()]
    } else {
        family.audience.clone()
    };

    let access_token = AccessToken {
        jti: new_access_jti.clone(),
        family_id: Some(family.id.clone()),
        user_id: family.user_id.clone(),
        client_id: family.client_id.clone(),
        realm_id: family.realm_id.clone(),
        scopes: scopes.clone(),
        audience: family_audience.clone(),
        resource: family.resource.clone(),
        authorization_details: family.authorization_details.clone(),
        cnf: cnf.cloned().or(family.sender_constraint.clone()),
        auth_time: Some(now),
        acr: None,
        amr: Vec::new(),
        nonce: None,
        sender_constraint: cnf.cloned().or(family.sender_constraint.clone()),
        token_format: token_ttl(state, &family.realm_id).access_token_format,
        expires_at: now + token_ttl(state, &family.realm_id).access_token_ttl_seconds,
        revoked: false,
        issued_at: now,
    };
    state.repo.create_access_token(&access_token).await?;
    state
        .repo
        .update_token_family_refresh_hash(&family.id, &new_hash)
        .await?;

    let access = format_access_token(
        state,
        &issuer,
        &new_access_jti,
        &user,
        &family.client_id,
        &family.realm_id,
        &scopes,
        TokenIssueClaims {
            audience: Some(&family_audience),
            resource: Some(&family.resource),
            authorization_details: family.authorization_details.as_ref(),
            cnf: cnf.or(family.sender_constraint.as_ref()),
            auth_time: Some(now),
            acr: None,
            amr: None,
            nonce: None,
            act: None,
            authorization_code: None,
            access_token: None,
        },
    )?;
    let refresh = sign_refresh_token(
        state,
        &issuer,
        &new_refresh_jti,
        &user,
        &family.client_id,
        &family.realm_id,
        Some(&family.id),
    )?;

    let response_cnf = cnf.or(family.sender_constraint.as_ref());
    Ok(TokenResponse {
        access_token: access,
        token_type: access_token_type_for_cnf(response_cnf).to_string(),
        expires_in: token_ttl(state, &family.realm_id).access_token_ttl_seconds,
        refresh_token: Some(refresh),
        id_token: None,
        scope: Some(scopes.join(" ")),
        issued_token_type: None,
    })
}

async fn find_client_across_realms<R: Repository>(
    state: &SharedState<R>,
    client_id: &str,
) -> QidResult<Client> {
    let mut found = None;
    for realm_config in &state.config.realms {
        if let Some(client) = state
            .repo
            .get_client_by_client_id(&RealmId::from(realm_config.id.clone()), client_id)
            .await?
        {
            if found.is_some() {
                return Err(QidError::Unauthorized {
                    message: "client realm is ambiguous".to_string(),
                });
            }
            found = Some(client);
        }
    }
    found.ok_or_else(|| QidError::Unauthorized {
        message: "unknown client".to_string(),
    })
}

async fn client_id_is_registered<R: Repository>(
    state: &SharedState<R>,
    client_id: &str,
) -> QidResult<bool> {
    for realm_config in &state.config.realms {
        if state
            .repo
            .get_client_by_client_id(&RealmId::from(realm_config.id.clone()), client_id)
            .await?
            .is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use qid_core::{
        error::QidError,
        models::{
            AuthorizationCode, BackchannelAuthenticationGrant, Client, ClientType,
            DeviceAuthorizationGrant, ParRequest, TokenFamily, User,
        },
        state::SharedState,
        tenant::{RealmId, TenantId},
        test_helpers, util,
    };
    use qid_crypto::{JwtClaims, LocalSigner};
    use qid_storage::FileRepository;
    use qid_storage::prelude::*;

    use super::{TokenRequest, client_credentials_grant, refresh_token_grant};

    async fn setup_state() -> (Arc<SharedState<FileRepository>>, Arc<FileRepository>) {
        let config = test_helpers::test_config();
        let tmp = std::env::temp_dir().join(format!("qid_oauth_unit_{}.json", ulid::Ulid::new()));
        let path = tmp.to_str().unwrap().to_string();
        let repo = Arc::new(FileRepository::new(&path).await.unwrap());
        repo.migrate().await.unwrap();
        qid_storage::RealmRepository::create_realm(
            repo.as_ref(),
            &TenantId::from("tenant-1"),
            &RealmId::from("test"),
            "https://id.example.com",
            Some("Test Realm"),
        )
        .await
        .unwrap();
        let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
        let jwks = serde_json::json!({});
        let state = Arc::new(SharedState::new(config, repo.clone(), signer, jwks).unwrap());
        (state, repo)
    }

    #[tokio::test]
    async fn concurrent_authorization_code_use_detected() {
        let (_state, repo) = setup_state().await;
        let code_hash = "concurrent-double-spend-hash";
        let now = util::now_seconds();
        let auth_code = AuthorizationCode {
            code_hash: code_hash.to_string(),
            client_id: "client-id".to_string(),
            user_id: "user-id".to_string(),
            realm_id: "test".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            state: None,
            nonce: None,
            auth_time: None,
            acr: None,
            amr: Vec::new(),
            code_challenge: None,
            code_challenge_method: None,
            scopes: vec!["openid".to_string()],
            resource: Vec::new(),
            authorization_details: None,
            expires_at: now + 3600,
            used: false,
            created_at: now,
        };
        repo.create_authorization_code(&auth_code).await.unwrap();

        let r1 = repo.mark_authorization_code_used(code_hash);
        let r2 = repo.mark_authorization_code_used(code_hash);
        let (r1, r2) = tokio::join!(r1, r2);

        assert!(r1.is_ok() || r2.is_ok(), "at least one call must succeed");
        assert!(
            r1.is_err() || r2.is_err(),
            "at least one call must be rejected"
        );
        if let Err(e) = &r1 {
            assert!(
                matches!(e, QidError::Conflict { .. }),
                "failure must be Conflict, got {e:?}"
            );
        }
        if let Err(e) = &r2 {
            assert!(
                matches!(e, QidError::Conflict { .. }),
                "failure must be Conflict, got {e:?}"
            );
        }
    }

    #[tokio::test]
    async fn concurrent_par_request_use_detected() {
        let (_state, repo) = setup_state().await;
        let request_uri = "urn:ietf:params:oauth:request_uri:concurrent-par";
        let now = util::now_seconds();
        let par = ParRequest {
            request_uri: request_uri.to_string(),
            client_id: "par-client".to_string(),
            realm_id: "test".to_string(),
            params_json: serde_json::json!({ "client_id": "par-client" }),
            expires_at: now + 3600,
            used: false,
            created_at: now,
        };
        repo.store_par_request(&par).await.unwrap();

        let r1 = repo.mark_par_request_used(request_uri);
        let r2 = repo.mark_par_request_used(request_uri);
        let (r1, r2) = tokio::join!(r1, r2);

        assert!(r1.is_ok() || r2.is_ok(), "at least one call must succeed");
        assert!(
            r1.is_err() || r2.is_err(),
            "at least one call must be rejected"
        );
        if let Err(e) = &r1 {
            assert!(
                matches!(e, QidError::Conflict { .. }),
                "failure must be Conflict, got {e:?}"
            );
        }
        if let Err(e) = &r2 {
            assert!(
                matches!(e, QidError::Conflict { .. }),
                "failure must be Conflict, got {e:?}"
            );
        }
    }

    #[tokio::test]
    async fn concurrent_device_code_consumption_detected() {
        let (_state, repo) = setup_state().await;
        let device_code_hash = "concurrent-device-code-hash";
        let now = util::now_seconds();
        let grant = DeviceAuthorizationGrant {
            device_code_hash: device_code_hash.to_string(),
            user_code: "CONCURRENT".to_string(),
            client_id: "device-client".to_string(),
            realm_id: "test".to_string(),
            scopes: vec!["openid".to_string()],
            user_id: None,
            expires_at: now + 3600,
            approved_at: None,
            consumed: false,
            last_poll_at: None,
            poll_interval_seconds: 5,
            created_at: now,
        };
        repo.store_device_authorization_grant(&grant).await.unwrap();

        let r1 = repo.consume_device_authorization_grant(device_code_hash);
        let r2 = repo.consume_device_authorization_grant(device_code_hash);
        let (r1, r2) = tokio::join!(r1, r2);

        assert!(r1.is_ok() || r2.is_ok(), "at least one call must succeed");
        assert!(
            r1.is_err() || r2.is_err(),
            "at least one call must be rejected"
        );
        if let Err(e) = &r1 {
            assert!(
                matches!(e, QidError::Conflict { .. }),
                "failure must be Conflict, got {e:?}"
            );
        }
        if let Err(e) = &r2 {
            assert!(
                matches!(e, QidError::Conflict { .. }),
                "failure must be Conflict, got {e:?}"
            );
        }
    }

    #[tokio::test]
    async fn refresh_reuse_triggers_family_revocation() {
        let (state, repo) = setup_state().await;
        let now = util::now_seconds();

        let client = Client {
            id: "reuse-client-id".to_string(),
            realm_id: "test".to_string(),
            client_id: "reuse-client".to_string(),
            client_type: ClientType::Confidential,
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            client_secret_hash: None,
            mtls_certificate_thumbprints: Vec::new(),
            jwks: serde_json::json!({ "keys": [] }),
            redirect_uris: Vec::new(),
            grant_types: vec!["refresh_token".to_string()],
            client_name: None,
            client_uri: None,
            logo_uri: None,
            contacts: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            default_max_age: None,
            require_auth_time: false,
            sector_identifier_uri: None,
            subject_type: None,
            backchannel_logout_uri: None,
            frontchannel_logout_uri: None,
            backchannel_client_notification_endpoint: None,
        };
        repo.create_client(&client).await.unwrap();

        let user = User {
            id: "refresh-reuse-user".to_string(),
            realm_id: "test".to_string(),
            email: None,
            email_verified: false,
            display_name: Some("test-user".to_string()),
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        };
        repo.create_user(&user).await.unwrap();

        let good_jti = "original-jti";
        let good_hash = util::sha256_base64url(good_jti);
        let family = TokenFamily {
            id: "reuse-test-family".to_string(),
            user_id: user.id.clone(),
            client_id: "reuse-client".to_string(),
            realm_id: "test".to_string(),
            current_refresh_hash: good_hash,
            audience: vec!["reuse-client".to_string()],
            resource: Vec::new(),
            authorization_details: None,
            sender_constraint: None,
            issued_at: now,
            revoked: false,
        };
        repo.create_token_family(&family).await.unwrap();

        let bad_jti = "reused-jti";
        let mut extra = HashMap::new();
        extra.insert(
            "family_id".to_string(),
            serde_json::Value::String(family.id.clone()),
        );
        let claims = JwtClaims {
            iss: Some("https://id.example.com".to_string()),
            sub: Some(user.id.clone()),
            aud: Some("reuse-client".to_string()),
            exp: Some((now + 3600) as usize),
            nbf: Some(now as usize),
            iat: Some(now as usize),
            jti: Some(bad_jti.to_string()),
            extra,
        };
        let bad_refresh = state.signer.sign(&claims).unwrap();

        let req = TokenRequest {
            grant_type: "refresh_token".to_string(),
            refresh_token: Some(bad_refresh),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            client_id: None,
            client_secret: None,
            scope: None,
            client_assertion: None,
            client_assertion_type: None,
            device_code: None,
            auth_req_id: None,
            assertion: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            resource: None,
            authorization_details: None,
        };

        let result = refresh_token_grant(&state, &req, None).await;
        assert!(result.is_err(), "reuse should be rejected");

        let updated = repo.get_token_family(&family.id).await.unwrap().unwrap();
        assert!(
            updated.revoked,
            "token family must be revoked after reuse detection"
        );
    }

    #[tokio::test]
    async fn non_first_realm_client_credentials() {
        let mut config = test_helpers::test_config();
        config.realms[0].issuer = "https://id.example.com/realms/test".to_string();
        let mut realm_b = config.realms[0].clone();
        realm_b.id = "realm-b".to_string();
        realm_b.issuer = "https://id.example.com/realms/realm-b".to_string();
        realm_b.protocols.oauth.tokens.access_token_ttl_seconds = 123;
        config.realms.push(realm_b);

        let tmp = std::env::temp_dir().join(format!("qid_oauth_unit_{}.json", ulid::Ulid::new()));
        let path = tmp.to_str().unwrap().to_string();
        let repo = Arc::new(FileRepository::new(&path).await.unwrap());
        repo.migrate().await.unwrap();
        qid_storage::RealmRepository::create_realm(
            repo.as_ref(),
            &TenantId::from("tenant-1"),
            &RealmId::from("test"),
            "https://id.example.com",
            Some("Test Realm"),
        )
        .await
        .unwrap();
        qid_storage::RealmRepository::create_realm(
            repo.as_ref(),
            &TenantId::from("tenant-1"),
            &RealmId::from("realm-b"),
            "https://id.example.com/realms/realm-b",
            Some("Realm B"),
        )
        .await
        .unwrap();

        let client = Client {
            id: "realm-b-client-id".to_string(),
            realm_id: "realm-b".to_string(),
            client_id: "client-in-realm-b".to_string(),
            client_type: ClientType::Confidential,
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            client_secret_hash: None,
            mtls_certificate_thumbprints: Vec::new(),
            jwks: serde_json::json!({ "keys": [] }),
            redirect_uris: Vec::new(),
            grant_types: vec!["client_credentials".to_string()],
            client_name: None,
            client_uri: None,
            logo_uri: None,
            contacts: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            default_max_age: None,
            require_auth_time: false,
            sector_identifier_uri: None,
            subject_type: None,
            backchannel_logout_uri: None,
            frontchannel_logout_uri: None,
            backchannel_client_notification_endpoint: None,
        };
        repo.create_client(&client).await.unwrap();

        let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
        let jwks = serde_json::json!({});
        let state = Arc::new(SharedState::new(config, repo.clone(), signer, jwks).unwrap());

        let req = TokenRequest {
            grant_type: "client_credentials".to_string(),
            client_id: Some("client-in-realm-b".to_string()),
            scope: Some("api".to_string()),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            client_secret: None,
            refresh_token: None,
            client_assertion: None,
            client_assertion_type: None,
            device_code: None,
            auth_req_id: None,
            assertion: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audience: None,
            resource: None,
            authorization_details: None,
        };

        let result = client_credentials_grant(&state, &req, "client-in-realm-b", None).await;
        assert!(
            result.is_ok(),
            "client_credentials_grant should succeed: {:?}",
            result
        );

        let resp = result.unwrap();
        assert_eq!(resp.expires_in, 123);
        let token_data = state
            .signer
            .decode_signature_only(&resp.access_token)
            .unwrap();
        assert_eq!(
            token_data.claims.iss.as_deref(),
            Some("https://id.example.com/realms/realm-b"),
            "token issuer should be realm-b, not the first realm"
        );
        let jti = token_data.claims.jti.as_deref().unwrap();
        let stored = repo.get_access_token(jti).await.unwrap().unwrap();
        assert_eq!(stored.expires_at, stored.issued_at + 123);
    }

    #[tokio::test]
    async fn concurrent_ciba_grant_consumption_detected() {
        let (_state, repo) = setup_state().await;
        let auth_req_id_hash = "concurrent-ciba-hash";
        let now = util::now_seconds();
        let grant = BackchannelAuthenticationGrant {
            auth_req_id_hash: auth_req_id_hash.to_string(),
            client_id: "ciba-client".to_string(),
            realm_id: "test".to_string(),
            login_hint: "user@example.com".to_string(),
            binding_message: None,
            scopes: vec!["openid".to_string()],
            user_id: None,
            expires_at: now + 3600,
            approved_at: None,
            consumed: false,
            last_poll_at: None,
            poll_interval_seconds: 5,
            created_at: now,
        };
        repo.store_backchannel_authentication_grant(&grant)
            .await
            .unwrap();

        let r1 = repo.consume_backchannel_authentication_grant(auth_req_id_hash);
        let r2 = repo.consume_backchannel_authentication_grant(auth_req_id_hash);
        let (r1, r2) = tokio::join!(r1, r2);

        assert!(r1.is_ok() || r2.is_ok(), "at least one call must succeed");
        assert!(
            r1.is_err() || r2.is_err(),
            "at least one call must be rejected"
        );
        if let Err(e) = &r1 {
            assert!(
                matches!(e, QidError::Conflict { .. }),
                "failure must be Conflict, got {e:?}"
            );
        }
        if let Err(e) = &r2 {
            assert!(
                matches!(e, QidError::Conflict { .. }),
                "failure must be Conflict, got {e:?}"
            );
        }
    }

    #[tokio::test]
    async fn concurrent_session_creation_detected() {
        let (_state, repo) = setup_state().await;
        let now = util::now_seconds();
        let session = qid_core::models::Session {
            id: "concurrent-session-id".to_string(),
            realm_id: "test".to_string(),
            user_id: "user-id".to_string(),
            auth_time: now,
            acr: None,
            amr: Vec::new(),
            absolute_expires_at: now + 3600,
            idle_expires_at: now + 900,
            revoked: false,
            created_at: now,
            cnf: None,
        };
        repo.create_session(&session).await.unwrap();

        let r1 = repo.create_session(&session);
        let r2 = repo.create_session(&session);
        let (r1, r2) = tokio::join!(r1, r2);

        assert!(
            r1.is_err() || r2.is_err(),
            "duplicate session creation must be rejected"
        );
    }
}
