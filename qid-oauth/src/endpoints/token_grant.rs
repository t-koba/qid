//! OAuth 2.0 token grant handlers.

use qid_core::{
    error::{QidError, QidResult},
    models::{AccessToken, Client, ClientType, ServiceAccount, User},
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
    authenticated_client: &Client,
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

    // RFC 6749 section 6 and RFC 9700 section 4.13: the refresh token must
    // have been issued to the authenticated caller. The `aud` claim carries
    // the original client_id; it must match the caller before any mutation
    // so foreign attempts cannot consume or revoke the owner's family.
    let refresh_aud = claims
        .aud
        .as_deref()
        .ok_or_else(|| QidError::Unauthorized {
            message: "refresh token missing aud claim".to_string(),
        })?;
    if refresh_aud != authenticated_client.client_id {
        return Err(QidError::Unauthorized {
            message: "refresh token was not issued to authenticated client".to_string(),
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
    if family.client_id != authenticated_client.client_id
        || family.realm_id != authenticated_client.realm_id
    {
        return Err(QidError::Unauthorized {
            message: "refresh token was not issued to authenticated client".to_string(),
        });
    }

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
    // RFC 6749 section 6: refresh preserves the original scope ceiling.
    // Omitted scope means the originally granted scopes; an explicit scope
    // must be a subset of that grant. The family ceiling never widens on
    // refresh, even when one access-token request narrows scope. Families
    // without trustworthy scope state fail closed and require fresh
    // authorization rather than inheriting the current default.
    if family.scopes.is_empty() {
        return Err(QidError::Unauthorized {
            message: "refresh token scope is not established".to_string(),
        });
    }
    let scopes = match req.scope.as_deref() {
        Some(requested) => {
            let narrowed: Vec<String> = requested.split_whitespace().map(str::to_string).collect();
            for scope in &narrowed {
                if !family.scopes.contains(scope) {
                    return Err(QidError::BadRequest {
                        message: format!("requested scope {scope} exceeds granted scope"),
                    });
                }
            }
            narrowed
        }
        None => family.scopes.clone(),
    };

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

    // DPoP refresh token binding enforcement (RFC 9449 section 5):
    // if the original token family is bound to a DPoP key and belongs to a
    // public client, the refresh request must present a matching DPoP proof.
    // Confidential families stay bound via client authentication instead.
    if let Some(sender) = &family.sender_constraint
        && sender.get("jkt").and_then(|v| v.as_str()).is_some()
    {
        let client = state
            .repo
            .get_client_by_client_id(&RealmId::from(family.realm_id.clone()), &family.client_id)
            .await?
            .ok_or_else(|| QidError::Unauthorized {
                message: "unknown client".to_string(),
            })?;
        if client.client_type == ClientType::Public {
            let expected = sender.get("jkt").and_then(|v| v.as_str()).unwrap_or("");
            let presented = cnf
                .and_then(|c| c.get("jkt"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if presented.is_empty() || !qid_core::util::constant_time_eq(expected, presented) {
                return Err(QidError::Unauthorized {
                    message: "DPoP binding required for refresh token".to_string(),
                });
            }
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

    // Atomically consume the presented refresh hash before issuing anything:
    // only one overlapping redemption can win; the loser is handled as reuse
    // below and leaves no usable access token behind.
    if let Err(rotate_err) = state
        .repo
        .update_token_family_refresh_hash(&family.id, &expected_hash, &new_hash)
        .await
    {
        match rotate_err {
            QidError::NotFound { .. } => {
                return Err(QidError::Unauthorized {
                    message: "invalid refresh token".to_string(),
                });
            }
            QidError::Conflict { .. } => {
                metrics::counter!("qid_refresh_reuse_detected_total").increment(1);
                if let Err(revoke_err) = state.repo.revoke_token_family(&family.id).await {
                    tracing::warn!(error = %revoke_err, family_id = %family.id, "revoke_token_family failed after refresh reuse detection");
                }
                return Err(QidError::Unauthorized {
                    message: "invalid refresh token".to_string(),
                });
            }
            other => return Err(other),
        }
    }

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
        auth_time: family.auth_time,
        acr: family.acr.clone(),
        amr: family.amr.clone(),
        nonce: None,
        sender_constraint: cnf.cloned().or(family.sender_constraint.clone()),
        token_format: token_ttl(state, &family.realm_id).access_token_format,
        expires_at: now + token_ttl(state, &family.realm_id).access_token_ttl_seconds,
        revoked: false,
        issued_at: now,
    };
    state.repo.create_access_token(&access_token).await?;

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
            auth_time: family.auth_time,
            acr: family.acr.as_deref(),
            amr: Some(&family.amr),
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

    fn refresh_test_client(
        id: &str,
        client_id: &str,
        client_type: ClientType,
        auth_method: &str,
    ) -> Client {
        Client {
            id: id.to_string(),
            realm_id: "test".to_string(),
            client_id: client_id.to_string(),
            client_type,
            token_endpoint_auth_method: auth_method.to_string(),
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
        }
    }

    async fn signed_refresh(
        state: &std::sync::Arc<SharedState<FileRepository>>,
        user_id: &str,
        client_id: &str,
        family_id: &str,
        jti: &str,
    ) -> String {
        let now = util::now_seconds();
        let mut extra = HashMap::new();
        extra.insert(
            "family_id".to_string(),
            serde_json::Value::String(family_id.to_string()),
        );
        let claims = JwtClaims {
            iss: Some("https://id.example.com".to_string()),
            sub: Some(user_id.to_string()),
            aud: Some(client_id.to_string()),
            exp: Some((now + 3600) as usize),
            nbf: Some(now as usize),
            iat: Some(now as usize),
            jti: Some(jti.to_string()),
            extra,
        };
        state.signer.sign(&claims).unwrap()
    }

    fn refresh_req(token: String, scope: Option<String>) -> TokenRequest {
        TokenRequest {
            grant_type: "refresh_token".to_string(),
            refresh_token: Some(token),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            client_id: None,
            client_secret: None,
            scope,
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
        }
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

        let client = refresh_test_client(
            "reuse-client-id",
            "reuse-client",
            ClientType::Confidential,
            "client_secret_basic",
        );
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
            scopes: vec!["api".to_string()],
            auth_time: None,
            acr: None,
            amr: Vec::new(),
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

        let result = refresh_token_grant(&state, &req, &client, None).await;
        assert!(result.is_err(), "reuse should be rejected");

        let updated = repo.get_token_family(&family.id).await.unwrap().unwrap();
        assert!(
            updated.revoked,
            "token family must be revoked after reuse detection"
        );
    }

    #[tokio::test]
    async fn dpop_bound_public_refresh_requires_same_key_proof() {
        // RFC 9449 section 5 + RFC 9700 BCP 240: public DPoP-bound refresh
        // must prove the same key; confidential refresh stays bound via
        // client authentication.
        let (state, repo) = setup_state().await;
        let now = util::now_seconds();

        let public_client =
            refresh_test_client("dpop-public-id", "dpop-public", ClientType::Public, "none");
        repo.create_client(&public_client).await.unwrap();

        let confidential_client = refresh_test_client(
            "dpop-conf-id",
            "dpop-conf",
            ClientType::Confidential,
            "client_secret_basic",
        );
        repo.create_client(&confidential_client).await.unwrap();

        let user = User {
            id: "dpop-refresh-user".to_string(),
            realm_id: "test".to_string(),
            email: None,
            email_verified: false,
            display_name: Some("dpop-user".to_string()),
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        };
        repo.create_user(&user).await.unwrap();

        // Public DPoP-bound family.
        let bound_jkt = "test-jkt-public-key-a";
        let family = TokenFamily {
            id: "dpop-public-family".to_string(),
            user_id: user.id.clone(),
            client_id: "dpop-public".to_string(),
            realm_id: "test".to_string(),
            current_refresh_hash: util::sha256_base64url("dpop-good-jti"),
            scopes: vec!["api".to_string()],
            auth_time: None,
            acr: None,
            amr: Vec::new(),
            audience: vec!["dpop-public".to_string()],
            resource: Vec::new(),
            authorization_details: None,
            sender_constraint: Some(serde_json::json!({ "jkt": bound_jkt })),
            issued_at: now,
            revoked: false,
        };
        repo.create_token_family(&family).await.unwrap();

        // No DPoP proof must fail closed.
        let token =
            signed_refresh(&state, &user.id, "dpop-public", &family.id, "dpop-good-jti").await;
        let err = refresh_token_grant(&state, &refresh_req(token, None), &public_client, None)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("DPoP binding required"),
            "no-proof refresh must fail closed, got {err:?}"
        );

        // Wrong-key proof must fail closed.
        let wrong = serde_json::json!({ "jkt": "different-key" });
        let token =
            signed_refresh(&state, &user.id, "dpop-public", &family.id, "dpop-good-jti").await;
        let err = refresh_token_grant(
            &state,
            &refresh_req(token, None),
            &public_client,
            Some(&wrong),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("DPoP binding required"),
            "wrong-key refresh must fail closed, got {err:?}"
        );

        // Same-key proof must succeed and rotate.
        let same = serde_json::json!({ "jkt": bound_jkt });
        let token =
            signed_refresh(&state, &user.id, "dpop-public", &family.id, "dpop-good-jti").await;
        let ok = refresh_token_grant(
            &state,
            &refresh_req(token, None),
            &public_client,
            Some(&same),
        )
        .await;
        assert!(ok.is_ok(), "same-key refresh must succeed: {ok:?}");

        // Confidential DPoP-bound family without fresh proof still succeeds
        // (bound via client authentication, per RFC 9449 section 5).
        let conf_family = TokenFamily {
            id: "dpop-conf-family".to_string(),
            user_id: user.id.clone(),
            client_id: "dpop-conf".to_string(),
            realm_id: "test".to_string(),
            current_refresh_hash: util::sha256_base64url("dpop-conf-jti"),
            scopes: vec!["api".to_string()],
            auth_time: None,
            acr: None,
            amr: Vec::new(),
            audience: vec!["dpop-conf".to_string()],
            resource: Vec::new(),
            authorization_details: None,
            sender_constraint: Some(serde_json::json!({ "jkt": "conf-key" })),
            issued_at: now,
            revoked: false,
        };
        repo.create_token_family(&conf_family).await.unwrap();
        let token = signed_refresh(
            &state,
            &user.id,
            "dpop-conf",
            &conf_family.id,
            "dpop-conf-jti",
        )
        .await;
        let ok = refresh_token_grant(
            &state,
            &refresh_req(token, None),
            &confidential_client,
            None,
        )
        .await;
        assert!(ok.is_ok(), "confidential refresh must succeed: {ok:?}");
    }

    #[tokio::test]
    async fn refresh_preserves_original_scope_ceiling_file() {
        // File-repository counterpart to the SQL HTTP fixture: omitted scope
        // means the original grant, explicit scope must be a subset, failures
        // do not consume the refresh token, and the family ceiling survives
        // narrowing. Legacy families without scope state fail closed.
        let (state, repo) = setup_state().await;
        let client = refresh_test_client(
            "scope-file-id",
            "scope-file-client",
            ClientType::Public,
            "none",
        );
        repo.create_client(&client).await.unwrap();
        let user = User {
            id: "scope-file-user".to_string(),
            realm_id: "test".to_string(),
            email: None,
            email_verified: false,
            display_name: None,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        };
        repo.create_user(&user).await.unwrap();

        let now = util::now_seconds();
        let family = TokenFamily {
            id: "scope-file-family".to_string(),
            user_id: user.id.clone(),
            client_id: "scope-file-client".to_string(),
            realm_id: "test".to_string(),
            current_refresh_hash: util::sha256_base64url("scope-file-jti-1"),
            scopes: vec!["read".to_string(), "profile".to_string()],
            auth_time: None,
            acr: None,
            amr: Vec::new(),
            audience: vec!["scope-file-client".to_string()],
            resource: Vec::new(),
            authorization_details: None,
            sender_constraint: None,
            issued_at: now,
            revoked: false,
        };
        repo.create_token_family(&family).await.unwrap();

        let token_1 = signed_refresh(
            &state,
            "scope-file-user",
            "scope-file-client",
            &family.id,
            "scope-file-jti-1",
        )
        .await;
        let first = refresh_token_grant(&state, &refresh_req(token_1, None), &client, None)
            .await
            .unwrap();
        assert_eq!(first.scope.as_deref(), Some("read profile"));
        let token_2 = first.refresh_token.clone().unwrap();

        let narrowed = refresh_token_grant(
            &state,
            &refresh_req(token_2, Some("read".to_string())),
            &client,
            None,
        )
        .await
        .unwrap();
        assert_eq!(narrowed.scope.as_deref(), Some("read"));
        let token_3 = narrowed.refresh_token.clone().unwrap();

        let restored = refresh_token_grant(&state, &refresh_req(token_3, None), &client, None)
            .await
            .unwrap();
        assert_eq!(restored.scope.as_deref(), Some("read profile"));
        let token_4 = restored.refresh_token.clone().unwrap();

        let before = repo
            .get_token_family(&family.id)
            .await
            .unwrap()
            .unwrap()
            .current_refresh_hash;
        let err = refresh_token_grant(
            &state,
            &refresh_req(token_4.clone(), Some("write".to_string())),
            &client,
            None,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, QidError::BadRequest { .. }),
            "exceeding scope must be invalid_scope, got {err:?}"
        );
        let after = repo
            .get_token_family(&family.id)
            .await
            .unwrap()
            .unwrap()
            .current_refresh_hash;
        assert_eq!(before, after, "failed scope check must not consume refresh");
        let retry = refresh_token_grant(&state, &refresh_req(token_4, None), &client, None)
            .await
            .unwrap();
        assert_eq!(retry.scope.as_deref(), Some("read profile"));

        let legacy = TokenFamily {
            id: "scope-legacy-family".to_string(),
            user_id: user.id.clone(),
            client_id: "scope-file-client".to_string(),
            realm_id: "test".to_string(),
            current_refresh_hash: util::sha256_base64url("scope-legacy-jti"),
            scopes: Vec::new(),
            auth_time: None,
            acr: None,
            amr: Vec::new(),
            audience: vec!["scope-file-client".to_string()],
            resource: Vec::new(),
            authorization_details: None,
            sender_constraint: None,
            issued_at: now,
            revoked: false,
        };
        repo.create_token_family(&legacy).await.unwrap();
        let legacy_token = signed_refresh(
            &state,
            "scope-file-user",
            "scope-file-client",
            &legacy.id,
            "scope-legacy-jti",
        )
        .await;
        let err = refresh_token_grant(&state, &refresh_req(legacy_token, None), &client, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, QidError::Unauthorized { .. }),
            "legacy family without scope ceiling must fail closed, got {err:?}"
        );
    }

    #[tokio::test]
    async fn refresh_preserves_original_authentication_context_file() {
        // File-repository counterpart: original auth_time/acr/amr survive
        // refresh with advancing issuance; unknown context stays omitted.
        let (state, repo) = setup_state().await;
        let client = refresh_test_client(
            "auth-file-id",
            "auth-file-client",
            ClientType::Public,
            "none",
        );
        repo.create_client(&client).await.unwrap();
        let user = User {
            id: "auth-file-user".to_string(),
            realm_id: "test".to_string(),
            email: None,
            email_verified: false,
            display_name: None,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        };
        repo.create_user(&user).await.unwrap();

        let now = util::now_seconds();
        let original_auth_time = now - 3600;
        let family = TokenFamily {
            id: "auth-file-family".to_string(),
            user_id: user.id.clone(),
            client_id: "auth-file-client".to_string(),
            realm_id: "test".to_string(),
            current_refresh_hash: util::sha256_base64url("auth-file-jti-1"),
            scopes: vec!["openid".to_string()],
            auth_time: Some(original_auth_time),
            acr: Some("urn:qid:acr:password".to_string()),
            amr: vec!["pwd".to_string()],
            audience: vec!["auth-file-client".to_string()],
            resource: Vec::new(),
            authorization_details: None,
            sender_constraint: None,
            issued_at: now - 3600,
            revoked: false,
        };
        repo.create_token_family(&family).await.unwrap();

        let token_1 = signed_refresh(
            &state,
            "auth-file-user",
            "auth-file-client",
            &family.id,
            "auth-file-jti-1",
        )
        .await;
        let refreshed = refresh_token_grant(&state, &refresh_req(token_1, None), &client, None)
            .await
            .unwrap();
        let access = refreshed.access_token.clone();
        let claims = state.signer.decode_signature_only(&access).unwrap().claims;
        assert_eq!(
            claims.extra["auth_time"],
            serde_json::json!(original_auth_time)
        );
        assert_eq!(
            claims.extra["acr"],
            serde_json::json!("urn:qid:acr:password")
        );
        assert_eq!(claims.extra["amr"], serde_json::json!(["pwd"]));
        assert!(u64::try_from(claims.iat.unwrap()).unwrap() >= now);
        let stored = repo
            .get_access_token(&claims.jti.clone().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.auth_time, Some(original_auth_time));
        assert_eq!(stored.acr.as_deref(), Some("urn:qid:acr:password"));
        assert_eq!(stored.amr, vec!["pwd".to_string()]);

        let legacy = TokenFamily {
            id: "auth-legacy-family".to_string(),
            user_id: user.id.clone(),
            client_id: "auth-file-client".to_string(),
            realm_id: "test".to_string(),
            current_refresh_hash: util::sha256_base64url("auth-legacy-jti"),
            scopes: vec!["openid".to_string()],
            auth_time: None,
            acr: None,
            amr: Vec::new(),
            audience: vec!["auth-file-client".to_string()],
            resource: Vec::new(),
            authorization_details: None,
            sender_constraint: None,
            issued_at: now,
            revoked: false,
        };
        repo.create_token_family(&legacy).await.unwrap();
        let legacy_token = signed_refresh(
            &state,
            "auth-file-user",
            "auth-file-client",
            &legacy.id,
            "auth-legacy-jti",
        )
        .await;
        let legacy_refreshed =
            refresh_token_grant(&state, &refresh_req(legacy_token, None), &client, None)
                .await
                .unwrap();
        let legacy_claims = state
            .signer
            .decode_signature_only(&legacy_refreshed.access_token)
            .unwrap()
            .claims;
        assert!(!legacy_claims.extra.contains_key("auth_time"));
        assert!(!legacy_claims.extra.contains_key("acr"));
        assert!(!legacy_claims.extra.contains_key("amr"));
    }

    #[tokio::test]
    async fn refresh_rejects_foreign_authenticated_caller_without_consuming() {
        // RFC 6749 section 6: only the owning client may redeem its family.
        // A foreign caller must fail before mutation so the owner's token
        // stays usable.
        let (state, repo) = setup_state().await;
        let now = util::now_seconds();
        let owner = refresh_test_client("owner-id", "owner-client", ClientType::Public, "none");
        let foreign =
            refresh_test_client("foreign-id", "foreign-client", ClientType::Public, "none");
        repo.create_client(&owner).await.unwrap();
        repo.create_client(&foreign).await.unwrap();
        let user = User {
            id: "owner-user".to_string(),
            realm_id: "test".to_string(),
            email: None,
            email_verified: false,
            display_name: None,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        };
        repo.create_user(&user).await.unwrap();
        let family = TokenFamily {
            id: "owner-family".to_string(),
            user_id: user.id.clone(),
            client_id: "owner-client".to_string(),
            realm_id: "test".to_string(),
            current_refresh_hash: util::sha256_base64url("owner-jti-1"),
            scopes: vec!["openid".to_string()],
            auth_time: None,
            acr: None,
            amr: Vec::new(),
            audience: vec!["owner-client".to_string()],
            resource: Vec::new(),
            authorization_details: None,
            sender_constraint: None,
            issued_at: now,
            revoked: false,
        };
        repo.create_token_family(&family).await.unwrap();

        let stolen = signed_refresh(
            &state,
            "owner-user",
            "owner-client",
            &family.id,
            "owner-jti-1",
        )
        .await;
        let before = repo
            .get_token_family(&family.id)
            .await
            .unwrap()
            .unwrap()
            .current_refresh_hash;
        let err = refresh_token_grant(&state, &refresh_req(stolen.clone(), None), &foreign, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, QidError::Unauthorized { .. }),
            "foreign caller must be rejected, got {err:?}"
        );
        let after = repo
            .get_token_family(&family.id)
            .await
            .unwrap()
            .unwrap()
            .current_refresh_hash;
        assert_eq!(before, after, "foreign attempt must not consume refresh");
        let ok = refresh_token_grant(&state, &refresh_req(stolen, None), &owner, None).await;
        assert!(ok.is_ok(), "owner must still succeed: {ok:?}");
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
