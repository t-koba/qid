//! OAuth 2.0 token grant handlers.

use qid_core::{
    error::{QidError, QidResult},
    models::{AccessToken, Client, ClientType, ServiceAccount, User},
    pkce::verify_code_verifier,
    state::SharedState,
    tenant::RealmId,
};
use qid_observability::audit::AuditEvent;
use qid_session::browser::session_is_active;
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
            access_expires_at: None,
            session_id: auth_code.session_id.as_deref(),
        },
    )
    .await?;

    log_token_issued(&auth_code.realm_id, &user.id);

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
                access_expires_at: None,
                session_id: None,
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

    let client = super::find_client_across_realms(state, client_id).await?;
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
            access_expires_at: None,
            session_id: None,
        },
    )
    .await?;

    log_token_issued(&realm_id, &sa.id);

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
        .as_ref()
        .and_then(qid_core::jwt::Audience::primary)
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

    // RFC 10017 section 6.3.2.3: rotation must not extend a token past the
    // initial expiration. The deadline persists with the family so later TTL
    // changes cannot extend existing grants; the rotation write pins legacy
    // families without one to issued_at plus the realm TTL.
    let now = qid_core::util::now_seconds();
    let refresh_deadline = family.refresh_expires_at.unwrap_or_else(|| {
        family
            .issued_at
            .saturating_add(token_ttl(state, &family.realm_id).refresh_token_ttl_seconds)
    });
    if now >= refresh_deadline {
        return Err(QidError::Unauthorized {
            message: "refresh token family expired".to_string(),
        });
    }

    // Logout linkage: a family authorized in a browser session dies with
    // it. Families without a known session are unaffected; a missing,
    // revoked, or expired session fails closed without consuming the token.
    if let Some(session_id) = &family.session_id
        && !state
            .repo
            .get_session(session_id)
            .await?
            .is_some_and(|session| {
                session.realm_id == family.realm_id && session_is_active(&session, now)
            })
    {
        return Err(QidError::Unauthorized {
            message: "refresh token family session ended".to_string(),
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

    let realm = state.require_realm(&family.realm_id)?;

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
        .update_token_family_refresh_hash(&family.id, &expected_hash, &new_hash, refresh_deadline)
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
        expires_at: now
            .saturating_add(token_ttl(state, &family.realm_id).access_token_ttl_seconds)
            .min(refresh_deadline),
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
            access_expires_at: Some(refresh_deadline),
            session_id: None,
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
        refresh_deadline,
    )?;

    let response_cnf = cnf.or(family.sender_constraint.as_ref());
    Ok(TokenResponse {
        access_token: access,
        token_type: access_token_type_for_cnf(response_cnf).to_string(),
        expires_in: refresh_deadline
            .saturating_sub(now)
            .min(token_ttl(state, &family.realm_id).access_token_ttl_seconds),
        refresh_token: Some(refresh),
        id_token: None,
        scope: Some(scopes.join(" ")),
        issued_token_type: None,
    })
}

fn log_token_issued(realm_id: &str, subject_id: &str) {
    let event = AuditEvent {
        r#type: "token.issued".to_string(),
        time: qid_core::util::now_seconds().to_string(),
        tenant: None,
        realm: Some(realm_id.to_string()),
        subject: Some(subject_id.to_string()),
        decision: Some("issued".to_string()),
        decision_id: None,
        extra: HashMap::new(),
    };
    tracing::info!(target: "audit", "{:?}", event);
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use qid_core::{
        error::{QidError, QidResult},
        models::{
            AuthorizationCode, BackchannelAuthenticationGrant, Client, ClientType,
            DeviceAuthorizationGrant, ParRequest, Session, TokenFamily, User,
        },
        state::SharedState,
        tenant::{RealmId, TenantId},
        test_helpers, util,
    };
    use qid_crypto::{Audience, JwtClaims, LocalSigner};
    use qid_storage::FileRepository;
    use qid_storage::prelude::*;

    use super::{
        TokenRequest, TokenResponse, authorization_code_grant, client_credentials_grant,
        refresh_token_grant,
    };

    async fn state_with_config(
        config: qid_core::config::QidConfig,
    ) -> (Arc<SharedState<FileRepository>>, Arc<FileRepository>) {
        let tmp = std::env::temp_dir().join(format!("qid_oauth_unit_{}.json", ulid::Ulid::new()));
        let path = tmp.to_str().unwrap().to_string();
        let repo = Arc::new(FileRepository::new(&path).await.unwrap());
        repo.migrate().await.unwrap();
        let signer = Arc::new(LocalSigner::from_secret("test", b"test-secret-for-tests"));
        let state = Arc::new(
            SharedState::new(config, repo.clone(), signer, serde_json::json!({})).unwrap(),
        );
        (state, repo)
    }

    async fn create_test_realm(repo: &FileRepository, realm: &str, issuer: &str) {
        qid_storage::RealmRepository::create_realm(
            repo,
            &TenantId::from("tenant-1"),
            &RealmId::from(realm),
            issuer,
            None,
        )
        .await
        .unwrap();
    }

    async fn setup_state() -> (Arc<SharedState<FileRepository>>, Arc<FileRepository>) {
        let (state, repo) = state_with_config(test_helpers::test_config()).await;
        create_test_realm(&repo, "test", "https://id.example.com").await;
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
        family: &TokenFamily,
        jti: &str,
    ) -> String {
        let now = util::now_seconds();
        let mut extra = HashMap::new();
        extra.insert(
            "family_id".to_string(),
            serde_json::Value::String(family.id.clone()),
        );
        let claims = JwtClaims {
            iss: Some("https://id.example.com".to_string()),
            sub: Some(family.user_id.clone()),
            aud: Some(Audience::single(family.client_id.clone())),
            exp: Some((now + 3600) as usize),
            nbf: Some(now as usize),
            iat: Some(now as usize),
            jti: Some(jti.to_string()),
            extra,
        };
        state.signer.sign(&claims).unwrap()
    }

    fn refresh_test_user(id: &str) -> User {
        User {
            id: id.to_string(),
            realm_id: "test".to_string(),
            email: None,
            email_verified: false,
            display_name: None,
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        }
    }

    fn refresh_test_family(
        id: &str,
        user_id: &str,
        client_id: &str,
        refresh_jti: &str,
        scopes: &[&str],
        issued_at: u64,
        deadline: Option<u64>,
    ) -> TokenFamily {
        TokenFamily {
            id: id.to_string(),
            user_id: user_id.to_string(),
            client_id: client_id.to_string(),
            realm_id: "test".to_string(),
            current_refresh_hash: util::sha256_base64url(refresh_jti),
            scopes: scopes.iter().map(ToString::to_string).collect(),
            auth_time: None,
            acr: None,
            amr: Vec::new(),
            audience: vec![client_id.to_string()],
            resource: Vec::new(),
            authorization_details: None,
            sender_constraint: None,
            issued_at,
            refresh_expires_at: deadline,
            session_id: None,
            revoked: false,
        }
    }

    async fn seed_linked_session(
        repo: &std::sync::Arc<FileRepository>,
        tag: &str,
        user_id: &str,
        absolute: u64,
    ) {
        let now = util::now_seconds();
        repo.create_session(&Session {
            id: format!("{tag}-session"),
            realm_id: "test".to_string(),
            user_id: user_id.to_string(),
            auth_time: now,
            acr: None,
            amr: Vec::new(),
            idle_expires_at: absolute,
            absolute_expires_at: absolute,
            revoked: false,
            created_at: now,
            cnf: None,
        })
        .await
        .unwrap();
    }

    async fn get_family(repo: &std::sync::Arc<FileRepository>, id: &str) -> TokenFamily {
        repo.get_token_family(id).await.unwrap().unwrap()
    }

    async fn family_hash(repo: &std::sync::Arc<FileRepository>, id: &str) -> String {
        get_family(repo, id).await.current_refresh_hash
    }

    async fn setup_refresh_case(
        tag: &str,
        issued_at: u64,
        deadline: Option<u64>,
        session_absolute: Option<u64>,
    ) -> (
        std::sync::Arc<SharedState<FileRepository>>,
        std::sync::Arc<FileRepository>,
        Client,
        TokenFamily,
        String,
    ) {
        let (state, repo) = setup_state().await;
        let client_id = format!("{tag}-client");
        let client =
            refresh_test_client(&format!("{tag}-id"), &client_id, ClientType::Public, "none");
        repo.create_client(&client).await.unwrap();
        let user = refresh_test_user(&format!("{tag}-user"));
        repo.create_user(&user).await.unwrap();
        let session_id = if let Some(absolute) = session_absolute {
            seed_linked_session(&repo, tag, &user.id, absolute).await;
            Some(format!("{tag}-session"))
        } else {
            None
        };
        let mut family = refresh_test_family(
            &format!("{tag}-family"),
            &user.id,
            &client_id,
            &format!("{tag}-jti-1"),
            &["api"],
            issued_at,
            deadline,
        );
        family.session_id = session_id;
        repo.create_token_family(&family).await.unwrap();
        let token = signed_refresh(&state, &family, &format!("{tag}-jti-1")).await;
        (state, repo, client, family, token)
    }

    async fn grant_refresh(
        state: &std::sync::Arc<SharedState<FileRepository>>,
        token: String,
        client: &Client,
        scope: Option<String>,
        cnf: Option<&serde_json::Value>,
    ) -> QidResult<TokenResponse> {
        refresh_token_grant(state, &refresh_req(token, scope), client, cnf).await
    }

    fn decode_exp(state: &std::sync::Arc<SharedState<FileRepository>>, token: &str) -> usize {
        state
            .signer
            .decode_signature_only(token)
            .unwrap()
            .claims
            .exp
            .unwrap()
    }

    fn refresh_req(token: String, scope: Option<String>) -> TokenRequest {
        TokenRequest {
            grant_type: "refresh_token".to_string(),
            refresh_token: Some(token),
            scope,
            ..Default::default()
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
            session_id: None,
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

        let mut user = refresh_test_user("refresh-reuse-user");
        user.display_name = Some("test-user".to_string());
        repo.create_user(&user).await.unwrap();

        let family = refresh_test_family(
            "reuse-test-family",
            &user.id.clone(),
            "reuse-client",
            "original-jti",
            &["api"],
            now,
            Some(now + 86_400),
        );
        repo.create_token_family(&family).await.unwrap();

        let bad_refresh = signed_refresh(&state, &family, "reused-jti").await;

        let result = grant_refresh(&state, bad_refresh, &client, None, None).await;
        assert!(result.is_err(), "reuse should be rejected");

        let updated = get_family(&repo, &family.id).await;
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

        let mut user = refresh_test_user("dpop-refresh-user");
        user.display_name = Some("dpop-user".to_string());
        repo.create_user(&user).await.unwrap();

        // Public DPoP-bound family.
        let bound_jkt = "test-jkt-public-key-a";
        let mut family = refresh_test_family(
            "dpop-public-family",
            &user.id.clone(),
            "dpop-public",
            "dpop-good-jti",
            &["api"],
            now,
            Some(now + 86_400),
        );
        family.sender_constraint = Some(serde_json::json!({ "jkt": bound_jkt }));
        repo.create_token_family(&family).await.unwrap();

        // No DPoP proof must fail closed.
        let token = signed_refresh(&state, &family, "dpop-good-jti").await;
        let err = grant_refresh(&state, token, &public_client, None, None)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("DPoP binding required"),
            "no-proof refresh must fail closed, got {err:?}"
        );

        // Wrong-key proof must fail closed.
        let wrong = serde_json::json!({ "jkt": "different-key" });
        let token = signed_refresh(&state, &family, "dpop-good-jti").await;
        let err = grant_refresh(&state, token, &public_client, None, Some(&wrong))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("DPoP binding required"),
            "wrong-key refresh must fail closed, got {err:?}"
        );

        // Same-key proof must succeed and rotate.
        let same = serde_json::json!({ "jkt": bound_jkt });
        let token = signed_refresh(&state, &family, "dpop-good-jti").await;
        let ok = grant_refresh(&state, token, &public_client, None, Some(&same)).await;
        assert!(ok.is_ok(), "same-key refresh must succeed: {ok:?}");

        // Confidential DPoP-bound family without fresh proof still succeeds
        // (bound via client authentication, per RFC 9449 section 5).
        let conf_family = refresh_test_family(
            "dpop-conf-family",
            &user.id.clone(),
            "dpop-conf",
            "dpop-conf-jti",
            &["api"],
            now,
            Some(now + 86_400),
        );
        repo.create_token_family(&conf_family).await.unwrap();
        let token = signed_refresh(&state, &conf_family, "dpop-conf-jti").await;
        let ok = grant_refresh(&state, token, &confidential_client, None, None).await;
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
        let user = refresh_test_user("scope-file-user");
        repo.create_user(&user).await.unwrap();

        let now = util::now_seconds();
        let family = refresh_test_family(
            "scope-file-family",
            &user.id.clone(),
            "scope-file-client",
            "scope-file-jti-1",
            &["read", "profile"],
            now,
            Some(now + 86_400),
        );
        repo.create_token_family(&family).await.unwrap();

        let token_1 = signed_refresh(&state, &family, "scope-file-jti-1").await;
        let first = grant_refresh(&state, token_1, &client, None, None)
            .await
            .unwrap();
        assert_eq!(first.scope.as_deref(), Some("read profile"));
        let token_2 = first.refresh_token.clone().unwrap();

        let narrowed = grant_refresh(&state, token_2, &client, Some("read".to_string()), None)
            .await
            .unwrap();
        assert_eq!(narrowed.scope.as_deref(), Some("read"));
        let token_3 = narrowed.refresh_token.clone().unwrap();

        let restored = grant_refresh(&state, token_3, &client, None, None)
            .await
            .unwrap();
        assert_eq!(restored.scope.as_deref(), Some("read profile"));
        let token_4 = restored.refresh_token.clone().unwrap();

        let before = family_hash(&repo, &family.id).await;
        let err = grant_refresh(
            &state,
            token_4.clone(),
            &client,
            Some("write".to_string()),
            None,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, QidError::BadRequest { .. }),
            "exceeding scope must be invalid_scope, got {err:?}"
        );
        let after = family_hash(&repo, &family.id).await;
        assert_eq!(before, after, "failed scope check must not consume refresh");
        let retry = grant_refresh(&state, token_4, &client, None, None)
            .await
            .unwrap();
        assert_eq!(retry.scope.as_deref(), Some("read profile"));

        let legacy = refresh_test_family(
            "scope-legacy-family",
            &user.id.clone(),
            "scope-file-client",
            "scope-legacy-jti",
            &[],
            now,
            None,
        );
        repo.create_token_family(&legacy).await.unwrap();
        let legacy_token = signed_refresh(&state, &legacy, "scope-legacy-jti").await;
        let err = grant_refresh(&state, legacy_token, &client, None, None)
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
        let user = refresh_test_user("auth-file-user");
        repo.create_user(&user).await.unwrap();

        let now = util::now_seconds();
        let original_auth_time = now - 3600;
        let mut family = refresh_test_family(
            "auth-file-family",
            &user.id.clone(),
            "auth-file-client",
            "auth-file-jti-1",
            &["openid"],
            now - 3600,
            Some(now + 86_400),
        );
        family.auth_time = Some(original_auth_time);
        family.acr = Some("urn:qid:acr:password".to_string());
        family.amr = vec!["pwd".to_string()];
        repo.create_token_family(&family).await.unwrap();

        let token_1 = signed_refresh(&state, &family, "auth-file-jti-1").await;
        let refreshed = grant_refresh(&state, token_1, &client, None, None)
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

        let legacy = refresh_test_family(
            "auth-legacy-family",
            &user.id.clone(),
            "auth-file-client",
            "auth-legacy-jti",
            &["openid"],
            now,
            None,
        );
        repo.create_token_family(&legacy).await.unwrap();
        let legacy_token = signed_refresh(&state, &legacy, "auth-legacy-jti").await;
        let legacy_refreshed = grant_refresh(&state, legacy_token, &client, None, None)
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
        let user = refresh_test_user("owner-user");
        repo.create_user(&user).await.unwrap();
        let family = refresh_test_family(
            "owner-family",
            &user.id.clone(),
            "owner-client",
            "owner-jti-1",
            &["openid"],
            now,
            Some(now + 86_400),
        );
        repo.create_token_family(&family).await.unwrap();

        let stolen = signed_refresh(&state, &family, "owner-jti-1").await;
        let before = family_hash(&repo, &family.id).await;
        let err = grant_refresh(&state, stolen.clone(), &foreign, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, QidError::Unauthorized { .. }),
            "foreign caller must be rejected, got {err:?}"
        );
        let after = family_hash(&repo, &family.id).await;
        assert_eq!(before, after, "foreign attempt must not consume refresh");
        let ok = grant_refresh(&state, stolen, &owner, None, None).await;
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

        let (state, repo) = state_with_config(config).await;
        create_test_realm(&repo, "test", "https://id.example.com").await;
        create_test_realm(&repo, "realm-b", "https://id.example.com/realms/realm-b").await;

        let mut client = refresh_test_client(
            "realm-b-client-id",
            "client-in-realm-b",
            ClientType::Confidential,
            "client_secret_basic",
        );
        client.realm_id = "realm-b".to_string();
        client.grant_types = vec!["client_credentials".to_string()];
        repo.create_client(&client).await.unwrap();

        let req = TokenRequest {
            grant_type: "client_credentials".to_string(),
            client_id: Some("client-in-realm-b".to_string()),
            scope: Some("api".to_string()),
            ..Default::default()
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

    #[tokio::test]
    async fn refresh_rotation_never_extends_past_initial_deadline() {
        // RFC 10017 section 6.3.2.3: rotation must not extend past the
        // initial expiration. Issued 1000s ago under a 3600s lifetime while
        // the realm TTL is 86400s: both replacements still end at the
        // original deadline.
        let now = util::now_seconds();
        let deadline = now + 2600;
        let (state, _, client, _, token_1) =
            setup_refresh_case("deadline", now - 1000, Some(deadline), None).await;
        let before_refresh = util::now_seconds();
        let rotated = grant_refresh(&state, token_1, &client, None, None)
            .await
            .unwrap();
        let after_refresh = util::now_seconds();
        let refresh_token = rotated.refresh_token.as_ref().unwrap();
        assert_eq!(decode_exp(&state, refresh_token), deadline as usize);
        assert_eq!(decode_exp(&state, &rotated.access_token), deadline as usize);
        assert!(
            before_refresh <= after_refresh && after_refresh < deadline,
            "refresh must complete within the measured validity interval"
        );
        assert!(rotated.expires_in >= deadline - after_refresh);
        assert!(rotated.expires_in <= deadline - before_refresh);
    }

    #[tokio::test]
    async fn refresh_rejects_expired_family_without_rotating() {
        // At the deadline redemption fails without creating tokens or
        // rotating the hash, and expiry alone revokes nothing.
        let now = util::now_seconds();
        let (state, repo, client, family, token) =
            setup_refresh_case("expired", now - 90000, Some(now - 10), None).await;
        let before = family.current_refresh_hash.clone();
        let err = grant_refresh(&state, token, &client, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, QidError::Unauthorized { .. }),
            "expired family must be rejected, got {err:?}"
        );
        let after = get_family(&repo, &family.id).await;
        assert_eq!(
            after.current_refresh_hash, before,
            "expired redemption must not rotate"
        );
        assert!(!after.revoked, "expiry alone revokes nothing");
    }

    #[tokio::test]
    async fn refresh_follows_linked_session_lifetime() {
        // A live linked session rotates normally; expired or idle ones fail
        // closed without rotating.
        let now = util::now_seconds();
        let (state, repo, client, family, token) =
            setup_refresh_case("live", now, Some(now + 86_400), Some(now + 3600)).await;
        grant_refresh(&state, token, &client, None, None)
            .await
            .unwrap();
        let rotated = family_hash(&repo, &family.id).await;
        assert_ne!(rotated, family.current_refresh_hash);

        let (state, repo, client, family, token) =
            setup_refresh_case("spent", now, Some(now + 86_400), Some(now - 10)).await;
        let before = family.current_refresh_hash.clone();
        let err = grant_refresh(&state, token, &client, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, QidError::Unauthorized { .. }),
            "expired session must end refresh, got {err:?}"
        );
        assert_eq!(
            family_hash(&repo, &family.id).await,
            before,
            "dead session must not rotate"
        );

        let (state, repo, client, family, token) =
            setup_refresh_case("idle", now, Some(now + 86_400), Some(now + 3600)).await;
        repo.update_session_idle_expiry("idle-session", now - 10)
            .await
            .unwrap();
        let before = family.current_refresh_hash.clone();
        let err = grant_refresh(&state, token, &client, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, QidError::Unauthorized { .. }),
            "idle session must end refresh"
        );
        assert_eq!(
            family_hash(&repo, &family.id).await,
            before,
            "idle session must not rotate"
        );
    }

    #[tokio::test]
    async fn refresh_dies_with_revoked_session_but_spares_other_family() {
        // Logout ends the refresh lineage: revoking S1 (the same
        // revoke_session call the logout path makes) rejects its refresh
        // without rotating, while a distinct S2 family still rotates.
        let (state, repo) = setup_state().await;
        let now = util::now_seconds();
        let client = refresh_test_client("s2-id", "s2-client", ClientType::Public, "none");
        repo.create_client(&client).await.unwrap();
        let user = refresh_test_user("s2-user");
        repo.create_user(&user).await.unwrap();
        seed_linked_session(&repo, "s1", &user.id, now + 3600).await;
        seed_linked_session(&repo, "s2", &user.id, now + 3600).await;
        let mut first = refresh_test_family(
            "s1-family",
            &user.id,
            "s2-client",
            "s1-jti",
            &["api"],
            now,
            Some(now + 86_400),
        );
        first.session_id = Some("s1-session".to_string());
        repo.create_token_family(&first).await.unwrap();
        let mut second = refresh_test_family(
            "s2-family",
            &user.id,
            "s2-client",
            "s2-jti",
            &["api"],
            now,
            Some(now + 86_400),
        );
        second.session_id = Some("s2-session".to_string());
        repo.create_token_family(&second).await.unwrap();
        let token_1 = signed_refresh(&state, &first, "s1-jti").await;
        let token_2 = signed_refresh(&state, &second, "s2-jti").await;

        repo.revoke_session("s1-session").await.unwrap();
        let err = grant_refresh(&state, token_1, &client, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, QidError::Unauthorized { .. }),
            "revoked session must end refresh, got {err:?}"
        );
        assert_eq!(
            family_hash(&repo, &first.id).await,
            first.current_refresh_hash,
            "dead session must not rotate"
        );
        grant_refresh(&state, token_2, &client, None, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn authorization_code_carries_session_into_family() {
        // Provenance: a code issued to a browser session links the minted
        // family, so logout reaches it.
        let (state, repo) = setup_state().await;
        let now = util::now_seconds();
        let client = refresh_test_client(
            "code-sess-id",
            "code-sess-client",
            ClientType::Public,
            "none",
        );
        repo.create_client(&client).await.unwrap();
        let user = refresh_test_user("code-sess-user");
        repo.create_user(&user).await.unwrap();
        seed_linked_session(&repo, "code-sess", &user.id, now + 3600).await;
        let code = "code-sess-code-1";
        repo.create_authorization_code(&AuthorizationCode {
            code_hash: util::sha256_base64url(code),
            client_id: "code-sess-client".to_string(),
            user_id: user.id.clone(),
            realm_id: "test".to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
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
            expires_at: now + 300,
            used: false,
            created_at: now,
            session_id: Some("code-sess-session".to_string()),
        })
        .await
        .unwrap();
        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(code.to_string()),
            redirect_uri: Some("https://app.example.com/callback".to_string()),
            ..Default::default()
        };
        let issued = authorization_code_grant(&state, &req, &client, None)
            .await
            .unwrap();
        let family_id = state
            .signer
            .decode_signature_only(issued.refresh_token.as_ref().unwrap())
            .unwrap()
            .claims
            .extra["family_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            get_family(&repo, &family_id).await.session_id,
            Some("code-sess-session".to_string())
        );
    }

    #[tokio::test]
    async fn initial_issuance_caps_access_at_family_deadline() {
        // Access TTL longer than refresh TTL must not let the first access
        // token outlive the family deadline: the family record and JWT share
        // the issued-plus-refresh-TTL deadline, and expires_in uses that TTL.
        let mut config = test_helpers::test_config();
        config.realms[0]
            .protocols
            .oauth
            .tokens
            .access_token_ttl_seconds = 100_000;
        config.realms[0]
            .protocols
            .oauth
            .tokens
            .refresh_token_ttl_seconds = 3600;
        let (state, repo) = state_with_config(config).await;
        create_test_realm(&repo, "test", "https://id.example.com").await;
        let now = util::now_seconds();
        let client = refresh_test_client("cap-id", "cap-client", ClientType::Public, "none");
        repo.create_client(&client).await.unwrap();
        let user = refresh_test_user("cap-user");
        repo.create_user(&user).await.unwrap();
        let code = "cap-code-1";
        repo.create_authorization_code(&AuthorizationCode {
            code_hash: util::sha256_base64url(code),
            client_id: "cap-client".to_string(),
            user_id: user.id.clone(),
            realm_id: "test".to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
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
            expires_at: now + 300,
            used: false,
            created_at: now,
            session_id: None,
        })
        .await
        .unwrap();
        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(code.to_string()),
            redirect_uri: Some("https://app.example.com/callback".to_string()),
            ..Default::default()
        };
        let issued = authorization_code_grant(&state, &req, &client, None)
            .await
            .unwrap();
        assert_eq!(issued.expires_in, 3600);
        let stored = get_family(
            &repo,
            state
                .signer
                .decode_signature_only(issued.refresh_token.as_ref().unwrap())
                .unwrap()
                .claims
                .extra["family_id"]
                .as_str()
                .unwrap(),
        )
        .await;
        let deadline = stored.refresh_expires_at.unwrap();
        assert_eq!(deadline, stored.issued_at + 3600);
        assert_eq!(decode_exp(&state, &issued.access_token), deadline as usize);
    }

    #[tokio::test]
    async fn refresh_pins_legacy_family_deadline_on_first_rotation() {
        // Families predating the deadline persist none; the first rotation
        // pins issued_at plus the realm TTL so later TTL changes cannot
        // extend them.
        let now = util::now_seconds();
        let issued_at = now - 100;
        let (state, repo, client, family, token_1) =
            setup_refresh_case("legacy-pin", issued_at, None, None).await;
        grant_refresh(&state, token_1, &client, None, None)
            .await
            .unwrap();
        let pinned = get_family(&repo, &family.id).await;
        assert_eq!(pinned.refresh_expires_at, Some(issued_at + 86_400));
    }
}
