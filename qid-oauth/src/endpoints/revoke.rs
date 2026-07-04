use axum::{
    Form,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use qid_core::{
    error::{QidError, QidResult},
    jwt::JwtClaims,
    models::{Client, ClientType},
    state::SharedState,
    tenant::RealmId,
};
use qid_storage::prelude::*;
use std::sync::Arc;

use super::{
    RevokeRequest, decode_opaque_access_token, extract_basic_client_auth, verify_client_secret,
};

pub async fn revoke<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    headers: HeaderMap,
    Form(req): Form<RevokeRequest>,
) -> Response {
    match handle_revoke(&state, &headers, &req).await {
        Ok(revoked) => {
            if revoked {
                metrics::counter!("qid_token_revoked_total").increment(1);
            }
            axum::http::StatusCode::OK.into_response()
        }
        Err(e) => qid_http::error_response(e),
    }
}

async fn handle_revoke<R: Repository>(
    state: &SharedState<R>,
    headers: &HeaderMap,
    req: &RevokeRequest,
) -> QidResult<bool> {
    let client = authenticate_revocation_client(state, headers, req).await?;
    if !state
        .config
        .realms
        .iter()
        .find(|realm| realm.id == client.realm_id)
        .is_some_and(|realm| realm.protocols.oauth.revocation.enabled)
    {
        return Err(QidError::BadRequest {
            message: "revocation is disabled".to_string(),
        });
    }
    if let Some(hint) = req.token_type_hint.as_deref() {
        match hint {
            "access_token" | "refresh_token" => {}
            _ => {
                return Err(QidError::BadRequest {
                    message: "unsupported token_type_hint".to_string(),
                });
            }
        }
    }

    if req.token_type_hint.as_deref() != Some("refresh_token")
        && let Some(jti) = decode_opaque_access_token(&req.token)
    {
        return revoke_access_token_if_owned(state, jti, &client).await;
    }

    let data = match state.signer.decode_signature_only(&req.token) {
        Ok(data) => data,
        Err(_) => return Ok(false),
    };
    if req.token_type_hint.as_deref() != Some("refresh_token")
        && revoke_jwt_access_token_if_owned(state, &data.claims, &client).await?
    {
        return Ok(true);
    }
    if req.token_type_hint.as_deref() == Some("access_token") {
        return Ok(false);
    }
    let revoked = revoke_refresh_token_family_if_owned(state, &data.claims, &client).await?;
    Ok(revoked)
}

async fn authenticate_revocation_client<R: Repository>(
    state: &SharedState<R>,
    headers: &HeaderMap,
    req: &RevokeRequest,
) -> QidResult<Client> {
    let basic_client_auth = extract_basic_client_auth(headers);
    let (client_id, presented_secret, used_auth_method) = match basic_client_auth.as_ref() {
        Some(auth) => (
            auth.client_id.as_str(),
            Some(auth.client_secret.as_str()),
            "client_secret_basic",
        ),
        None => (
            req.client_id
                .as_deref()
                .ok_or_else(|| QidError::Unauthorized {
                    message: "client_id is required for revocation".to_string(),
                })?,
            req.client_secret.as_deref(),
            if req.client_secret.is_some() {
                "client_secret_post"
            } else {
                "none"
            },
        ),
    };
    if req.client_secret.is_some() && used_auth_method == "client_secret_basic" {
        return Err(QidError::Unauthorized {
            message: "multiple client authentication methods are not allowed".to_string(),
        });
    }
    let client = find_revocation_client_across_realms(state, client_id).await?;
    match client.client_type {
        ClientType::Public => {
            if used_auth_method != "none" || client.token_endpoint_auth_method != "none" {
                return Err(QidError::Unauthorized {
                    message: "public revocation client must not use confidential authentication"
                        .to_string(),
                });
            }
        }
        ClientType::Confidential => {
            if client.token_endpoint_auth_method != used_auth_method {
                return Err(QidError::Unauthorized {
                    message: format!(
                        "revocation client must authenticate with {}",
                        client.token_endpoint_auth_method
                    ),
                });
            }
            if !matches!(
                used_auth_method,
                "client_secret_basic" | "client_secret_post"
            ) {
                return Err(QidError::Unauthorized {
                    message: "revocation client authentication method is not supported".to_string(),
                });
            }
            verify_client_secret(&client, presented_secret)?;
        }
    }
    Ok(client)
}

async fn find_revocation_client_across_realms<R: Repository>(
    state: &SharedState<R>,
    client_id: &str,
) -> QidResult<Client> {
    let mut found = None;
    for realm in &state.config.realms {
        if let Some(client) = state
            .repo
            .get_client_by_client_id(&RealmId::from(realm.id.clone()), client_id)
            .await?
        {
            if found.is_some() {
                return Err(QidError::Unauthorized {
                    message: "revocation client realm is ambiguous".to_string(),
                });
            }
            found = Some(client);
        }
    }
    found.ok_or_else(|| QidError::Unauthorized {
        message: "unknown client".to_string(),
    })
}

async fn revoke_access_token_if_owned<R: Repository>(
    state: &SharedState<R>,
    jti: &str,
    client: &Client,
) -> QidResult<bool> {
    let Some(record) = state.repo.get_access_token(jti).await? else {
        return Ok(false);
    };
    if record.client_id != client.client_id || record.realm_id != client.realm_id {
        tracing::info!(
            target: "audit",
            "token_revoke_owner_mismatch jti={} requested_by={}/{} actual_owner={}/{}",
            jti,
            client.realm_id,
            client.client_id,
            record.realm_id,
            record.client_id,
        );
        return Ok(false);
    }
    state.repo.revoke_access_token(jti).await?;
    Ok(true)
}

async fn revoke_jwt_access_token_if_owned<R: Repository>(
    state: &SharedState<R>,
    claims: &JwtClaims,
    client: &Client,
) -> QidResult<bool> {
    let Some(jti) = claims.jti.as_deref() else {
        return Ok(false);
    };
    revoke_access_token_if_owned(state, jti, client).await
}

async fn revoke_refresh_token_family_if_owned<R: Repository>(
    state: &SharedState<R>,
    claims: &JwtClaims,
    client: &Client,
) -> QidResult<bool> {
    if claims.aud.as_deref() != Some(client.client_id.as_str()) {
        return Ok(false);
    }
    let Some(family_id) = claims
        .extra
        .get("family_id")
        .and_then(|value| value.as_str())
    else {
        return Ok(false);
    };
    let Some(family) = state.repo.get_token_family(family_id).await? else {
        return Ok(false);
    };
    if family.client_id != client.client_id || family.realm_id != client.realm_id {
        return Ok(false);
    }
    state.repo.revoke_token_family(family_id).await?;
    Ok(true)
}
