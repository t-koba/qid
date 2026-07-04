//! OAuth 2.0 token issuance helpers.

use base64::Engine;
use qid_core::{
    error::{QidError, QidResult},
    models::{AccessToken, TokenFamily, TokenFormat, User},
    state::SharedState,
};
use qid_crypto::{JwtClaims, TokenPair};
use qid_storage::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use super::token_ttl;

#[derive(Clone, Copy, Debug, Default)]
pub struct TokenIssueClaims<'a> {
    pub audience: Option<&'a [String]>,
    pub resource: Option<&'a [String]>,
    pub authorization_details: Option<&'a serde_json::Value>,
    pub cnf: Option<&'a serde_json::Value>,
    pub auth_time: Option<u64>,
    pub acr: Option<&'a str>,
    pub amr: Option<&'a [String]>,
    pub nonce: Option<&'a str>,
    pub act: Option<&'a serde_json::Value>,
    /// Authorization code issued alongside the id_token in hybrid/code flow.
    /// When present, the id_token receives a `c_hash` claim per OIDC Core §3.3.2.11.
    pub authorization_code: Option<&'a str>,
    /// Access token issued alongside the id_token. When present, the id_token
    /// receives an `at_hash` claim per OIDC Core §3.1.3.7 / §3.3.2.11.
    pub access_token: Option<&'a str>,
}

pub async fn issue_token_pair<R: Repository>(
    state: &SharedState<R>,
    issuer: &str,
    user: &User,
    client_id: &str,
    realm_id: &str,
    scopes: &[String],
    claims: TokenIssueClaims<'_>,
) -> QidResult<TokenPair> {
    let now = qid_core::util::now_seconds();
    let access_jti = generate_jti();
    let refresh_jti = generate_jti();
    let family_id = generate_jti();

    let family = TokenFamily {
        id: family_id.clone(),
        user_id: user.id.clone(),
        client_id: client_id.to_string(),
        realm_id: realm_id.to_string(),
        current_refresh_hash: qid_core::util::sha256_base64url(&refresh_jti),
        audience: token_audience(client_id, claims),
        resource: token_resource(claims),
        authorization_details: claims.authorization_details.cloned(),
        sender_constraint: claims.cnf.cloned(),
        issued_at: now,
        revoked: false,
    };
    state.repo.create_token_family(&family).await?;

    let access_token = AccessToken {
        jti: access_jti.clone(),
        family_id: Some(family_id.clone()),
        user_id: user.id.clone(),
        client_id: client_id.to_string(),
        realm_id: realm_id.to_string(),
        scopes: scopes.to_vec(),
        audience: token_audience(client_id, claims),
        resource: token_resource(claims),
        authorization_details: claims.authorization_details.cloned(),
        cnf: claims.cnf.cloned(),
        auth_time: claims.auth_time.or(Some(now)),
        acr: claims.acr.map(ToOwned::to_owned),
        amr: token_amr(claims),
        nonce: claims.nonce.map(ToOwned::to_owned),
        sender_constraint: claims.cnf.cloned(),
        token_format: token_ttl(state, realm_id).access_token_format,
        expires_at: now + token_ttl(state, realm_id).access_token_ttl_seconds,
        revoked: false,
        issued_at: now,
    };
    state.repo.create_access_token(&access_token).await?;

    let access = format_access_token(
        state,
        issuer,
        &access_jti,
        user,
        client_id,
        realm_id,
        scopes,
        claims,
    )?;
    let refresh = sign_refresh_token(
        state,
        issuer,
        &refresh_jti,
        user,
        client_id,
        realm_id,
        Some(&family_id),
    )?;

    Ok(TokenPair {
        access_token: access,
        refresh_token: refresh,
        access_jti,
        refresh_jti,
        expires_in: token_ttl(state, realm_id).access_token_ttl_seconds,
    })
}

pub fn generate_jti() -> String {
    format!("oat_{}", ulid::Ulid::new())
}

#[expect(
    clippy::too_many_arguments,
    reason = "token issuance keeps protocol context explicit at call sites"
)]
pub fn sign_access_token<R: Repository>(
    state: &SharedState<R>,
    issuer: &str,
    jti: &str,
    user: &User,
    client_id: &str,
    realm_id: &str,
    scopes: &[String],
    claims: TokenIssueClaims<'_>,
) -> QidResult<String> {
    let now = qid_core::util::now_seconds();
    let token_type = access_token_type_for_cnf(claims.cnf);
    let mut extra = HashMap::new();
    extra.insert(
        "scope".to_string(),
        serde_json::Value::String(scopes.join(" ")),
    );
    extra.insert(
        "client_id".to_string(),
        serde_json::Value::String(client_id.to_string()),
    );
    extra.insert(
        "token_type".to_string(),
        serde_json::Value::String(token_type.to_string()),
    );
    if let Some(details) = claims.authorization_details {
        extra.insert("authorization_details".to_string(), details.clone());
    }
    if let Some(resource) = claims.resource.filter(|value| !value.is_empty()) {
        extra.insert("resource".to_string(), serde_json::json!(resource));
    }
    if let Some(auth_time) = claims.auth_time {
        extra.insert("auth_time".to_string(), serde_json::json!(auth_time));
    }
    if let Some(acr) = claims.acr {
        extra.insert(
            "acr".to_string(),
            serde_json::Value::String(acr.to_string()),
        );
    }
    if let Some(amr) = claims.amr.filter(|value| !value.is_empty()) {
        extra.insert("amr".to_string(), serde_json::json!(amr));
    }
    if let Some(nonce) = claims.nonce {
        extra.insert(
            "nonce".to_string(),
            serde_json::Value::String(nonce.to_string()),
        );
    }
    if let Some(cnf) = claims.cnf {
        extra.insert("cnf".to_string(), cnf.clone());
    }
    if let Some(act) = claims.act {
        extra.insert("act".to_string(), act.clone());
    }

    let audience = claims
        .audience
        .and_then(|value| value.first())
        .cloned()
        .unwrap_or_else(|| client_id.to_string());
    let claims = JwtClaims {
        iss: Some(issuer.to_string()),
        sub: Some(user.id.clone()),
        aud: Some(audience),
        exp: Some((now + token_ttl(state, realm_id).access_token_ttl_seconds) as usize),
        nbf: Some(now as usize),
        iat: Some(now as usize),
        jti: Some(jti.to_string()),
        extra,
    };

    state
        .signer
        .sign_with_typ(&claims, "at+jwt")
        .map_err(|e| QidError::Crypto {
            message: format!("failed to sign access token: {e}"),
        })
}

pub fn access_token_type_for_cnf(cnf: Option<&serde_json::Value>) -> &'static str {
    if cnf.and_then(|value| value.get("jkt")).is_some() {
        "DPoP"
    } else {
        "Bearer"
    }
}

pub async fn issue_access_token<R: Repository>(
    state: &SharedState<R>,
    issuer: &str,
    user: &User,
    client_id: &str,
    realm_id: &str,
    scopes: &[String],
    claims: TokenIssueClaims<'_>,
) -> QidResult<(String, u64)> {
    let now = qid_core::util::now_seconds();
    let access_jti = generate_jti();
    let expires_in = token_ttl(state, realm_id).access_token_ttl_seconds;

    let access_token = AccessToken {
        jti: access_jti.clone(),
        family_id: None,
        user_id: user.id.clone(),
        client_id: client_id.to_string(),
        realm_id: realm_id.to_string(),
        scopes: scopes.to_vec(),
        audience: token_audience(client_id, claims),
        resource: token_resource(claims),
        authorization_details: claims.authorization_details.cloned(),
        cnf: claims.cnf.cloned(),
        auth_time: claims.auth_time.or(Some(now)),
        acr: claims.acr.map(ToOwned::to_owned),
        amr: token_amr(claims),
        nonce: claims.nonce.map(ToOwned::to_owned),
        sender_constraint: claims.cnf.cloned(),
        token_format: token_ttl(state, realm_id).access_token_format,
        expires_at: now + expires_in,
        revoked: false,
        issued_at: now,
    };
    state.repo.create_access_token(&access_token).await?;

    let access = format_access_token(
        state,
        issuer,
        &access_jti,
        user,
        client_id,
        realm_id,
        scopes,
        claims,
    )?;
    Ok((access, expires_in))
}

#[expect(
    clippy::too_many_arguments,
    reason = "token issuance keeps protocol context explicit at call sites"
)]
pub fn format_access_token<R: Repository>(
    state: &SharedState<R>,
    issuer: &str,
    jti: &str,
    user: &User,
    client_id: &str,
    realm_id: &str,
    scopes: &[String],
    claims: TokenIssueClaims<'_>,
) -> QidResult<String> {
    match token_ttl(state, realm_id).access_token_format {
        TokenFormat::Jwt => sign_access_token(
            state, issuer, jti, user, client_id, realm_id, scopes, claims,
        ),
        TokenFormat::Opaque => Ok(encode_opaque_access_token(jti)),
    }
}

pub fn encode_opaque_access_token(jti: &str) -> String {
    format!("oat_{jti}")
}

pub fn decode_opaque_access_token(token: &str) -> Option<&str> {
    token.strip_prefix("oat_")
}

pub fn sign_refresh_token<R: Repository>(
    state: &SharedState<R>,
    issuer: &str,
    jti: &str,
    user: &User,
    client_id: &str,
    realm_id: &str,
    family_id: Option<&str>,
) -> QidResult<String> {
    let now = qid_core::util::now_seconds();
    let mut extra = HashMap::new();
    if let Some(fid) = family_id {
        extra.insert(
            "family_id".to_string(),
            serde_json::Value::String(fid.to_string()),
        );
    }
    let claims = JwtClaims {
        iss: Some(issuer.to_string()),
        sub: Some(user.id.clone()),
        aud: Some(client_id.to_string()),
        exp: Some((now + token_ttl(state, realm_id).refresh_token_ttl_seconds) as usize),
        nbf: Some(now as usize),
        iat: Some(now as usize),
        jti: Some(jti.to_string()),
        extra,
    };

    state.signer.sign(&claims).map_err(|e| QidError::Crypto {
        message: format!("failed to sign refresh token: {e}"),
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "ID token issuance keeps protocol context explicit at call sites"
)]
pub fn issue_id_token<R: Repository>(
    state: &SharedState<R>,
    issuer: &str,
    user: &User,
    client_id: &str,
    realm_id: &str,
    scopes: &[String],
    claims: TokenIssueClaims<'_>,
    sub_override: Option<&str>,
) -> QidResult<String> {
    let now = qid_core::util::now_seconds();
    let mut extra = HashMap::new();
    if scopes.contains(&"email".to_string())
        && let Some(ref email) = user.email
    {
        extra.insert(
            "email".to_string(),
            serde_json::Value::String(email.clone()),
        );
    }
    if let Some(nonce) = claims.nonce {
        extra.insert(
            "nonce".to_string(),
            serde_json::Value::String(nonce.to_string()),
        );
    }
    if let Some(auth_time) = claims.auth_time {
        extra.insert("auth_time".to_string(), serde_json::json!(auth_time));
    }
    if let Some(acr) = claims.acr {
        extra.insert(
            "acr".to_string(),
            serde_json::Value::String(acr.to_string()),
        );
    }
    if let Some(amr) = claims.amr.filter(|value| !value.is_empty()) {
        extra.insert("amr".to_string(), serde_json::json!(amr));
    }
    if let Some(access) = claims.access_token {
        let at_hash = left_most_128_hash_base64url(access.as_bytes());
        extra.insert("at_hash".to_string(), serde_json::Value::String(at_hash));
    }
    if let Some(code) = claims.authorization_code {
        let c_hash = left_most_128_hash_base64url(code.as_bytes());
        extra.insert("c_hash".to_string(), serde_json::Value::String(c_hash));
    }

    let sub = sub_override.unwrap_or(&user.id);
    let claims = JwtClaims {
        iss: Some(issuer.to_string()),
        sub: Some(sub.to_string()),
        aud: Some(client_id.to_string()),
        exp: Some((now + token_ttl(state, realm_id).id_token_ttl_seconds) as usize),
        nbf: Some(now as usize),
        iat: Some(now as usize),
        jti: Some(generate_jti()),
        extra,
    };

    state.signer.sign(&claims).map_err(|e| QidError::Crypto {
        message: format!("failed to sign id token: {e}"),
    })
}

/// OIDC Core §3.1.3.7 / §3.3.2.11: `at_hash` and `c_hash` are the left-most
/// 128 bits of the SHA-256 digest of the ASCII bytes of the access token or
/// authorization code, base64url-encoded without padding.
fn left_most_128_hash_base64url(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..16])
}

fn token_audience(client_id: &str, claims: TokenIssueClaims<'_>) -> Vec<String> {
    claims
        .audience
        .filter(|value| !value.is_empty())
        .map(|value| value.to_vec())
        .unwrap_or_else(|| vec![client_id.to_string()])
}

fn token_resource(claims: TokenIssueClaims<'_>) -> Vec<String> {
    claims
        .resource
        .filter(|value| !value.is_empty())
        .map(|value| value.to_vec())
        .unwrap_or_default()
}

fn token_amr(claims: TokenIssueClaims<'_>) -> Vec<String> {
    claims
        .amr
        .filter(|value| !value.is_empty())
        .map(|value| value.to_vec())
        .unwrap_or_default()
}
