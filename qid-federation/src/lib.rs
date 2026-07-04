//! OpenID Federation surface.
#![forbid(unsafe_code)]
#![allow(dead_code)]

use qid_core::{QidError, jwt::JwtClaims};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

mod broker;
mod routes;

pub use broker::{
    BrokerAccountLink, BrokerLoginPlan, BrokerRouteDecision, ClaimMapping, ExternalIdentityClaims,
    HomeRealmDiscoveryRequest, InboundIdentityProvider, InboundProviderKind, KerberosSpnegoConfig,
    azure_ad_provider, google_workspace_provider, normalize_enterprise_claims, okta_provider,
    plan_inbound_login, route_inbound_provider, validate_kerberos_spnego_token,
    verify_inbound_idp_token,
};
pub use routes::{
    TrustChainValidationRequest, TrustChainValidationResponse, exchange_code_for_tokens,
    federation_routes, fetch_userinfo, providers_from_config,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustAnchor {
    pub entity_id: String,
    #[serde(default)]
    pub required_trust_marks: Vec<String>,
    #[serde(default)]
    pub trusted_trust_mark_issuers: Vec<String>,
    #[serde(default)]
    pub allowed_redirect_hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustMark {
    pub id: String,
    pub issuer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FederationMetadata {
    #[serde(default)]
    pub openid_provider: Option<OpenIdProviderMetadata>,
    #[serde(default)]
    pub openid_relying_party: Option<OpenIdRelyingPartyMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenIdProviderMetadata {
    pub issuer: String,
    pub jwks_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenIdRelyingPartyMetadata {
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub grant_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntityStatement {
    pub iss: String,
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    #[serde(default)]
    pub authority_hints: Vec<String>,
    #[serde(default)]
    pub metadata: Option<FederationMetadata>,
    #[serde(default)]
    pub trust_marks: Vec<TrustMark>,
}

pub fn sign_entity_statement(
    signer: &dyn qid_core::jwt::Signer,
    statement: &EntityStatement,
) -> Result<String, QidError> {
    signer
        .sign(&entity_statement_claims(statement)?)
        .map_err(|err| jwt_error("entity_statement_sign_failed", format!("{err}")))
}

pub fn decode_signed_entity_statement(
    signer: &dyn qid_core::jwt::Signer,
    token: &str,
) -> Result<EntityStatement, QidError> {
    let claims = signer
        .decode_signature_only(token)
        .map_err(|err| jwt_error("entity_statement_decode_failed", format!("{err}")))?
        .claims;
    entity_statement_from_claims(&claims)
}

pub fn validate_signed_trust_chain(
    signer: &dyn qid_core::jwt::Signer,
    subject: &str,
    signed_chain: &[String],
    anchors: &[TrustAnchor],
    now_epoch_seconds: u64,
) -> Result<TrustChainValidation, QidError> {
    let chain = signed_chain
        .iter()
        .map(|token| {
            decode_signed_entity_statement(signer, token).map_err(|err| {
                error(
                    "signed_entity_statement_invalid",
                    &format!(
                        "Signed entity statement is invalid: {}",
                        federation_error_description(&err)
                    ),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_trust_chain(subject, &chain, anchors, now_epoch_seconds)
}

fn entity_statement_claims(statement: &EntityStatement) -> Result<JwtClaims, QidError> {
    let mut extra = HashMap::new();
    extra.insert(
        "authority_hints".to_string(),
        serde_json::to_value(&statement.authority_hints)
            .map_err(|err| jwt_error("entity_statement_encode_failed", format!("{err}")))?,
    );
    if let Some(metadata) = &statement.metadata {
        extra.insert(
            "metadata".to_string(),
            serde_json::to_value(metadata)
                .map_err(|err| jwt_error("entity_statement_encode_failed", format!("{err}")))?,
        );
    }
    extra.insert(
        "trust_marks".to_string(),
        serde_json::to_value(&statement.trust_marks)
            .map_err(|err| jwt_error("entity_statement_encode_failed", format!("{err}")))?,
    );

    Ok(JwtClaims {
        iss: Some(statement.iss.clone()),
        sub: Some(statement.sub.clone()),
        aud: None,
        exp: Some(statement.exp as usize),
        nbf: Some(statement.iat as usize),
        iat: Some(statement.iat as usize),
        jti: None,
        extra,
    })
}

fn entity_statement_from_claims(claims: &JwtClaims) -> Result<EntityStatement, QidError> {
    let iss = claims
        .iss
        .clone()
        .ok_or_else(|| jwt_error("entity_statement_missing_iss", "missing iss"))?;
    let sub = claims
        .sub
        .clone()
        .ok_or_else(|| jwt_error("entity_statement_missing_sub", "missing sub"))?;
    let iat = claims
        .iat
        .ok_or_else(|| jwt_error("entity_statement_missing_iat", "missing iat"))?
        as u64;
    let exp = claims
        .exp
        .ok_or_else(|| jwt_error("entity_statement_missing_exp", "missing exp"))?
        as u64;
    let authority_hints = match claims.extra.get("authority_hints") {
        Some(value) => serde_json::from_value(value.clone()).map_err(|err| {
            jwt_error("entity_statement_invalid_authority_hints", format!("{err}"))
        })?,
        None => Vec::new(),
    };
    let metadata = match claims.extra.get("metadata") {
        Some(value) => Some(
            serde_json::from_value(value.clone())
                .map_err(|err| jwt_error("entity_statement_invalid_metadata", format!("{err}")))?,
        ),
        None => None,
    };
    let trust_marks = match claims.extra.get("trust_marks") {
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|err| jwt_error("entity_statement_invalid_trust_marks", format!("{err}")))?,
        None => Vec::new(),
    };

    Ok(EntityStatement {
        iss,
        sub,
        iat,
        exp,
        authority_hints,
        metadata,
        trust_marks,
    })
}

fn jwt_error(code: &str, message: impl Into<String>) -> QidError {
    coded_error(code, message)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustChainValidation {
    pub subject: String,
    pub trust_anchor: String,
    pub issuers: Vec<String>,
    pub trust_marks: Vec<String>,
    pub automatic_client_trust: bool,
    #[serde(default)]
    pub effective_openid_relying_party: Option<OpenIdRelyingPartyMetadata>,
}

const MAX_TRUST_CHAIN_DEPTH: usize = 5;

pub fn validate_trust_chain(
    subject: &str,
    chain: &[EntityStatement],
    anchors: &[TrustAnchor],
    now_epoch_seconds: u64,
) -> Result<TrustChainValidation, QidError> {
    if chain.is_empty() {
        return Err(error("empty_trust_chain", "Trust chain is empty"));
    }
    if chain.len() > MAX_TRUST_CHAIN_DEPTH {
        return Err(error(
            "trust_chain_too_deep",
            &format!(
                "Trust chain depth {} exceeds maximum of {MAX_TRUST_CHAIN_DEPTH}",
                chain.len()
            ),
        ));
    }
    let leaf = &chain[0];
    if leaf.sub != subject {
        return Err(error(
            "subject_mismatch",
            "Leaf entity statement subject does not match requested subject",
        ));
    }

    for statement in chain {
        if statement.iat > now_epoch_seconds || statement.exp <= now_epoch_seconds {
            return Err(error(
                "expired_entity_statement",
                "Entity statement is not valid at the evaluation time",
            ));
        }
    }

    for pair in chain.windows(2) {
        let child = &pair[0];
        let parent = &pair[1];
        if child.iss != parent.sub {
            return Err(error(
                "broken_issuer_link",
                "Entity statement issuer must match the next authority subject",
            ));
        }
        if !child.authority_hints.is_empty() && !child.authority_hints.contains(&parent.sub) {
            return Err(error(
                "missing_authority_hint",
                "Authority hint does not name the next authority",
            ));
        }
    }

    let Some(root) = chain.last() else {
        return Err(error("empty_trust_chain", "Trust chain is empty"));
    };
    let Some(anchor) = anchors.iter().find(|anchor| anchor.entity_id == root.sub) else {
        return Err(error(
            "unknown_trust_anchor",
            "Trust chain does not terminate at a configured trust anchor",
        ));
    };
    if root.iss != root.sub {
        return Err(error(
            "trust_anchor_not_self_issued",
            "Trust anchor entity statement must be self-issued",
        ));
    }

    let trust_marks = chain
        .iter()
        .flat_map(|statement| statement.trust_marks.iter().map(|mark| mark.id.clone()))
        .collect::<HashSet<_>>();
    for required in &anchor.required_trust_marks {
        if !trust_marks.contains(required) {
            return Err(error(
                "missing_required_trust_mark",
                "Trust chain is missing a required trust mark",
            ));
        }
    }
    validate_trust_mark_issuers(chain, anchor)?;

    let effective_openid_relying_party = leaf
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.openid_relying_party.as_ref())
        .map(|rp| apply_metadata_policy(rp, &anchor.allowed_redirect_hosts))
        .transpose()?;
    let automatic_client_trust = effective_openid_relying_party
        .as_ref()
        .map(|rp| {
            !rp.redirect_uris.is_empty()
                && !rp
                    .grant_types
                    .iter()
                    .any(|grant| grant == "implicit" || grant == "password")
        })
        .unwrap_or(false);

    Ok(TrustChainValidation {
        subject: subject.to_string(),
        trust_anchor: anchor.entity_id.clone(),
        issuers: chain
            .iter()
            .map(|statement| statement.iss.clone())
            .collect(),
        trust_marks: trust_marks.into_iter().collect(),
        automatic_client_trust,
        effective_openid_relying_party,
    })
}

fn validate_trust_mark_issuers(
    chain: &[EntityStatement],
    anchor: &TrustAnchor,
) -> Result<(), QidError> {
    let mut trusted_issuers = HashSet::from([anchor.entity_id.as_str()]);
    for issuer in &anchor.trusted_trust_mark_issuers {
        trusted_issuers.insert(issuer.as_str());
    }
    for statement in chain {
        trusted_issuers.insert(statement.sub.as_str());
    }
    for mark in chain
        .iter()
        .flat_map(|statement| statement.trust_marks.iter())
    {
        if !trusted_issuers.contains(mark.issuer.as_str()) {
            return Err(error(
                "untrusted_trust_mark_issuer",
                "Trust mark issuer is not trusted by the selected anchor",
            ));
        }
    }
    Ok(())
}

pub fn apply_metadata_policy(
    metadata: &OpenIdRelyingPartyMetadata,
    allowed_redirect_hosts: &[String],
) -> Result<OpenIdRelyingPartyMetadata, QidError> {
    let allowed: HashSet<&str> = allowed_redirect_hosts.iter().map(String::as_str).collect();
    let mut redirect_uris = Vec::new();
    for redirect_uri in &metadata.redirect_uris {
        let (scheme, rest) = redirect_uri.split_once("://").ok_or_else(|| {
            error(
                "invalid_redirect_uri",
                &format!("redirect_uri {redirect_uri} has no scheme"),
            )
        })?;
        if scheme != "https" && !(scheme == "http" && rest.starts_with("localhost")) {
            return Err(error(
                "redirect_uri_scheme_not_allowed",
                &format!("redirect_uri {redirect_uri} must be https or http://localhost"),
            ));
        }
        let host = rest.split('/').next().unwrap_or_default();
        if !allowed.is_empty() && !allowed.contains(host) {
            return Err(error(
                "redirect_host_not_allowed",
                "Relying party redirect URI host is not allowed by metadata policy",
            ));
        }
        redirect_uris.push(redirect_uri.clone());
    }

    let mut grant_types = metadata.grant_types.clone();
    grant_types.retain(|grant| grant != "implicit" && grant != "password");
    Ok(OpenIdRelyingPartyMetadata {
        redirect_uris,
        grant_types,
    })
}

pub fn trust_mark_index(chain: &[EntityStatement]) -> HashMap<String, Vec<String>> {
    let mut index: HashMap<String, Vec<String>> = HashMap::new();
    for statement in chain {
        for mark in &statement.trust_marks {
            index
                .entry(mark.id.clone())
                .or_default()
                .push(statement.sub.clone());
        }
    }
    index
}

fn error(code: &str, message: &str) -> QidError {
    coded_error(code, message)
}

pub fn federation_error_code(error: &QidError) -> &str {
    coded_error_parts(error).0
}

pub fn federation_error_description(error: &QidError) -> &str {
    coded_error_parts(error).1
}

pub(crate) fn coded_error(code: &str, message: impl Into<String>) -> QidError {
    QidError::BadRequest {
        message: format!("{}: {}", code, message.into()),
    }
}

fn coded_error_parts(error: &QidError) -> (&str, &str) {
    let QidError::BadRequest { message } = error else {
        return ("server_error", "Internal server error");
    };
    message
        .split_once(": ")
        .unwrap_or(("bad_request", message.as_str()))
}

#[cfg(test)]
mod tests;
