//! Signed identity assertion issuance for PEP adapters.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, Method},
    response::IntoResponse,
};
use qid_core::{
    error::{QidError, QidResult},
    models::{IgaAccessGrantRecord, ScimGroup, Session, User},
    state::SharedState,
    tenant::RealmId,
};
use qid_crypto::JwtClaims;
use qid_observability::audit::AuditEvent;
use qid_session::browser::{decode_cached_session, session_cache_put};
use qid_storage::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

#[derive(Debug, Deserialize, Default)]
pub struct AssertionRequest {
    #[serde(default)]
    pub edge: Option<String>,
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub access_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AssertionResponse {
    pub assertion: String,
    pub expires_at: u64,
}

/// Issue a signed assertion for a PEP adapter.
pub async fn issue_assertion<R: Repository>(
    State(state): State<Arc<SharedState<R>>>,
    Path(realm): Path<String>,
    Query(req): Query<AssertionRequest>,
    headers: HeaderMap,
) -> impl IntoResponse {
    match do_issue_assertion(&state, &realm, &req, &headers).await {
        Ok(resp) => Json(resp).into_response(),
        Err(e) => qid_http::error_response(e),
    }
}

async fn do_issue_assertion<R: Repository>(
    state: &SharedState<R>,
    realm_id: &str,
    req: &AssertionRequest,
    headers: &HeaderMap,
) -> QidResult<AssertionResponse> {
    do_issue_assertion_with_device_repo(state, realm_id, req, headers, state.repo.as_ref()).await
}

async fn do_issue_assertion_with_device_repo<R: Repository, D: DeviceRepository>(
    state: &SharedState<R>,
    realm_id: &str,
    req: &AssertionRequest,
    headers: &HeaderMap,
    device_repo: &D,
) -> QidResult<AssertionResponse> {
    let realm = state
        .config
        .realms
        .iter()
        .find(|r| r.id == realm_id)
        .ok_or_else(|| QidError::NotFound {
            resource: format!("realm {}", realm_id),
        })?;

    let now = qid_core::util::now_seconds();
    let (session, user) = if let Some(session_id) = &req.session {
        // Session hot cache check
        let session = if let Some(cached) = state.session_cache_get(session_id) {
            decode_cached_session(&cached, now)
                .map_err(|_| QidError::Unauthorized {
                    message: "invalid session".to_string(),
                })?
                .ok_or_else(|| QidError::Unauthorized {
                    message: "invalid session".to_string(),
                })?
        } else {
            let session = state.repo.get_session(session_id).await?.ok_or_else(|| {
                QidError::Unauthorized {
                    message: "invalid session".to_string(),
                }
            })?;
            // Cache active sessions
            if let Ok(Some(cache_put)) = session_cache_put(&session, now) {
                state.session_cache_put(session_id.clone(), cache_put.value, cache_put.ttl_seconds);
            }
            session
        };
        validate_assertion_session(&session, realm_id, now)?;
        state
            .repo
            .get_user_by_id(&session.user_id)
            .await?
            .ok_or_else(|| QidError::NotFound {
                resource: "user".to_string(),
            })
            .map(|user| (session, user))?
    } else if let Some(token) = &req.access_token {
        let decoded = qid_oauth::endpoints::decode_access_token(state, token)
            .await
            .map_err(|_| QidError::Unauthorized {
                message: "invalid access token".to_string(),
            })?;
        if decoded.realm_id != realm_id {
            return Err(QidError::Unauthorized {
                message: "access token realm does not match assertion realm".to_string(),
            });
        }
        let edge_name = req.edge.as_deref().ok_or_else(|| QidError::BadRequest {
            message: "edge required".to_string(),
        })?;
        let edge_config = realm
            .pep_registrations
            .served()
            .iter()
            .find(|e| e.name == edge_name)
            .ok_or_else(|| QidError::Unauthorized {
                message: "unknown PEP adapter".to_string(),
            })?;
        let edge_audience = assertion_audience(edge_config, edge_name)?;
        if !decoded.aud.iter().any(|aud| aud == &edge_audience)
            && !decoded
                .resource
                .iter()
                .any(|resource| resource == &edge_audience)
        {
            return Err(QidError::Unauthorized {
                message: "access token is not intended for requested PEP adapter".to_string(),
            });
        }
        let htu = format!(
            "{}/realms/{}/pep/assertion",
            state.plan.public_base_url.trim_end_matches('/'),
            realm_id
        );
        qid_oauth::endpoints::enforce_sender_constrained_access_token(
            state,
            headers,
            &Method::GET,
            &htu,
            token,
            &decoded,
        )?;
        let scopes = decoded
            .scope
            .split(' ')
            .filter(|scope| !scope.is_empty())
            .collect::<BTreeSet<_>>();
        if !(scopes.contains("qid_pep_assertion") || scopes.contains("qid_identity")) {
            return Err(QidError::Unauthorized {
                message: "access token scope does not allow PEP assertion issuance".to_string(),
            });
        }
        let user = state
            .repo
            .get_user_by_id(&decoded.user_id)
            .await?
            .ok_or_else(|| QidError::Unauthorized {
                message: "access token subject user is not registered".to_string(),
            })?;
        if user.realm_id != realm_id {
            return Err(QidError::Unauthorized {
                message: "access token subject user realm does not match assertion realm"
                    .to_string(),
            });
        }
        let session = Session {
            id: String::new(),
            realm_id: realm_id.to_string(),
            user_id: decoded.user_id,
            auth_time: decoded.auth_time.unwrap_or(now),
            acr: decoded.acr,
            amr: decoded.amr,
            idle_expires_at: now + 3600,
            absolute_expires_at: decoded.exp,
            revoked: false,
            created_at: now,
            cnf: decoded.cnf,
        };
        (session, user)
    } else {
        return Err(QidError::Unauthorized {
            message: "session or access_token required".to_string(),
        });
    };

    let edge_name = req.edge.as_deref().ok_or_else(|| QidError::BadRequest {
        message: "edge required".to_string(),
    })?;

    let edge_config = realm
        .pep_registrations
        .served()
        .iter()
        .find(|e| e.name == edge_name)
        .ok_or_else(|| QidError::Unauthorized {
            message: "unknown PEP adapter".to_string(),
        })?;

    let ttl = edge_config.assertion.ttl_seconds;
    let exp = now + ttl;
    let audience = assertion_audience(edge_config, edge_name)?;
    let subject_context =
        assertion_subject_context(state.repo.as_ref(), realm_id, &user, now).await?;
    let device_context = assertion_device_context(device_repo, &user).await?;

    let extra = assertion_extra_claims(realm_id, &user, &session, subject_context, device_context);

    let jti = generate_jti();
    if state
        .assertion_replay_cache
        .record_jti(&jti, now, now)
        .is_err()
    {
        // Should not happen with freshly generated jti, but fail closed
        return Err(QidError::Internal {
            message: "assertion jti collision".to_string(),
        });
    }

    let claims = JwtClaims {
        iss: Some(realm.issuer.clone()),
        sub: Some(user.id.clone()),
        aud: Some(qid_core::jwt::Audience::single(audience)),
        exp: Some(exp as usize),
        nbf: Some(now as usize),
        iat: Some(now as usize),
        jti: Some(jti),
        extra,
    };

    let assertion = state
        .pep_assertion_signer(realm_id)
        .ok_or_else(|| QidError::Config {
            message: format!("realm {realm_id} must configure a dedicated pep_assertion keyring"),
        })?
        .sign(&claims)
        .map_err(|e| QidError::Crypto {
            message: format!("failed to sign assertion: {e}"),
        })?;

    let event = AuditEvent {
        r#type: "assertion.issued".to_string(),
        time: qid_core::util::now_seconds().to_string(),
        tenant: realm.tenant_id.clone(),
        realm: Some(realm_id.to_string()),
        subject: Some(user.id.clone()),
        decision: Some("issued".to_string()),
        decision_id: None,
        extra: HashMap::new(),
    };
    tracing::info!(target: "audit", "{:?}", event);

    metrics::counter!("qid_proxy_assertion_issued_total").increment(1);

    Ok(AssertionResponse {
        assertion,
        expires_at: exp,
    })
}

fn validate_assertion_session(session: &Session, realm_id: &str, now: u64) -> QidResult<()> {
    if session.realm_id != realm_id {
        return Err(QidError::Unauthorized {
            message: "session realm mismatch".to_string(),
        });
    }
    if session.revoked {
        return Err(QidError::Unauthorized {
            message: "session revoked".to_string(),
        });
    }
    if session.idle_expires_at <= now || session.absolute_expires_at <= now {
        return Err(QidError::Unauthorized {
            message: "session expired".to_string(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AssertionSubjectContext {
    groups: Vec<String>,
    roles: Vec<String>,
    entitlements: Vec<String>,
}

async fn assertion_subject_context<R: Repository>(
    repo: &R,
    realm_id: &str,
    user: &User,
    now: u64,
) -> QidResult<AssertionSubjectContext> {
    let realm = RealmId(realm_id.to_string());
    let groups = scim_group_names_for_user(repo.list_scim_groups(&realm).await?, user);
    let grants = if let Some(tenant_id) = repo.get_realm_tenant(&realm).await? {
        repo.list_iga_access_grants(&tenant_id, Some(user.id.as_str()))
            .await?
    } else {
        Vec::new()
    };
    let entitlements = active_entitlements(grants, now);
    let roles = role_claims_from_entitlements(&entitlements);

    Ok(AssertionSubjectContext {
        groups,
        roles,
        entitlements,
    })
}

#[derive(Debug, Clone)]
struct AssertionDeviceContext {
    id: Option<String>,
    posture: Vec<String>,
    trust_level: String,
}

async fn assertion_device_context<R: DeviceRepository>(
    repo: &R,
    user: &User,
) -> QidResult<AssertionDeviceContext> {
    let devices = repo.get_user_devices(&user.id).await?;
    let device = devices.first();
    Ok(AssertionDeviceContext {
        id: device.map(|d| d.id.clone()),
        posture: device.map(|d| d.posture.clone()).unwrap_or_default(),
        trust_level: device
            .map(|d| {
                if d.posture.is_empty() {
                    "unknown".to_string()
                } else {
                    "managed".to_string()
                }
            })
            .unwrap_or_else(|| "unknown".to_string()),
    })
}

fn assertion_extra_claims(
    realm_id: &str,
    user: &User,
    session: &Session,
    subject_context: AssertionSubjectContext,
    device_context: AssertionDeviceContext,
) -> HashMap<String, Value> {
    let acr = session
        .acr
        .clone()
        .unwrap_or_else(|| "urn:qid:acr:password".to_string());
    let amr = if session.amr.is_empty() {
        vec!["pwd".to_string()]
    } else {
        session.amr.clone()
    };

    let mut extra = HashMap::new();
    extra.insert("sid".to_string(), Value::String(session.id.clone()));
    extra.insert("tid".to_string(), Value::String(realm_id.to_string()));
    if let Some(org) = &user.org {
        extra.insert("org".to_string(), Value::String(org.clone()));
    }
    extra.insert("groups".to_string(), json_array(&subject_context.groups));
    extra.insert("roles".to_string(), json_array(&subject_context.roles));
    extra.insert(
        "entitlements".to_string(),
        json_array(&subject_context.entitlements),
    );
    extra.insert("email".to_string(), optional_string(user.email.as_ref()));
    extra.insert(
        "email_verified".to_string(),
        Value::Bool(user.email_verified),
    );
    extra.insert(
        "auth".to_string(),
        serde_json::json!({
            "acr": acr,
            "amr": amr,
            "auth_time": session.auth_time,
        }),
    );
    extra.insert(
        "device".to_string(),
        serde_json::json!({
            "id": device_context.id,
            "posture": device_context.posture,
            "trust_level": device_context.trust_level,
        }),
    );
    extra.insert(
        "risk".to_string(),
        serde_json::json!({
            "score": 10,
            "labels": ["phase0-default"],
        }),
    );
    extra.insert(
        "policy_tags".to_string(),
        json_array(&["qid-session".to_string()]),
    );
    extra.insert(
        "cnf".to_string(),
        session.cnf.clone().unwrap_or(serde_json::json!({})),
    );
    extra
}

fn scim_group_names_for_user(groups: Vec<ScimGroup>, user: &User) -> Vec<String> {
    let mut names = BTreeSet::new();
    for group in groups {
        if scim_members_include_user(&group.members_json, user) {
            names.insert(group.display_name);
        }
    }
    names.into_iter().collect()
}

fn scim_members_include_user(members: &Value, user: &User) -> bool {
    let Some(members) = members.as_array() else {
        return false;
    };
    members.iter().any(|member| {
        let value = member
            .get("value")
            .and_then(Value::as_str)
            .or_else(|| member.get("$ref").and_then(Value::as_str))
            .or_else(|| member.get("display").and_then(Value::as_str));
        match value {
            Some(value) if value == user.id => true,
            Some(value) => user.email.as_deref() == Some(value),
            None => false,
        }
    })
}

fn active_entitlements(grants: Vec<IgaAccessGrantRecord>, now: u64) -> Vec<String> {
    grants
        .into_iter()
        .filter(|grant| !grant.revoked)
        .filter(|grant| {
            grant
                .expires_at_epoch_seconds
                .map(|expires_at| expires_at > now)
                .unwrap_or(true)
        })
        .map(|grant| grant.entitlement)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn role_claims_from_entitlements(entitlements: &[String]) -> Vec<String> {
    entitlements
        .iter()
        .filter_map(|entitlement| entitlement.strip_prefix("role:"))
        .map(ToString::to_string)
        .collect()
}

fn optional_string(value: Option<&String>) -> Value {
    value
        .map(|value| Value::String(value.clone()))
        .unwrap_or(Value::Null)
}

fn json_array(values: &[String]) -> serde_json::Value {
    serde_json::Value::Array(
        values
            .iter()
            .map(|s| serde_json::Value::String(s.clone()))
            .collect(),
    )
}

fn assertion_audience(
    edge_config: &qid_core::config::PepRegistrationConfig,
    edge_name: &str,
) -> QidResult<String> {
    edge_config
        .audience
        .clone()
        .ok_or_else(|| QidError::Config {
            message: format!("PEP adapter {edge_name} must declare audience"),
        })
}

fn generate_jti() -> String {
    format!("qas_{}", ulid::Ulid::new())
}

#[cfg(test)]
#[path = "assertion_tests.rs"]
mod tests;
