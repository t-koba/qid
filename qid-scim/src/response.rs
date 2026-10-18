//! SCIM 2.0 response helpers.

use axum::{
    Json,
    http::{
        HeaderMap, StatusCode,
        header::{ETAG, IF_MATCH},
    },
    response::IntoResponse,
};
use base64::Engine;
use qid_core::models::{ScimGroup, ScimUser};

use crate::ENTERPRISE_USER_SCHEMA;

/// RFC 9865 §4.2 opaque pagination cursor. The cursor encodes the
/// index of the next page to return and a fingerprint of the filter so
/// that cursors issued for one filter cannot be replayed against a
/// different one. The cursor is HMAC-signed to prevent tampering.
pub fn encode_cursor(
    secret: &[u8],
    start_index: usize,
    count: usize,
    filter_fingerprint: &str,
) -> String {
    let payload = serde_json::json!({
        "s": start_index,
        "c": count,
        "f": filter_fingerprint,
        "v": SCIM_CURSOR_VERSION,
    });
    let body =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
    let tag = compute_cursor_tag(secret, &body);
    format!("{SCIM_CURSOR_PREFIX}{body}.{tag}")
}

pub fn decode_cursor(
    secret: &[u8],
    cursor: &str,
    expected_filter_fingerprint: &str,
) -> Option<CursorState> {
    let body_and_tag = cursor.strip_prefix(SCIM_CURSOR_PREFIX)?;
    let (body, tag) = body_and_tag.split_once('.')?;
    if !qid_core::util::constant_time_eq(
        compute_cursor_tag(secret, body).as_bytes(),
        tag.as_bytes(),
    ) {
        return None;
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let version = value.get("v")?.as_u64()?;
    if version != SCIM_CURSOR_VERSION {
        return None;
    }
    let filter = value.get("f")?.as_str()?;
    if filter != expected_filter_fingerprint {
        return None;
    }
    let start = value.get("s")?.as_u64()? as usize;
    let count = value.get("c")?.as_u64()? as usize;
    Some(CursorState { start, count })
}

pub struct CursorState {
    pub start: usize,
    pub count: usize,
}

const SCIM_CURSOR_PREFIX: &str = "scim-cursor-v1-";
const SCIM_CURSOR_VERSION: u64 = 1;

fn compute_cursor_tag(secret: &[u8], body: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body.as_bytes());
    let result = mac.finalize().into_bytes();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(result)
}

/// Produce a stable, collision-resistant fingerprint of the SCIM filter
/// that was applied to a list query. The fingerprint is included in the
/// pagination cursor so the server can reject a cursor that was issued
/// for a different filter.
pub fn filter_fingerprint(filter: Option<&str>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(filter.unwrap_or("").as_bytes());
    let digest = hasher.finalize();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..16])
}

pub(crate) fn scim_user_response(status: StatusCode, user: ScimUser) -> axum::response::Response {
    let etag = scim_user_version(&user);
    (status, [(ETAG, etag)], Json(scim_user(user))).into_response()
}

pub(crate) fn scim_group_response(
    status: StatusCode,
    group: ScimGroup,
) -> axum::response::Response {
    let etag = scim_group_version(&group);
    (status, [(ETAG, etag)], Json(scim_group(group))).into_response()
}

pub(crate) fn check_if_match(
    headers: &HeaderMap,
    current_version: &str,
) -> Result<(), &'static str> {
    let Some(value) = headers.get(IF_MATCH) else {
        return Ok(());
    };
    let Ok(value) = value.to_str() else {
        return Err("invalid If-Match header");
    };
    if value
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == "*" || candidate == current_version)
    {
        Ok(())
    } else {
        Err("SCIM resource version mismatch")
    }
}

pub(crate) fn precondition_failed(detail: &str) -> axum::response::Response {
    (
        StatusCode::PRECONDITION_FAILED,
        Json(serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": detail,
            "status": "412"
        })),
    )
        .into_response()
}

/// Sanitized enterprise projection for SCIM responses and ETags.
///
/// `enterprise_json` is SCIM client-writable and must never act as authority
/// for the deprovision timestamp. Strip any client-supplied or legacy
/// `deprovisioned_at` marker, then project the server-owned
/// `ScimUser.deprovisioned_at` when present. When the authority is `None`,
/// no forged or legacy value is exposed.
pub(crate) fn projected_enterprise_json(user: &ScimUser) -> serde_json::Value {
    let mut enterprise = user.enterprise_json.clone();
    if !enterprise.is_object() {
        enterprise = serde_json::json!({});
    }
    if let Some(object) = enterprise.as_object_mut() {
        object.remove("deprovisioned_at");
        if let Some(deprovisioned_at) = user.deprovisioned_at {
            object.insert(
                "deprovisioned_at".to_string(),
                serde_json::Value::Number(deprovisioned_at.into()),
            );
        }
    }
    enterprise
}

/// Remove a client-supplied or legacy `deprovisioned_at` marker from stored
/// `enterprise_json`. The authoritative timestamp lives only in
/// `ScimUser.deprovisioned_at`; storage must never persist a forged value.
pub(crate) fn strip_stored_enterprise_marker(enterprise_json: &mut serde_json::Value) {
    if let Some(object) = enterprise_json.as_object_mut() {
        object.remove("deprovisioned_at");
    }
}

pub(crate) fn scim_user(user: ScimUser) -> serde_json::Value {
    let version = scim_user_version(&user);
    let enterprise = projected_enterprise_json(&user);
    let mut value = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": user.id,
        "userName": user.user_name,
        "active": user.active,
        "name": user.name_json,
        "emails": user.emails_json,
        "meta": { "resourceType": "User", "version": version }
    });
    if let Some(external_id) = user.external_id {
        value["externalId"] = serde_json::Value::String(external_id);
    }
    if enterprise.as_object().is_some_and(|obj| !obj.is_empty()) {
        value["schemas"]
            .as_array_mut()
            .expect("schemas must be an array")
            .push(serde_json::Value::String(
                ENTERPRISE_USER_SCHEMA.to_string(),
            ));
        value[ENTERPRISE_USER_SCHEMA] = enterprise;
    }
    value
}

pub(crate) fn scim_group(group: ScimGroup) -> serde_json::Value {
    let version = scim_group_version(&group);
    serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "id": group.id,
        "displayName": group.display_name,
        "members": group.members_json,
        "meta": { "resourceType": "Group", "version": version }
    })
}

pub(crate) fn scim_user_version(user: &ScimUser) -> String {
    let material = serde_json::json!({
        "id": user.id,
        "realm_id": user.realm_id,
        "external_id": user.external_id,
        "user_name": user.user_name,
        "name": user.name_json,
        "emails": user.emails_json,
        "enterprise": projected_enterprise_json(user),
        "active": user.active
    });
    weak_etag(&material)
}

pub(crate) fn scim_group_version(group: &ScimGroup) -> String {
    let material = serde_json::json!({
        "id": group.id,
        "realm_id": group.realm_id,
        "display_name": group.display_name,
        "members": group.members_json
    });
    weak_etag(&material)
}

pub(crate) fn weak_etag(value: &serde_json::Value) -> String {
    format!(
        "W/\"{}\"",
        qid_core::util::sha256_base64url(value.to_string())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scim_user_response_never_exposes_directory_provider_id() {
        let user = ScimUser {
            id: "user-1".to_string(),
            realm_id: "corp".to_string(),
            external_id: Some("uid=alice,dc=example,dc=com".to_string()),
            user_name: "alice@example.com".to_string(),
            name_json: serde_json::json!({}),
            emails_json: serde_json::json!([]),
            enterprise_json: serde_json::json!({
                "source": "urn:qid:directory:ldap",
                "department": "Platform",
            }),
            directory_provider_id: Some("ad-main".to_string()),
            deprovisioned_at: None,
            active: true,
        };
        let body = scim_user(user);
        assert_eq!(body["userName"], "alice@example.com");
        // Server-owned ownership stays out of the wire projection, even when set.
        assert!(body.get("directory_provider_id").is_none());
        assert!(body.get("directoryProviderId").is_none());
        assert_eq!(body[ENTERPRISE_USER_SCHEMA]["department"], "Platform");
    }

    fn lifecycle_user(deprovisioned_at: Option<u64>, enterprise: serde_json::Value) -> ScimUser {
        ScimUser {
            id: "user-1".to_string(),
            realm_id: "corp".to_string(),
            external_id: None,
            user_name: "alice@example.com".to_string(),
            name_json: serde_json::json!({}),
            emails_json: serde_json::json!([]),
            enterprise_json: enterprise,
            directory_provider_id: None,
            deprovisioned_at,
            active: true,
        }
    }

    #[test]
    fn enterprise_projection_hides_forged_marker_when_authority_is_none() {
        let user = lifecycle_user(
            None,
            serde_json::json!({ "department": "Platform", "deprovisioned_at": 1_050 }),
        );
        let body = scim_user(user);
        let enterprise = &body[ENTERPRISE_USER_SCHEMA];
        assert_eq!(enterprise["department"], "Platform");
        assert!(enterprise.get("deprovisioned_at").is_none());
        // Forged marker must not affect the version either.
        let forged_version = scim_user_version(&lifecycle_user(
            None,
            serde_json::json!({ "department": "Platform", "deprovisioned_at": 9_999 }),
        ));
        let clean_version = scim_user_version(&lifecycle_user(
            None,
            serde_json::json!({ "department": "Platform" }),
        ));
        assert_eq!(forged_version, clean_version);
    }

    #[test]
    fn enterprise_projection_uses_trusted_timestamp_when_authority_is_some() {
        let user = lifecycle_user(
            Some(1_050),
            serde_json::json!({ "department": "Platform", "deprovisioned_at": 9_999 }),
        );
        let body = scim_user(user);
        let enterprise = &body[ENTERPRISE_USER_SCHEMA];
        assert_eq!(enterprise["department"], "Platform");
        assert_eq!(enterprise["deprovisioned_at"], 1_050);
        // Trusted value is part of the version, distinct from None.
        let some_version = scim_user_version(&lifecycle_user(
            Some(1_050),
            serde_json::json!({ "department": "Platform" }),
        ));
        let none_version = scim_user_version(&lifecycle_user(
            None,
            serde_json::json!({ "department": "Platform" }),
        ));
        assert_ne!(some_version, none_version);
    }
}
