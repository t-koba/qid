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

pub(crate) fn scim_user(user: ScimUser) -> serde_json::Value {
    let version = scim_user_version(&user);
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
    if user
        .enterprise_json
        .as_object()
        .is_some_and(|obj| !obj.is_empty())
    {
        value["schemas"]
            .as_array_mut()
            .expect("schemas must be an array")
            .push(serde_json::Value::String(
                ENTERPRISE_USER_SCHEMA.to_string(),
            ));
        value[ENTERPRISE_USER_SCHEMA] = user.enterprise_json;
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
        "enterprise": user.enterprise_json,
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
