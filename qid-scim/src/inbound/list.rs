//! Shared cursor policy and list response shape for Users and Groups.
use super::{ListQuery, MAX_LIST_RESULTS, users::scim_cursor_secret};
use crate::response::{decode_cursor, encode_cursor, filter_fingerprint};
use axum::{
    Json,
    response::{IntoResponse, Response},
};
use qid_core::{
    error::{QidError, QidResult},
    state::SharedState,
};
use qid_storage::Repository;

pub(super) struct Pagination {
    pub start: usize,
    pub count: usize,
    secret: String,
    fingerprint: String,
}

impl Pagination {
    pub fn new<R: Repository>(
        state: &SharedState<R>,
        realm: &str,
        query: &ListQuery,
    ) -> QidResult<Self> {
        let secret = scim_cursor_secret(state, realm)?;
        let fingerprint = filter_fingerprint(query.filter.as_deref());
        // RFC 9865 §4.2: cursors take precedence over startIndex/count.
        let (start, count) = if let Some(cursor) = query.cursor.as_deref() {
            let cursor =
                decode_cursor(secret.as_bytes(), cursor, &fingerprint).ok_or_else(|| {
                    QidError::BadRequest {
                        message: "invalid or expired SCIM pagination cursor".to_string(),
                    }
                })?;
            (cursor.start, cursor.count.min(MAX_LIST_RESULTS))
        } else {
            (
                query.start_index.unwrap_or(1).saturating_sub(1),
                query.count.unwrap_or(100).min(MAX_LIST_RESULTS),
            )
        };
        Ok(Self {
            start,
            count,
            secret,
            fingerprint,
        })
    }

    pub fn response(self, total: usize, resources: Vec<serde_json::Value>) -> Response {
        let mut body = serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": total,
            "startIndex": self.start + 1,
            "itemsPerPage": resources.len(),
            "Resources": resources
        });
        if self.start + self.count < total {
            body["nextCursor"] = serde_json::Value::String(encode_cursor(
                self.secret.as_bytes(),
                self.start + self.count,
                self.count,
                &self.fingerprint,
            ));
        }
        Json(body).into_response()
    }
}
