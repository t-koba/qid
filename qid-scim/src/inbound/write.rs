//! Conditional SCIM writes: match policy stays outside storage.
use axum::response::{IntoResponse, Response};
use qid_core::error::QidError;

pub(super) type WriteResult<T> = Result<T, WriteError>;

#[derive(Debug)]
pub(super) enum WriteError {
    PreconditionFailed,
    Other(QidError),
}

impl From<QidError> for WriteError {
    fn from(error: QidError) -> Self {
        Self::Other(error)
    }
}

impl WriteError {
    pub(super) fn status_code(&self) -> u16 {
        match self {
            Self::PreconditionFailed => 412,
            Self::Other(error) => error.status_code(),
        }
    }

    pub(super) fn message(&self) -> String {
        match self {
            Self::PreconditionFailed => "SCIM resource version mismatch".to_string(),
            Self::Other(error) => error.message(),
        }
    }
}

impl IntoResponse for WriteError {
    fn into_response(self) -> Response {
        match self {
            Self::PreconditionFailed => crate::response::precondition_failed(&self.message()),
            Self::Other(error) => qid_http::error_response(error),
        }
    }
}

/// Keep the complete client condition, not the bytes of a previously read row.
/// The realm is pinned by the initial visibility check and rechecked under lock.
#[derive(Clone)]
pub(super) struct Condition {
    realm_id: String,
    version: String,
}

impl Condition {
    pub(super) fn new(realm_id: String, version: &str) -> Self {
        Self {
            realm_id,
            version: version.to_string(),
        }
    }

    pub(super) fn from_headers(realm_id: String, headers: &axum::http::HeaderMap) -> Option<Self> {
        // The route has already rejected invalid header text.
        headers
            .get(axum::http::header::IF_MATCH)
            .map(|value| Self::new(realm_id, value.to_str().expect("validated If-Match")))
    }

    pub(super) fn matches_user(&self, user: &qid_core::models::ScimUser) -> bool {
        self.realm_id == user.realm_id
            && crate::response::check_resource_version(
                &self.version,
                &crate::response::scim_user_version(user),
            )
            .is_ok()
    }

    pub(super) fn matches_group(&self, group: &qid_core::models::ScimGroup) -> bool {
        self.realm_id == group.realm_id
            && crate::response::check_resource_version(
                &self.version,
                &crate::response::scim_group_version(group),
            )
            .is_ok()
    }
}

/// Preserve visibility-before-precondition ordering for each conditional route.
pub(super) fn checked_resource<T>(
    result: qid_core::error::QidResult<Option<T>>,
    realm: Option<&str>,
    headers: Option<&axum::http::HeaderMap>,
    resource: &str,
    realm_of: impl Fn(&T) -> &str,
    version_of: impl FnOnce(&T) -> String,
) -> Result<T, Box<Response>> {
    let value = result.map_err(|error| Box::new(qid_http::error_response(error)))?;
    let value = value
        .filter(|value| realm.is_none_or(|realm| realm == realm_of(value)))
        .ok_or_else(|| {
            Box::new(qid_http::error_response(QidError::NotFound {
                resource: resource.to_string(),
            }))
        })?;
    if let Some(headers) = headers {
        crate::response::check_if_match(headers, &version_of(&value))
            .map_err(|detail| Box::new(crate::response::precondition_failed(detail)))?;
    }
    Ok(value)
}
