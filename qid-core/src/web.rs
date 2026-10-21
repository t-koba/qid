//! Shared HTTP request helpers.

use axum::body::Bytes;
use axum::extract::FromRequest;
use axum::http::Request;
use serde::de::DeserializeOwned;

use crate::error::QidError;

/// Require a JSON object body.
///
/// A JSON array is deserialized positionally onto the fields of a derived
/// struct, so a body like `["chosen-id", "value"]` would fill a client-chosen
/// identifier. Only an object is accepted.
pub fn require_json_object(raw: &serde_json::Value, description: &str) -> Result<(), QidError> {
    if raw.is_object() {
        Ok(())
    } else {
        Err(QidError::BadRequest {
            message: format!("{description} must be a JSON object"),
        })
    }
}

/// A JSON request body that must be a JSON object.
///
/// A JSON array is deserialized positionally onto the fields of a derived
/// struct, so a body like `["chosen-id", "value"]` would fill a client-chosen
/// identifier. Only an object is accepted here.
#[derive(Debug)]
pub struct JsonObject<T>(pub T);

impl<T> std::ops::Deref for JsonObject<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

#[axum::async_trait]
impl<T, S> FromRequest<S> for JsonObject<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = QidError;

    async fn from_request(
        req: Request<axum::body::Body>,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let bytes =
            Bytes::from_request(req, state)
                .await
                .map_err(|error| QidError::BadRequest {
                    message: format!("the request body could not be read: {error}"),
                })?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|error| QidError::BadRequest {
                message: format!("the request body is not valid JSON: {error}"),
            })?;
        require_json_object(&value, "the request body")?;
        let body = serde_json::from_value(value).map_err(|error| QidError::BadRequest {
            message: format!("the request body does not match the expected shape: {error}"),
        })?;
        Ok(JsonObject(body))
    }
}
