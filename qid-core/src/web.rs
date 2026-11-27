//! Shared HTTP request helpers.

use axum::body::Bytes;
use axum::extract::FromRequest;
use axum::http::Request;
use serde::de::{DeserializeOwned, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use std::fmt;

use crate::error::QidError;

/// Deserialize a JSON value, rejecting duplicate object member names at any depth.
///
/// `serde_json::Value` silently keeps the last of duplicate members, which would
/// let one reader of a protocol message see different parameters than another.
pub fn parse_strict_json_value(slice: &[u8]) -> serde_json::Result<serde_json::Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(slice);
    let value = deserializer.deserialize_any(StrictValueVisitor)?;
    deserializer.end()?;
    Ok(value)
}

struct StrictValueVisitor;

impl<'de> DeserializeSeed<'de> for StrictValueVisitor {
    type Value = serde_json::Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = serde_json::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate member names")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate JSON member name: {key}"
                )));
            }
            object.insert(key, map.next_value_seed(StrictValueVisitor)?);
        }
        Ok(serde_json::Value::Object(object))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(StrictValueVisitor)? {
            values.push(value);
        }
        Ok(serde_json::Value::Array(values))
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Bool(value))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Number(value.into()))
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Number(value.into()))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(value.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(value))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }
}

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
            parse_strict_json_value(&bytes).map_err(|error| QidError::BadRequest {
                message: format!("the request body is not valid JSON: {error}"),
            })?;
        require_json_object(&value, "the request body")?;
        let body = serde_json::from_value(value).map_err(|error| QidError::BadRequest {
            message: format!("the request body does not match the expected shape: {error}"),
        })?;
        Ok(JsonObject(body))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_strict_json_value;

    #[test]
    fn rejects_duplicate_root_member() {
        let error = parse_strict_json_value(br#"{"client_id":"one","client_id":"two"}"#)
            .expect_err("a duplicate root member is rejected");
        assert!(
            error
                .to_string()
                .contains("duplicate JSON member name: client_id"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_duplicate_nested_member() {
        let error = parse_strict_json_value(br#"{"claims":{"acr":"one","acr":"two"}}"#)
            .expect_err("a duplicate nested member is rejected");
        assert!(
            error
                .to_string()
                .contains("duplicate JSON member name: acr"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_duplicate_member_in_array_element() {
        let error = parse_strict_json_value(br#"{"items":[{"type":"one","type":"two"}]}"#)
            .expect_err("a duplicate member inside an array is rejected");
        assert!(
            error
                .to_string()
                .contains("duplicate JSON member name: type"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn preserves_unique_members_independent_of_order() {
        let left = parse_strict_json_value(br#"{"a":1,"nested":{"x":true,"y":[1,"two",null]}}"#)
            .expect("unique members are accepted");
        let right = parse_strict_json_value(br#"{"nested":{"y":[1,"two",null],"x":true},"a":1}"#)
            .expect("unique members are accepted");
        assert_eq!(left, right);
        assert_eq!(left["a"], 1);
        assert_eq!(left["nested"]["x"], true);
        assert_eq!(left["nested"]["y"][1], "two");
        assert!(left["nested"]["y"][2].is_null());
    }
}
