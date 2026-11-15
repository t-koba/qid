use super::{
    OutboundScimClientConfig, OutboundScimHttpRequest, OutboundScimTransport, join_scim_url,
};
use qid_core::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Inventory policy. A full, stable inventory is required before orphan cleanup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundInventoryLimits {
    pub page_size: usize,
    pub max_resources: usize,
}
impl Default for OutboundInventoryLimits {
    fn default() -> Self {
        Self {
            page_size: 100,
            max_resources: 10_000,
        }
    }
}
pub(crate) fn invalid(message: &str) -> QidError {
    QidError::BadRequest {
        message: format!("outbound SCIM: {message}"),
    }
}
pub(crate) fn resource_path(collection: &str, id: &str) -> QidResult<String> {
    if id.is_empty() || matches!(id, "." | "..") {
        return Err(invalid("invalid resource id"));
    }
    let mut url = url::Url::parse("https://scim.invalid/").map_err(|_| invalid("invalid URL"))?;
    url.path_segments_mut()
        .map_err(|_| invalid("invalid URL"))?
        .push(collection)
        .push(id);
    Ok(url.path().to_string())
}
pub(crate) fn remote_path(collection: &str, remote: &Value) -> QidResult<String> {
    resource_path(
        collection,
        remote
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("resource missing id"))?,
    )
}
pub(crate) fn request(
    config: &OutboundScimClientConfig,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> QidResult<OutboundScimHttpRequest> {
    let mut headers = BTreeMap::from([
        ("Accept".into(), "application/scim+json".into()),
        ("Content-Type".into(), "application/scim+json".into()),
    ]);
    if let Some(token) = &config.bearer_token {
        headers.insert("Authorization".into(), format!("Bearer {token}"));
    }
    Ok(OutboundScimHttpRequest {
        method: method.into(),
        url: join_scim_url(&config.base_url, path)?,
        headers,
        body,
    })
}
fn collection_path(collection: &str) -> QidResult<String> {
    match collection {
        "Users" | "Groups" => Ok(format!("/{collection}")),
        _ => Err(invalid("unsupported collection")),
    }
}
fn page(
    body: Option<Value>,
    start: usize,
    count: usize,
    max: usize,
) -> QidResult<(usize, Vec<Value>)> {
    let body = body.ok_or_else(|| invalid("missing ListResponse"))?;
    let number = |key| {
        body.get(key)
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| invalid("invalid pagination metadata"))
    };
    let total = number("totalResults")?;
    let resources = body
        .get("Resources")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("missing Resources"))?;
    if !body
        .get("schemas")
        .and_then(Value::as_array)
        .is_some_and(|schemas| {
            schemas
                .iter()
                .any(|v| v == "urn:ietf:params:scim:api:messages:2.0:ListResponse")
        })
        || total > max
        || number("startIndex")? != start
        || number("itemsPerPage")? != resources.len()
        || resources.len() > count
        || start - 1 + resources.len() > total
        || (resources.is_empty() && start - 1 < total)
    {
        return Err(invalid("incomplete or invalid ListResponse"));
    }
    for resource in resources {
        remote_path("Users", resource)?;
    }
    Ok((total, resources.clone()))
}
/// Resolve a stable identity. Only a complete zero-result response permits creation.
pub async fn lookup_outbound_resource<T: OutboundScimTransport>(
    config: &OutboundScimClientConfig,
    transport: &T,
    collection: &str,
    external_id: &str,
) -> QidResult<Option<Value>> {
    if external_id.is_empty() {
        return Err(invalid("empty externalId"));
    }
    let filter = format!(
        "externalId eq {}",
        serde_json::to_string(external_id).map_err(|_| invalid("invalid externalId"))?
    );
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("filter", &filter)
        .append_pair("startIndex", "1")
        .append_pair("count", "2")
        .finish();
    let response = transport
        .send(request(
            config,
            "GET",
            &format!("{}?{query}", collection_path(collection)?),
            None,
        )?)
        .await?;
    if response.status != 200 {
        return Err(invalid(&format!(
            "lookup failed with status {}",
            response.status
        )));
    }
    let (total, mut resources) = page(response.body, 1, 2, 1)?;
    if total != resources.len() {
        return Err(invalid("incomplete lookup"));
    }
    if resources
        .first()
        .is_some_and(|r| r.get("externalId").and_then(Value::as_str) != Some(external_id))
    {
        return Err(invalid("lookup identity mismatch"));
    }
    Ok(resources.pop())
}
/// Fetch and validate every page, refusing changing totals or duplicate identities.
pub async fn list_outbound_resources<T: OutboundScimTransport>(
    config: &OutboundScimClientConfig,
    transport: &T,
    collection: &str,
    limits: &OutboundInventoryLimits,
) -> QidResult<Vec<Value>> {
    if limits.page_size == 0 || limits.max_resources == 0 {
        return Err(invalid("inventory limits must be positive"));
    }
    let path = collection_path(collection)?;
    let (mut result, mut ids, mut external_ids, mut expected) =
        (Vec::new(), BTreeSet::new(), BTreeSet::new(), None);
    loop {
        let start = result.len() + 1;
        let response = transport
            .send(request(
                config,
                "GET",
                &format!("{path}?startIndex={start}&count={}", limits.page_size),
                None,
            )?)
            .await?;
        if response.status != 200 {
            return Err(invalid(&format!(
                "inventory failed with status {}",
                response.status
            )));
        }
        let (total, resources) =
            page(response.body, start, limits.page_size, limits.max_resources)?;
        if expected.is_some_and(|n| n != total) {
            return Err(invalid("inventory changed during pagination"));
        }
        expected = Some(total);
        for resource in resources {
            let id = remote_path(collection, &resource)?;
            if !ids.insert(id) {
                return Err(invalid("duplicate remote id"));
            }
            if let Some(external) = resource.get("externalId") {
                let external = external
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| invalid("invalid externalId"))?;
                if !external_ids.insert(external.to_string()) {
                    return Err(invalid("duplicate externalId"));
                }
            }
            result.push(resource);
        }
        if result.len() == total {
            return Ok(result);
        }
    }
}
