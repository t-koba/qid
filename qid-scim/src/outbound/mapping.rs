use qid_core::{
    error::{QidError, QidResult},
    models::ScimUser,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::ENTERPRISE_USER_SCHEMA;

use super::{OutboundDrift, OutboundOperation, OutboundProvisioningPlan, collect_drift};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OutboundAttributeSource {
    UserName,
    ExternalId,
    Active,
    NameFormatted,
    PrimaryEmail,
    Enterprise(String),
    Constant(serde_json::Value),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutboundUserMapping {
    pub user_name: OutboundAttributeSource,
    pub external_id: Option<OutboundAttributeSource>,
    pub active: Option<OutboundAttributeSource>,
    pub name_formatted: Option<OutboundAttributeSource>,
    pub primary_email: Option<OutboundAttributeSource>,
    #[serde(default)]
    pub enterprise: BTreeMap<String, OutboundAttributeSource>,
}

pub fn default_outbound_user_mapping() -> OutboundUserMapping {
    OutboundUserMapping {
        user_name: OutboundAttributeSource::UserName,
        external_id: Some(OutboundAttributeSource::ExternalId),
        active: Some(OutboundAttributeSource::Active),
        name_formatted: Some(OutboundAttributeSource::NameFormatted),
        primary_email: Some(OutboundAttributeSource::PrimaryEmail),
        enterprise: BTreeMap::from([(
            "department".to_string(),
            OutboundAttributeSource::Enterprise("department".to_string()),
        )]),
    }
}

pub fn render_outbound_user(
    user: &ScimUser,
    mapping: &OutboundUserMapping,
) -> QidResult<serde_json::Value> {
    let user_name =
        outbound_value(user, &mapping.user_name).ok_or_else(|| QidError::BadRequest {
            message: "outbound SCIM userName mapping produced no value".to_string(),
        })?;
    let user_name = user_name
        .as_str()
        .ok_or_else(|| QidError::BadRequest {
            message: "outbound SCIM userName must be a string".to_string(),
        })?
        .to_string();
    let mut desired = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": user_name
    });
    set_optional_field(
        user,
        &mut desired,
        "externalId",
        mapping.external_id.as_ref(),
    );
    set_optional_field(user, &mut desired, "active", mapping.active.as_ref());
    if let Some(source) = &mapping.name_formatted
        && let Some(value) = outbound_value(user, source)
    {
        desired["name"] = serde_json::json!({ "formatted": value });
    }
    if let Some(source) = &mapping.primary_email
        && let Some(value) = outbound_value(user, source)
    {
        desired["emails"] = serde_json::json!([{ "value": value, "primary": true }]);
    }
    let mut enterprise = serde_json::Map::new();
    for (target, source) in &mapping.enterprise {
        if let Some(value) = outbound_value(user, source) {
            enterprise.insert(target.clone(), value);
        }
    }
    if !enterprise.is_empty() {
        desired["schemas"]
            .as_array_mut()
            .expect("schemas must be an array")
            .push(serde_json::Value::String(
                ENTERPRISE_USER_SCHEMA.to_string(),
            ));
        desired[ENTERPRISE_USER_SCHEMA] = serde_json::Value::Object(enterprise);
    }
    Ok(desired)
}

pub fn plan_outbound_user_provisioning(
    user: &ScimUser,
    remote: Option<&serde_json::Value>,
    mapping: &OutboundUserMapping,
    dry_run: bool,
) -> QidResult<OutboundProvisioningPlan> {
    let desired = render_outbound_user(user, mapping)?;
    let path = user
        .external_id
        .as_ref()
        .map(|external_id| format!("/Users?filter=externalId eq \"{external_id}\""))
        .unwrap_or_else(|| format!("/Users/{}", user.id));
    let drift = remote
        .map(|remote| outbound_user_drift(&desired, remote))
        .unwrap_or_default();
    let operation = match remote {
        None => OutboundOperation::Create,
        Some(_) if drift.is_empty() => OutboundOperation::Noop,
        Some(_) => OutboundOperation::Replace,
    };
    Ok(OutboundProvisioningPlan {
        dry_run,
        operation,
        path,
        desired,
        drift,
    })
}

fn set_optional_field(
    user: &ScimUser,
    desired: &mut serde_json::Value,
    field: &str,
    source: Option<&OutboundAttributeSource>,
) {
    let Some(source) = source else {
        return;
    };
    if let Some(value) = outbound_value(user, source) {
        desired[field] = value;
    }
}

fn outbound_value(user: &ScimUser, source: &OutboundAttributeSource) -> Option<serde_json::Value> {
    match source {
        OutboundAttributeSource::UserName => {
            Some(serde_json::Value::String(user.user_name.clone()))
        }
        OutboundAttributeSource::ExternalId => user
            .external_id
            .as_ref()
            .map(|value| serde_json::Value::String(value.clone())),
        OutboundAttributeSource::Active => Some(serde_json::Value::Bool(user.active)),
        OutboundAttributeSource::NameFormatted => user
            .name_json
            .get("formatted")
            .and_then(|value| value.as_str())
            .map(|value| serde_json::Value::String(value.to_string())),
        OutboundAttributeSource::PrimaryEmail => user
            .emails_json
            .as_array()
            .into_iter()
            .flatten()
            .find(|email| {
                email
                    .get("primary")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false)
            })
            .or_else(|| {
                user.emails_json
                    .as_array()
                    .and_then(|emails| emails.first())
            })
            .and_then(|email| email.get("value"))
            .and_then(|value| value.as_str())
            .map(|value| serde_json::Value::String(value.to_string())),
        OutboundAttributeSource::Enterprise(attribute) => user
            .enterprise_json
            .get(attribute)
            .filter(|value| !value.is_null())
            .cloned(),
        OutboundAttributeSource::Constant(value) => Some(value.clone()),
    }
}

fn outbound_user_drift(
    desired: &serde_json::Value,
    remote: &serde_json::Value,
) -> Vec<OutboundDrift> {
    let mut drift = Vec::new();
    collect_drift("userName", &["userName"], desired, remote, &mut drift);
    collect_drift("externalId", &["externalId"], desired, remote, &mut drift);
    collect_drift("active", &["active"], desired, remote, &mut drift);
    collect_drift(
        "name.formatted",
        &["name", "formatted"],
        desired,
        remote,
        &mut drift,
    );
    collect_drift(
        "emails.0.value",
        &["emails", "0", "value"],
        desired,
        remote,
        &mut drift,
    );
    if let Some(enterprise) = desired
        .get(ENTERPRISE_USER_SCHEMA)
        .and_then(|v| v.as_object())
    {
        for attribute in enterprise.keys() {
            collect_drift(
                &format!("{ENTERPRISE_USER_SCHEMA}.{attribute}"),
                &[ENTERPRISE_USER_SCHEMA, attribute],
                desired,
                remote,
                &mut drift,
            );
        }
    }
    drift
}
