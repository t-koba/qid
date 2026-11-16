//! Shared validation for atomic grant-set materialization. Persistence and its
//! serialization boundary belong to each backend, not to this reconciliation.
use std::collections::BTreeSet;

use qid_core::{
    error::{QidError, QidResult},
    models::{IgaAccessGrantRecord, IgaAccessRequestRecord},
};

fn invalid(message: &str) -> QidError {
    QidError::BadRequest {
        message: message.to_string(),
    }
}

pub(crate) fn validate_candidates(
    candidates: &[IgaAccessGrantRecord],
) -> QidResult<&IgaAccessGrantRecord> {
    let first = candidates
        .first()
        .ok_or_else(|| invalid("IGA grant candidates must not be empty"))?;
    let mut entitlements = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for candidate in candidates {
        candidate.validate()?;
        if candidate.revoked
            || candidate.tenant_id != first.tenant_id
            || candidate.request_id != first.request_id
            || candidate.subject != first.subject
            || !entitlements.insert(&candidate.entitlement)
            || !ids.insert(&candidate.id)
        {
            return Err(invalid(
                "IGA grant candidates have mixed or duplicate bindings",
            ));
        }
    }
    Ok(first)
}

/// Call only after validate_candidates, while holding the backend's boundary.
/// Incumbents must include *all* grants for the tenant/request, not just active
/// grants or grants for the expected subject. Never choose among duplicates.
pub(crate) fn missing_grants(
    candidates: &[IgaAccessGrantRecord],
    request: &IgaAccessRequestRecord,
    incumbents: &[IgaAccessGrantRecord],
) -> QidResult<Vec<IgaAccessGrantRecord>> {
    let first = &candidates[0];
    if request.status != "approved"
        || request.tenant_id != first.tenant_id
        || request.id != first.request_id
        || request.subject != first.subject
    {
        return Err(invalid(
            "IGA grant candidates do not match their access request",
        ));
    }
    let expected: Vec<String> = if request.entitlement.starts_with("access_package:") {
        serde_json::from_value(request.package_entitlement_ids_json.clone())
            .map_err(|_| invalid("IGA access package snapshot is malformed"))?
    } else {
        vec![request.entitlement.clone()]
    };
    let bindings: BTreeSet<_> = candidates.iter().map(|g| &g.entitlement).collect();
    if expected.is_empty()
        || expected.len() != bindings.len()
        || expected.iter().collect::<BTreeSet<_>>() != bindings
    {
        return Err(invalid(
            "IGA grant candidates must cover the complete request snapshot",
        ));
    }
    let mut present = BTreeSet::new();
    for incumbent in incumbents {
        incumbent.validate()?;
        if incumbent.tenant_id != first.tenant_id
            || incumbent.request_id != first.request_id
            || incumbent.subject != first.subject
            || !bindings.contains(&incumbent.entitlement)
            || !present.insert(&incumbent.entitlement)
            || candidates.iter().any(|candidate| {
                candidate.id == incumbent.id && candidate.entitlement != incumbent.entitlement
            })
        {
            return Err(invalid(
                "IGA access request has inconsistent incumbent grant bindings",
            ));
        }
    }
    Ok(candidates
        .iter()
        .filter(|candidate| !present.contains(&candidate.entitlement))
        .cloned()
        .collect())
}

#[cfg(test)]
#[path = "iga_grants_tests.rs"]
pub(crate) mod tests;
