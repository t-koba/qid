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
pub(crate) mod tests {
    use super::*;
    use crate::IgaRepository;

    pub(crate) fn fixture() -> (IgaAccessRequestRecord, Vec<IgaAccessGrantRecord>) {
        let request = IgaAccessRequestRecord {
            id: "request".into(),
            tenant_id: "tenant".into(),
            subject: "subject".into(),
            entitlement: "access_package:package".into(),
            reason: None,
            status: "approved".into(),
            approval_steps_json: serde_json::json!([]),
            violations_json: serde_json::json!([]),
            package_entitlement_ids_json: serde_json::json!(["member-a", "member-b"]),
            created_at_epoch_seconds: 100,
            expires_at_epoch_seconds: Some(1000),
        };
        let candidates = ["member-a", "member-b"]
            .into_iter()
            .map(|entitlement| IgaAccessGrantRecord {
                id: format!("grant-{entitlement}"),
                tenant_id: request.tenant_id.clone(),
                request_id: request.id.clone(),
                subject: request.subject.clone(),
                entitlement: entitlement.into(),
                granted_at_epoch_seconds: 200,
                expires_at_epoch_seconds: Some(900),
                approval_ids: vec!["approval".into()],
                revoked: false,
            })
            .collect();
        (request, candidates)
    }

    /// Run against both real backends. Direct storage seeds otherwise
    /// unreachable historical states; rejection must not select or delete them.
    pub(crate) async fn rejects_invalid_sets(repo: &impl IgaRepository) {
        let (request, candidates) = fixture();
        assert!(repo.ensure_iga_access_grants(&candidates).await.is_err());
        repo.store_iga_access_request(&request).await.unwrap();
        let mut revoked_candidate = candidates.clone();
        revoked_candidate[0].revoked = true;
        assert!(
            repo.ensure_iga_access_grants(&revoked_candidate)
                .await
                .is_err()
        );
        for status in ["approval_required", "rejected"] {
            let mut pending = request.clone();
            pending.id = status.into();
            pending.status = status.into();
            repo.store_iga_access_request(&pending).await.unwrap();
            let mut pending_candidates = candidates.clone();
            for candidate in &mut pending_candidates {
                candidate.request_id = status.into();
                candidate.id = format!("{status}-{}", candidate.id);
            }
            assert!(
                repo.ensure_iga_access_grants(&pending_candidates)
                    .await
                    .is_err(),
                "{status}"
            );
        }
        assert!(
            repo.list_iga_access_grants("tenant", None)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(repo.ensure_iga_access_grants(&[]).await.is_err());
        assert!(
            repo.ensure_iga_access_grants(&candidates[..1])
                .await
                .is_err()
        );
        for field in [
            "tenant",
            "request",
            "subject",
            "entitlement",
            "id",
            "timestamp",
            "empty",
        ] {
            let mut invalid = candidates.clone();
            match field {
                "tenant" => invalid[1].tenant_id = "other".into(),
                "request" => invalid[1].request_id = "other".into(),
                "subject" => invalid[1].subject = "other".into(),
                "entitlement" => invalid[1].entitlement = invalid[0].entitlement.clone(),
                "id" => invalid[1].id = invalid[0].id.clone(),
                "timestamp" => invalid[1].expires_at_epoch_seconds = Some(1),
                "empty" => invalid[1].entitlement.clear(),
                _ => unreachable!(),
            }
            assert!(
                repo.ensure_iga_access_grants(&invalid).await.is_err(),
                "{field}"
            );
            assert!(
                repo.list_iga_access_grants("tenant", None)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        let mut wrong_subject = candidates.clone();
        for grant in &mut wrong_subject {
            grant.subject = "other".into();
        }
        assert!(repo.ensure_iga_access_grants(&wrong_subject).await.is_err());

        for kind in ["duplicate", "subject", "entitlement", "id-alias"] {
            let mut parent = request.clone();
            parent.id = kind.into();
            repo.store_iga_access_request(&parent).await.unwrap();
            let mut batch = candidates.clone();
            for grant in &mut batch {
                grant.request_id = kind.into();
                grant.id = format!("{kind}-{}", grant.id);
            }
            let mut incumbent = batch[0].clone();
            match kind {
                "subject" => incumbent.subject = "other".into(),
                "entitlement" => incumbent.entitlement = "unexpected".into(),
                "id-alias" => incumbent.request_id = "another-request".into(),
                "duplicate" => {
                    let mut duplicate = incumbent.clone();
                    duplicate.id = "historical-duplicate".into();
                    repo.store_iga_access_grant(&duplicate).await.unwrap();
                }
                _ => unreachable!(),
            }
            repo.store_iga_access_grant(&incumbent).await.unwrap();
            let before = repo.list_iga_access_grants("tenant", None).await.unwrap();
            assert!(
                repo.ensure_iga_access_grants(&batch).await.is_err(),
                "{kind}"
            );
            assert_eq!(
                repo.list_iga_access_grants("tenant", None).await.unwrap(),
                before
            );
        }
    }
}
