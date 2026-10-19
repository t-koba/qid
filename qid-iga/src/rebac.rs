//! ReBAC / Zanzibar-style authorization engine.
//!
//! Provides the core `check` and `expand` operations over relationship tuples.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use qid_core::{
    error::QidResult,
    models::{CheckRequest, ExpandNode, RelationshipTuple},
    util::now_seconds,
};
use qid_policy::models::RebacEvaluator;
use qid_storage::traits::RebacRepository;

/// Maximum recursion depth for userset expansion during Check / Expand.
const MAX_DEPTH: usize = 10;

/// Result of a single check operation.
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub allowed: bool,
}

/// Check whether `subject` has `relation` on `(namespace, object_id)`.
///
/// Performs an iterative BFS walk through the relationship graph:
///   1. Direct tuple match.
///   2. Userset (group) membership expansion (bounded by MAX_DEPTH).
pub async fn check<R: RebacRepository>(
    repo: &R,
    namespace: &str,
    object_id: &str,
    relation: &str,
    subject_namespace: &str,
    subject_id: &str,
) -> QidResult<bool> {
    let mut visited: HashSet<(String, String, String)> = HashSet::new();

    struct WorkItem {
        namespace: String,
        object_id: String,
        relation: String,
        depth: usize,
    }

    let mut queue = std::collections::VecDeque::new();
    queue.push_back(WorkItem {
        namespace: namespace.to_string(),
        object_id: object_id.to_string(),
        relation: relation.to_string(),
        depth: 0,
    });

    while let Some(item) = queue.pop_front() {
        if item.depth > MAX_DEPTH {
            continue;
        }

        let node_key = (
            item.namespace.clone(),
            item.object_id.clone(),
            item.relation.clone(),
        );
        if !visited.insert(node_key) {
            continue;
        }

        let tuples = repo
            .list_relationship_tuples(&item.namespace, &item.object_id, Some(&item.relation))
            .await?;

        for t in &tuples {
            if t.subject_namespace == subject_namespace
                && t.subject_id == subject_id
                && t.subject_relation.is_empty()
            {
                return Ok(true);
            }
        }

        for t in &tuples {
            if t.subject_relation.is_empty() {
                continue;
            }
            queue.push_back(WorkItem {
                namespace: t.subject_namespace.clone(),
                object_id: t.subject_id.clone(),
                relation: t.subject_relation.clone(),
                depth: item.depth + 1,
            });
        }
    }

    Ok(false)
}

/// Expand the set of subjects that have `relation` on `(namespace, object_id)`.
///
/// Uses two phases:
///   1. BFS to read each reachable tuple group once, up to MAX_DEPTH.
///   2. Render each path separately, preserving cyclic and depth-limited edges as leaves.
pub async fn expand<R: RebacRepository>(
    repo: &R,
    namespace: &str,
    object_id: &str,
    relation: &str,
) -> QidResult<ExpandNode> {
    type TupleGroupKey = (String, String, String);

    let root_key = (
        namespace.to_string(),
        object_id.to_string(),
        relation.to_string(),
    );
    let mut groups = HashMap::new();
    let mut seen = HashSet::from([root_key.clone()]);
    let mut queue = std::collections::VecDeque::from([(root_key.clone(), 0usize)]);

    // BFS discovers each group at its shortest depth. Mark it seen on enqueue
    // so shared and cyclic edges cannot duplicate either queue entries or reads.
    while let Some((key, depth)) = queue.pop_front() {
        let tuples = repo
            .list_relationship_tuples(&key.0, &key.1, Some(&key.2))
            .await?;
        if depth < MAX_DEPTH {
            for t in &tuples {
                if !t.subject_relation.is_empty() {
                    let sub_key = (
                        t.subject_namespace.clone(),
                        t.subject_id.clone(),
                        t.subject_relation.clone(),
                    );
                    if seen.insert(sub_key.clone()) {
                        queue.push_back((sub_key, depth + 1));
                    }
                }
            }
        }
        groups.insert(key, tuples);
    }

    // A rendered subtree depends on its path and depth, not just its group key.
    // Only raw tuples are shared; remove ancestors on return so siblings retain
    // their own copies of shared children. Recursion is bounded by MAX_DEPTH.
    fn render_children(
        groups: &HashMap<TupleGroupKey, Vec<RelationshipTuple>>,
        key: &TupleGroupKey,
        depth: usize,
        ancestry: &mut HashSet<TupleGroupKey>,
    ) -> Vec<ExpandNode> {
        let Some(tuples) = groups.get(key) else {
            return Vec::new();
        };
        let mut children = Vec::with_capacity(tuples.len());
        for t in tuples {
            if !t.subject_relation.is_empty() && depth < MAX_DEPTH {
                let sub_key = (
                    t.subject_namespace.clone(),
                    t.subject_id.clone(),
                    t.subject_relation.clone(),
                );
                if groups.get(&sub_key).is_some_and(|group| !group.is_empty())
                    && ancestry.insert(sub_key.clone())
                {
                    let grand_children = render_children(groups, &sub_key, depth + 1, ancestry);
                    ancestry.remove(&sub_key);
                    children.push(ExpandNode::Branch {
                        namespace: t.subject_namespace.clone(),
                        object_id: t.subject_id.clone(),
                        relation: t.subject_relation.clone(),
                        children: grand_children,
                    });
                    continue;
                }
            }
            children.push(ExpandNode::Leaf {
                namespace: t.subject_namespace.clone(),
                subject_id: t.subject_id.clone(),
                subject_relation: if t.subject_relation.is_empty() {
                    None
                } else {
                    Some(t.subject_relation.clone())
                },
            });
        }
        children
    }

    let root_children = render_children(
        &groups,
        &root_key,
        0,
        &mut HashSet::from([root_key.clone()]),
    );
    Ok(ExpandNode::Branch {
        namespace: namespace.to_string(),
        object_id: object_id.to_string(),
        relation: relation.to_string(),
        children: root_children,
    })
}

/// Write one or more relationship tuples.
pub async fn write_tuples<R: RebacRepository>(
    repo: &R,
    tuples: &[RelationshipTuple],
) -> QidResult<()> {
    for t in tuples {
        let mut tuple = t.clone();
        if tuple.created_at_epoch_seconds == 0 {
            tuple.created_at_epoch_seconds = now_seconds();
        }
        repo.create_relationship_tuple(&tuple).await?;
    }
    Ok(())
}

/// Delete one or more relationship tuples.
pub async fn delete_tuples<R: RebacRepository>(
    repo: &R,
    tuples: &[RelationshipTuple],
) -> QidResult<()> {
    for t in tuples {
        repo.delete_relationship_tuple(t).await?;
    }
    Ok(())
}

/// Perform a batch of check operations.
pub async fn check_batch<R: RebacRepository>(
    repo: &R,
    checks: &[CheckRequest],
) -> QidResult<Vec<CheckResult>> {
    let mut results = Vec::with_capacity(checks.len());
    for c in checks {
        let allowed = check(
            repo,
            &c.namespace,
            &c.object_id,
            &c.relation,
            &c.subject.namespace,
            &c.subject.subject_id,
        )
        .await?;
        results.push(CheckResult { allowed });
    }
    Ok(results)
}

/// Bridge that adapts a `RebacRepository` into a `RebacEvaluator`
/// for use with the policy engine.
#[derive(Clone)]
pub struct RebacEvaluatorBridge<R> {
    repo: R,
}

impl<R> RebacEvaluatorBridge<R> {
    pub fn new(repo: R) -> Self {
        Self { repo }
    }
}

#[async_trait::async_trait]
impl<R> RebacEvaluator for RebacEvaluatorBridge<R>
where
    R: RebacRepository + Send + Sync + 'static,
{
    async fn check(
        &self,
        namespace: &str,
        object_id: &str,
        relation: &str,
        subject_namespace: &str,
        subject_id: &str,
    ) -> QidResult<bool> {
        crate::rebac::check(
            &self.repo,
            namespace,
            object_id,
            relation,
            subject_namespace,
            subject_id,
        )
        .await
    }
}

/// Convenience function to create a `RebacEvaluator` from any
/// `RebacRepository`.
pub fn rebac_evaluator_from_repo<R: RebacRepository + Send + Sync + 'static>(
    repo: R,
) -> Arc<dyn RebacEvaluator> {
    Arc::new(RebacEvaluatorBridge::new(repo))
}

/// ReBAC evaluator applying the same `{tenant_id}::{namespace}` scoping as the
/// admin ReBAC API, so policy rules keep using unscoped namespaces while only
/// matching tuples written through the tenant-scoped API.
#[derive(Clone)]
pub struct TenantScopedRebacEvaluator<R> {
    repo: Arc<R>,
    tenant_id: String,
}

impl<R> TenantScopedRebacEvaluator<R> {
    pub fn new(repo: Arc<R>, tenant_id: &str) -> Self {
        Self {
            repo,
            tenant_id: tenant_id.to_string(),
        }
    }

    fn scoped(&self, namespace: &str) -> String {
        let prefix = format!("{}::", self.tenant_id);
        if namespace.starts_with(&prefix) {
            namespace.to_string()
        } else {
            format!("{prefix}{namespace}")
        }
    }
}

#[async_trait::async_trait]
impl<R> RebacEvaluator for TenantScopedRebacEvaluator<R>
where
    R: RebacRepository + Send + Sync + 'static,
{
    async fn check(
        &self,
        namespace: &str,
        object_id: &str,
        relation: &str,
        subject_namespace: &str,
        subject_id: &str,
    ) -> QidResult<bool> {
        crate::rebac::check(
            &*self.repo,
            &self.scoped(namespace),
            object_id,
            relation,
            &self.scoped(subject_namespace),
            subject_id,
        )
        .await
    }
}

/// Build a tenant-scoped `RebacEvaluator` over a shared repository handle.
pub fn tenant_scoped_rebac_evaluator<R: RebacRepository + Send + Sync + 'static>(
    repo: Arc<R>,
    tenant_id: &str,
) -> Arc<dyn RebacEvaluator> {
    Arc::new(TenantScopedRebacEvaluator::new(repo, tenant_id))
}

#[cfg(test)]
#[path = "rebac_tests.rs"]
mod tests;
