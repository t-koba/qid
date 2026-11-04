//! ReBAC / Zanzibar-style authorization engine.
//!
//! Provides the core `check` and `expand` operations over relationship tuples.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use qid_core::{
    error::{QidError, QidResult},
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

/// Failure to expand a complete response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpandError {
    Repository(QidError),
    ResponseTooLarge { limit_bytes: usize },
}

impl std::fmt::Display for ExpandError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Repository(error) => std::fmt::Display::fmt(error, formatter),
            Self::ResponseTooLarge { limit_bytes } => write!(
                formatter,
                "ReBAC Expand response exceeds the configured {limit_bytes}-byte limit"
            ),
        }
    }
}

impl std::error::Error for ExpandError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Repository(error) => Some(error),
            Self::ResponseTooLarge { .. } => None,
        }
    }
}

impl From<QidError> for ExpandError {
    fn from(error: QidError) -> Self {
        Self::Repository(error)
    }
}

type TupleGroupKey = (String, String, String);
type TupleGroups = HashMap<TupleGroupKey, Vec<RelationshipTuple>>;

// Lazy borrowed tree: serialization and materialization share edge selection.
// Preflight allocates only the current path, never the expanded tree.
#[derive(serde::Serialize)]
#[serde(untagged)]
enum ExpandView<'a> {
    Leaf {
        namespace: &'a str,
        subject_id: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        subject_relation: Option<&'a str>,
    },
    Branch {
        namespace: &'a str,
        object_id: &'a str,
        relation: &'a str,
        children: ExpandChildren<'a>,
    },
}

struct ExpandChildren<'a> {
    groups: &'a TupleGroups,
    key: &'a TupleGroupKey,
    ancestry: Vec<&'a TupleGroupKey>,
}

impl<'a> ExpandChildren<'a> {
    fn nodes(&self) -> impl Iterator<Item = ExpandView<'a>> + '_ {
        self.groups.get(self.key).into_iter().flatten().map(|t| {
            if !t.subject_relation.is_empty() && self.ancestry.len() <= MAX_DEPTH {
                let key = (
                    t.subject_namespace.clone(),
                    t.subject_id.clone(),
                    t.subject_relation.clone(),
                );
                if let Some((key, tuples)) = self.groups.get_key_value(&key)
                    && !tuples.is_empty()
                    && !self.ancestry.contains(&key)
                {
                    let mut ancestry = self.ancestry.clone();
                    ancestry.push(key);
                    return ExpandView::branch(self.groups, key, ancestry);
                }
            }
            ExpandView::Leaf {
                namespace: &t.subject_namespace,
                subject_id: &t.subject_id,
                subject_relation: (!t.subject_relation.is_empty())
                    .then_some(t.subject_relation.as_str()),
            }
        })
    }
}

impl serde::Serialize for ExpandChildren<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.nodes())
    }
}

impl<'a> ExpandView<'a> {
    fn branch(
        groups: &'a TupleGroups,
        key: &'a TupleGroupKey,
        ancestry: Vec<&'a TupleGroupKey>,
    ) -> Self {
        Self::Branch {
            namespace: &key.0,
            object_id: &key.1,
            relation: &key.2,
            children: ExpandChildren {
                groups,
                key,
                ancestry,
            },
        }
    }

    fn materialize(self) -> ExpandNode {
        match self {
            Self::Leaf {
                namespace,
                subject_id,
                subject_relation,
            } => ExpandNode::Leaf {
                namespace: namespace.into(),
                subject_id: subject_id.into(),
                subject_relation: subject_relation.map(Into::into),
            },
            Self::Branch {
                namespace,
                object_id,
                relation,
                children,
            } => ExpandNode::Branch {
                namespace: namespace.into(),
                object_id: object_id.into(),
                relation: relation.into(),
                children: children.nodes().map(Self::materialize).collect(),
            },
        }
    }
}

struct ByteBudget(usize);

impl std::io::Write for ByteBudget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("expand response byte budget exceeded"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Expand the set of subjects that have `relation` on `(namespace, object_id)`.
///
/// Preflight the complete compact JSON response before materializing the tree.
/// Uses two traversal phases:
///   1. BFS to read each reachable tuple group once, up to MAX_DEPTH.
///   2. Render each path separately, preserving cyclic and depth-limited edges as leaves.
pub async fn expand<R: RebacRepository>(
    repo: &R,
    namespace: &str,
    object_id: &str,
    relation: &str,
    max_response_bytes: usize,
) -> Result<ExpandNode, ExpandError> {
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

    let tree = ExpandView::branch(&groups, &root_key, vec![&root_key]);
    #[derive(serde::Serialize)]
    struct ResponseView<'a> {
        tree: &'a ExpandView<'a>,
    }
    // Include the envelope. serde_json encodes strings exactly as the HTTP Json
    // response does, without allocating an output buffer or an owned tree.
    serde_json::to_writer(
        ByteBudget(max_response_bytes),
        &ResponseView { tree: &tree },
    )
    .map_err(|_| ExpandError::ResponseTooLarge {
        limit_bytes: max_response_bytes,
    })?;
    Ok(tree.materialize())
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
