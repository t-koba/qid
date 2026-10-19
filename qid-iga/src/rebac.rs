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
mod tests {
    use super::*;
    use qid_storage::FileRepository;
    use tempfile::TempDir;

    async fn make_repo() -> (FileRepository, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test_rebac.json");
        let repo = FileRepository::new(path.to_str().unwrap()).await.unwrap();
        (repo, dir)
    }

    /// Helper to insert a relationship tuple.
    async fn insert(repo: &FileRepository, t: RelationshipTuple) {
        write_tuples(repo, &[t]).await.unwrap();
    }

    /// Helper to make a direct subject tuple.
    fn direct(
        namespace: &str,
        object_id: &str,
        relation: &str,
        subject_ns: &str,
        subject_id: &str,
    ) -> RelationshipTuple {
        RelationshipTuple {
            namespace: namespace.to_string(),
            object_id: object_id.to_string(),
            relation: relation.to_string(),
            subject_namespace: subject_ns.to_string(),
            subject_id: subject_id.to_string(),
            subject_relation: String::new(),
            created_at_epoch_seconds: now_seconds(),
        }
    }

    /// Helper to make a userset (group) subject tuple.
    fn userset(
        namespace: &str,
        object_id: &str,
        relation: &str,
        subject_ns: &str,
        subject_id: &str,
        sub_rel: &str,
    ) -> RelationshipTuple {
        RelationshipTuple {
            namespace: namespace.to_string(),
            object_id: object_id.to_string(),
            relation: relation.to_string(),
            subject_namespace: subject_ns.to_string(),
            subject_id: subject_id.to_string(),
            subject_relation: sub_rel.to_string(),
            created_at_epoch_seconds: now_seconds(),
        }
    }

    // ---------------------------------------------------------------
    // Nested group traversal
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_direct_member_check() {
        let (repo, _dir) = make_repo().await;
        insert(&repo, direct("group", "eng", "member", "user", "alice")).await;
        assert!(
            check(&repo, "group", "eng", "member", "user", "alice")
                .await
                .unwrap()
        );
        assert!(
            !check(&repo, "group", "eng", "member", "user", "bob")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_single_nesting_group_membership() {
        let (repo, _dir) = make_repo().await;
        // group:eng -> member -> group:backend -> member -> alice
        insert(&repo, direct("group", "backend", "member", "user", "alice")).await;
        insert(
            &repo,
            userset("group", "eng", "member", "group", "backend", "member"),
        )
        .await;

        assert!(
            check(&repo, "group", "eng", "member", "user", "alice")
                .await
                .unwrap()
        );
        assert!(
            !check(&repo, "group", "eng", "member", "user", "bob")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_deeply_nested_group_traversal() {
        let (repo, _dir) = make_repo().await;
        // group:root -> member -> group:a -> member -> group:b -> member -> alice
        insert(&repo, direct("group", "b", "member", "user", "alice")).await;
        insert(
            &repo,
            userset("group", "a", "member", "group", "b", "member"),
        )
        .await;
        insert(
            &repo,
            userset("group", "root", "member", "group", "a", "member"),
        )
        .await;

        assert!(
            check(&repo, "group", "root", "member", "user", "alice")
                .await
                .unwrap()
        );
        assert!(
            !check(&repo, "group", "root", "member", "user", "bob")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_max_depth_exceeded_returns_false() {
        let (repo, _dir) = make_repo().await;
        // Build a chain of depth MAX_DEPTH+1
        let max = MAX_DEPTH;
        let mut prev = "user".to_string();
        let mut prev_id = "alice".to_string();
        for i in 0..=max {
            let ns = "group".to_string();
            let oid = format!("g{i}");
            if i == 0 {
                insert(&repo, direct(&ns, &oid, "member", &prev, &prev_id)).await;
            } else {
                insert(
                    &repo,
                    userset(&ns, &oid, "member", &prev, &prev_id, "member"),
                )
                .await;
            }
            prev = ns;
            prev_id = oid;
        }
        // group:g{max} -> member -> ... -> user:alice  (depth = max)
        // Now check with depth = max+1 chain:
        let last = format!("g{max}");
        assert!(
            check(&repo, "group", &last, "member", "user", "alice")
                .await
                .unwrap()
        );
        // For a chain longer than max, check returns false
        assert!(
            !check(&repo, "group", "too_deep", "member", "user", "alice")
                .await
                .unwrap()
        );
    }

    // ---------------------------------------------------------------
    // Ownership transitivity
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_direct_ownership() {
        let (repo, _dir) = make_repo().await;
        insert(&repo, direct("doc", "doc-1", "owner", "user", "alice")).await;
        assert!(
            check(&repo, "doc", "doc-1", "owner", "user", "alice")
                .await
                .unwrap()
        );
        assert!(
            !check(&repo, "doc", "doc-1", "owner", "user", "bob")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_ownership_through_team_group() {
        let (repo, _dir) = make_repo().await;
        // team:platform -> owner -> user:alice
        // doc:doc-1 -> owner -> team:platform#owner
        insert(&repo, direct("team", "platform", "owner", "user", "alice")).await;
        insert(
            &repo,
            userset("doc", "doc-1", "owner", "team", "platform", "owner"),
        )
        .await;

        assert!(
            check(&repo, "doc", "doc-1", "owner", "user", "alice")
                .await
                .unwrap()
        );
        assert!(
            !check(&repo, "doc", "doc-1", "owner", "user", "bob")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_ownership_transitivity_through_multiple_groups() {
        let (repo, _dir) = make_repo().await;
        // org:acme -> owner -> team:platform#owner
        // team:platform -> owner -> user:alice
        // doc:doc-1 -> owner -> org:acme#owner
        insert(
            &repo,
            userset("org", "acme", "owner", "team", "platform", "owner"),
        )
        .await;
        insert(&repo, direct("team", "platform", "owner", "user", "alice")).await;
        insert(
            &repo,
            userset("doc", "doc-1", "owner", "org", "acme", "owner"),
        )
        .await;

        assert!(
            check(&repo, "doc", "doc-1", "owner", "user", "alice")
                .await
                .unwrap()
        );
        assert!(
            !check(&repo, "doc", "doc-1", "owner", "user", "bob")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_ownership_transitivity_chain() {
        let (repo, _dir) = make_repo().await;
        // doc:project-plan -> owner -> folder:strategic#owner
        // folder:strategic -> owner -> workspace:corp#owner
        // workspace:corp -> owner -> user:alice
        insert(
            &repo,
            userset(
                "doc",
                "project-plan",
                "owner",
                "folder",
                "strategic",
                "owner",
            ),
        )
        .await;
        insert(
            &repo,
            userset("folder", "strategic", "owner", "workspace", "corp", "owner"),
        )
        .await;
        insert(&repo, direct("workspace", "corp", "owner", "user", "alice")).await;

        assert!(
            check(&repo, "doc", "project-plan", "owner", "user", "alice")
                .await
                .unwrap()
        );
        assert!(
            !check(&repo, "doc", "project-plan", "owner", "user", "bob")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_ownership_transitivity_multiple_relations() {
        let (repo, _dir) = make_repo().await;
        // alice is owner of workspace:corp
        // doc:doc-1 -> viewer -> workspace:corp#owner
        // doc:doc-1 -> editor -> workspace:corp#member
        // bob is member of workspace:corp
        insert(&repo, direct("workspace", "corp", "owner", "user", "alice")).await;
        insert(&repo, direct("workspace", "corp", "member", "user", "bob")).await;
        insert(
            &repo,
            userset("doc", "doc-1", "viewer", "workspace", "corp", "owner"),
        )
        .await;
        insert(
            &repo,
            userset("doc", "doc-1", "editor", "workspace", "corp", "member"),
        )
        .await;

        assert!(
            check(&repo, "doc", "doc-1", "viewer", "user", "alice")
                .await
                .unwrap()
        );
        assert!(
            !check(&repo, "doc", "doc-1", "viewer", "user", "bob")
                .await
                .unwrap()
        );
        assert!(
            check(&repo, "doc", "doc-1", "editor", "user", "bob")
                .await
                .unwrap()
        );
        assert!(
            !check(&repo, "doc", "doc-1", "editor", "user", "alice")
                .await
                .unwrap()
        );
    }

    // ---------------------------------------------------------------
    // Expand tests
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_expand_flat_members() {
        let (repo, _dir) = make_repo().await;
        insert(&repo, direct("group", "eng", "member", "user", "alice")).await;
        insert(&repo, direct("group", "eng", "member", "user", "bob")).await;

        let tree = expand(&repo, "group", "eng", "member").await.unwrap();
        let ExpandNode::Branch { children, .. } = &tree else {
            panic!("expected branch");
        };
        assert_eq!(children.len(), 2);
    }

    #[tokio::test]
    async fn test_expand_nested_group() {
        let (repo, _dir) = make_repo().await;
        insert(&repo, direct("group", "backend", "member", "user", "alice")).await;
        insert(
            &repo,
            userset("group", "eng", "member", "group", "backend", "member"),
        )
        .await;

        let tree = expand(&repo, "group", "eng", "member").await.unwrap();
        let ExpandNode::Branch { children, .. } = &tree else {
            panic!("expected branch");
        };
        assert_eq!(children.len(), 1);
        match &children[0] {
            ExpandNode::Branch {
                namespace,
                object_id,
                relation,
                children: inner,
            } => {
                assert_eq!(namespace, "group");
                assert_eq!(object_id, "backend");
                assert_eq!(relation, "member");
                assert_eq!(inner.len(), 1);
                match &inner[0] {
                    ExpandNode::Leaf { subject_id, .. } => {
                        assert_eq!(subject_id, "alice");
                    }
                    _ => panic!("expected leaf"),
                }
            }
            _ => panic!("expected nested branch"),
        }
    }

    fn count_alice_leaves(node: &ExpandNode) -> usize {
        match node {
            ExpandNode::Leaf { subject_id, .. } => usize::from(subject_id == "alice"),
            ExpandNode::Branch { children, .. } => children.iter().map(count_alice_leaves).sum(),
        }
    }

    #[tokio::test]
    async fn test_expand_shared_child_appears_under_every_parent() {
        let (repo, _dir) = make_repo().await;
        insert(
            &repo,
            userset("group", "root", "member", "group", "a", "member"),
        )
        .await;
        insert(
            &repo,
            userset("group", "root", "member", "group", "b", "member"),
        )
        .await;
        insert(
            &repo,
            userset("group", "a", "member", "group", "shared", "member"),
        )
        .await;
        insert(
            &repo,
            userset("group", "b", "member", "group", "shared", "member"),
        )
        .await;
        insert(&repo, direct("group", "shared", "member", "user", "alice")).await;

        let tree = expand(&repo, "group", "root", "member").await.unwrap();
        let ExpandNode::Branch { children, .. } = &tree else {
            panic!("expected branch");
        };
        assert_eq!(children.len(), 2);
        for child in children {
            let ExpandNode::Branch {
                children: inner, ..
            } = child
            else {
                panic!("expected every parent to keep its shared branch");
            };
            assert_eq!(inner.len(), 1);
        }
        assert_eq!(count_alice_leaves(&tree), 2);
    }

    struct ReadCountingRepository {
        tuples: Vec<RelationshipTuple>,
        reads: std::sync::atomic::AtomicUsize,
        max_reads: usize,
    }

    impl ReadCountingRepository {
        fn new(tuples: Vec<RelationshipTuple>, max_reads: usize) -> Self {
            Self {
                tuples,
                reads: std::sync::atomic::AtomicUsize::new(0),
                max_reads,
            }
        }
    }

    #[async_trait::async_trait]
    impl RebacRepository for ReadCountingRepository {
        async fn create_relationship_tuple(&self, _: &RelationshipTuple) -> QidResult<()> {
            unreachable!("read-only expansion fixture")
        }

        async fn delete_relationship_tuple(&self, _: &RelationshipTuple) -> QidResult<()> {
            unreachable!("read-only expansion fixture")
        }

        async fn list_relationship_tuples(
            &self,
            namespace: &str,
            object_id: &str,
            relation: Option<&str>,
        ) -> QidResult<Vec<RelationshipTuple>> {
            let reads = self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            // Fail before a regression can allocate an exponentially large tree.
            assert!(
                reads <= self.max_reads,
                "too many tuple-group reads: {reads}"
            );
            Ok(self
                .tuples
                .iter()
                .filter(|t| {
                    t.namespace == namespace
                        && t.object_id == object_id
                        && relation.is_none_or(|r| t.relation == r)
                })
                .cloned()
                .collect())
        }

        async fn list_relationship_tuples_by_subject(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
            _: Option<&str>,
        ) -> QidResult<Vec<RelationshipTuple>> {
            unreachable!("expansion reads by tuple group")
        }
    }

    #[tokio::test]
    async fn test_check_structural_visited_keys_preserve_distinct_usersets() {
        for found_group_first in [false, true] {
            let missing_group = userset(
                "tenant::root",
                "root",
                "member",
                "tenant::group",
                "a:b",
                "member",
            );
            let found_group = userset(
                "tenant::root",
                "root",
                "member",
                "tenant::group:a",
                "b",
                "member",
            );
            let mut tuples = if found_group_first {
                vec![found_group, missing_group]
            } else {
                vec![missing_group, found_group]
            };
            tuples.push(direct("tenant::group:a", "b", "member", "user", "alice"));

            let repo = ReadCountingRepository::new(tuples, 3);
            assert!(
                check(&repo, "tenant::root", "root", "member", "user", "alice",)
                    .await
                    .unwrap(),
                "membership must be found with sibling order found_first={found_group_first}"
            );
            assert_eq!(
                repo.reads.load(std::sync::atomic::Ordering::SeqCst),
                if found_group_first { 2 } else { 3 }
            );
        }
    }

    #[tokio::test]
    async fn test_expand_complete_three_group_cycle_reads_each_group_once() {
        let mut tuples = Vec::new();
        for parent in ["a", "b", "c"] {
            for child in ["a", "b", "c"] {
                tuples.push(userset("group", parent, "member", "group", child, "member"));
            }
        }
        let repo = ReadCountingRepository::new(tuples, 3);
        let tree = expand(&repo, "group", "a", "member").await.unwrap();
        assert_eq!(repo.reads.load(std::sync::atomic::Ordering::SeqCst), 3);

        fn inspect(node: &ExpandNode, path: &mut HashSet<String>) -> (usize, usize) {
            match node {
                ExpandNode::Leaf {
                    namespace,
                    subject_id,
                    subject_relation,
                } => {
                    assert_eq!(namespace, "group");
                    assert_eq!(subject_relation.as_deref(), Some("member"));
                    assert!(path.contains(subject_id), "only cyclic edges are leaves");
                    (1, 0)
                }
                ExpandNode::Branch {
                    namespace,
                    object_id,
                    relation,
                    children,
                } => {
                    assert_eq!(namespace, "group");
                    assert_eq!(relation, "member");
                    assert!(path.insert(object_id.clone()), "cycle rendered as branch");
                    assert_eq!(children.len(), 3, "every userset edge is preserved");
                    let mut nodes = 1;
                    let mut depth = 0;
                    for child in children {
                        let (child_nodes, child_depth) = inspect(child, path);
                        nodes += child_nodes;
                        depth = depth.max(child_depth + 1);
                    }
                    path.remove(object_id);
                    (nodes, depth)
                }
            }
        }
        // Root, two one-hop branches and two two-hop branches; every repeated
        // key is a leaf, including self-edges. No branch is dropped globally.
        let (nodes, depth) = inspect(&tree, &mut HashSet::new());
        assert_eq!(nodes, 16);
        assert_eq!(depth, 3);
    }

    #[tokio::test]
    async fn test_expand_max_depth_is_path_local_even_for_cached_groups() {
        let mut tuples = vec![
            userset("group", "g0", "member", "group", "shared", "member"),
            direct("group", "shared", "member", "user", "alice"),
        ];
        for i in 0..MAX_DEPTH {
            tuples.push(userset(
                "group",
                &format!("g{i}"),
                "member",
                "group",
                &format!("g{}", i + 1),
                "member",
            ));
        }
        tuples.push(direct(
            "group",
            &format!("g{MAX_DEPTH}"),
            "member",
            "user",
            "bob",
        ));
        tuples.push(userset(
            "group",
            &format!("g{MAX_DEPTH}"),
            "member",
            "group",
            "shared",
            "member",
        ));
        // 'shared' is cached at depth 1 but must not be expanded at depth 11.
        let repo = ReadCountingRepository::new(tuples, MAX_DEPTH + 2);
        let tree = expand(&repo, "group", "g0", "member").await.unwrap();
        assert_eq!(count_alice_leaves(&tree), 1);
        let mut node = &tree;
        for depth in 0..=MAX_DEPTH {
            let ExpandNode::Branch {
                object_id,
                children,
                ..
            } = node
            else {
                panic!("expected group branch at depth {depth}");
            };
            assert_eq!(object_id, &format!("g{depth}"));
            assert_eq!(
                children.len(),
                if depth == 0 || depth == MAX_DEPTH {
                    2
                } else {
                    1
                }
            );
            if depth == MAX_DEPTH {
                assert!(matches!(&children[0], ExpandNode::Leaf {
                    subject_id, subject_relation: None, ..
                } if subject_id == "bob"));
                assert!(matches!(&children[1], ExpandNode::Leaf {
                    subject_id, subject_relation: Some(relation), ..
                } if subject_id == "shared" && relation == "member"));
            } else {
                node = children.last().unwrap();
            }
        }
    }

    #[tokio::test]
    async fn test_expand_empty_groups_keep_userset_leaves_and_root_branch() {
        let repo = ReadCountingRepository::new(
            vec![userset(
                "group", "root", "member", "group", "missing", "member",
            )],
            3,
        );
        let tree = expand(&repo, "group", "root", "member").await.unwrap();
        let ExpandNode::Branch { children, .. } = tree else {
            panic!("expected root branch");
        };
        assert_eq!(children.len(), 1);
        assert!(matches!(&children[0], ExpandNode::Leaf {
            namespace, subject_id, subject_relation: Some(relation),
        } if namespace == "group" && subject_id == "missing" && relation == "member"));
        let empty = expand(&repo, "group", "missing", "member").await.unwrap();
        assert!(matches!(empty, ExpandNode::Branch {
            namespace, object_id, relation, children,
        } if namespace == "group" && object_id == "missing"
            && relation == "member" && children.is_empty()));
    }

    #[tokio::test]
    async fn test_expand_cyclic_membership_terminates() {
        let (repo, _dir) = make_repo().await;
        insert(&repo, direct("group", "cycle-a", "member", "user", "alice")).await;
        insert(
            &repo,
            userset("group", "cycle-a", "member", "group", "cycle-b", "member"),
        )
        .await;
        insert(
            &repo,
            userset("group", "cycle-b", "member", "group", "cycle-a", "member"),
        )
        .await;

        let tree = expand(&repo, "group", "cycle-a", "member").await.unwrap();
        assert!(count_alice_leaves(&tree) >= 1);
    }

    #[tokio::test]
    async fn test_tenant_scoped_evaluator_matches_only_its_tenant() {
        let (repo, _dir) = make_repo().await;
        insert(
            &repo,
            direct(
                "tenant-a::document",
                "doc-1",
                "viewer",
                "tenant-a::user",
                "alice",
            ),
        )
        .await;

        let repo = std::sync::Arc::new(repo);
        let same_tenant = tenant_scoped_rebac_evaluator(repo.clone(), "tenant-a");
        assert!(
            same_tenant
                .check("document", "doc-1", "viewer", "user", "alice")
                .await
                .unwrap()
        );
        assert!(
            same_tenant
                .check(
                    "tenant-a::document",
                    "doc-1",
                    "viewer",
                    "tenant-a::user",
                    "alice"
                )
                .await
                .unwrap()
        );
        let other_tenant = tenant_scoped_rebac_evaluator(repo, "tenant-b");
        assert!(
            !other_tenant
                .check("document", "doc-1", "viewer", "user", "alice")
                .await
                .unwrap()
        );
    }

    /// Storage failures must surface as errors, not as `false` evidence.
    struct FailingRebacRepo;

    #[async_trait::async_trait]
    impl qid_storage::traits::RebacRepository for FailingRebacRepo {
        async fn create_relationship_tuple(&self, _tuple: &RelationshipTuple) -> QidResult<()> {
            Err(qid_core::error::QidError::Storage {
                message: "failing repo".to_string(),
            })
        }

        async fn delete_relationship_tuple(&self, _tuple: &RelationshipTuple) -> QidResult<()> {
            Err(qid_core::error::QidError::Storage {
                message: "failing repo".to_string(),
            })
        }

        async fn list_relationship_tuples(
            &self,
            _namespace: &str,
            _object_id: &str,
            _relation: Option<&str>,
        ) -> QidResult<Vec<RelationshipTuple>> {
            Err(qid_core::error::QidError::Storage {
                message: "failing repo".to_string(),
            })
        }

        async fn list_relationship_tuples_by_subject(
            &self,
            _namespace: &str,
            _object_id: &str,
            _relation: &str,
            _subject_namespace: &str,
            _subject_id: &str,
            _subject_relation: Option<&str>,
        ) -> QidResult<Vec<RelationshipTuple>> {
            Err(qid_core::error::QidError::Storage {
                message: "failing repo".to_string(),
            })
        }
    }

    #[tokio::test]
    async fn test_unscoped_bridge_propagates_storage_error() {
        let bridge = RebacEvaluatorBridge::new(FailingRebacRepo);
        assert!(
            bridge
                .check("doc", "doc-1", "viewer", "user", "alice")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_tenant_scoped_bridge_propagates_storage_error() {
        let evaluator =
            TenantScopedRebacEvaluator::new(std::sync::Arc::new(FailingRebacRepo), "tenant-a");
        assert!(
            evaluator
                .check("document", "doc-1", "viewer", "user", "alice")
                .await
                .is_err()
        );
    }
}
