//! ReBAC / Zanzibar-style authorization engine.
//!
//! Provides the core `check` and `expand` operations over relationship tuples.

use std::collections::HashMap;
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
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();

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

        let node_key = format!(
            "{}:{}#{}@{}:{}",
            item.namespace, item.object_id, item.relation, subject_namespace, subject_id
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
/// Uses a two-phase iterative approach:
///   1. BFS to collect tuple groups at each level of the userset tree.
///   2. Build the tree bottom-up from leaves.
pub async fn expand<R: RebacRepository>(
    repo: &R,
    namespace: &str,
    object_id: &str,
    relation: &str,
) -> QidResult<ExpandNode> {
    // Phase 1: collect tuple groups by (namespace, object_id, relation) key.
    type TupleGroupKey = (String, String, String);

    let mut groups: Vec<(TupleGroupKey, Vec<RelationshipTuple>)> = Vec::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back((
        namespace.to_string(),
        object_id.to_string(),
        relation.to_string(),
        0usize,
    ));

    while let Some((ns, oid, rel, depth)) = queue.pop_front() {
        if depth > MAX_DEPTH {
            continue;
        }
        let tuples = repo.list_relationship_tuples(&ns, &oid, Some(&rel)).await?;
        groups.push(((ns.clone(), oid.clone(), rel.clone()), tuples.clone()));
        for t in &tuples {
            if !t.subject_relation.is_empty() {
                queue.push_back((
                    t.subject_namespace.clone(),
                    t.subject_id.clone(),
                    t.subject_relation.clone(),
                    depth + 1,
                ));
            }
        }
    }

    // Phase 2: build tree bottom-up by processing groups in reverse order.
    let mut node_cache: HashMap<TupleGroupKey, Vec<ExpandNode>> = HashMap::new();

    for ((ns, oid, rel), tuples) in groups.into_iter().rev() {
        let mut children = Vec::with_capacity(tuples.len());
        for t in &tuples {
            if t.subject_relation.is_empty() {
                children.push(ExpandNode::Leaf {
                    namespace: t.subject_namespace.clone(),
                    subject_id: t.subject_id.clone(),
                    subject_relation: None,
                });
            } else {
                let sub_key = (
                    t.subject_namespace.clone(),
                    t.subject_id.clone(),
                    t.subject_relation.clone(),
                );
                if let Some(grand_children) = node_cache.remove(&sub_key) {
                    if grand_children.is_empty() {
                        children.push(ExpandNode::Leaf {
                            namespace: t.subject_namespace.clone(),
                            subject_id: t.subject_id.clone(),
                            subject_relation: Some(t.subject_relation.clone()),
                        });
                    } else {
                        children.push(ExpandNode::Branch {
                            namespace: t.subject_namespace.clone(),
                            object_id: t.subject_id.clone(),
                            relation: t.subject_relation.clone(),
                            children: grand_children,
                        });
                    }
                } else {
                    children.push(ExpandNode::Leaf {
                        namespace: t.subject_namespace.clone(),
                        subject_id: t.subject_id.clone(),
                        subject_relation: Some(t.subject_relation.clone()),
                    });
                }
            }
        }
        node_cache.insert((ns, oid, rel), children);
    }

    let root_key = (
        namespace.to_string(),
        object_id.to_string(),
        relation.to_string(),
    );
    let root_children = node_cache.remove(&root_key).unwrap_or_default();

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
    ) -> bool {
        crate::rebac::check(
            &self.repo,
            namespace,
            object_id,
            relation,
            subject_namespace,
            subject_id,
        )
        .await
        .unwrap_or(false)
    }
}

/// Convenience function to create a `RebacEvaluator` from any
/// `RebacRepository`.
pub fn rebac_evaluator_from_repo<R: RebacRepository + Send + Sync + 'static>(
    repo: R,
) -> Arc<dyn RebacEvaluator> {
    Arc::new(RebacEvaluatorBridge::new(repo))
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
}
