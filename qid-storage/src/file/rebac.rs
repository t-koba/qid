use async_trait::async_trait;

use super::*;

fn same_relationship_tuple_identity(a: &RelationshipTuple, b: &RelationshipTuple) -> bool {
    a.namespace == b.namespace
        && a.object_id == b.object_id
        && a.relation == b.relation
        && a.subject_namespace == b.subject_namespace
        && a.subject_id == b.subject_id
        && a.subject_relation == b.subject_relation
}

#[async_trait]
impl RebacRepository for FileRepository {
    async fn create_relationship_tuple(&self, tuple: &RelationshipTuple) -> QidResult<()> {
        let mut store = self.store.write().await;
        if store
            .relationship_tuples
            .iter()
            .any(|stored| same_relationship_tuple_identity(stored, tuple))
        {
            return Err(qid_core::error::QidError::Conflict {
                message: "relationship tuple already exists".into(),
            });
        }
        store.relationship_tuples.push(tuple.clone());
        drop(store);
        self.save().await
    }

    async fn delete_relationship_tuple(&self, tuple: &RelationshipTuple) -> QidResult<()> {
        let mut store = self.store.write().await;
        store
            .relationship_tuples
            .retain(|stored| !same_relationship_tuple_identity(stored, tuple));
        drop(store);
        self.save().await
    }

    async fn list_relationship_tuples(
        &self,
        namespace: &str,
        object_id: &str,
        relation: Option<&str>,
    ) -> QidResult<Vec<RelationshipTuple>> {
        let store = self.store.read().await;
        let mut tuples: Vec<_> = store
            .relationship_tuples
            .iter()
            .filter(|t| t.namespace == namespace && t.object_id == object_id)
            .filter(|t| relation.is_none_or(|rel| t.relation == rel))
            .cloned()
            .collect();
        tuples.sort_by_key(|tuple| tuple.created_at_epoch_seconds);
        Ok(tuples)
    }

    async fn list_relationship_tuples_by_subject(
        &self,
        namespace: &str,
        object_id: &str,
        relation: &str,
        subject_namespace: &str,
        subject_id: &str,
        subject_relation: Option<&str>,
    ) -> QidResult<Vec<RelationshipTuple>> {
        let store = self.store.read().await;
        let mut tuples: Vec<_> = store
            .relationship_tuples
            .iter()
            .filter(|t| {
                t.namespace == namespace
                    && t.object_id == object_id
                    && t.relation == relation
                    && t.subject_namespace == subject_namespace
                    && t.subject_id == subject_id
            })
            .filter(|t| subject_relation.is_none_or(|sub_rel| t.subject_relation == sub_rel))
            .cloned()
            .collect();
        tuples.sort_by_key(|tuple| tuple.created_at_epoch_seconds);
        Ok(tuples)
    }
}
