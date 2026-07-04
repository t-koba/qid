use async_trait::async_trait;

use super::*;

#[async_trait]
impl RebacRepository for SqlRepository {
    async fn create_relationship_tuple(&self, tuple: &RelationshipTuple) -> QidResult<()> {
        sqlx::query(
            "INSERT INTO relationship_tuples (namespace, object_id, relation, subject_namespace, subject_id, subject_relation, created_at_epoch_seconds) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&tuple.namespace)
        .bind(&tuple.object_id)
        .bind(&tuple.relation)
        .bind(&tuple.subject_namespace)
        .bind(&tuple.subject_id)
        .bind(&tuple.subject_relation)
        .bind(tuple.created_at_epoch_seconds as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn delete_relationship_tuple(&self, tuple: &RelationshipTuple) -> QidResult<()> {
        sqlx::query(
            "DELETE FROM relationship_tuples WHERE namespace = ? AND object_id = ? AND relation = ? AND subject_namespace = ? AND subject_id = ? AND subject_relation = ?",
        )
        .bind(&tuple.namespace)
        .bind(&tuple.object_id)
        .bind(&tuple.relation)
        .bind(&tuple.subject_namespace)
        .bind(&tuple.subject_id)
        .bind(&tuple.subject_relation)
        .execute(&self.pool)
        .await
        .map_err(storage_to_qid_error)?;
        Ok(())
    }

    async fn list_relationship_tuples(
        &self,
        namespace: &str,
        object_id: &str,
        relation: Option<&str>,
    ) -> QidResult<Vec<RelationshipTuple>> {
        let rows = match relation {
            Some(rel) => {
                sqlx::query_as::<_, RelationshipTupleRow>(
                    "SELECT * FROM relationship_tuples WHERE namespace = ? AND object_id = ? AND relation = ? ORDER BY created_at_epoch_seconds ASC",
                )
                .bind(namespace)
                .bind(object_id)
                .bind(rel)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?
            }
            None => {
                sqlx::query_as::<_, RelationshipTupleRow>(
                    "SELECT * FROM relationship_tuples WHERE namespace = ? AND object_id = ? ORDER BY created_at_epoch_seconds ASC",
                )
                .bind(namespace)
                .bind(object_id)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?
            }
        };
        Ok(rows.into_iter().map(Into::into).collect())
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
        let rows = match subject_relation {
            Some(sub_rel) => {
                sqlx::query_as::<_, RelationshipTupleRow>(
                    "SELECT * FROM relationship_tuples WHERE namespace = ? AND object_id = ? AND relation = ? AND subject_namespace = ? AND subject_id = ? AND subject_relation = ? ORDER BY created_at_epoch_seconds ASC",
                )
                .bind(namespace)
                .bind(object_id)
                .bind(relation)
                .bind(subject_namespace)
                .bind(subject_id)
                .bind(sub_rel)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?
            }
            None => {
                sqlx::query_as::<_, RelationshipTupleRow>(
                    "SELECT * FROM relationship_tuples WHERE namespace = ? AND object_id = ? AND relation = ? AND subject_namespace = ? AND subject_id = ? ORDER BY created_at_epoch_seconds ASC",
                )
                .bind(namespace)
                .bind(object_id)
                .bind(relation)
                .bind(subject_namespace)
                .bind(subject_id)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_to_qid_error)?
            }
        };
        Ok(rows.into_iter().map(Into::into).collect())
    }
}
