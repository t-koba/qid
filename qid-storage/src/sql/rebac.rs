use async_trait::async_trait;

use super::*;

#[async_trait]
impl RebacRepository for SqlRepository {
    async fn create_relationship_tuple(&self, tuple: &RelationshipTuple) -> QidResult<()> {
        let result = sqlx::query(
            "INSERT INTO relationship_tuples (namespace, object_id, relation, subject_namespace, subject_id, subject_relation, created_at_epoch_seconds) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (namespace, object_id, relation, subject_namespace, subject_id, subject_relation) DO NOTHING",
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
        crate::ownership::ensure_upsert_applied(result.rows_affected(), || {
            "relationship tuple already exists".into()
        })
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

    async fn list_relationship_tuples_bounded(
        &self,
        namespace: &str,
        object_id: &str,
        relation: Option<&str>,
        limit: usize,
    ) -> QidResult<Vec<RelationshipTuple>> {
        let sql = match relation {
            Some(_) => {
                "SELECT * FROM relationship_tuples WHERE namespace = ? AND object_id = ? AND relation = ? ORDER BY created_at_epoch_seconds ASC LIMIT ?"
            }
            None => {
                "SELECT * FROM relationship_tuples WHERE namespace = ? AND object_id = ? ORDER BY created_at_epoch_seconds ASC LIMIT ?"
            }
        };
        let mut query = sqlx::query_as::<_, RelationshipTupleRow>(sql)
            .bind(namespace)
            .bind(object_id);
        if let Some(relation) = relation {
            query = query.bind(relation);
        }
        let rows = query
            .bind(i64::try_from(limit).unwrap_or(i64::MAX))
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
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
        let sql = match subject_relation {
            Some(_) => {
                "SELECT * FROM relationship_tuples WHERE namespace = ? AND object_id = ? AND relation = ? AND subject_namespace = ? AND subject_id = ? AND subject_relation = ? ORDER BY created_at_epoch_seconds ASC"
            }
            None => {
                "SELECT * FROM relationship_tuples WHERE namespace = ? AND object_id = ? AND relation = ? AND subject_namespace = ? AND subject_id = ? ORDER BY created_at_epoch_seconds ASC"
            }
        };
        let mut query = sqlx::query_as::<_, RelationshipTupleRow>(sql)
            .bind(namespace)
            .bind(object_id)
            .bind(relation)
            .bind(subject_namespace)
            .bind(subject_id);
        if let Some(subject_relation) = subject_relation {
            query = query.bind(subject_relation);
        }
        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(storage_to_qid_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
}
