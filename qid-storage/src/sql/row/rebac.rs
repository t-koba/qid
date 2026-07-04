use qid_core::models::RelationshipTuple;

#[derive(sqlx::FromRow)]
pub(in crate::sql) struct RelationshipTupleRow {
    pub namespace: String,
    pub object_id: String,
    pub relation: String,
    pub subject_namespace: String,
    pub subject_id: String,
    pub subject_relation: String,
    pub created_at_epoch_seconds: i64,
}

impl From<RelationshipTupleRow> for RelationshipTuple {
    fn from(row: RelationshipTupleRow) -> Self {
        Self {
            namespace: row.namespace,
            object_id: row.object_id,
            relation: row.relation,
            subject_namespace: row.subject_namespace,
            subject_id: row.subject_id,
            subject_relation: row.subject_relation,
            created_at_epoch_seconds: row.created_at_epoch_seconds as u64,
        }
    }
}
