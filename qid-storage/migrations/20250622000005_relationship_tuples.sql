CREATE TABLE IF NOT EXISTS relationship_tuples (
    namespace TEXT NOT NULL,
    object_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    subject_namespace TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    subject_relation TEXT NOT NULL DEFAULT '',
    created_at_epoch_seconds INTEGER NOT NULL,
    PRIMARY KEY (namespace, object_id, relation, subject_namespace, subject_id, subject_relation)
);
