use serde::{Deserialize, Serialize};

/// A Zanzibar-style relationship tuple.
///
/// `subject_namespace#subject_id@subject_relation` is expressed as
/// three separate fields.  An empty `subject_relation` means the subject
/// is referenced directly; a non-empty value means the subject is itself
/// a userset (e.g. `group#member`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelationshipTuple {
    pub namespace: String,
    pub object_id: String,
    pub relation: String,
    pub subject_namespace: String,
    pub subject_id: String,
    #[serde(default)]
    pub subject_relation: String,
    #[serde(default)]
    pub created_at_epoch_seconds: u64,
}

/// Subject reference used in Check / Expand requests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubjectRef {
    pub namespace: String,
    pub subject_id: String,
}

/// Check request body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckRequest {
    pub namespace: String,
    pub object_id: String,
    pub relation: String,
    pub subject: SubjectRef,
}

/// Check response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckResponse {
    pub allowed: bool,
}

/// Tuple write (create or delete) request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TupleWriteRequest {
    pub tuples: Vec<RelationshipTuple>,
}

/// Tuple read request – filter by resource and optional relation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadRequest {
    pub namespace: String,
    pub object_id: String,
    #[serde(default)]
    pub relation: String,
}

/// Tuple read response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadResponse {
    pub tuples: Vec<RelationshipTuple>,
}

/// Delete request (identical to tuple write but inverted).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TupleDeleteRequest {
    pub tuples: Vec<RelationshipTuple>,
}

/// Node in an Expand tree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ExpandNode {
    Leaf {
        namespace: String,
        subject_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        subject_relation: Option<String>,
    },
    Branch {
        namespace: String,
        object_id: String,
        relation: String,
        children: Vec<ExpandNode>,
    },
}

/// Expand request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExpandRequest {
    pub namespace: String,
    pub object_id: String,
    pub relation: String,
}

/// Expand response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExpandResponse {
    pub tree: ExpandNode,
}
