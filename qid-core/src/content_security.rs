//! Content provenance and security: C2PA, TUF, in-toto.

use crate::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct C2paManifest {
    pub version: String,
    pub claim_generator: String,
    pub assertions: Vec<C2paAssertion>,
    pub credentials: Vec<C2paCredential>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct C2paAssertion {
    pub label: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct C2paCredential {
    pub format: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TufRoot {
    pub spec_version: String,
    pub consistent_snapshot: bool,
    pub keys: HashMap<String, TufKey>,
    pub roles: HashMap<String, TufRole>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TufKey {
    pub key_type: String,
    pub scheme: String,
    pub key_value: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TufRole {
    pub key_ids: Vec<String>,
    pub threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InTotoLayout {
    pub expires: String,
    pub steps: Vec<InTotoStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InTotoStep {
    pub name: String,
    pub expected_materials: Vec<String>,
    pub expected_products: Vec<String>,
}

pub fn parse_c2pa_manifest(json: &str) -> QidResult<C2paManifest> {
    serde_json::from_str(json).map_err(|e| QidError::BadRequest {
        message: format!("C2PA manifest parse failed: {e}"),
    })
}

pub fn parse_tuf_root(json: &str) -> QidResult<TufRoot> {
    serde_json::from_str(json).map_err(|e| QidError::BadRequest {
        message: format!("TUF root parse failed: {e}"),
    })
}

pub fn parse_in_toto_layout(json: &str) -> QidResult<InTotoLayout> {
    serde_json::from_str(json).map_err(|e| QidError::BadRequest {
        message: format!("in-toto layout parse failed: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c2pa_manifest_round_trip() {
        let manifest = C2paManifest {
            version: "2.0".to_string(),
            claim_generator: "qid".to_string(),
            assertions: vec![C2paAssertion {
                label: "c2pa.actions".to_string(),
                data: serde_json::json!([{"action": "created"}]),
            }],
            credentials: vec![],
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed = parse_c2pa_manifest(&json).unwrap();
        assert_eq!(parsed.version, "2.0");
    }

    #[test]
    fn tuf_root_round_trip() {
        let root = TufRoot {
            spec_version: "1.0".to_string(),
            consistent_snapshot: true,
            keys: HashMap::new(),
            roles: HashMap::new(),
        };
        let json = serde_json::to_string(&root).unwrap();
        let parsed = parse_tuf_root(&json).unwrap();
        assert!(parsed.consistent_snapshot);
    }

    #[test]
    fn in_toto_layout_minimal() {
        let layout = InTotoLayout {
            expires: "2027-01-01T00:00:00Z".to_string(),
            steps: vec![InTotoStep {
                name: "build".to_string(),
                expected_materials: vec![],
                expected_products: vec![],
            }],
        };
        let json = serde_json::to_string(&layout).unwrap();
        let parsed = parse_in_toto_layout(&json).unwrap();
        assert_eq!(parsed.steps.len(), 1);
    }
}
