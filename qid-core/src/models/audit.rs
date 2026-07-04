use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Immutable administrative audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub realm_id: Option<String>,
    pub actor: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub reason: String,
    pub metadata_json: serde_json::Value,
    pub created_at: u64,
    #[serde(default)]
    pub previous_hash: Option<String>,
    #[serde(default)]
    pub event_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditChainVerification {
    pub valid: bool,
    pub checked_events: usize,
    pub first_event_id: Option<String>,
    pub last_event_id: Option<String>,
    pub broken_event_id: Option<String>,
    pub expected_previous_hash: Option<String>,
    pub actual_previous_hash: Option<String>,
    pub expected_event_hash: Option<String>,
    pub actual_event_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRetentionConfig {
    pub realm_id: Option<String>,
    pub retention_days: u64,
    pub legal_hold: bool,
    pub updated_by: String,
    pub reason: String,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRetentionEnforcementPlan {
    pub realm_id: Option<String>,
    pub retention_days: u64,
    pub legal_hold: bool,
    pub cutoff_epoch: Option<u64>,
    pub checked_events: usize,
    pub retained_event_ids: Vec<String>,
    pub expired_event_ids: Vec<String>,
}

impl AuditEvent {
    pub fn with_chain_hashes(mut self, previous_hash: Option<String>) -> Self {
        self.previous_hash = previous_hash;
        self.event_hash = Some(self.compute_hash());
        self
    }

    pub fn compute_hash(&self) -> String {
        let mut fields = BTreeMap::new();
        fields.insert("action", serde_json::json!(self.action));
        fields.insert("actor", serde_json::json!(self.actor));
        fields.insert("created_at", serde_json::json!(self.created_at));
        fields.insert("id", serde_json::json!(self.id));
        fields.insert("metadata_json", canonical_json_value(&self.metadata_json));
        fields.insert("previous_hash", serde_json::json!(self.previous_hash));
        fields.insert("realm_id", serde_json::json!(self.realm_id));
        fields.insert("reason", serde_json::json!(self.reason));
        fields.insert("target_id", serde_json::json!(self.target_id));
        fields.insert("target_type", serde_json::json!(self.target_type));

        let bytes = serde_json::to_vec(&fields).unwrap_or_default();
        hex_sha256(&bytes)
    }
}

pub fn plan_audit_retention_enforcement<'a, I>(
    config: &AuditRetentionConfig,
    now_epoch: u64,
    events: I,
) -> AuditRetentionEnforcementPlan
where
    I: IntoIterator<Item = &'a AuditEvent>,
{
    let events: Vec<&AuditEvent> = events.into_iter().collect();
    if config.legal_hold {
        return AuditRetentionEnforcementPlan {
            realm_id: config.realm_id.clone(),
            retention_days: config.retention_days,
            legal_hold: true,
            cutoff_epoch: None,
            checked_events: events.len(),
            retained_event_ids: events.into_iter().map(|event| event.id.clone()).collect(),
            expired_event_ids: Vec::new(),
        };
    }

    let retention_seconds = config.retention_days.saturating_mul(24 * 60 * 60);
    let cutoff_epoch = now_epoch.saturating_sub(retention_seconds);
    let mut retained_event_ids = Vec::new();
    let mut expired_event_ids = Vec::new();

    for event in events {
        if event.created_at < cutoff_epoch {
            expired_event_ids.push(event.id.clone());
        } else {
            retained_event_ids.push(event.id.clone());
        }
    }

    AuditRetentionEnforcementPlan {
        realm_id: config.realm_id.clone(),
        retention_days: config.retention_days,
        legal_hold: false,
        cutoff_epoch: Some(cutoff_epoch),
        checked_events: retained_event_ids.len() + expired_event_ids.len(),
        retained_event_ids,
        expired_event_ids,
    }
}

pub fn verify_audit_chain_ordered<'a, I>(events: I) -> AuditChainVerification
where
    I: IntoIterator<Item = &'a AuditEvent>,
{
    let mut previous_hash: Option<String> = None;
    let mut checked_events = 0;
    let mut first_event_id = None;
    let mut last_event_id = None;

    for event in events {
        if first_event_id.is_none() {
            first_event_id = Some(event.id.clone());
        }
        checked_events += 1;
        last_event_id = Some(event.id.clone());

        if event.previous_hash != previous_hash {
            return AuditChainVerification {
                valid: false,
                checked_events,
                first_event_id,
                last_event_id,
                broken_event_id: Some(event.id.clone()),
                expected_previous_hash: previous_hash,
                actual_previous_hash: event.previous_hash.clone(),
                expected_event_hash: None,
                actual_event_hash: event.event_hash.clone(),
            };
        }

        let expected_event_hash = event.compute_hash();
        if event.event_hash.as_deref() != Some(expected_event_hash.as_str()) {
            return AuditChainVerification {
                valid: false,
                checked_events,
                first_event_id,
                last_event_id,
                broken_event_id: Some(event.id.clone()),
                expected_previous_hash: event.previous_hash.clone(),
                actual_previous_hash: event.previous_hash.clone(),
                expected_event_hash: Some(expected_event_hash),
                actual_event_hash: event.event_hash.clone(),
            };
        }

        previous_hash = event.event_hash.clone();
    }

    AuditChainVerification {
        valid: true,
        checked_events,
        first_event_id,
        last_event_id,
        broken_event_id: None,
        expected_previous_hash: None,
        actual_previous_hash: None,
        expected_event_hash: None,
        actual_event_hash: None,
    }
}

pub fn verify_audit_chain_linked<'a, I>(events: I) -> AuditChainVerification
where
    I: IntoIterator<Item = &'a AuditEvent>,
{
    let events: Vec<&AuditEvent> = events.into_iter().collect();
    if events.is_empty() {
        return AuditChainVerification {
            valid: true,
            checked_events: 0,
            first_event_id: None,
            last_event_id: None,
            broken_event_id: None,
            expected_previous_hash: None,
            actual_previous_hash: None,
            expected_event_hash: None,
            actual_event_hash: None,
        };
    }

    let mut by_previous_hash: BTreeMap<Option<String>, &AuditEvent> = BTreeMap::new();
    for event in &events {
        let expected_event_hash = event.compute_hash();
        if event.event_hash.as_deref() != Some(expected_event_hash.as_str()) {
            return AuditChainVerification {
                valid: false,
                checked_events: 1,
                first_event_id: Some(event.id.clone()),
                last_event_id: Some(event.id.clone()),
                broken_event_id: Some(event.id.clone()),
                expected_previous_hash: event.previous_hash.clone(),
                actual_previous_hash: event.previous_hash.clone(),
                expected_event_hash: Some(expected_event_hash),
                actual_event_hash: event.event_hash.clone(),
            };
        }
        if by_previous_hash
            .insert(event.previous_hash.clone(), *event)
            .is_some()
        {
            return AuditChainVerification {
                valid: false,
                checked_events: 1,
                first_event_id: Some(event.id.clone()),
                last_event_id: Some(event.id.clone()),
                broken_event_id: Some(event.id.clone()),
                expected_previous_hash: event.previous_hash.clone(),
                actual_previous_hash: event.previous_hash.clone(),
                expected_event_hash: event.event_hash.clone(),
                actual_event_hash: event.event_hash.clone(),
            };
        }
    }

    let Some(mut current) = by_previous_hash.get(&None).copied() else {
        let event = events[0];
        return AuditChainVerification {
            valid: false,
            checked_events: 0,
            first_event_id: Some(event.id.clone()),
            last_event_id: Some(event.id.clone()),
            broken_event_id: Some(event.id.clone()),
            expected_previous_hash: None,
            actual_previous_hash: event.previous_hash.clone(),
            expected_event_hash: event.event_hash.clone(),
            actual_event_hash: event.event_hash.clone(),
        };
    };

    let first_event_id = Some(current.id.clone());
    let mut checked_events = 1;
    while let Some(current_hash) = current.event_hash.clone() {
        let Some(next) = by_previous_hash.get(&Some(current_hash.clone())).copied() else {
            break;
        };
        current = next;
        checked_events += 1;
    }

    if checked_events != events.len() {
        return AuditChainVerification {
            valid: false,
            checked_events,
            first_event_id,
            last_event_id: Some(current.id.clone()),
            broken_event_id: Some(current.id.clone()),
            expected_previous_hash: current.event_hash.clone(),
            actual_previous_hash: None,
            expected_event_hash: current.event_hash.clone(),
            actual_event_hash: current.event_hash.clone(),
        };
    }

    AuditChainVerification {
        valid: true,
        checked_events,
        first_event_id,
        last_event_id: Some(current.id.clone()),
        broken_event_id: None,
        expected_previous_hash: None,
        actual_previous_hash: None,
        expected_event_hash: None,
        actual_event_hash: None,
    }
}

pub fn verify_audit_chains_by_realm<'a, I>(events: I) -> AuditChainVerification
where
    I: IntoIterator<Item = &'a AuditEvent>,
{
    let mut streams: BTreeMap<Option<String>, Vec<&AuditEvent>> = BTreeMap::new();
    for event in events {
        streams
            .entry(event.realm_id.clone())
            .or_default()
            .push(event);
    }

    let mut checked_events = 0;
    let mut first_event_id = None;
    let mut last_event_id = None;
    for events in streams.values() {
        let verification = verify_audit_chain_linked(events.iter().copied());
        if first_event_id.is_none() {
            first_event_id = verification.first_event_id.clone();
        }
        checked_events += verification.checked_events;
        if verification.last_event_id.is_some() {
            last_event_id = verification.last_event_id.clone();
        }
        if !verification.valid {
            return AuditChainVerification {
                checked_events,
                first_event_id,
                last_event_id,
                ..verification
            };
        }
    }

    AuditChainVerification {
        valid: true,
        checked_events,
        first_event_id,
        last_event_id,
        broken_event_id: None,
        expected_previous_hash: None,
        actual_previous_hash: None,
        expected_event_hash: None,
        actual_event_hash: None,
    }
}

fn canonical_json_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(canonical_json_value).collect())
        }
        serde_json::Value::Object(map) => {
            let mut sorted = serde_json::Map::new();
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            for key in keys {
                if let Some(value) = map.get(key) {
                    sorted.insert(key.clone(), canonical_json_value(value));
                }
            }
            serde_json::Value::Object(sorted)
        }
        value => value.clone(),
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(hex_nibble(byte >> 4));
        out.push(hex_nibble(byte & 0x0f));
    }
    out
}

fn hex_nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + (value - 10)) as char,
    }
}
