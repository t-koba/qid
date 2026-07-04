//! Event bus for internal pub/sub.

use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

/// Categories of internal events.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A session was revoked (global or realm-scoped).
    SessionRevoked,
    /// A token family was revoked.
    TokenFamilyRevoked,
    /// A policy decision was recorded.
    PepDecision,
    /// A key rotation completed.
    KeyRotated,
    /// An audit event was appended.
    AuditAppended,
    /// A user was created, updated, or deleted.
    UserChanged,
    /// A client was created or deleted.
    ClientChanged,
    /// A realm configuration was updated.
    RealmConfigChanged,
    /// A SCIM provisioning event occurred.
    ScimProvisioned,
}

/// An event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub kind: EventKind,
    pub realm_id: Option<String>,
    pub tenant_id: Option<String>,
    pub payload: serde_json::Value,
    pub timestamp: u64,
}

/// Internal event bus trait.
pub trait EventBus: Send + Sync {
    /// Publish an event to all subscribers.
    fn publish(&self, event: Event);
    /// Register a callback invoked for every event.
    /// Returns an ID that can be used to unsubscribe.
    fn subscribe<F: Fn(&Event) + Send + Sync + 'static>(&self, f: F) -> usize;
}

/// In-memory event bus backed by a subscriber list.
type SubscriberEntry = (usize, Box<dyn Fn(&Event) + Send + Sync>);

pub struct MemoryEventBus {
    subscribers: std::sync::Mutex<Vec<SubscriberEntry>>,
    next_id: std::sync::atomic::AtomicUsize,
}

impl MemoryEventBus {
    pub fn new() -> Self {
        Self {
            subscribers: std::sync::Mutex::new(Vec::new()),
            next_id: std::sync::atomic::AtomicUsize::new(1),
        }
    }
}

impl Default for MemoryEventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus for MemoryEventBus {
    fn publish(&self, event: Event) {
        let subs = self.subscribers.lock().unwrap_or_else(|e| e.into_inner());
        for (_, f) in subs.iter() {
            f(&event);
        }
    }

    fn subscribe<F: Fn(&Event) + Send + Sync + 'static>(&self, f: F) -> usize {
        let mut subs = self.subscribers.lock().unwrap_or_else(|e| e.into_inner());
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        subs.push((id, Box::new(f)));
        id
    }
}

/// Global event bus instance for in-process pub/sub.
pub static GLOBAL_EVENT_BUS: LazyLock<MemoryEventBus> = LazyLock::new(MemoryEventBus::new);
