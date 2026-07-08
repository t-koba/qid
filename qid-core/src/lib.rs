#![forbid(unsafe_code)]

pub mod assurance;
pub mod baggage;
pub mod cache;
pub mod cloudevents;
pub mod config;
pub mod content_security;
pub mod contract;
pub mod did;
pub mod dpop;
pub mod email_auth;
pub mod error;
pub mod event;
pub mod forwarded;
pub mod idempotency;
pub mod idna;
pub mod json;
pub mod jwt;
pub mod ldif;
pub mod models;
pub mod notifications;
pub mod oauth;
pub mod pkce;
pub mod plan;
pub mod problem_details;
pub mod security_txt;
pub mod state;
pub mod structured_fields;
pub mod tenant;
pub mod util;
pub mod web_push;
pub mod zero_rtt;

#[cfg(feature = "test-utils")]
pub mod test_helpers;

pub use util::{compute_pairwise_sub, sector_identifier_for_client};

#[cfg(feature = "redis-cache")]
pub use cache::redis_cache;
pub use cache::{MemoryCache, SharedCache};
pub use config::QidConfig;
pub use error::{QidError, QidResult};
pub use models::*;
pub use plan::RuntimePlan;
pub use tenant::{RealmId, TenantId};
