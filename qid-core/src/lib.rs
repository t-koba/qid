#![forbid(unsafe_code)]

pub mod cache;
pub mod config;
pub mod dpop;
pub mod error;
pub mod event;
pub mod idempotency;
pub mod json;
pub mod jwt;
pub mod models;
pub mod oauth;
pub mod pkce;
pub mod plan;
pub mod state;
pub mod tenant;
pub mod util;

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
