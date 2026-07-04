//! OAuth 2.0 Authorization Server implementation.
#![forbid(unsafe_code)]
//!
//! Phase 0: token endpoint, introspection, revocation.

pub mod dpop;
pub mod endpoints;
pub mod grant_management;
pub mod mtls;
pub mod transaction_tokens;

#[cfg(feature = "gnap")]
pub mod gnap;

pub use endpoints::{routes, signed_routes, unsigned_routes};
