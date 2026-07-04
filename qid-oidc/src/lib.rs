//! OIDC Provider implementation.
#![forbid(unsafe_code)]
//!
//! Phase 0: Discovery, Authorization Code + PKCE, UserInfo.

pub mod discovery;
pub mod provider;
pub mod rp_metadata;
pub mod shared_signals;

pub use discovery::routes;
