//! Proxy integration for qid.
#![forbid(unsafe_code)]
//!
//! Phase 0: signed identity assertion and pep_decision endpoint.

pub mod assertion;
pub mod captive_portal;
pub mod pep_decision;

pub use assertion::issue_assertion;
pub use captive_portal::{capport_routes_enabled, captive_portal_routes};
pub use pep_decision::pep_decision_routes;
