//! CIAM control-plane helpers.

pub mod auth;
pub mod identity_links;
pub mod profile;

pub use auth::*;
pub use identity_links::*;
pub use profile::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum VerificationChannel {
    Email,
    Phone,
}
