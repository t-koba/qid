//! OIDC Provider implementation.
#![forbid(unsafe_code)]
//!
//! Phase 0: Discovery, Authorization Code + PKCE, UserInfo.

pub mod discovery;
pub mod provider;
pub mod rp_metadata;
pub mod shared_signals;

pub use discovery::{routes, routes_with_password_attempt_limiter};

pub(crate) fn bad_request(message: impl Into<String>) -> qid_core::error::QidError {
    qid_core::error::QidError::BadRequest {
        message: message.into(),
    }
}

pub(crate) fn unauthorized(message: impl Into<String>) -> qid_core::error::QidError {
    qid_core::error::QidError::Unauthorized {
        message: message.into(),
    }
}

pub(crate) fn internal_error(message: impl Into<String>) -> qid_core::error::QidError {
    qid_core::error::QidError::Internal {
        message: message.into(),
    }
}

pub(crate) fn not_found(resource: impl Into<String>) -> qid_core::error::QidError {
    qid_core::error::QidError::NotFound {
        resource: resource.into(),
    }
}
