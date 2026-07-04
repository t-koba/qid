mod ciam;
mod identity;
mod iga;
mod rebac;
mod saas;
mod security;

pub(super) use ciam::*;
/// Convert sqlx errors into domain errors for SQL repository implementations.
pub(super) fn storage_to_qid_error(err: sqlx::Error) -> qid_core::QidError {
    qid_core::QidError::Storage {
        message: err.to_string(),
    }
}

pub(super) use identity::*;
pub(super) use iga::*;
pub(super) use rebac::*;
pub(super) use saas::*;
pub(super) use security::*;
