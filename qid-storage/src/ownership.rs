//! Owner-bound ID upserts: resource code chooses the binding and mutable fields.

use qid_core::error::{QidError, QidResult};

/// Compare bindings while holding the file store's exclusive write lock.
pub(super) fn ensure_same_binding<T: PartialEq>(
    incumbent: Option<T>,
    incoming: T,
    message: impl FnOnce() -> String,
) -> QidResult<()> {
    if incumbent.is_some_and(|binding| binding != incoming) {
        return Err(QidError::Conflict { message: message() });
    }
    Ok(())
}

/// Use only after an atomic SQL upsert with an explicit owner/identity predicate.
/// Zero rows means the predicate rejected the write, including lifecycle checks.
pub(super) fn ensure_upsert_applied(
    rows_affected: u64,
    message: impl FnOnce() -> String,
) -> QidResult<()> {
    if rows_affected == 0 {
        return Err(QidError::Conflict { message: message() });
    }
    Ok(())
}
