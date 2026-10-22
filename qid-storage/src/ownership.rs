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

/// Refuse a write the statement itself refused.
///
/// Use after an atomic SQL statement that returns zero rows because a
/// duplicate identity, owner/identity predicate, or one-shot lifecycle
/// predicate refused it. The outcome is the same (`Conflict`); the resource
/// contract states which predicate enforces the refusal.
pub(super) fn ensure_upsert_applied(
    rows_affected: u64,
    message: impl FnOnce() -> String,
) -> QidResult<()> {
    if rows_affected == 0 {
        return Err(QidError::Conflict { message: message() });
    }
    Ok(())
}

/// The refusal a user write earns when the realm already holds the email.
pub(super) fn user_email_conflict(email: &str, realm_id: &str) -> QidError {
    QidError::Conflict {
        message: format!("user email {email} already exists in realm {realm_id}"),
    }
}

/// Refuse a write that changed no row because the record is gone.
pub(super) fn ensure_row_present(
    rows_affected: u64,
    resource: impl FnOnce() -> String,
) -> QidResult<()> {
    if rows_affected == 0 {
        return Err(QidError::NotFound {
            resource: resource(),
        });
    }
    Ok(())
}

/// The collision rule a migrated write states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum CollisionRule {
    /// Refuse the write and leave the incumbent unchanged.
    Refuse,
    /// Replace the incumbent.
    Replace,
}

/// A typed statement of a write's ownership contract: the owner key, the
/// identity key, and the collision rule. One per migrated write; both
/// backends enforce the same three things in their own idiom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub struct OwnershipContract {
    pub owner_key: &'static str,
    pub identity_key: &'static str,
    pub collision: CollisionRule,
}

/// Ownership contract for the user resource (create and update).
#[allow(dead_code)]
pub const USER: OwnershipContract = OwnershipContract {
    owner_key: "realm_id",
    identity_key: "id, email",
    collision: CollisionRule::Refuse,
};

/// Ownership contract for the CIAM consent grant resource (store).
#[allow(dead_code)]
pub const CIAM_CONSENT_GRANT: OwnershipContract = OwnershipContract {
    owner_key: "realm_id, user_id, client_id",
    identity_key: "id",
    collision: CollisionRule::Replace,
};

/// Ownership contract for the device resource (register).
#[allow(dead_code)]
pub const DEVICE: OwnershipContract = OwnershipContract {
    owner_key: "realm_id, user_id",
    identity_key: "id",
    collision: CollisionRule::Refuse,
};

/// Ownership contract for the FedCM identity resource (store).
#[allow(dead_code)]
pub const FEDCM_IDENTITY: OwnershipContract = OwnershipContract {
    owner_key: "realm_id",
    identity_key: "id",
    collision: CollisionRule::Refuse,
};

/// Ownership contract for the service-account resource (create).
#[allow(dead_code)]
pub const SERVICE_ACCOUNT: OwnershipContract = OwnershipContract {
    owner_key: "realm_id",
    identity_key: "id",
    collision: CollisionRule::Refuse,
};

/// Ownership contract for the WebAuthn credential resource (store).
#[allow(dead_code)]
pub const WEBAUTHN_CREDENTIAL: OwnershipContract = OwnershipContract {
    owner_key: "user_id",
    identity_key: "id",
    collision: CollisionRule::Refuse,
};

/// Ownership contract for the append-only audit-event resource.
#[allow(dead_code)]
pub const AUDIT_EVENT: OwnershipContract = OwnershipContract {
    owner_key: "realm_id",
    identity_key: "id",
    collision: CollisionRule::Refuse,
};
