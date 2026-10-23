use super::*;

/// Keys for create-only records, not replacement or lifecycle writes.
pub(super) trait InsertIdentity: Clone {
    const RECORD: &'static str;
    const IDENTITY: &'static str;
    fn id(&self) -> &str;
    fn identity(&self) -> Option<(&str, &str)>;
}

impl InsertIdentity for PolicyBundle {
    const RECORD: &'static str = "policy bundle";
    const IDENTITY: &'static str = "policy bundle";
    fn id(&self) -> &str {
        &self.id
    }
    fn identity(&self) -> Option<(&str, &str)> {
        Some((&self.realm_id, &self.name))
    }
}

impl InsertIdentity for User {
    const RECORD: &'static str = "user";
    const IDENTITY: &'static str = "user email";
    fn id(&self) -> &str {
        &self.id
    }
    fn identity(&self) -> Option<(&str, &str)> {
        self.email
            .as_deref()
            .map(|email| (self.realm_id.as_str(), email))
    }
}

impl InsertIdentity for ScimUser {
    const RECORD: &'static str = "SCIM user";
    const IDENTITY: &'static str = "user name";
    fn id(&self) -> &str {
        &self.id
    }
    fn identity(&self) -> Option<(&str, &str)> {
        Some((&self.realm_id, &self.user_name))
    }
}

impl InsertIdentity for ScimGroup {
    const RECORD: &'static str = "SCIM group";
    const IDENTITY: &'static str = "display name";
    fn id(&self) -> &str {
        &self.id
    }
    fn identity(&self) -> Option<(&str, &str)> {
        Some((&self.realm_id, &self.display_name))
    }
}

impl InsertIdentity for Client {
    const RECORD: &'static str = "client";
    const IDENTITY: &'static str = "client id";
    fn id(&self) -> &str {
        &self.id
    }
    fn identity(&self) -> Option<(&str, &str)> {
        Some((&self.realm_id, &self.client_id))
    }
}

/// Check both keys and insert under the caller's exclusive store lock.
/// An absent identity is not unique, matching SQL's multiple-NULL behavior.
pub(super) fn insert_new<T: InsertIdentity>(
    map: &mut HashMap<String, T>,
    record: &T,
) -> QidResult<()> {
    if map.contains_key(record.id()) {
        return Err(QidError::Conflict {
            message: format!("{} record ID {} already exists", T::RECORD, record.id()),
        });
    }
    if let Some((owner, identity)) = record.identity()
        && map
            .values()
            .any(|stored| stored.identity() == Some((owner, identity)))
    {
        return Err(QidError::Conflict {
            message: format!("{} {identity} already exists in realm {owner}", T::IDENTITY),
        });
    }
    map.insert(record.id().to_owned(), record.clone());
    Ok(())
}

/// Stable identity for updates: the owner/identity that must not change.
pub(super) trait StableUpdateIdentity: Clone {
    const RECORD: &'static str;
    fn id(&self) -> &str;
    fn stable_binding(&self) -> (&str, &str);
}

impl StableUpdateIdentity for Client {
    const RECORD: &'static str = "client";
    fn id(&self) -> &str {
        &self.id
    }
    fn stable_binding(&self) -> (&str, &str) {
        (&self.realm_id, &self.client_id)
    }
}

/// Replace under the caller's exclusive lock, refusing a binding change.
/// A missing ID inserts, preserving the legacy file update semantics.
pub(super) fn replace_guarded<T: StableUpdateIdentity>(
    map: &mut HashMap<String, T>,
    record: &T,
) -> QidResult<()> {
    crate::ownership::ensure_same_binding(
        map.get(record.id()).map(|stored| stored.stable_binding()),
        record.stable_binding(),
        || format!("{} ID belongs to another identity", T::RECORD),
    )?;
    map.insert(record.id().to_owned(), record.clone());
    Ok(())
}
