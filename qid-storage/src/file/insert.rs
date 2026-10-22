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
