use super::*;

/// Keys for create-only writes and SCIM replacement validation.
pub(super) trait InsertIdentity: Clone {
    const RECORD: &'static str;
    const IDENTITY: &'static str;
    const GLOBAL_IDENTITY: bool = false;
    fn id(&self) -> &str;
    fn identity(&self) -> Option<(&str, &str)>;
}

macro_rules! insert_identity {
    ($type:ty, $record:literal, $identity:literal, $id:ident, |$record_var:ident| $key:expr) => {
        insert_identity!($type, $record, $identity, $id, |$record_var| $key, false);
    };
    ($type:ty, $record:literal, $identity:literal, $id:ident, |$record_var:ident| $key:expr, $global:expr) => {
        impl InsertIdentity for $type {
            const RECORD: &'static str = $record;
            const IDENTITY: &'static str = $identity;
            const GLOBAL_IDENTITY: bool = $global;
            fn id(&self) -> &str {
                &self.$id
            }
            fn identity(&self) -> Option<(&str, &str)> {
                let $record_var = self;
                $key
            }
        }
    };
}

insert_identity!(
    PolicyBundle,
    "policy bundle",
    "policy bundle",
    id,
    |record| Some((&record.realm_id, &record.name))
);
insert_identity!(User, "user", "user email", id, |record| record
    .email
    .as_deref()
    .map(|email| (record.realm_id.as_str(), email)));
insert_identity!(ScimUser, "SCIM user", "user name", id, |record| Some((
    &record.realm_id,
    &record.user_name
)));
insert_identity!(ScimGroup, "SCIM group", "display name", id, |record| Some(
    (&record.realm_id, &record.display_name)
));
insert_identity!(Client, "client", "client id", id, |record| Some((
    &record.realm_id,
    &record.client_id
)));
impl FileRepository {
    /// Check both keys and insert under the exclusive store lock, then persist.
    /// An absent identity is not unique, matching SQL's multiple-NULL behavior.
    pub(super) async fn insert_new<T: InsertIdentity>(
        &self,
        record: &T,
        select: fn(&mut Store) -> &mut HashMap<String, T>,
    ) -> QidResult<()> {
        let mut store = self.store.write().await;
        insert_new_in_store(&mut store, record, select)?;
        drop(store);
        self.save().await
    }
}

pub(super) fn insert_new_in_store<T: InsertIdentity>(
    store: &mut Store,
    record: &T,
    select: fn(&mut Store) -> &mut HashMap<String, T>,
) -> QidResult<()> {
    let map = select(store);
    reject_duplicate_id(map.contains_key(record.id()), || {
        format!("{} record ID {} already exists", T::RECORD, record.id())
    })?;
    if let Some((owner, identity)) = record.identity()
        && map
            .values()
            .any(|stored| stored.identity() == Some((owner, identity)))
    {
        let message = if T::GLOBAL_IDENTITY {
            format!("{} {identity} already exists globally", T::IDENTITY)
        } else {
            format!("{} {identity} already exists in realm {owner}", T::IDENTITY)
        };
        return Err(QidError::Conflict { message });
    }
    map.insert(record.id().to_owned(), record.clone());
    Ok(())
}

insert_identity!(
    ParRequest,
    "PAR request",
    "PAR request URI",
    request_uri,
    |_record| None
);
// The user code is globally unique, so every grant shares one scope.
insert_identity!(
    DeviceAuthorizationGrant,
    "device authorization grant",
    "device user code",
    device_code_hash,
    |record| Some(("", &record.user_code)),
    true
);
insert_identity!(
    BackchannelAuthenticationGrant,
    "backchannel authentication grant",
    "backchannel authentication grant",
    auth_req_id_hash,
    |_record| None
);
