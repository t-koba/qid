//! Dev-only adapter from the strict production keytab parser to pinned krb5.
//!
//! The fixture's krb5 `Keytab` still owns ordinary `Vec<u8>` keys and does
//! not zeroize them on drop; this wrapper deliberately exposes neither
//! `Debug` nor `Clone` but cannot change that upstream ownership behavior.
use krb5::{
    Keytab,
    acceptor::{EncType, ServiceKey},
};
use qid_federation::kerberos_keytab::load_keytab;
use std::{ops::Deref, path::Path};

/// Private owner that keeps the keytab out of public/debuggable state.
pub(super) struct KeytabOwner(Keytab);

impl Deref for KeytabOwner {
    type Target = Keytab;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Load through the strict parser; never include the path in errors.
pub(super) fn load(path: &Path) -> Result<KeytabOwner, &'static str> {
    let parsed = load_keytab(path).map_err(|_| "keytab unavailable")?;
    let keys = parsed
        .keys()
        .iter()
        .map(|key| {
            let enctype =
                EncType::from_i32(key.enctype.rfc_number()).ok_or("unsupported keytab enctype")?;
            Ok(ServiceKey::new(
                key.principal.clone(),
                key.realm.clone(),
                key.kvno,
                enctype,
                key.key().to_vec(),
            ))
        })
        .collect::<Result<Vec<_>, &'static str>>()?;
    Ok(KeytabOwner(Keytab::from_keys(keys)))
}
