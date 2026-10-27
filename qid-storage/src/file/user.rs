use async_trait::async_trait;

use super::*;

#[async_trait]
impl UserRepository for FileRepository {
    async fn create_user(&self, user: &User) -> QidResult<()> {
        let mut store = self.store.write().await;
        super::insert::insert_new(&mut store.users, user)?;
        drop(store);
        self.save().await
    }

    async fn get_user_by_id(&self, id: &str) -> QidResult<Option<User>> {
        Ok(self.map_get(|store| store.users.get(id)).await)
    }

    async fn get_user_by_id_in_realm(
        &self,
        realm_id: &RealmId,
        id: &str,
    ) -> QidResult<Option<User>> {
        let store = self.store.read().await;
        Ok(store
            .users
            .get(id)
            .filter(|user| user.realm_id == realm_id.0)
            .cloned())
    }

    async fn get_user_by_email(&self, realm_id: &RealmId, email: &str) -> QidResult<Option<User>> {
        let store = self.store.read().await;
        Ok(store
            .users
            .values()
            .find(|u| u.realm_id == realm_id.0 && u.email.as_deref() == Some(email))
            .cloned())
    }

    async fn list_users_page(
        &self,
        realm_id: &RealmId,
        offset: usize,
        limit: usize,
    ) -> QidResult<Vec<User>> {
        let store = self.store.read().await;
        let mut users: Vec<_> = store
            .users
            .values()
            .filter(|u| u.realm_id == realm_id.0)
            .cloned()
            .collect();
        users.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(users.into_iter().skip(offset).take(limit).collect())
    }

    async fn delete_user(&self, id: &str, realm: Option<&str>) -> QidResult<()> {
        let mut store = self.store.write().await;
        if realm.is_some_and(|realm| store.users.get(id).is_none_or(|u| u.realm_id != realm)) {
            return Err(QidError::NotFound {
                resource: format!("user {id}"),
            });
        }
        store.remove_auth_state(&std::collections::HashSet::from([id.to_string()]), None);
        drop(store);
        self.save().await
    }

    async fn update_user(&self, user: &User) -> QidResult<()> {
        let mut store = self.store.write().await;
        // The owner (realm) of a user does not change on update, so keep the
        // incumbent's realm and check the email against it, matching the SQL
        // backend which does not update realm_id.
        let realm_id = store
            .users
            .get(&user.id)
            .map(|stored| stored.realm_id.clone())
            .unwrap_or_else(|| user.realm_id.clone());
        let mut user = user.clone();
        user.realm_id = realm_id.clone();
        if let Some(email) = email_held_by_another(&store, &user) {
            return Err(crate::ownership::user_email_conflict(email, &realm_id));
        }
        store.users.insert(user.id.clone(), user.clone());
        drop(store);
        self.save().await
    }

    async fn store_password_credential(&self, cred: &PasswordCredential) -> QidResult<()> {
        let mut store = self.store.write().await;
        store
            .credentials_password
            .insert(cred.user_id.clone(), cred.clone());
        drop(store);
        self.save().await
    }

    async fn get_password_credential(
        &self,
        user_id: &str,
    ) -> QidResult<Option<PasswordCredential>> {
        let store = self.store.read().await;
        Ok(store.credentials_password.get(user_id).cloned())
    }
}

impl Store {
    // Shared by user and realm deletion so their dependent authentication state
    // has the same lifetime, including indirect session/family ownership.
    pub(super) fn remove_auth_state(
        &mut self,
        users: &std::collections::HashSet<String>,
        realm: Option<&str>,
    ) {
        let in_realm = |owner: &str| realm == Some(owner);
        self.push.authenticators.retain(|_, row| {
            let a = row.authenticator();
            !users.contains(&a.user_id) && !in_realm(&a.realm_id)
        });
        self.push
            .logins
            .retain(|_, c| !users.contains(&c.user_id) && !in_realm(&c.realm_id));
        let live: std::collections::HashSet<&String> = self.push.authenticators.keys().collect();
        self.push
            .login_issued_at
            .retain(|id, _| self.push.logins.contains_key(id));
        self.push
            .registration_issued_at
            .retain(|id, _| live.contains(id));
        // Follow ownership links before removing their parents. All live auth state
        // disappears together under this write lock; realm/client peers are untouched.
        let sessions: std::collections::HashSet<_> = self
            .sessions
            .values()
            .filter(|session| users.contains(&session.user_id) || in_realm(&session.realm_id))
            .map(|session| session.id.clone())
            .collect();
        self.authorization_codes.retain(|_, code| {
            !users.contains(&code.user_id)
                && !in_realm(&code.realm_id)
                && !code
                    .session_id
                    .as_ref()
                    .is_some_and(|sid| sessions.contains(sid))
        });
        let families: std::collections::HashSet<_> = self
            .token_families
            .values()
            .filter(|family| {
                users.contains(&family.user_id)
                    || in_realm(&family.realm_id)
                    || family
                        .session_id
                        .as_ref()
                        .is_some_and(|sid| sessions.contains(sid))
            })
            .map(|family| family.id.clone())
            .collect();
        self.access_tokens.retain(|_, token| {
            !users.contains(&token.user_id)
                && !in_realm(&token.realm_id)
                && !token
                    .family_id
                    .as_ref()
                    .is_some_and(|fid| families.contains(fid))
        });
        self.token_families.retain(|fid, _| !families.contains(fid));
        self.sessions.retain(|sid, _| !sessions.contains(sid));
        self.webauthn_credentials
            .retain(|user, _| !users.contains(user));
        self.totp_credentials
            .retain(|_, cred| !users.contains(&cred.user_id));
        self.devices
            .retain(|_, device| !users.contains(&device.user_id) && !in_realm(&device.realm_id));
        self.device_authorization_grants.retain(|_, grant| {
            !grant
                .user_id
                .as_ref()
                .is_some_and(|user| users.contains(user))
                && !in_realm(&grant.realm_id)
        });
        self.backchannel_authentication_grants.retain(|_, grant| {
            !grant
                .user_id
                .as_ref()
                .is_some_and(|user| users.contains(user))
                && !in_realm(&grant.realm_id)
        });
        self.users.retain(|user, _| !users.contains(user));
        self.credentials_password
            .retain(|user, _| !users.contains(user));
        self.ciam_profiles
            .retain(|_, profile| !users.contains(&profile.user_id) && !in_realm(&profile.realm_id));
        self.ciam_consent_grants
            .retain(|_, grant| !users.contains(&grant.user_id) && !in_realm(&grant.realm_id));
        self.ciam_verification_challenges.retain(|_, challenge| {
            !users.contains(&challenge.user_id) && !in_realm(&challenge.realm_id)
        });
        self.ciam_identity_links
            .retain(|_, link| !users.contains(&link.user_id) && !in_realm(&link.realm_id));
        self.password_reset_tokens
            .retain(|_, token| !users.contains(&token.user_id) && !in_realm(&token.realm_id));
    }
}

/// The email another user of the realm already holds, if any.
fn email_held_by_another<'a>(store: &Store, user: &'a User) -> Option<&'a str> {
    let email = user.email.as_deref()?;
    store
        .users
        .values()
        .any(|stored| {
            stored.id != user.id
                && stored.realm_id == user.realm_id
                && stored.email.as_deref() == Some(email)
        })
        .then_some(email)
}
