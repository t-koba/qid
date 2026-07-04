use async_trait::async_trait;

use super::*;

#[async_trait]
impl SessionRepository for FileRepository {
    async fn create_session(&self, session: &Session) -> QidResult<()> {
        let mut store = self.store.write().await;
        crate::domain::validate_session_creation(store.sessions.get(&session.id))?;
        store.sessions.insert(session.id.clone(), session.clone());
        drop(store);
        self.save().await
    }

    async fn get_session(&self, id: &str) -> QidResult<Option<Session>> {
        let store = self.store.read().await;
        Ok(store.sessions.get(id).cloned())
    }

    async fn update_session_idle_expiry(&self, id: &str, idle_expires_at: u64) -> QidResult<()> {
        let mut store = self.store.write().await;
        if let Some(session) = store.sessions.get_mut(id) {
            session.idle_expires_at = idle_expires_at;
        }
        drop(store);
        self.save().await
    }

    async fn revoke_session(&self, id: &str) -> QidResult<()> {
        let mut store = self.store.write().await;
        if let Some(session) = store.sessions.get_mut(id) {
            crate::domain::validate_session_revocation(session)?;
            session.revoked = true;
        }
        drop(store);
        self.save().await
    }

    async fn list_sessions(
        &self,
        realm_id: &str,
        user_id: Option<&str>,
    ) -> QidResult<Vec<Session>> {
        let store = self.store.read().await;
        let mut sessions: Vec<Session> = store
            .sessions
            .values()
            .filter(|s| s.realm_id == realm_id)
            .filter(|s| user_id.is_none_or(|uid| s.user_id == uid))
            .cloned()
            .collect();
        sessions.sort_by_key(|session| std::cmp::Reverse(session.created_at));
        Ok(sessions)
    }
}
