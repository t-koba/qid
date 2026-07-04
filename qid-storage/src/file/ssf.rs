use async_trait::async_trait;

use super::*;

#[async_trait]
impl SsfRepository for FileRepository {
    async fn upsert_ssf_stream(&self, stream: &SsfStreamRecord) -> QidResult<()> {
        let mut store = self.store.write().await;
        store.ssf_streams.insert(
            ssf_stream_key(&stream.realm_id, &stream.stream_id),
            stream.clone(),
        );
        drop(store);
        self.save().await
    }

    async fn list_ssf_streams(&self, realm_id: &str) -> QidResult<Vec<SsfStreamRecord>> {
        let store = self.store.read().await;
        Ok(store
            .ssf_streams
            .values()
            .filter(|stream| stream.realm_id == realm_id)
            .cloned()
            .collect())
    }

    async fn get_ssf_stream(
        &self,
        realm_id: &str,
        stream_id: &str,
    ) -> QidResult<Option<SsfStreamRecord>> {
        let store = self.store.read().await;
        Ok(store
            .ssf_streams
            .get(&ssf_stream_key(realm_id, stream_id))
            .cloned())
    }

    async fn delete_ssf_stream(&self, realm_id: &str, stream_id: &str) -> QidResult<bool> {
        let mut store = self.store.write().await;
        let removed = store
            .ssf_streams
            .remove(&ssf_stream_key(realm_id, stream_id))
            .is_some();
        drop(store);
        if removed {
            self.save().await?;
        }
        Ok(removed)
    }

    async fn record_ssf_set_jti(
        &self,
        realm_id: &str,
        issuer: &str,
        stream_id: &str,
        jti: &str,
        expires_at: u64,
        now: u64,
    ) -> QidResult<bool> {
        let mut store = self.store.write().await;
        store.ssf_set_replay.retain(|_, exp| *exp > now);
        let key = ssf_set_replay_key(realm_id, issuer, stream_id, jti);
        if store.ssf_set_replay.contains_key(&key) {
            return Ok(false);
        }
        store.ssf_set_replay.insert(key, expires_at);
        drop(store);
        self.save().await?;
        Ok(true)
    }
}
