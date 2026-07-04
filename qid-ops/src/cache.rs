use crate::{bad_request, sha256_hex};
use qid_core::error::QidResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheBackendConfig {
    pub kind: CacheBackendKind,
    pub endpoints: Vec<String>,
    pub key_prefix: String,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CacheBackendKind {
    Disabled,
    Redis,
    Valkey,
}

impl CacheBackendConfig {
    pub fn validate(&self) -> QidResult<()> {
        if self.kind == CacheBackendKind::Disabled {
            return Ok(());
        }
        if self.endpoints.is_empty() {
            return Err(bad_request("Cache backend requires at least one endpoint"));
        }
        if self.key_prefix.trim().is_empty() {
            return Err(bad_request("Cache key prefix must not be empty"));
        }
        if self.ttl_seconds == 0 {
            return Err(bad_request("Cache TTL must be greater than zero"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheKey {
    pub namespace: String,
    pub digest: String,
}

impl CacheKey {
    pub fn new(namespace: impl Into<String>, material: impl AsRef<[u8]>) -> QidResult<Self> {
        let namespace = namespace.into();
        if namespace.trim().is_empty() {
            return Err(bad_request("Cache namespace must not be empty"));
        }
        Ok(Self {
            namespace,
            digest: sha256_hex(material),
        })
    }

    pub fn render(&self, config: &CacheBackendConfig) -> QidResult<String> {
        config.validate()?;
        Ok(format!(
            "{}:{}:{}",
            config.key_prefix.trim_matches(':'),
            self.namespace,
            self.digest
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheEntry {
    pub value: Vec<u8>,
    pub expires_at_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachePut {
    pub key: CacheKey,
    pub value: Vec<u8>,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheHealth {
    pub healthy: bool,
    pub backend: CacheBackendKind,
    pub endpoint_count: usize,
    pub latency_ms: Option<u64>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RedisLikeCommand {
    Get {
        key: String,
    },
    SetEx {
        key: String,
        ttl_seconds: u64,
        value: Vec<u8>,
    },
    SetNxEx {
        key: String,
        ttl_seconds: u64,
        value: Vec<u8>,
    },
    Del {
        key: String,
    },
    Ping,
}

pub trait RedisLikeTransport {
    fn execute(&mut self, command: RedisLikeCommand)
    -> Result<Option<Vec<u8>>, qid_core::QidError>;
    fn latency_ms(&self) -> Option<u64> {
        None
    }
}

pub struct RedisLikeCache<T> {
    config: CacheBackendConfig,
    transport: T,
}

impl<T: RedisLikeTransport> RedisLikeCache<T> {
    pub fn new(config: CacheBackendConfig, transport: T) -> QidResult<Self> {
        config.validate()?;
        if config.kind == CacheBackendKind::Disabled {
            return Err(bad_request(
                "Redis-like cache requires redis or valkey backend",
            ));
        }
        Ok(Self { config, transport })
    }

    pub fn put(&mut self, put: CachePut) -> QidResult<()> {
        if put.ttl_seconds == 0 {
            return Err(bad_request("Cache put TTL must be greater than zero"));
        }
        if put.value.is_empty() {
            return Err(bad_request("Cache value must not be empty"));
        }
        let key = put.key.render(&self.config)?;
        self.transport.execute(RedisLikeCommand::SetEx {
            key,
            ttl_seconds: put.ttl_seconds.min(self.config.ttl_seconds),
            value: put.value,
        })?;
        Ok(())
    }

    pub fn put_if_absent(&mut self, put: CachePut) -> QidResult<bool> {
        if put.ttl_seconds == 0 {
            return Err(bad_request("Cache put TTL must be greater than zero"));
        }
        if put.value.is_empty() {
            return Err(bad_request("Cache value must not be empty"));
        }
        let key = put.key.render(&self.config)?;
        let response = self.transport.execute(RedisLikeCommand::SetNxEx {
            key,
            ttl_seconds: put.ttl_seconds.min(self.config.ttl_seconds),
            value: put.value,
        })?;
        Ok(response.as_deref() == Some(b"OK"))
    }

    pub fn get(&mut self, key: &CacheKey) -> QidResult<Option<Vec<u8>>> {
        let key = key.render(&self.config)?;
        self.transport.execute(RedisLikeCommand::Get { key })
    }

    pub fn delete(&mut self, key: &CacheKey) -> QidResult<()> {
        let key = key.render(&self.config)?;
        self.transport.execute(RedisLikeCommand::Del { key })?;
        Ok(())
    }

    pub fn health(&mut self) -> CacheHealth {
        match self.transport.execute(RedisLikeCommand::Ping) {
            Ok(_) => CacheHealth {
                healthy: true,
                backend: self.config.kind.clone(),
                endpoint_count: self.config.endpoints.len(),
                latency_ms: self.transport.latency_ms(),
                reason: None,
            },
            Err(reason) => CacheHealth {
                healthy: false,
                backend: self.config.kind.clone(),
                endpoint_count: self.config.endpoints.len(),
                latency_ms: self.transport.latency_ms(),
                reason: Some(reason.to_string()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MemoryRedisLikeTransport {
        values: BTreeMap<String, Vec<u8>>,
        ttls: BTreeMap<String, u64>,
        fail_ping: bool,
        last_command: Option<RedisLikeCommand>,
    }

    impl RedisLikeTransport for MemoryRedisLikeTransport {
        fn execute(
            &mut self,
            command: RedisLikeCommand,
        ) -> Result<Option<Vec<u8>>, qid_core::QidError> {
            self.last_command = Some(command.clone());
            match command {
                RedisLikeCommand::Get { key } => Ok(self.values.get(&key).cloned()),
                RedisLikeCommand::SetEx {
                    key,
                    ttl_seconds,
                    value,
                } => {
                    self.values.insert(key.clone(), value);
                    self.ttls.insert(key, ttl_seconds);
                    Ok(None)
                }
                RedisLikeCommand::SetNxEx {
                    key,
                    ttl_seconds,
                    value,
                } => {
                    if self.values.contains_key(&key) {
                        Ok(None)
                    } else {
                        self.values.insert(key.clone(), value);
                        self.ttls.insert(key, ttl_seconds);
                        Ok(Some(b"OK".to_vec()))
                    }
                }
                RedisLikeCommand::Del { key } => {
                    self.values.remove(&key);
                    self.ttls.remove(&key);
                    Ok(None)
                }
                RedisLikeCommand::Ping => {
                    if self.fail_ping {
                        Err(qid_core::QidError::Storage {
                            message: "redis unavailable".to_string(),
                        })
                    } else {
                        Ok(Some(b"PONG".to_vec()))
                    }
                }
            }
        }

        fn latency_ms(&self) -> Option<u64> {
            Some(7)
        }
    }

    #[test]
    fn cache_config_requires_endpoint_for_redis_or_valkey() {
        let config = CacheBackendConfig {
            kind: CacheBackendKind::Redis,
            endpoints: Vec::new(),
            key_prefix: "qid".to_string(),
            ttl_seconds: 60,
        };

        assert!(config.validate().is_err());

        let disabled = CacheBackendConfig {
            kind: CacheBackendKind::Disabled,
            endpoints: Vec::new(),
            key_prefix: String::new(),
            ttl_seconds: 0,
        };
        disabled.validate().unwrap();
    }

    #[test]
    fn redis_like_cache_hashes_keys_clamps_ttl_and_deletes() {
        let config = CacheBackendConfig {
            kind: CacheBackendKind::Valkey,
            endpoints: vec!["valkey://127.0.0.1:6379".to_string()],
            key_prefix: "qid".to_string(),
            ttl_seconds: 30,
        };
        let key = CacheKey::new("session", b"user@example.com").unwrap();
        let rendered_key = key.render(&config).unwrap();
        assert!(!rendered_key.contains("user@example.com"));
        assert!(rendered_key.starts_with("qid:session:"));

        let mut cache = RedisLikeCache::new(config, MemoryRedisLikeTransport::default()).unwrap();
        cache
            .put(CachePut {
                key: key.clone(),
                value: b"cached-session".to_vec(),
                ttl_seconds: 60,
            })
            .unwrap();
        assert_eq!(cache.get(&key).unwrap(), Some(b"cached-session".to_vec()));
        assert_eq!(cache.transport.ttls.get(&rendered_key), Some(&30));

        cache.delete(&key).unwrap();
        assert_eq!(cache.get(&key).unwrap(), None);
    }

    #[test]
    fn redis_like_cache_put_if_absent_is_atomic_replay_guard() {
        let config = CacheBackendConfig {
            kind: CacheBackendKind::Redis,
            endpoints: vec!["redis://127.0.0.1:6379".to_string()],
            key_prefix: "qid".to_string(),
            ttl_seconds: 120,
        };
        let key = CacheKey::new("dpop_jti", b"jti-1").unwrap();
        let mut cache = RedisLikeCache::new(config, MemoryRedisLikeTransport::default()).unwrap();

        let first = cache
            .put_if_absent(CachePut {
                key: key.clone(),
                value: b"seen".to_vec(),
                ttl_seconds: 120,
            })
            .unwrap();
        let second = cache
            .put_if_absent(CachePut {
                key,
                value: b"seen".to_vec(),
                ttl_seconds: 120,
            })
            .unwrap();

        assert!(first);
        assert!(!second);
    }

    #[test]
    fn redis_like_cache_health_reports_backend_failure() {
        let config = CacheBackendConfig {
            kind: CacheBackendKind::Redis,
            endpoints: vec!["redis://127.0.0.1:6379".to_string()],
            key_prefix: "qid".to_string(),
            ttl_seconds: 30,
        };
        let transport = MemoryRedisLikeTransport {
            fail_ping: true,
            ..MemoryRedisLikeTransport::default()
        };
        let mut cache = RedisLikeCache::new(config, transport).unwrap();

        let health = cache.health();

        assert!(!health.healthy);
        assert_eq!(health.backend, CacheBackendKind::Redis);
        assert_eq!(health.latency_ms, Some(7));
        assert!(
            health
                .reason
                .unwrap_or_default()
                .contains("redis unavailable")
        );
    }
}
