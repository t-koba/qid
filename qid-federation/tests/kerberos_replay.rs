use qid_core::{
    QidError,
    cache::{MemoryCache, SharedCache},
    error::QidResult,
};
use qid_federation::KerberosReplayStore;
use std::{
    io,
    sync::{Arc, Barrier, Mutex},
    thread,
};

#[test]
fn shared_cache_rejects_duplicate_and_concurrent_tags() -> io::Result<()> {
    let cache = Arc::new(MemoryCache::new());
    let stores = [
        Arc::new(KerberosReplayStore::new(cache.clone())),
        Arc::new(KerberosReplayStore::new(cache)),
    ];
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let store = stores[i % 2].clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                store.insert(b"same-tag", 1000, 1300)
            })
        })
        .collect();
    let mut accepted = 0;
    for handle in handles {
        if handle
            .join()
            .map_err(|_| io::Error::other("worker panicked"))??
        {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 1);
    assert!(!stores[0].insert(b"same-tag", 1000, 1600)?);
    assert!(stores[1].insert(b"different-tag", 1000, 1300)?);

    let short = [9; 12];
    let mut padded = [0; 24];
    padded[..short.len()].copy_from_slice(&short);
    assert!(stores[0].insert(&short, 1000, 1300)?);
    assert!(!stores[1].insert(&padded, 1000, 1300)?);
    Ok(())
}

#[derive(Default)]
struct RecordingCache {
    writes: Mutex<Vec<(String, Vec<u8>, u64)>>,
    fail: bool,
}

impl SharedCache for RecordingCache {
    fn get(&self, _: &str) -> Option<Vec<u8>> {
        panic!("replay insertion must not use get")
    }

    fn set(&self, _: &str, _: Vec<u8>, _: u64) {
        panic!("replay insertion must not use set")
    }

    fn delete(&self, _: &str) {
        panic!("replay insertion must not use delete")
    }

    fn set_if_absent(&self, key: &str, value: Vec<u8>, ttl: u64) -> QidResult<bool> {
        self.writes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((key.into(), value, ttl));
        if self.fail {
            Err(QidError::Internal {
                message: "cache backend endpoint details".into(),
            })
        } else {
            Ok(true)
        }
    }
}

#[test]
fn keys_are_namespaced_bounded_and_ttls_cover_inclusive_expiry() -> io::Result<()> {
    let cache = Arc::new(RecordingCache::default());
    let store = KerberosReplayStore::new(cache.clone());
    let mut tag = vec![42; 4096];
    for (now, expires) in [
        (1000, 1300),
        (1000, 1001),
        (1000, 1000),
        (1000, 999),
        (i64::MAX, i64::MIN),
    ] {
        assert!(store.insert(&tag, now, expires)?);
    }
    tag[23] ^= 1;
    assert!(store.insert(&tag, 1000, 1300)?);
    let writes = cache.writes.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(
        writes.iter().map(|w| w.2).collect::<Vec<_>>(),
        [301, 2, 1, 1, 1, 301]
    );
    for (key, value, _) in writes.iter() {
        let digest = key
            .strip_prefix("kerberos:replay:")
            .ok_or_else(|| io::Error::other("missing namespace"))?;
        assert_eq!(digest.len(), 43);
        assert!(
            digest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert!(value.is_empty());
    }
    assert_eq!(writes[0].0, writes[4].0);
    assert_ne!(writes[0].0, writes[5].0);
    Ok(())
}

#[test]
fn backend_errors_fail_closed_and_debug_is_opaque() {
    let cache = Arc::new(RecordingCache {
        fail: true,
        ..Default::default()
    });
    let store = KerberosReplayStore::new(cache.clone());
    assert_eq!(format!("{store:?}"), "KerberosReplayStore { .. }");
    for _ in 0..2 {
        let error = store.insert(b"tag", 1000, 1300).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(error.to_string(), "Kerberos replay cache unavailable");
        assert_eq!(
            format!("{error:?}"),
            "Custom { kind: Other, error: \"Kerberos replay cache unavailable\" }"
        );
        assert!(std::error::Error::source(&error).is_none());
    }
    assert_eq!(
        cache.writes.lock().unwrap_or_else(|e| e.into_inner()).len(),
        2
    );
}
