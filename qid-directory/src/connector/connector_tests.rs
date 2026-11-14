use super::*;
use qid_core::config::{MAX_DIRECTORY_SEARCH_ENTRIES, MAX_DIRECTORY_SEARCH_ENTRIES_LIMIT};

/// In-memory test connector that returns pre-configured entries.
pub(super) struct TestDirectoryConnector {
    entries: Vec<LdapDirectoryEntry>,
}

impl TestDirectoryConnector {
    pub(super) fn new(entries: Vec<LdapDirectoryEntry>) -> Self {
        Self { entries }
    }
}

#[async_trait]
impl DirectoryConnector for TestDirectoryConnector {
    async fn connect(&mut self, _config: &DirectoryConnectionConfig) -> QidResult<()> {
        Ok(())
    }

    async fn fetch_users(
        &self,
        _sync: &DirectorySyncConfig,
        _mapping: &DirectoryAttributeMapping,
    ) -> QidResult<Vec<LdapDirectoryEntry>> {
        Ok(self.entries.clone())
    }

    async fn disconnect(&mut self) -> QidResult<()> {
        Ok(())
    }
}

#[test]
fn the_connection_page_size_reaches_the_search_options() {
    let mut config = DirectoryConnectionConfig {
        page_size: None,
        url: "ldaps://dir.example.com".to_string(),
        ..DirectoryConnectionConfig::default()
    };
    assert_eq!(search_options(&config).page_size, None);
    config.page_size = Some(500);
    let options = search_options(&config);
    assert_eq!(options.page_size, Some(500));
}

#[test]
fn a_search_that_keeps_returning_a_cookie_fails_instead_of_looping() {
    // A directory that always hands back a paging cookie must not keep the
    // sync running: the search fails with the bound in the message.
    let mut progress = PagedSearch::new(1000, None);
    let error = (|| -> QidResult<()> {
        for _ in 0..10_000 {
            progress.record_page(1)?;
        }
        Ok(())
    })()
    .expect_err("a search that never ends fails");
    assert!(
        error.message().contains("fetched more than"),
        "the failure names the bound: {}",
        error.message()
    );
}

#[test]
fn a_search_that_collects_more_entries_than_the_ceiling_fails() {
    // The entry ceiling is the product's guarantee, and it is above the
    // number of objects the supported servers are documented to hold.
    let mut progress = PagedSearch::new(1000, None);
    progress
        .record_page(MAX_DIRECTORY_SEARCH_ENTRIES as usize)
        .expect("the ceiling itself is allowed");
    let error = progress
        .record_page(1)
        .expect_err("one entry beyond the ceiling fails");
    assert!(
        error.message().contains("returned more than"),
        "the failure names the bound: {}",
        error.message()
    );
}

#[test]
fn a_search_without_paging_fetches_one_page() {
    // An unpaged search is one request, so it collects what that request
    // returns; the page bound does not turn a large directory into a
    // failure.
    let mut progress = PagedSearch::new(0, None);
    progress
        .record_page(MAX_DIRECTORY_SEARCH_ENTRIES as usize)
        .expect("a large unpaged result is allowed");
    let error = progress
        .record_page(1)
        .expect_err("one page is the bound without paging");
    assert!(
        error.message().contains("fetched more than"),
        "the failure names the bound: {}",
        error.message()
    );
}

#[test]
fn the_configured_ceiling_is_the_bound_the_search_uses() {
    // The ceiling is the operator's setting, so a directory that holds more
    // objects than the default syncs, and a smaller one fails early.
    let raised = PagedSearch::new(1000, Some(4_000));
    assert_eq!(raised.max_entries, 4_000);
    let mut lowered = PagedSearch::new(1000, Some(10));
    assert_eq!(lowered.max_entries, 10);
    let error = lowered
        .record_page(11)
        .expect_err("one entry beyond the configured ceiling fails");
    assert!(
        error.message().contains("returned more than"),
        "the failure names the bound: {}",
        error.message()
    );
}

#[test]
fn a_ceiling_above_the_limit_is_clamped() {
    // The loader rejects a ceiling above the limit, and a caller that skips
    // the loader cannot ask for more than a host can serve.
    let progress = PagedSearch::new(1000, Some(u32::MAX));
    assert_eq!(
        progress.max_entries,
        MAX_DIRECTORY_SEARCH_ENTRIES_LIMIT as usize
    );
}

#[test]
fn the_page_bound_follows_the_requested_page_size() {
    // A small page size must not shrink what a directory may hold: the
    // pages a search may fetch follow from the entry ceiling.
    let small = PagedSearch::new(10, None);
    let large = PagedSearch::new(1000, None);
    assert!(
        small.max_pages > large.max_pages,
        "a smaller page allows more pages"
    );
    assert_eq!(small.max_entries, large.max_entries);
}

#[test]
fn runtime_initialization_retries_after_failure() -> std::io::Result<()> {
    let value = std::sync::OnceLock::new();
    let lock = std::sync::Mutex::new(());
    let attempts = std::cell::Cell::new(0);
    let initialize = || {
        attempts.set(attempts.get() + 1);
        if attempts.get() == 1 {
            Err(std::io::Error::other("transient initialization failure"))
        } else {
            Ok(42)
        }
    };

    let Err(error) = retry_init(&value, &lock, initialize) else {
        panic!("first attempt must fail");
    };
    assert_eq!(error.to_string(), "transient initialization failure");
    assert!(value.get().is_none());
    let initialized = retry_init(&value, &lock, initialize)?;
    assert_eq!(*initialized, 42);
    let cached = retry_init(&value, &lock, initialize)?;
    assert!(std::ptr::eq(initialized, cached));
    assert_eq!(attempts.get(), 2);
    Ok(())
}

#[test]
fn runtime_initialization_is_shared_across_concurrent_callers() -> std::io::Result<()> {
    use std::sync::{
        Barrier, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    };

    let value = OnceLock::new();
    let lock = Mutex::new(());
    let attempts = AtomicUsize::new(0);
    let start = Barrier::new(8);
    std::thread::scope(|scope| -> std::io::Result<()> {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    start.wait();
                    retry_init(&value, &lock, || {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        Ok(42)
                    })
                })
            })
            .collect();
        for handle in handles {
            let initialized = handle
                .join()
                .map_err(|_| std::io::Error::other("initialization thread panicked"))??;
            assert_eq!(*initialized, 42);
            assert!(
                value
                    .get()
                    .is_some_and(|cached| std::ptr::eq(initialized, cached))
            );
        }
        Ok(())
    })?;
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    Ok(())
}
