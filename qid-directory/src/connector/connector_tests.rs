use super::*;

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
