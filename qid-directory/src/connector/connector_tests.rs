use super::*;

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
