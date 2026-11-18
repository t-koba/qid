use super::*;

#[test]
fn postgres_migrations_adapt_sqlite_expressions_and_keep_source_checksums() {
    let postgres = postgres_migrator();
    assert_eq!(postgres.iter().count(), MIGRATOR.iter().count());
    for (original, adapted) in MIGRATOR.iter().zip(postgres.iter()) {
        let expected_sql = original
            .sql.as_str()
            .replace("PRAGMA foreign_keys = off;", "")
            .replace("\r\n", "\n")
            .replace("PRAGMA foreign_keys = on;", "")
            .replace("DATETIME", "BIGINT")
            .replace("CURRENT_TIMESTAMP", POSTGRES_EPOCH_DEFAULT)
            .replace("strftime('%s', 'now')", POSTGRES_EPOCH_DEFAULT)
            .replace(
                "LOWER(hostname) FROM custom_domains\n    GROUP BY LOWER(hostname) HAVING",
                "LOWER(hostname COLLATE \"C\") FROM custom_domains\n    GROUP BY LOWER(hostname COLLATE \"C\") HAVING",
            )
            .replace(
                "ON custom_domains (LOWER(hostname));",
                "ON custom_domains (LOWER(hostname COLLATE \"C\"));",
            );
        assert_eq!(adapted.version, original.version);
        assert_eq!(adapted.sql.as_str(), expected_sql);
        assert_eq!(adapted.checksum, original.checksum);
    }
    let original = MIGRATOR
        .iter()
        .find(|migration| {
            migration
                .sql
                .as_str()
                .contains("custom_domain_hostname_guard")
        })
        .expect("custom-domain migration exists");
    let adapted = postgres
        .iter()
        .find(|migration| {
            migration
                .sql
                .as_str()
                .contains("custom_domain_hostname_guard")
        })
        .expect("adapted custom-domain migration exists");
    assert!(!original.sql.as_str().contains("COLLATE \"C\""));
    assert_eq!(
        adapted
            .sql
            .as_str()
            .matches("LOWER(hostname COLLATE \"C\")")
            .count(),
        3
    );
    assert!(
        adapted
            .sql
            .as_str()
            .contains("duplicate LOWER(hostname); repair externally; retry migration")
    );
    assert_eq!(
        POSTGRES_EPOCH_DEFAULT,
        "FLOOR(EXTRACT(EPOCH FROM NOW()))::BIGINT"
    );
    assert!(
        postgres
            .iter()
            .any(|migration| { migration.sql.as_str().contains(POSTGRES_EPOCH_DEFAULT) })
    );
    assert!(
        postgres
            .iter()
            .all(|migration| !migration.sql.as_str().contains("PRAGMA"))
    );
}
