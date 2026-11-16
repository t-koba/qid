use super::*;

#[test]
fn postgres_migrations_adapt_sqlite_expressions_and_keep_source_checksums() {
    let postgres = postgres_migrator();
    assert_eq!(postgres.iter().count(), MIGRATOR.iter().count());
    for (original, adapted) in MIGRATOR.iter().zip(postgres.iter()) {
        let expected_sql = original
            .sql
            .replace("PRAGMA foreign_keys = off;", "").replace("\r\n", "\n")
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
        assert_eq!(adapted.sql, expected_sql);
        assert_eq!(adapted.checksum, original.checksum);
    }
    let original = MIGRATOR
        .iter()
        .find(|migration| migration.sql.contains("custom_domain_hostname_guard"))
        .expect("custom-domain migration exists");
    let adapted = postgres
        .iter()
        .find(|migration| migration.sql.contains("custom_domain_hostname_guard"))
        .expect("adapted custom-domain migration exists");
    assert!(!original.sql.contains("COLLATE \"C\""));
    assert_eq!(
        adapted.sql.matches("LOWER(hostname COLLATE \"C\")").count(),
        3
    );
    assert!(
        adapted
            .sql
            .contains("duplicate LOWER(hostname); repair externally; retry migration")
    );
    assert_eq!(
        POSTGRES_EPOCH_DEFAULT,
        "FLOOR(EXTRACT(EPOCH FROM NOW()))::BIGINT"
    );
    assert!(
        postgres
            .iter()
            .any(|migration| { migration.sql.contains(POSTGRES_EPOCH_DEFAULT) })
    );
    assert!(
        postgres
            .iter()
            .all(|migration| !migration.sql.contains("PRAGMA"))
    );
}
