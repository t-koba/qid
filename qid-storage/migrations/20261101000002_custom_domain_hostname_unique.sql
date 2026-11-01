-- Never choose a domain or tenant to resolve an ambiguous hostname.
-- If the guard fails, inspect collisions with:
-- SELECT LOWER(hostname), COUNT(*) FROM custom_domains
-- GROUP BY LOWER(hostname) HAVING COUNT(*) > 1;
-- Inspect the matching rows, explicitly repair the hostname bindings externally,
-- then retry migration. Failure rolls back without changing rows or the ledger.
CREATE TEMPORARY TABLE custom_domain_hostname_guard (
    duplicates INTEGER CONSTRAINT "duplicate LOWER(hostname); repair externally; retry migration"
        CHECK (duplicates = 0)
);
INSERT INTO custom_domain_hostname_guard (duplicates)
SELECT COUNT(*) FROM (
    SELECT LOWER(hostname) FROM custom_domains
    GROUP BY LOWER(hostname) HAVING COUNT(*) > 1
) AS ambiguous_hostnames;
DROP TABLE custom_domain_hostname_guard;

CREATE UNIQUE INDEX idx_custom_domains_hostname_lower_unique
    ON custom_domains (LOWER(hostname));
