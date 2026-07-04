# qid sample data

Most use-case samples write their runtime JSON store below `runtime/`.
Those files are intentionally ignored because `qidd` seeds configured realms,
clients, and policy bundles into the store on startup.

`01-getting-started/local-dev.yaml` points at the checked-in
`01-getting-started/local-dev.json` seed so a new user can list and inspect a
real password-backed account without creating one first. The sample user is
`alice@example.test` with password `change-me`.
