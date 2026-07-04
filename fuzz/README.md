# qid fuzz targets

Run all fuzz targets:

```shell
cargo fuzz run jwt -- -max_total=60000
cargo fuzz run scim_filter -- -max_total=60000
```

List available targets:

```shell
cargo fuzz list
```

## Requirements

Install `cargo-fuzz`:

```shell
cargo install cargo-fuzz
```

## Corpus

Corpus directories are stored under `fuzz/corpus/<target>/` and are
automatically seeded on first run.
