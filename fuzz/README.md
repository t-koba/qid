# qid fuzz targets

Run all fuzz targets, each for a bounded 60 seconds:

```shell
cargo fuzz run jwt -- -max_total_time=60
cargo fuzz run scim_filter -- -max_total_time=60
cargo fuzz run saml_xml -- -max_total_time=60
cargo fuzz run policy -- -max_total_time=60
cargo fuzz run radius -- -max_total_time=60
cargo fuzz run tacacs -- -max_total_time=60
cargo fuzz run eap -- -max_total_time=60
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
