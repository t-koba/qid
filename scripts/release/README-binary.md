# qid binary release

This archive contains prebuilt `qid` executables for one target platform. It
ships no Rust toolchain and no source checkout; everything needed to validate
a configuration and start the daemon is included.

## Documentation

Full documentation for this release (`__QID_RELEASE_REF__`):

- Documentation index: https://github.com/t-koba/qid/tree/__QID_RELEASE_REF__/docs
- Configuration reference: https://github.com/t-koba/qid/blob/__QID_RELEASE_REF__/docs/configuration.md
- CLI reference: https://github.com/t-koba/qid/blob/__QID_RELEASE_REF__/docs/cli.md
- Operations guide: https://github.com/t-koba/qid/blob/__QID_RELEASE_REF__/docs/operations.md

## Included executables

`qidd` (identity daemon), `qidc` (control CLI), `qid-agent`, `qid-migrate`,
`qid-sync`, and `qid-worker`. On Windows, append `.exe` to each name.

## Quick start

From the directory containing these files:

1. Validate the bundled configuration:

   ```sh
   ./qidc --config quickstart.yaml check
   ```

2. Start the daemon:

   ```sh
   ./qidd --config quickstart.yaml
   ```

3. From another terminal, check health and discovery:

   ```sh
   curl -fsS http://127.0.0.1:8080/health
   curl -fsS http://127.0.0.1:8080/realms/dev/.well-known/openid-configuration
   ```

`quickstart.yaml` is a self-contained local profile: file-backed state in
`qid-data.json` beside the binaries, a local ES256 signing key, and one public
client bound to `127.0.0.1`. It is for local inspection only. Before any real
deployment, change the issuer and base URL, use a durable storage backend and
managed key material, and add a policy bundle; the default policy decision is
deny.

The developer quick start, the full configuration sample tree, and the build
and test workflow are in the source repository linked above.
