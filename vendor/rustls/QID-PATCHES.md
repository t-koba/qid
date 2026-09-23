# qid rustls Fork

## Provenance

- Upstream project: `https://github.com/rustls/rustls`
- Upstream crate and tag: `rustls` 0.23.45, `v/0.23.45`
- Upstream licenses: Apache-2.0, MIT, and ISC
- qid integration: the workspace `[patch.crates-io]` entry replaces every rustls 0.23 dependency with this source tree

The upstream base source and test assets were copied from the exact GitHub tag before applying the qid patches. Do not replace this directory with an unversioned branch snapshot.

## qid Patch Boundary

The fork adds two opt-in protocol surfaces:

1. RFC 9258 imported external PSKs and RFC 8773 certificate authentication with an external PSK, used by RFC 9966 TLS-POK. This includes the `imp binder`, mandatory `psk_dhe_ke`, TLS 1.3 and Raw Public Key restrictions, constant-time identity/key matching, and fail-closed rejection of incompatible resumption, 0-RTT, ECH, and QUIC modes.
2. RFC 6961 `status_request_v2` and TLS 1.2 `ocsp_multi`, including ordered response lists, legacy RFC 6066 fallback, extension-conflict rejection, and an explicit client verifier capability and validation callback.

Neither surface is enabled by an ordinary upstream rustls configuration. New behavior requires explicit use of the imported-PSK builder/resolver or the multi-OCSP builder/verifier methods.

## Update Notes (0.23.41 -> 0.23.45)

- Includes upstream fix for GHSA-2mjx-qc3c-rqvc (RUSTSEC-2026-0285): TLS 1.3 handshake messages are now rejected when they span a key-change record boundary.
- Carries upstream RFC 9149 ticket request extensions, RFC 9846 second-ClientHello PSK rules, `supports_version` protocol check, QUIC version suitability, OCSP non-empty enforcement (`PayloadU24<NonEmpty>`), ML-DSA support, and key-log file permission hardening.
- qid protocol patches were re-applied on the 0.23.45 base: imported-PSK flows now use the `previous_hello` retry tracker, ticket counts honor both the imported-PSK policy (`send_tickets = 0`) and the client ticket request hint, and `CertificateStatus` keeps the `Ocsp`/`OcspMulti` enum with `NonEmpty` responses.

## Update Procedure

1. Verify the new upstream tag and licenses.
2. Replace the source from that exact tag without carrying generated `target` output. Use `cargo run -p xtask --locked -- vendor-sync --to <version> --dry-run` first to preview the three-way merge; it leaves the vendor tree untouched when conflicts remain.
3. Reapply the qid changes as a reviewable patch; resolve upstream protocol changes deliberately. When the dry run reports no conflicts, re-run without `--dry-run` to write the tree.
4. Run `cargo fmt --all` in this directory.
5. Run `cargo test --manifest-path vendor/rustls/Cargo.toml --lib`.
6. Run qid's RFC 9966, RFC 6961, RFC 5280, and workspace test suites with warnings denied.
7. Run `cargo deny check` and `cargo audit`; review every new transitive dependency and license.

Do not silently drop a protocol patch, substitute another TLS implementation, or add a compatibility fallback during an update.
