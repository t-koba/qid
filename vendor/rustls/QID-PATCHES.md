# qid rustls Fork

## Provenance

- Upstream project: `https://github.com/rustls/rustls`
- Upstream crate and tag: `rustls` 0.23.46, `v/0.23.46`
- Upstream tag commit: `f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb` (also the published crate's `.cargo_vcs_info.json` revision)
- Upstream licenses: Apache-2.0, MIT, and ISC
- qid integration: the workspace `[patch.crates-io]` entry replaces every rustls 0.23 dependency with this source tree

The upstream base source and test assets were copied from the exact GitHub tag before applying the qid changes. The manifest uses the published crate's standalone dependency declarations. Do not replace this directory with an unversioned branch snapshot.

## qid Patch Boundary

The sole qid protocol extension is RFC 6961 `status_request_v2` and TLS 1.2
`ocsp_multi`: ordered response lists, legacy RFC 6066 fallback, extension-conflict
rejection, and an explicit client verifier capability and validation callback.
Servers opt in through `with_single_cert_with_ocsp_multi` (or a certificate
resolver's `CertifiedKey::ocsp_multi`); clients opt in through
`ServerCertVerifier::supports_ocsp_multi_stapling` and validate through
`verify_server_cert_with_ocsp_multi`. Ordinary upstream configurations do not
negotiate multi-OCSP. TLS 1.3 retains ordinary RFC 6066 single-response stapling.

The unused imported-external-PSK/TLS-POK patch has been removed. Upstream session
resumption, its PSK binders, early data, ECH, QUIC, and certificate authentication
are unchanged by that removal.

## Upstream Security Baseline

The 0.23.46 update used the `xtask vendor-sync` three-way merge with the published
0.23.45 crate as the base. Source and test assets were checked against the exact
0.23.46 revision above. The fork retains all upstream changes, including:

- Reject ECH before enabling application traffic (`4de14a50`), enforce the
  HelloRetryRequest ECH decision (`ca4a9c21`), and delay caching the key-exchange
  hint until handshake confirmation (`f04804fa`).
- Record-confidentiality-limit checks and timely TLS 1.3 key updates for buffered,
  fragmented, and unbuffered writes (`93636305`, `ab3ca337`, `74343e70`, `2b82b814`).
- Protected ChangeCipherSpec rejection (`fce9c85c`), strict compressed-certificate
  decoding (`1aa987af`, `b10cdb0d`), session Debug secret redaction (`dcdb9464`,
  `6d0ba089`), and PSK-index-zero enforcement for early data (`5ed42b32`).

The inherited baseline also includes the 0.23.45 fix for handshake messages
spanning a key-change record boundary (RUSTSEC-2026-0285), RFC 9149 ticket request
extensions, RFC 9846 second-ClientHello PSK rules, and non-empty OCSP enforcement.
The multi-OCSP patch preserves the latter for single RFC 6066 responses while
allowing omitted entries in RFC 6961 response lists.

Public RustSec records identify RUSTSEC-2026-0346 through RUSTSEC-2026-0349 as
patched in `>=0.23.46`. The retained offline advisory database predates this
release and is not current audit evidence; no advisory exemptions were added.

## Local Record-Limit Correction

A buffered application-data write rejected by the last-fragment record-limit preflight returns zero accepted bytes, rather than reporting the unsent input as consumed. TLS 1.2 still queues `close_notify` without sending any application-data fragment from that write; TLS 1.3 key-update handling is unchanged. The unit regression exercises `std::io::Write` with a two-record write crossing a small TLS 1.2 limit and checks both the byte count and the alert-only output.

## Update Procedure

1. Verify the new upstream tag and licenses.
2. Replace the source from that exact tag without carrying generated `target` output. Use `cargo run -p xtask --locked -- vendor-sync --to <version> --dry-run` first to preview the three-way merge; it leaves the vendor tree untouched when conflicts remain.
3. Reapply the multi-OCSP extension and local record-limit correction as reviewable changes; resolve upstream protocol changes deliberately. When the dry run reports no conflicts, re-run without `--dry-run` to write the tree.
4. Format in this directory using the verified upstream style: `cargo fmt --all -- --config chain_width=40,style_edition=2024`.
5. Run `cargo test --manifest-path vendor/rustls/Cargo.toml --lib` from the workspace root, including the multi-OCSP codec and server-flight regressions.
6. Run qid's TLS handshake tests (`qidd`'s `tls::tests`) and the `qid-network` tests with `radius-tls,quic` enabled, then the workspace test suites with warnings denied.
7. Run `cargo deny check` and `cargo audit`; review every new transitive dependency and license.
8. Record whether the update still uses the aws-lc-rs provider's default key-exchange list with hybrid `X25519MLKEM768` preferred. An explicit `kx_groups` list or provider switch that drops it is a deliberate, reviewed change; qidd does not claim post-quantum signatures or authentication.

Do not silently drop multi-OCSP, substitute another TLS implementation, or add a compatibility fallback during an update.
