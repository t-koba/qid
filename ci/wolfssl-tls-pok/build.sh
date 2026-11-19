#!/usr/bin/env bash
# Build the test-only wolfSSL TLS-POK peer outside the workspace.
set -euo pipefail

readonly WOLFSSL_TAG="v5.9.4-stable"
readonly WOLFSSL_URL="https://github.com/wolfSSL/wolfssl.git"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runner_temp="${RUNNER_TEMP:-$(mktemp -d)}"
mkdir -p "$runner_temp"
work="$(mktemp -d "$runner_temp/qid-wolfssl-tls-pok.XXXXXX")"
source_dir="$work/wolfssl"
prefix="$work/prefix"
binary="$work/server"

# Only the build tree is disposable; the compiled helper stays for the test step.
trap 'rm -rf "$source_dir" "$prefix"' EXIT

git clone --depth 1 --branch "$WOLFSSL_TAG" "$WOLFSSL_URL" "$source_dir"
cd "$source_dir"
# Keep the parser rejection site visible in CI logs for protocol diagnosis.
sed -n '26410,26435p' src/internal.c >&2
./autogen.sh
./configure \
  --prefix="$prefix" \
  --enable-tls13 \
  --enable-psk \
  --enable-cert-with-extern-psk \
  --enable-rpk \
  --enable-ecc \
  --enable-supportedcurves \
  --enable-opensslextra \
  --enable-opensslall \
  --disable-shared \
  --disable-examples
make -j"$(nproc)"
make install

cc -std=c11 -O2 -Wall -Wextra -Werror \
  -I"$prefix/include" \
  "$repo_root/ci/wolfssl-tls-pok/server.c" \
  -o "$binary" -L"$prefix/lib" -lwolfssl -lm

cc -std=c11 -O2 -Wall -Wextra -Werror -Wno-unused-function \
  -DQID_WOLFSSL_HELPER_NO_MAIN -I"$prefix/include" \
  "$repo_root/ci/wolfssl-tls-pok/server.c" \
  "$repo_root/ci/wolfssl-tls-pok/test_decode_hex.c" \
  -o "$work/decode_hex_test" -L"$prefix/lib" -lwolfssl -lm
"$work/decode_hex_test"

line="QID_WOLFSSL_SERVER_BIN=$binary"
if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf '%s\n' "$line" >> "$GITHUB_ENV"
fi
printf '%s\n' "$line"
