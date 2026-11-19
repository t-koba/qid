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

# wolfSSL 5.9.4 derives PSK binder keys with RFC 8446's "ext binder" label.
# TLS-POK imports its PSK under RFC 9258, which mandates "imp binder" (the
# same length). Adapt this CI-only peer so it verifies qid's imported-PSK
# binder. The helper receives the raw EPSK that qid imports, not an already-
# imported key; this checks binder and transcript handling with a shared key.
binder_file="$source_dir/src/tls13.c"
python3 - "$binder_file" <<'PYEOF'
import sys
from pathlib import Path

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
old = 'static const byte binderKeyLabel[BINDER_KEY_LABEL_SZ + 1] = "ext binder";'
new = 'static const byte binderKeyLabel[BINDER_KEY_LABEL_SZ + 1] = "imp binder";'
if source.count(old) != 1:
    raise SystemExit("pinned wolfSSL binder label not found exactly once")
path.write_text(source.replace(old, new, 1), encoding="utf-8")
PYEOF

# The Rust test prints this window beside its failure, where CI logs are not elided.
source_window="$work/source_window.txt"
python3 - > "$source_window" <<'PYEOF'
from pathlib import Path

files = ("src/tls.c", "src/tls13.c", "src/internal.c")


def print_window(path, needle, before, after):
    if not path.is_file():
        return
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    for index, line in enumerate(lines):
        if needle not in line:
            continue
        print(f"# {path}:{index + 1}")
        start = max(0, index - before)
        end = min(len(lines), index + after)
        for number in range(start, end):
            print(f"{number + 1}: {lines[number]}")
        return


for name in files:
    print_window(Path(name), "Supported Versions extension received", 30, 30)
for name in files:
    print_window(Path(name), "int DoTls13ClientHello(", 5, 320)
for name in files:
    print_window(Path(name), "TLSX_GetMinSize_Client(", 0, 170)
for name in files:
    print_window(Path(name), "Derive Binder Key", 70, 30)
for name in files:
    print_window(Path(name), "static int DoPreSharedKeys(", 0, 220)
for name in files:
    print_window(Path(name), "\"imp binder\"", 8, 8)
for name in files:
    print_window(Path(name), "\"ext binder\"", 8, 8)
for name in files:
    print_window(Path(name), "TLSX_Parse(WOLFSSL", 0, 600)
for name in files:
    print_window(Path(name), "TLSX_CertWithExternPsk_Parse", 20, 70)
for name in files:
    print_window(Path(name), "static int TLSX_PreSharedKey_Parse", 5, 160)
for name in files:
    print_window(Path(name), "static int TLSX_ClientCertType_Parse", 5, 100)
PYEOF
source_window_assignment="QID_WOLFSSL_SOURCE_WINDOW=$source_window"
if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf '%s\n' "$source_window_assignment" >> "$GITHUB_ENV"
fi
printf '%s\n' "$source_window_assignment"
./autogen.sh
./configure \
  --prefix="$prefix" \
  --enable-debug \
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
