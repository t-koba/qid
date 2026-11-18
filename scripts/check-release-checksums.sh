#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qid-release-check.XXXXXX")"

cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

cd "${TMP_DIR}"
mkdir dist download
archive="qid-x86_64-unknown-linux-musl.tar.gz"
sidecar="${archive}.sha256"
printf 'stub release archive\n' > "dist/${archive}"
bash "${ROOT_DIR}/scripts/release-checksum.sh" "dist/${archive}"
if grep -Fq 'dist/' "dist/${sidecar}"; then
  echo "checksum sidecar contains a dist/ staging path" >&2
  exit 1
fi

cp "dist/${archive}" "dist/${sidecar}" download/
cd download
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c "${sidecar}"
else
  shasum -a 256 -c "${sidecar}"
fi
