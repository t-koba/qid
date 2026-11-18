#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 ARCHIVE" >&2
  exit 1
fi

archive="$(basename -- "$1")"
CDPATH= cd -- "$(dirname -- "$1")"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -- "${archive}" > "${archive}.sha256"
else
  shasum -a 256 -- "${archive}" > "${archive}.sha256"
fi
