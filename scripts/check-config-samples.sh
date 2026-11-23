#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qid-config-check.XXXXXX")"
TARGET_DIR="${QID_CONFIG_CHECK_TARGET_DIR:-${ROOT_DIR}/target}"
QIDC_BUILD_BIN="${TARGET_DIR}/debug/qidc"
QIDC="${TMP_DIR}/qidc"
REPORT_FILE="${TMP_DIR}/report.json"
PLACEHOLDER_URL="offline-sample://valid"

cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

link_or_copy() {
  local src="$1"
  local dst="$2"
  ln "$src" "$dst" 2>/dev/null || cp "$src" "$dst"
}

cargo build -p qidc --locked --target-dir "${TARGET_DIR}"

if [ ! -x "${QIDC_BUILD_BIN}" ]; then
  echo "missing built qidc binary: ${QIDC_BUILD_BIN}" >&2
  exit 1
fi
link_or_copy "${QIDC_BUILD_BIN}" "${QIDC}"

if [ ! -x "${QIDC}" ]; then
  echo "missing runnable qidc binary: ${QIDC}" >&2
  exit 1
fi

samples=("${ROOT_DIR}/config/qid.example.yaml" "${ROOT_DIR}/scripts/release/quickstart.yaml")
while IFS= read -r sample; do
  samples+=("${sample}")
done < <(find "${ROOT_DIR}/config/usecases" -type f -name '*.yaml' | sort)

for sample in "${samples[@]}"; do
  rel="${sample#${ROOT_DIR}/}"
  echo "checking ${rel}"
  # Supply every url_env explicitly so checks never depend on (or expose) real
  # environment values and the placeholder file backend is used offline.
  env_overrides=()
  while IFS= read -r name; do
    [[ -n "${name}" ]] || continue
    name="${name%\"}"
    name="${name#\"}"
    name="${name%'}"
    name="${name#'}"
    if [[ ! "${name}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      echo "unsafe url_env name in ${rel}" >&2
      exit 1
    fi
    env_overrides+=("${name}=${PLACEHOLDER_URL}")
  done < <(sed -n 's/^[[:space:]]*url_env:[[:space:]]*\([^[:space:]#][^[:space:]#]*\).*/\1/p' "${sample}" | sort -u)
  (
    cd "${TMP_DIR}"
    env "${env_overrides[@]}" "${QIDC}" --config "${sample}" check >"${REPORT_FILE}"
  )
  python3 - "${rel}" "${REPORT_FILE}" <<'PY'
import json
import sys

rel = sys.argv[1]
path = sys.argv[2]
with open(path, "r", encoding="utf-8") as handle:
    report = json.load(handle)

status = report.get("status")
errors = int(report.get("summary", {}).get("errors", 0))
if status == "error" or errors > 0:
    print(f"{rel}: qidc check reported status={status!r} errors={errors}", file=sys.stderr)
    sys.exit(1)
PY
done

echo "checked ${#samples[@]} config sample(s)"
