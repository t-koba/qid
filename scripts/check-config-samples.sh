#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qid-config-check.XXXXXX")"
TARGET_DIR="${QID_CONFIG_CHECK_TARGET_DIR:-${TMP_DIR}/target}"
QIDC_BUILD_BIN="${TARGET_DIR}/debug/qidc"
QIDC="${TMP_DIR}/qidc"
REPORT_FILE="${TMP_DIR}/report.json"

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

samples=("${ROOT_DIR}/config/qid.example.yaml")
while IFS= read -r sample; do
  samples+=("${sample}")
done < <(find "${ROOT_DIR}/config/usecases" -type f -name '*.yaml' | sort)

for sample in "${samples[@]}"; do
  rel="${sample#${ROOT_DIR}/}"
  echo "checking ${rel}"
  (
    cd "${TMP_DIR}"
    "${QIDC}" --config "${sample}" check >"${REPORT_FILE}"
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
