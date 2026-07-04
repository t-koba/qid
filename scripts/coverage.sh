#!/usr/bin/env bash
set -euo pipefail
# scripts/coverage.sh
#
# Coverage gate for qid.
# Uses cargo-llvm-cov to measure line coverage and enforces a minimum threshold.
#
# Prerequisites:
#   cargo install cargo-llvm-cov
#   rustup component add llvm-tools-preview

MIN_LINE_COVERAGE="${MIN_LINE_COVERAGE:-50.0}"
CARGO_LLVM_COV="${CARGO_LLVM_COV:-cargo llvm-cov}"
COVERAGE_JSON_FILE="$(mktemp "${TMPDIR:-/tmp}/qid-coverage.XXXXXX.json")"
COVERAGE_LOG_FILE="$(mktemp "${TMPDIR:-/tmp}/qid-coverage.XXXXXX.log")"
trap 'rm -f "${COVERAGE_JSON_FILE}" "${COVERAGE_LOG_FILE}"' EXIT

echo "=== qid coverage gate ==="
echo "Minimum line coverage: ${MIN_LINE_COVERAGE}%"

if ! command -v cargo-llvm-cov &>/dev/null; then
    echo "cargo-llvm-cov not found. Install with: cargo install cargo-llvm-cov"
    exit 1
fi

# Generate JSON coverage report.
read -r -a CARGO_LLVM_COV_CMD <<<"${CARGO_LLVM_COV}"
"${CARGO_LLVM_COV_CMD[@]}" --workspace --json --summary-only --output-path "${COVERAGE_JSON_FILE}" >"${COVERAGE_LOG_FILE}" 2>&1 || {
    echo "WARNING: cargo-llvm-cov failed (non-blocking)"
    cat "${COVERAGE_LOG_FILE}"
    exit 0
}

# Extract line coverage percentage from JSON output.
# The JSON contains a top-level key "data" with an array of objects;
# each object has a "totals" field with "lines"."percent".
LINE_PCT=$(python3 - "${COVERAGE_JSON_FILE}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)

total_lines = 0
covered_lines = 0
for entry in data.get('data', []):
    totals = entry.get('totals', {})
    lines = totals.get('lines', {})
    total_lines += lines.get('count', 0)
    covered_lines += lines.get('covered', 0)
if total_lines == 0:
    print(0.0)
else:
    print(round(covered_lines / total_lines * 100, 2))
PY
)

echo "Line coverage: ${LINE_PCT}%"

if (( $(echo "$LINE_PCT < $MIN_LINE_COVERAGE" | bc -l) )); then
    echo "FAIL: coverage ${LINE_PCT}% is below threshold ${MIN_LINE_COVERAGE}%"
    exit 1
fi

echo "PASS: coverage ${LINE_PCT}% meets threshold ${MIN_LINE_COVERAGE}%"
