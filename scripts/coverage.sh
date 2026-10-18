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
#   python3

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

if ! command -v python3 &>/dev/null; then
    echo "python3 not found. Install Python 3 to run the coverage gate."
    exit 1
fi

# Generate JSON coverage report.
read -r -a CARGO_LLVM_COV_CMD <<<"${CARGO_LLVM_COV}"
"${CARGO_LLVM_COV_CMD[@]}" --workspace --json --summary-only --output-path "${COVERAGE_JSON_FILE}" >"${COVERAGE_LOG_FILE}" 2>&1 || {
    echo "FAIL: cargo-llvm-cov failed"
    cat "${COVERAGE_LOG_FILE}"
    exit 1
}

# Validate the threshold and the JSON report, then compare the unrounded
# coverage ratio against the threshold. The displayed percentage is rounded
# to two decimals; the pass/fail decision uses the unrounded ratio.
# Python exit codes: 0 meets threshold, 1 below threshold, 2 malformed input/config.
if LINE_PCT=$(python3 - "${COVERAGE_JSON_FILE}" "${MIN_LINE_COVERAGE}" <<'PY'
import json
import sys
from decimal import Decimal, InvalidOperation

json_path = sys.argv[1]
threshold_raw = sys.argv[2]

try:
    threshold = Decimal(threshold_raw.strip())
except (InvalidOperation, ValueError, AttributeError):
    print(f"FAIL: invalid MIN_LINE_COVERAGE {threshold_raw!r}: expected a finite decimal in [0, 100]", file=sys.stderr)
    sys.exit(2)
if not threshold.is_finite():
    print(f"FAIL: invalid MIN_LINE_COVERAGE {threshold_raw!r}: expected a finite decimal in [0, 100]", file=sys.stderr)
    sys.exit(2)
if threshold < 0 or threshold > 100:
    print(f"FAIL: invalid MIN_LINE_COVERAGE {threshold_raw!r}: expected a value in [0, 100]", file=sys.stderr)
    sys.exit(2)

try:
    with open(json_path, encoding="utf-8") as handle:
        data = json.load(handle)
except (OSError, json.JSONDecodeError) as exc:
    print(f"FAIL: malformed coverage report: {exc}", file=sys.stderr)
    sys.exit(2)

if not isinstance(data, dict) or not isinstance(data.get("data"), list):
    print("FAIL: malformed coverage report: expected an object with a 'data' array", file=sys.stderr)
    sys.exit(2)

total_lines = 0
covered_lines = 0
for index, entry in enumerate(data["data"]):
    if not isinstance(entry, dict) or not isinstance(entry.get("totals"), dict):
        print(f"FAIL: malformed coverage report: entry {index} is missing 'totals'", file=sys.stderr)
        sys.exit(2)
    lines = entry["totals"].get("lines")
    if not isinstance(lines, dict):
        print(f"FAIL: malformed coverage report: entry {index} is missing 'totals.lines'", file=sys.stderr)
        sys.exit(2)
    count = lines.get("count")
    covered = lines.get("covered")
    for name, value in (("count", count), ("covered", covered)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            print(f"FAIL: malformed coverage report: entry {index} has invalid lines.{name} {value!r}: expected a nonnegative integer", file=sys.stderr)
            sys.exit(2)
    if covered > count:
        print(f"FAIL: malformed coverage report: entry {index} has covered {covered} > count {count}", file=sys.stderr)
        sys.exit(2)
    total_lines += count
    covered_lines += covered

if total_lines == 0:
    ratio = Decimal(0)
else:
    ratio = Decimal(covered_lines) / Decimal(total_lines) * Decimal(100)

print(f"{float(ratio):.2f}")

if total_lines == 0:
    meets = Decimal(0) >= threshold
else:
    meets = Decimal(covered_lines) * Decimal(100) >= threshold * Decimal(total_lines)
sys.exit(0 if meets else 1)
PY
); then
    echo "Line coverage: ${LINE_PCT}%"
    echo "PASS: coverage ${LINE_PCT}% meets threshold ${MIN_LINE_COVERAGE}%"
else
    PY_STATUS=$?
    if [ "${PY_STATUS}" -eq 1 ]; then
        echo "Line coverage: ${LINE_PCT}%"
        echo "FAIL: coverage ${LINE_PCT}% is below threshold ${MIN_LINE_COVERAGE}%"
        exit 1
    else
        echo "FAIL: invalid coverage report or threshold (see error above)"
        exit 1
    fi
fi
