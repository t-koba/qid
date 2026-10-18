#!/usr/bin/env bash
set -euo pipefail

# Exercise the coverage gate with fake reports and no `bc` in PATH.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/qid-test-coverage.XXXXXX")"
trap 'rm -rf "${TMP_ROOT}"' EXIT

FIXTURES="${TMP_ROOT}/fixtures"
FAKE_BIN="${TMP_ROOT}/fakebin"
CLEAN_BIN="${TMP_ROOT}/cleanbin"
mkdir -p "${FIXTURES}" "${FAKE_BIN}" "${CLEAN_BIN}"
printf '{"data":[{"totals":{"lines":{"count":100,"covered":40}}}]}' >"${FIXTURES}/below.json"
printf '{"data":[{"totals":{"lines":{"count":100,"covered":50}}}]}' >"${FIXTURES}/exact.json"
printf '{"data":[{"totals":{"lines":{"count":10,"covered":20}}}]}' >"${FIXTURES}/invalid.json"

cat >"${FAKE_BIN}/cargo" <<'EOF_FAKE_CARGO'
#!/bin/sh
set -eu
[ "${1:-}" = "llvm-cov" ]
shift
output=""
while [ "$#" -gt 0 ]; do
    if [ "$1" = "--output-path" ]; then
        shift
        output="$1"
        break
    fi
    shift
done
[ -n "$output" ]
cp "$COVERAGE_FIXTURE" "$output"
EOF_FAKE_CARGO
chmod +x "${FAKE_BIN}/cargo"

# Satisfy coverage.sh's explicit installation check; the default command is
# the fake `cargo llvm-cov` wrapper above.
cat >"${FAKE_BIN}/cargo-llvm-cov" <<'EOF_FAKE_COV'
#!/bin/sh
exit 0
EOF_FAKE_COV
chmod +x "${FAKE_BIN}/cargo-llvm-cov"

# Provide only utilities used by coverage.sh and the fake command. No bc or
# system directories are present in this PATH.
for tool in cp mktemp rm python3; do
    ln -s "$(command -v "$tool")" "${CLEAN_BIN}/${tool}"
done
SANITIZED_PATH="${CLEAN_BIN}:${FAKE_BIN}"
if PATH="${SANITIZED_PATH}" command -v bc >/dev/null 2>&1; then
    echo "FAIL: sanitized PATH unexpectedly contains bc"
    exit 1
fi

run_gate() {
    local fixture="$1" threshold="$2"
    COVERAGE_FIXTURE="${FIXTURES}/${fixture}.json" \
        CARGO_LLVM_COV="cargo llvm-cov" \
        MIN_LINE_COVERAGE="${threshold}" \
        PATH="${SANITIZED_PATH}" \
        /bin/bash "${REPO_ROOT}/scripts/coverage.sh" 2>&1
}

assert_fails() {
    local fixture="$1" threshold="$2" description="$3" output
    if output="$(run_gate "${fixture}" "${threshold}")"; then
        echo "FAIL: ${description} unexpectedly passed"
        echo "${output}"
        exit 1
    fi
    if [[ "${output}" != *FAIL* || "${output}" == *PASS* ]]; then
        echo "FAIL: ${description} did not fail clearly"
        echo "${output}"
        exit 1
    fi
    echo "ok: ${description} fails without PASS"
}

assert_passes() {
    local fixture="$1" threshold="$2" description="$3" output
    if ! output="$(run_gate "${fixture}" "${threshold}")"; then
        echo "FAIL: ${description} unexpectedly failed"
        echo "${output}"
        exit 1
    fi
    if [[ "${output}" != *PASS* ]]; then
        echo "FAIL: ${description} did not report PASS"
        echo "${output}"
        exit 1
    fi
    echo "ok: ${description} passes"
}

assert_fails below 50.0 "below-threshold coverage"
assert_passes exact 50.0 "exact-threshold coverage without bc"
assert_fails exact not-a-number "invalid threshold"
assert_fails invalid 50.0 "invalid report"
echo "PASS: coverage gate regression (4/4 cases)"
