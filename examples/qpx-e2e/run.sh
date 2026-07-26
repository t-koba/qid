#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${SCRIPT_DIR}"

CARGO_BUILD=(cargo build --manifest-path "${REPO_ROOT}/Cargo.toml" --locked)
CARGO_RUN=(cargo run --manifest-path "${REPO_ROOT}/Cargo.toml" --locked)

if [[ -n "${QID_QPX_E2E_TMP_DIR:-}" ]]; then
    E2E_TMP_DIR="${QID_QPX_E2E_TMP_DIR}"
    E2E_TMP_CREATED=0
    mkdir -p "${E2E_TMP_DIR}"
else
    E2E_TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qid-qpx-e2e.XXXXXX")"
    E2E_TMP_CREATED=1
fi
QPX_STATE_DIR="${E2E_TMP_DIR}/qpx-state"
QID_STATE_DIR="${E2E_TMP_DIR}/qid-state"
DB_FILE="${E2E_TMP_DIR}/qid-e2e.db"
QID_CONFIG="${E2E_TMP_DIR}/qid.yaml"
QIDD_LOG="${E2E_TMP_DIR}/qidd.log"
QPXD_LOG="${E2E_TMP_DIR}/qpxd.log"
QPXD_INTROSPECTION_LOG="${E2E_TMP_DIR}/qpxd-introspection.log"
UPSTREAM_LOG="${E2E_TMP_DIR}/upstream.log"
QPXD_BIN="${QPXD_BIN:-${REPO_ROOT}/../qpx/target/debug/qpxd}"
QIDD_PID=""
UPSTREAM_PID=""
QPXD_PID=""
QPXD_INTROSPECTION_PID=""

cleanup() {
    stop_pid "${QIDD_PID:-}"
    stop_pid "${UPSTREAM_PID:-}"
    stop_pid "${QPXD_PID:-}"
    stop_pid "${QPXD_INTROSPECTION_PID:-}"
    if [[ "${E2E_TMP_CREATED}" == "1" && "${QID_QPX_E2E_KEEP_TMP:-0}" != "1" ]]; then
        rm -rf "${E2E_TMP_DIR}"
    fi
}

stop_pid() {
    local pid="$1"
    if [[ -z "${pid}" ]]; then
        return 0
    fi
    if kill -0 "${pid}" 2>/dev/null; then
        kill "${pid}" 2>/dev/null || true
    fi
    wait "${pid}" 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "${QID_STATE_DIR}" "${QPX_STATE_DIR}" "${QPX_STATE_DIR}-introspection" "${DB_FILE}" "${DB_FILE}-shm" "${DB_FILE}-wal"
cp "${SCRIPT_DIR}/policy.json" "${E2E_TMP_DIR}/policy.json"
sed "s#sqlite:qid-e2e.db#sqlite:${DB_FILE}#" "${SCRIPT_DIR}/qid.yaml" >"${QID_CONFIG}"
export QPX_STATE_DIR
export QPX_DECISION_CLIENT_SECRET="qpx-smoke-secret"

info() {
    echo "[e2e] $*"
}

wait_for_http() {
    local url="$1"
    local max_attempts="${2:-120}"
    for _ in $(seq 1 "${max_attempts}"); do
        if curl -fsS "${url}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

wait_for_tcp() {
    local host="$1"
    local port="$2"
    local max_attempts="${3:-60}"
    for _ in $(seq 1 "${max_attempts}"); do
        if nc -z "${host}" "${port}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

if [[ ! -x "${QPXD_BIN}" ]]; then
    info "qpxd binary not found or not executable at ${QPXD_BIN}"
    info "build qpxd or set QPXD_BIN to a compatible binary"
    exit 1
fi

info "validating qpx configurations"
"${QPXD_BIN}" check -c "${SCRIPT_DIR}/qpx.yaml" >/dev/null
"${QPXD_BIN}" check -c "${SCRIPT_DIR}/qpx-introspection.yaml" >/dev/null

info "building qidd and qidc"
"${CARGO_BUILD[@]}" --quiet --bin qidd --bin qidc

info "starting qidd"
"${CARGO_RUN[@]}" --quiet --bin qidd -- -c "${QID_CONFIG}" >"${QIDD_LOG}" 2>&1 &
QIDD_PID=$!

if ! wait_for_http "http://127.0.0.1:8443/health"; then
    info "qidd failed to start"
    cat "${QIDD_LOG}"
    exit 1
fi
info "qidd ready"

info "bootstrapping test subject"
USER_OUT=$("${CARGO_RUN[@]}" --quiet --bin qidc -- -c "${QID_CONFIG}" user create \
    --realm e2e \
    --email alice@example.com \
    --password hunter2 \
    --display-name Alice)
USER_ID=$(echo "${USER_OUT}" | awk '{print $3}')
info "created user ${USER_ID}"

SESSION_OUT=$("${CARGO_RUN[@]}" --quiet --bin qidc -- -c "${QID_CONFIG}" session create \
    --realm e2e \
    --user-id "${USER_ID}")
SESSION_ID=$(echo "${SESSION_OUT}" | awk '{print $3}')
info "created session ${SESSION_ID}"

info "smoke testing qidd endpoints"
curl -fsS http://127.0.0.1:8443/health | grep -q '^ok$'
curl -fsS http://127.0.0.1:8443/realms/e2e/.well-known/openid-configuration | grep -q 'issuer'
curl -fsS http://127.0.0.1:8443/jwks | grep -q '"kty":"EC"'

info "requesting a client credentials token"
ACCESS_TOKEN=$(curl -fsS -X POST http://127.0.0.1:8443/oauth2/token \
    -u 'e2e-egress:qpx-smoke-secret' \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data 'grant_type=client_credentials&scope=api&resource=urn:qid:pep:qpx:edge/e2e-egress' \
    | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
if [[ -z "${ACCESS_TOKEN}" ]]; then
    info "token endpoint did not return an access token"
    exit 1
fi
info "access token length: ${#ACCESS_TOKEN}"

info "fetching a qpx signed assertion"
ASSERTION=$(curl -fsS "http://127.0.0.1:8443/pep/e2e/assertion?edge=service:e2e-egress&session=${SESSION_ID}" | sed -n 's/.*"assertion":"\([^"]*\)".*/\1/p')
if [[ -z "${ASSERTION}" ]]; then
    info "assertion endpoint did not return a token"
    exit 1
fi
info "assertion token length: ${#ASSERTION}"

info "evaluating the standard AuthZEN endpoint"
AUTHZEN_RESPONSE=$(curl -sS -X POST http://127.0.0.1:8443/access/v1/evaluation \
    -H "authorization: Bearer ${ACCESS_TOKEN}" \
    -H 'content-type: application/json' \
    --data '{"subject":{"type":"identity","id":"e2e-egress","properties":{}},"resource":{"type":"forward","id":"http://127.0.0.1:18090/","properties":{"host":"127.0.0.1"}},"action":{"name":"GET","properties":{}},"context":{}}')
if ! grep -q '"decision":true' <<<"${AUTHZEN_RESPONSE}"; then
    info "AuthZEN evaluation failed: ${AUTHZEN_RESPONSE}"
    exit 1
fi

PUBLIC_KEY_FILE="${QID_STATE_DIR}/signing-key-e2e-pep-assertion-ES256.pub.pem"
if [[ ! -f "${PUBLIC_KEY_FILE}" ]]; then
    info "PEP assertion public key was not generated"
    exit 1
fi
info "starting local upstream server"
python3 -m http.server 18090 >"${UPSTREAM_LOG}" 2>&1 &
UPSTREAM_PID=$!

info "starting qpxd (${QPXD_BIN})"
"${QPXD_BIN}" run -c "${SCRIPT_DIR}/qpx.yaml" >"${QPXD_LOG}" 2>&1 &
QPXD_PID=$!

if ! wait_for_tcp 127.0.0.1 18088 30; then
    info "qpxd failed to start"
    cat "${QPXD_LOG}"
    exit 1
fi
info "qpxd ready"

info "verifying an invalid JWT is denied by qpx"
if curl -fsS -x http://127.0.0.1:18088 \
    -H 'Authorization: Bearer invalid-jwt' \
    http://127.0.0.1:18090/ >/dev/null 2>&1; then
    info "qpx accepted an invalid JWT"
    exit 1
fi

info "sending authenticated request through qpx"
curl -fsS -x http://127.0.0.1:18088 \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    http://127.0.0.1:18090/ >/dev/null
info "qpx forwarded authenticated request successfully"

info "starting qpxd with RFC 7662 introspection resource server configuration"
"${QPXD_BIN}" run -c "${SCRIPT_DIR}/qpx-introspection.yaml" >"${QPXD_INTROSPECTION_LOG}" 2>&1 &
QPXD_INTROSPECTION_PID=$!
if ! wait_for_tcp 127.0.0.1 18089 30; then
    info "qpxd introspection instance failed to start"
    cat "${QPXD_INTROSPECTION_LOG}"
    exit 1
fi
info "verifying an invalid token is denied by qpx introspection"
if curl -fsS -x http://127.0.0.1:18089 \
    -H 'Authorization: Bearer invalid-introspection-token' \
    http://127.0.0.1:18090/ >/dev/null 2>&1; then
    info "qpx introspection accepted an invalid token"
    exit 1
fi
curl -fsS -x http://127.0.0.1:18089 \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    http://127.0.0.1:18090/ >/dev/null
info "qpx RFC 7662 introspection request succeeded"

info "all smoke tests passed"
