#!/usr/bin/env bash
set -euo pipefail

echo "=== qid sensitive artifact check ==="

fail=0

is_allowed_fixture() {
    case "$1" in
        ./qid-oauth/tests/data/test-sp.key | \
        ./qid-oauth/tests/data/test-untrusted-saml.key) return 0 ;;
        # Static keys used only by qid-crypto's JWE integration tests.
        ./qid-crypto/tests/fixtures/jwe_rsa_private.pem | \
        ./qid-crypto/tests/fixtures/jwe_rsa_public.pem | \
        ./qid-crypto/tests/fixtures/jwe_rsa_wrong_private.pem) return 0 ;;
        ./qid-saml/src/test-ec-key.pem) return 0 ;;
        ./qid-saml/tests/data/test-sp.key) return 0 ;;
        *) return 1 ;;
    esac
}

while IFS= read -r path; do
    if is_allowed_fixture "$path"; then
        continue
    fi
    echo "ERROR: sensitive/runtime artifact should not be tracked: $path"
    fail=1
done < <(
    find . \
        \( -path './.git' -o -path './target' -o -path './*/target' \) -prune -o \
        -type f \( \
            -name '*.pem' -o \
            -name '*.key' -o \
            -name '*.p12' -o \
            -name '*.pfx' -o \
            -name '*.db' -o \
            -name '*.db-*' -o \
            -name '*.sqlite' -o \
            -name '*.sqlite3' -o \
            -name '*.sqlite-shm' -o \
            -name '*.sqlite-wal' -o \
            -name '*.log' -o \
            -name '*.pid' -o \
            -name '*.pcapng' -o \
            -name '.env' \
        \) -print | sort
)

if leak_output="$(grep -REInI \
    --exclude-dir='.git' \
    --exclude-dir='target' \
    --exclude='check-sensitive-artifacts.sh' \
    -- '/Users/[A-Za-z_][A-Za-z0-9_.-]*/|/private/var/folders|/var/folders|/private/tmp/qid[-_[:alnum:]]*' \
    .)"; then
    printf '%s\n' "${leak_output}"
    echo "ERROR: local machine path or temporary build path leaked into tracked files"
    fail=1
else
    grep_status=$?
    if (( grep_status != 1 )); then
        echo "ERROR: local path scan failed with exit code ${grep_status}"
        fail=1
    fi
fi

if (( fail != 0 )); then
    exit 1
fi

echo "PASS: no unexpected sensitive/runtime artifacts found"
