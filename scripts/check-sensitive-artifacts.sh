#!/usr/bin/env bash
set -euo pipefail

echo "=== qid sensitive artifact check ==="

fail=0

is_allowed_rustls_test_ca_fixture() {
    case "$1" in
        ./vendor/test-ca/ecdsa-p256/* | \
        ./vendor/test-ca/ecdsa-p384/* | \
        ./vendor/test-ca/ecdsa-p521/* | \
        ./vendor/test-ca/eddsa/* | \
        ./vendor/test-ca/rsa-2048/* | \
        ./vendor/test-ca/rsa-3072/* | \
        ./vendor/test-ca/rsa-4096/*) ;;
        *) return 1 ;;
    esac

    case "${1##*/}" in
        ca.key | client.key | end.key | inter.key | \
        client.expired.crl.pem | client.revoked.crl.pem | client.spki.pem | \
        end.expired.crl.pem | end.revoked.crl.pem | end.spki.pem | \
        inter.expired.crl.pem | inter.revoked.crl.pem) return 0 ;;
        *) return 1 ;;
    esac
}

is_allowed_fixture() {
    if is_allowed_rustls_test_ca_fixture "$1"; then
        return 0
    fi

    case "$1" in
        ./qid-oauth/tests/data/test-sp.key) return 0 ;;
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
    -- '/Users/tk|/private/var/folders|/var/folders|/private/tmp/qid[-_[:alnum:]]*' \
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
