#!/usr/bin/env bash
set -euo pipefail

echo "=== qid sensitive artifact check ==="

fail=0

is_allowed_fixture() {
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

if rg -n --hidden \
    --glob '!.git/**' \
    --glob '!target/**' \
    --glob '!**/target/**' \
    --glob '!scripts/check-sensitive-artifacts.sh' \
    '/Users/tk|/private/var/folders|/var/folders|/private/tmp/qid[-_[:alnum:]]*' \
    .; then
    echo "ERROR: local machine path or temporary build path leaked into tracked files"
    fail=1
fi

if (( fail != 0 )); then
    exit 1
fi

echo "PASS: no unexpected sensitive/runtime artifacts found"
