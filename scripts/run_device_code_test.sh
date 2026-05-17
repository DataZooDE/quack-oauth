#!/usr/bin/env bash
# Live device_code flow against Keycloak (S-17).
#
# This is a shell-level integration test, not a sqllogictest: we need to
# drive consent in parallel with the polling loop. Run by
# scripts/run_integration_keycloak.sh AFTER Keycloak is already up and
# AFTER an access token has been acquired through ROPC for the other tests.
#
# Args (positional):
#   1. BASE_URL  -- e.g. http://localhost:8080
#   2. REALM     -- e.g. quack-test
#   3. DUCKDB    -- path to the duckdb binary with quack_oauth statically linked
#   4. CONSENT_PY -- path to scripts/keycloak_device_consent.py
#
# Exit 0 on success, non-zero on failure.

set -euo pipefail

BASE_URL="$1"
REALM="$2"
DUCKDB="$3"
CONSENT_PY="$4"

DEVICE_CLIENT_ID="quack-device"
DEVICE_AUTH_URL="$BASE_URL/realms/$REALM/protocol/openid-connect/auth/device"
TOKEN_URL="$BASE_URL/realms/$REALM/protocol/openid-connect/token"
USERNAME="alice"
PASSWORD="secret"

TMPDIR_S17=$(mktemp -d)
STDERR_LOG="$TMPDIR_S17/duckdb.stderr"
STDOUT_LOG="$TMPDIR_S17/duckdb.stdout"
trap 'rm -rf "$TMPDIR_S17"' EXIT

# Spawn the DuckDB CLI running quack_oauth_device_login() in the background.
# We capture stderr (the verification URI + user_code go there) and stdout
# (the resulting access token comes back as a SELECT result).
(
    "$DUCKDB" -unsigned -csv -noheader <<SQL >"$STDOUT_LOG" 2>"$STDERR_LOG" &
LOAD quack_oauth;
CREATE SECRET cli (
    TYPE quack_oauth,
    device_authorization_endpoint '$DEVICE_AUTH_URL',
    token_endpoint                '$TOKEN_URL',
    client_id                     '$DEVICE_CLIENT_ID'
);
SELECT length(quack_oauth_device_login('cli')) > 0 AS got_expires_at;
SQL
    echo $! > "$TMPDIR_S17/duckdb.pid"
    wait
    echo $? > "$TMPDIR_S17/duckdb.rc"
) &
WATCHER_PID=$!

# Tail the stderr file until we see the "visit X and enter code: Y" line,
# or 30 seconds elapse. Then capture the verification URI.
deadline=$(( $(date +%s) + 30 ))
NOTICE_LINE=""
while (( $(date +%s) < deadline )); do
    if [[ -s "$STDERR_LOG" ]]; then
        NOTICE_LINE=$(grep -m1 -F "[quack_oauth_device_login] visit" "$STDERR_LOG" 2>/dev/null || true)
        if [[ -n "$NOTICE_LINE" ]]; then
            break
        fi
    fi
    sleep 0.5
done

if [[ -z "$NOTICE_LINE" ]]; then
    echo "FAIL: did not see device_login notice in stderr within 30s" >&2
    echo "stderr was:" >&2
    cat "$STDERR_LOG" >&2 || true
    kill $WATCHER_PID 2>/dev/null || true
    exit 1
fi

# Parse: "[quack_oauth_device_login] visit <URI> and enter code: <CODE>"
VERIFICATION_URI=$(echo "$NOTICE_LINE" | sed -nE 's/.*visit (\S+) and enter code:.*/\1/p')
USER_CODE=$(echo "$NOTICE_LINE" | sed -nE 's/.*and enter code: (\S+)/\1/p')
echo "    device flow started: uri=$VERIFICATION_URI code=$USER_CODE"

# Complete consent. If verification_uri doesn't have the user_code in it
# (some IdPs don't fill verification_uri_complete), append it.
if [[ "$VERIFICATION_URI" != *user_code=* ]]; then
    VERIFICATION_URI="${VERIFICATION_URI}?user_code=${USER_CODE}"
fi

python3 "$CONSENT_PY" "$VERIFICATION_URI" "$USERNAME" "$PASSWORD"

# Wait for DuckDB to finish polling.
echo "    consent submitted; waiting for poll loop to complete..."
deadline=$(( $(date +%s) + 30 ))
while (( $(date +%s) < deadline )); do
    if [[ -f "$TMPDIR_S17/duckdb.rc" ]]; then
        break
    fi
    sleep 0.5
done

if [[ ! -f "$TMPDIR_S17/duckdb.rc" ]]; then
    echo "FAIL: DuckDB polling did not complete within 30s after consent" >&2
    cat "$STDERR_LOG" >&2 || true
    exit 1
fi

RC=$(cat "$TMPDIR_S17/duckdb.rc")
if [[ "$RC" != "0" ]]; then
    echo "FAIL: DuckDB exited with rc=$RC" >&2
    cat "$STDERR_LOG" >&2 || true
    cat "$STDOUT_LOG" >&2 || true
    exit 1
fi

# The SELECT returned a single boolean. With -csv -noheader and our query,
# stdout will be `true` (length(access_token) > 0).
GOT_TOKEN=$(tail -n1 "$STDOUT_LOG" | tr -d '[:space:]')
if [[ "$GOT_TOKEN" != "true" ]]; then
    echo "FAIL: device_login did not return a non-empty access token (got: '$GOT_TOKEN')" >&2
    echo "stdout was:" >&2
    cat "$STDOUT_LOG" >&2 || true
    echo "stderr was:" >&2
    cat "$STDERR_LOG" >&2 || true
    exit 1
fi

echo "    PASS: quack_oauth_device_login returned a non-empty access token"
