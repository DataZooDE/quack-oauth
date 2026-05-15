#!/usr/bin/env bash
# quack-oauth quickstart demo (S-16).
#
# Brings up the Keycloak compose used by the integration tests, then drives
# the DuckDB shell through:
#
#   1. CREATE SECRET for the resource server (provider preset: keycloak)
#   2. Acquire a real ROPC access token via curl
#   3. quack_oauth_check_token() to validate it
#   4. Create + populate a SQL policy table inside the database
#   5. quack_oauth_check_authorization() with allow + deny outcomes
#   6. SELECT * FROM quack_oauth_audit_log() -- inspect what happened
#   7. SELECT * FROM quack_oauth_diagnose() -- live extension health
#
# Tears the container down on exit. Requires `docker compose` + port 8080.

set -euo pipefail

PROJ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INTEGRATION_DIR="$PROJ_DIR/test/integration/keycloak"
DUCKDB="$PROJ_DIR/build/release/duckdb"

REALM="quack-test"
CLIENT_ID="quack-client"
CLIENT_SECRET="quack-client-test-secret"
USERNAME="alice"
PASSWORD="secret"
BASE_URL="http://localhost:8080"

if [[ ! -x "$DUCKDB" ]]; then
    echo "FAIL: $DUCKDB not found -- run 'make' first" >&2
    exit 2
fi

# Pretty banners. ANSI bold + cyan if the terminal supports it.
if [[ -t 1 ]]; then
    BOLD=$(printf '\033[1m'); CYAN=$(printf '\033[36m'); GREEN=$(printf '\033[32m'); RESET=$(printf '\033[0m')
else
    BOLD=""; CYAN=""; GREEN=""; RESET=""
fi
banner() { printf '\n%s== %s ==%s\n' "${BOLD}${CYAN}" "$1" "${RESET}"; }
ok()     { printf '%s    %s%s\n' "${GREEN}" "$1" "${RESET}"; }

cleanup() {
    local rc=$?
    banner "tearing down Keycloak"
    docker compose -f "$INTEGRATION_DIR/docker-compose.yml" down --remove-orphans --volumes >/dev/null 2>&1 || true
    exit $rc
}
trap cleanup EXIT

banner "1. bringing Keycloak up"
docker compose -f "$INTEGRATION_DIR/docker-compose.yml" up -d --quiet-pull
deadline=$(( $(date +%s) + 180 ))
while true; do
    if curl -sf -o /dev/null "$BASE_URL/realms/$REALM" 2>/dev/null; then
        break
    fi
    if (( $(date +%s) > deadline )); then
        echo "FAIL: realm '$REALM' did not become available within 180s" >&2
        exit 1
    fi
    sleep 2
done
ok "realm '$REALM' is serving at $BASE_URL"

banner "2. acquiring a real access token (ROPC, alice@$REALM)"
TOKEN_RESPONSE=$(curl -sf \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "username=$USERNAME" \
    -d "password=$PASSWORD" \
    -d "grant_type=password" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/token")
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
ok "got an access token (${#ACCESS_TOKEN} chars; RS256 JWT)"

banner "3. running the demo SQL through quack-oauth"
"$DUCKDB" -unsigned <<SQL
LOAD quack_oauth;

-- 3a. Configure the resource server side. Provider preset fills issuer +
-- jwks_uri from the realm URL; we just declare the SECRET + tenant.
CREATE SECRET rs (
    TYPE quack_oauth_server,
    tenant_or_realm '$BASE_URL/realms/$REALM',
    audience 'account'
);
SET quack_oauth_provider = 'keycloak';
SET quack_oauth_server_secret_name = 'rs';

-- 3b. Validate the live token (3-arg form -- the same shape quack calls).
SELECT '--- token validation ---' AS step;
SELECT quack_oauth_check_token('demo-session', 'bearer',
    '$ACCESS_TOKEN') AS token_valid;

-- 3c. Inspect the cached Principal via diagnose().
SELECT '--- principals cached ---' AS step;
SELECT component, status, detail FROM quack_oauth_diagnose()
WHERE component = 'session_principals';

-- 3d. Define a SQL-native policy granting Scan + Attach to anyone with
-- the `email` scope (alice's default ROPC token has it).
CREATE TABLE main.policies (
    priority  INTEGER NOT NULL,
    subject   VARCHAR,
    any_scope VARCHAR[],
    actions   VARCHAR[],
    allow     BOOLEAN NOT NULL
);
INSERT INTO main.policies VALUES
    (10, NULL, ['email'], ['Scan', 'Attach'], true);

CREATE SECRET rs_with_policy (
    TYPE quack_oauth_server,
    tenant_or_realm '$BASE_URL/realms/$REALM',
    audience 'account',
    policy_table 'main.policies'
);
SET quack_oauth_server_secret_name = 'rs_with_policy';

SELECT '--- authorization ---' AS step;
SELECT 'SELECT * FROM t (Scan)'              AS attempted_action,
       quack_oauth_check_authorization('demo-session', 'SELECT * FROM t') AS allowed;
SELECT 'ATTACH ''quack:rs'' AS r (Attach)'    AS attempted_action,
       quack_oauth_check_authorization('demo-session', 'ATTACH ''quack:rs'' AS r') AS allowed;
SELECT 'COPY t TO ''out.csv'' (CopyTo)'       AS attempted_action,
       quack_oauth_check_authorization('demo-session', 'COPY t TO ''out.csv''') AS allowed;
SELECT 'PRAGMA quack_serve(''rs'') (ServeAdmin)' AS attempted_action,
       quack_oauth_check_authorization('demo-session', 'PRAGMA quack_serve(''rs'')') AS allowed;

-- 3e. The in-memory audit ring records every decision.
SELECT '--- audit log ---' AS step;
SELECT event_type, subject, action, reason
FROM quack_oauth_audit_log()
ORDER BY timestamp_unix_s, event_type;

-- 3f. Health snapshot.
SELECT '--- diagnose ---' AS step;
SELECT * FROM quack_oauth_diagnose();
SQL

ok ""
ok "Demo complete. Next steps:"
ok "  - Inspect API_REFERENCE.md for the full surface."
ok "  - Replace the heredoc SQL with your own setup."
ok "  - For production: set audit_table on the SECRET to persist auth events."
