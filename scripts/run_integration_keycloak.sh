#!/usr/bin/env bash
# End-to-end Keycloak integration test for quack_oauth (S-7b.3 + S-10b).
#
# Spins up Keycloak in docker-compose, acquires a token via ROPC, materialises
# both the JWKS-mode and introspection-mode SQL tests from templates, and
# runs DuckDB's unittest binary against them. Tears the container down on
# exit (success or failure) so the port is always released.

set -euo pipefail

PROJ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INTEGRATION_DIR="$PROJ_DIR/test/integration/keycloak"
JWKS_TEMPLATE="$INTEGRATION_DIR/oauth_jwks_keycloak.test.template"
INTROSPECT_TEMPLATE="$INTEGRATION_DIR/oauth_introspect_keycloak.test.template"
LOGIN_TEMPLATE="$INTEGRATION_DIR/oauth_login_keycloak.test.template"
PRESET_TEMPLATE="$INTEGRATION_DIR/oauth_provider_preset_keycloak.test.template"
REFRESH_TEMPLATE="$INTEGRATION_DIR/oauth_refresh_keycloak.test.template"
AUTHZ_TEMPLATE="$INTEGRATION_DIR/oauth_authz_keycloak.test.template"
POLICY_TEMPLATE="$INTEGRATION_DIR/oauth_policy_table_keycloak.test.template"
AUDIT_TEMPLATE="$INTEGRATION_DIR/oauth_audit_keycloak.test.template"
# Generated INSIDE test/ so DuckDB's unittest scanner discovers them; gitignored.
JWKS_TEST="$INTEGRATION_DIR/oauth_jwks_keycloak.test"
INTROSPECT_TEST="$INTEGRATION_DIR/oauth_introspect_keycloak.test"
LOGIN_TEST="$INTEGRATION_DIR/oauth_login_keycloak.test"
PRESET_TEST="$INTEGRATION_DIR/oauth_provider_preset_keycloak.test"
REFRESH_TEST="$INTEGRATION_DIR/oauth_refresh_keycloak.test"
AUTHZ_TEST="$INTEGRATION_DIR/oauth_authz_keycloak.test"
POLICY_TEST="$INTEGRATION_DIR/oauth_policy_table_keycloak.test"
AUDIT_TEST="$INTEGRATION_DIR/oauth_audit_keycloak.test"
JWKS_REL="test/integration/keycloak/oauth_jwks_keycloak.test"
INTROSPECT_REL="test/integration/keycloak/oauth_introspect_keycloak.test"
LOGIN_REL="test/integration/keycloak/oauth_login_keycloak.test"
PRESET_REL="test/integration/keycloak/oauth_provider_preset_keycloak.test"
REFRESH_REL="test/integration/keycloak/oauth_refresh_keycloak.test"
AUTHZ_REL="test/integration/keycloak/oauth_authz_keycloak.test"
POLICY_REL="test/integration/keycloak/oauth_policy_table_keycloak.test"
AUDIT_REL="test/integration/keycloak/oauth_audit_keycloak.test"
UNITTEST="$PROJ_DIR/build/release/test/unittest"

REALM="quack-test"
CLIENT_ID="quack-client"
CLIENT_SECRET="quack-client-test-secret"
MACHINE_CLIENT_ID="quack-machine"
MACHINE_CLIENT_SECRET="quack-machine-test-secret"
USERNAME="alice"
PASSWORD="secret"
BASE_URL="http://localhost:8080"

if [[ ! -x "$UNITTEST" ]]; then
    echo "FAIL: $UNITTEST not found -- run 'make' first" >&2
    exit 2
fi

cleanup() {
    local rc=$?
    echo "=== tearing down Keycloak ==="
    docker compose -f "$INTEGRATION_DIR/docker-compose.yml" down --remove-orphans --volumes >/dev/null 2>&1 || true
    # The generated test files MUST NOT linger inside `test/` -- DuckDB's
    # unittest scanner picks up everything there, so `make test` would
    # otherwise try to run the integration tests without Keycloak.
    rm -f "$JWKS_TEST" "$INTROSPECT_TEST" "$LOGIN_TEST" "$PRESET_TEST" "$REFRESH_TEST" "$AUTHZ_TEST" "$POLICY_TEST" "$AUDIT_TEST"
    exit $rc
}
trap cleanup EXIT

echo "=== bringing Keycloak up ==="
docker compose -f "$INTEGRATION_DIR/docker-compose.yml" up -d --quiet-pull

echo "=== waiting for Keycloak realm to be serving ==="
# Poll from the host -- a 200 from the realm endpoint means import is done
# AND the listener is ready. More reliable than docker's healthcheck for
# this image.
deadline=$(( $(date +%s) + 180 ))
while true; do
    if curl -sf -o /dev/null "$BASE_URL/realms/$REALM" 2>/dev/null; then
        break
    fi
    if (( $(date +%s) > deadline )); then
        echo "FAIL: realm '$REALM' did not become available within 180s" >&2
        docker logs quack-oauth-keycloak --tail 50 >&2 || true
        exit 1
    fi
    sleep 2
done
echo "    realm '$REALM' is serving at $BASE_URL"

echo "=== acquiring access token (ROPC, confidential client) ==="
# quack-client is now confidential (S-10b: introspection requires it), so
# ROPC needs client_secret in addition to user credentials.
TOKEN_RESPONSE=$(curl -sf \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "username=$USERNAME" \
    -d "password=$PASSWORD" \
    -d "grant_type=password" \
    "$BASE_URL/realms/$REALM/protocol/openid-connect/token")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("refresh_token", ""))')
if [[ -z "$ACCESS_TOKEN" ]]; then
    echo "FAIL: no access_token in Keycloak response" >&2
    echo "$TOKEN_RESPONSE" >&2
    exit 1
fi
if [[ -z "$REFRESH_TOKEN" ]]; then
    echo "FAIL: no refresh_token in Keycloak response (offline_access scope missing?)" >&2
    exit 1
fi
echo "    token acquired (access=${#ACCESS_TOKEN} chars, refresh=${#REFRESH_TOKEN} chars)."

# Build a tampered token: flip a middle character of the signature segment.
TAMPERED=$(python3 -c "
t = '$ACCESS_TOKEN'
i = t.rfind('.') + 16
ch = t[i]
new = 'B' if ch == 'A' else 'A'
print(t[:i] + new + t[i+1:])
")

ISSUER="$BASE_URL/realms/$REALM"
JWKS_URI="$BASE_URL/realms/$REALM/protocol/openid-connect/certs"
INTROSPECT_URL="$BASE_URL/realms/$REALM/protocol/openid-connect/token/introspect"

echo "=== materialising SQL tests ==="
sed \
    -e "s|@ISSUER@|$ISSUER|g" \
    -e "s|@JWKS_URI@|$JWKS_URI|g" \
    -e "s|@TOKEN@|$ACCESS_TOKEN|g" \
    -e "s|@TOKEN_TAMPERED@|$TAMPERED|g" \
    "$JWKS_TEMPLATE" > "$JWKS_TEST"

sed \
    -e "s|@ISSUER@|$ISSUER|g" \
    -e "s|@INTROSPECT_URL@|$INTROSPECT_URL|g" \
    -e "s|@CLIENT_ID@|$CLIENT_ID|g" \
    -e "s|@CLIENT_SECRET@|$CLIENT_SECRET|g" \
    -e "s|@TOKEN@|$ACCESS_TOKEN|g" \
    -e "s|@TOKEN_TAMPERED@|$TAMPERED|g" \
    "$INTROSPECT_TEMPLATE" > "$INTROSPECT_TEST"

TOKEN_URL="$BASE_URL/realms/$REALM/protocol/openid-connect/token"
sed \
    -e "s|@ISSUER@|$ISSUER|g" \
    -e "s|@TOKEN_URL@|$TOKEN_URL|g" \
    -e "s|@JWKS_URI@|$JWKS_URI|g" \
    -e "s|@MACHINE_CLIENT_ID@|$MACHINE_CLIENT_ID|g" \
    -e "s|@MACHINE_CLIENT_SECRET@|$MACHINE_CLIENT_SECRET|g" \
    "$LOGIN_TEMPLATE" > "$LOGIN_TEST"

REALM_URL="$BASE_URL/realms/$REALM"
sed \
    -e "s|@REALM_URL@|$REALM_URL|g" \
    -e "s|@TOKEN@|$ACCESS_TOKEN|g" \
    "$PRESET_TEMPLATE" > "$PRESET_TEST"

sed \
    -e "s|@ISSUER@|$ISSUER|g" \
    -e "s|@TOKEN_URL@|$TOKEN_URL|g" \
    -e "s|@JWKS_URI@|$JWKS_URI|g" \
    -e "s|@CLIENT_ID@|$CLIENT_ID|g" \
    -e "s|@CLIENT_SECRET@|$CLIENT_SECRET|g" \
    -e "s|@REFRESH_TOKEN@|$REFRESH_TOKEN|g" \
    "$REFRESH_TEMPLATE" > "$REFRESH_TEST"

sed \
    -e "s|@ISSUER@|$ISSUER|g" \
    -e "s|@JWKS_URI@|$JWKS_URI|g" \
    -e "s|@TOKEN@|$ACCESS_TOKEN|g" \
    "$AUTHZ_TEMPLATE" > "$AUTHZ_TEST"

# The SQL-table policy test creates its own table inside the test body --
# no external file needed. Just substitute the live token.
sed \
    -e "s|@ISSUER@|$ISSUER|g" \
    -e "s|@JWKS_URI@|$JWKS_URI|g" \
    -e "s|@TOKEN@|$ACCESS_TOKEN|g" \
    "$POLICY_TEMPLATE" > "$POLICY_TEST"

# Audit test creates its own audit table inside the test body.
sed \
    -e "s|@ISSUER@|$ISSUER|g" \
    -e "s|@JWKS_URI@|$JWKS_URI|g" \
    -e "s|@TOKEN@|$ACCESS_TOKEN|g" \
    "$AUDIT_TEMPLATE" > "$AUDIT_TEST"

echo "=== running JWKS integration test ==="
cd "$PROJ_DIR"
"$UNITTEST" "$JWKS_REL"

echo "=== running INTROSPECT integration test ==="
"$UNITTEST" "$INTROSPECT_REL"

echo "=== running LOGIN (client_credentials) integration test ==="
"$UNITTEST" "$LOGIN_REL"

echo "=== running PROVIDER PRESET (keycloak) integration test ==="
"$UNITTEST" "$PRESET_REL"

echo "=== running REFRESH (refresh_token) integration test ==="
"$UNITTEST" "$REFRESH_REL"

echo "=== running AUTHZ (check_authorization) integration test ==="
"$UNITTEST" "$AUTHZ_REL"

echo "=== running POLICY TABLE integration test ==="
"$UNITTEST" "$POLICY_REL"

echo "=== running AUDIT integration test ==="
"$UNITTEST" "$AUDIT_REL"

echo "=== running DEVICE_CODE end-to-end test ==="
bash "$PROJ_DIR/scripts/run_device_code_test.sh" \
    "$BASE_URL" \
    "$REALM" \
    "$PROJ_DIR/build/release/duckdb" \
    "$PROJ_DIR/scripts/keycloak_device_consent.py"

echo "=== PASS ==="
