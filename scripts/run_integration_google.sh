#!/usr/bin/env bash
# End-to-end Google tokeninfo integration test.
#
# Mints a fresh access token using the service account in .env.google,
# materialises the SQL test from the template, and runs unittest. Unlike
# the Keycloak runner there's no container to bring up / down -- Google's
# endpoints are public-internet. The freshly-minted token is alive for
# ~1 hour, plenty for one SQL test run.

set -euo pipefail

PROJ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$PROJ_DIR/.env.google"
INTEGRATION_DIR="$PROJ_DIR/test/integration/google"
TEMPLATE="$INTEGRATION_DIR/oauth_tokeninfo_google.test.template"
GENERATED_TEST="$INTEGRATION_DIR/oauth_tokeninfo_google.test"
GENERATED_REL="test/integration/google/oauth_tokeninfo_google.test"
UNITTEST="$PROJ_DIR/build/release/test/unittest"

if [[ ! -x "$UNITTEST" ]]; then
    echo "FAIL: $UNITTEST not found -- run 'make' first" >&2
    exit 2
fi
if [[ ! -f "$ENV_FILE" ]]; then
    echo "FAIL: $ENV_FILE not found. Copy .env.google.example and fill in." >&2
    exit 2
fi

# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a
: "${QUACK_OAUTH_GOOGLE_KEY_FILE:?QUACK_OAUTH_GOOGLE_KEY_FILE not set}"
: "${QUACK_OAUTH_GOOGLE_SCOPE:=https://www.googleapis.com/auth/cloud-platform.read-only}"

KEY_FILE_PATH="$QUACK_OAUTH_GOOGLE_KEY_FILE"
if [[ "$KEY_FILE_PATH" != /* ]]; then
    KEY_FILE_PATH="$PROJ_DIR/$KEY_FILE_PATH"
fi

cleanup() {
    rm -f "$GENERATED_TEST"
}
trap cleanup EXIT

echo "=== minting Google access token + harvesting fields ==="
read ACCESS_TOKEN AUD TOKENINFO_URL <<<"$(
KEY_FILE_PATH_PY="$KEY_FILE_PATH" SCOPE_PY="$QUACK_OAUTH_GOOGLE_SCOPE" python3 <<'PY'
import base64, json, os, sys, time, urllib.parse, urllib.request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

with open(os.environ["KEY_FILE_PATH_PY"]) as f:
    key = json.load(f)
scope = os.environ["SCOPE_PY"]

def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
now = int(time.time())
header = {"alg": "RS256", "typ": "JWT", "kid": key["private_key_id"]}
payload = {
    "iss": key["client_email"], "scope": scope,
    "aud": key["token_uri"], "exp": now + 3600, "iat": now,
}
signing_input = (
    b64u(json.dumps(header, separators=(",", ":")).encode()) + "." +
    b64u(json.dumps(payload, separators=(",", ":")).encode()))
priv = serialization.load_pem_private_key(key["private_key"].encode(), password=None)
sig = priv.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
assertion = signing_input + "." + b64u(sig)
body = urllib.parse.urlencode({
    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "assertion": assertion,
}).encode()
req = urllib.request.Request(key["token_uri"], data=body,
    headers={"Content-Type": "application/x-www-form-urlencoded"})
with urllib.request.urlopen(req) as r:
    tok = json.loads(r.read())

# Call tokeninfo once to discover the audience (the SA's unique numeric id).
ti_url = "https://oauth2.googleapis.com/tokeninfo"
ti_req = urllib.request.Request(ti_url,
    data=urllib.parse.urlencode({"access_token": tok["access_token"]}).encode(),
    headers={"Content-Type": "application/x-www-form-urlencoded"})
with urllib.request.urlopen(ti_req) as r:
    ti = json.loads(r.read())

print(tok["access_token"], ti["aud"], ti_url)
PY
)"

if [[ -z "$ACCESS_TOKEN" ]]; then
    echo "FAIL: could not mint Google access token" >&2
    exit 1
fi
echo "    token acquired (len=${#ACCESS_TOKEN}, aud=$AUD)"

# Tampered token: flip a middle character.
TAMPERED=$(python3 -c "
t = '$ACCESS_TOKEN'
i = len(t) // 2
ch = t[i]
new = 'B' if ch == 'A' else 'A'
print(t[:i] + new + t[i+1:])
")

echo "=== materialising SQL test ==="
sed \
    -e "s|@TOKENINFO_URL@|$TOKENINFO_URL|g" \
    -e "s|@AUDIENCE@|$AUD|g" \
    -e "s|@TOKEN@|$ACCESS_TOKEN|g" \
    -e "s|@TAMPERED_TOKEN@|$TAMPERED|g" \
    "$TEMPLATE" > "$GENERATED_TEST"

echo "=== running Google tokeninfo integration test ==="
cd "$PROJ_DIR"
"$UNITTEST" "$GENERATED_REL"

echo "=== PASS ==="
