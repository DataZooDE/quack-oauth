#!/usr/bin/env bash
# Capture a Google Cloud transcript for slice S-11b replay tests.
#
# Reads QUACK_OAUTH_GOOGLE_* from .env.google (gitignored). Uses the
# referenced service-account JSON key to:
#   1. Build a JWT assertion (RFC 7523, JWT-bearer grant)
#   2. Exchange it at https://oauth2.googleapis.com/token for an access token
#   3. Call https://oauth2.googleapis.com/tokeninfo to validate it
# Writes the two responses under test/integration/transcripts/google/.
#
# Sensitive material is filtered before write:
#   - the JWT-bearer assertion (which embeds the signing key indirectly)
#     is captured as a redacted placeholder
#   - the captured access_token expires in 1 hour; by the time the
#     transcript is in git its only value is as a fixture for replay
#
# Usage:
#   cp .env.google.example .env.google && $EDITOR .env.google
#   ./scripts/capture_google_transcript.sh

set -euo pipefail

PROJ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$PROJ_DIR/.env.google"
OUT_DIR="$PROJ_DIR/test/integration/transcripts/google"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "FAIL: $ENV_FILE not found. Copy .env.google.example and fill in." >&2
    exit 2
fi

# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

: "${QUACK_OAUTH_GOOGLE_KEY_FILE:?QUACK_OAUTH_GOOGLE_KEY_FILE not set in $ENV_FILE}"
: "${QUACK_OAUTH_GOOGLE_SCOPE:=https://www.googleapis.com/auth/cloud-platform.read-only}"

# Resolve key file path (relative paths are relative to project root).
KEY_FILE_PATH="$QUACK_OAUTH_GOOGLE_KEY_FILE"
if [[ "$KEY_FILE_PATH" != /* ]]; then
    KEY_FILE_PATH="$PROJ_DIR/$KEY_FILE_PATH"
fi
if [[ ! -f "$KEY_FILE_PATH" ]]; then
    echo "FAIL: service-account key file not found at $KEY_FILE_PATH" >&2
    exit 2
fi

mkdir -p "$OUT_DIR"

echo "=== minting Google access token (JWT-bearer flow) ==="

# Use python (stdlib + cryptography) to build the signed assertion and POST.
# This avoids requiring `google-auth` / `pyjwt` packages.
KEY_FILE_PATH_PY="$KEY_FILE_PATH" \
SCOPE_PY="$QUACK_OAUTH_GOOGLE_SCOPE" \
OUT_DIR_PY="$OUT_DIR" \
python3 - <<'PY'
import base64, json, os, sys, time, urllib.parse, urllib.request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

key_path = os.environ["KEY_FILE_PATH_PY"]
scope = os.environ["SCOPE_PY"]
out_dir = os.environ["OUT_DIR_PY"]

with open(key_path) as f:
    key = json.load(f)

# 1. Build the assertion JWT (RFC 7523 §2.1).
def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

now = int(time.time())
header = {"alg": "RS256", "typ": "JWT", "kid": key["private_key_id"]}
payload = {
    "iss": key["client_email"],
    "scope": scope,
    "aud": key["token_uri"],
    "exp": now + 3600,
    "iat": now,
}
signing_input = (
    b64u(json.dumps(header, separators=(",", ":")).encode())
    + "."
    + b64u(json.dumps(payload, separators=(",", ":")).encode())
)
private_key = serialization.load_pem_private_key(
    key["private_key"].encode(), password=None
)
sig = private_key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
assertion = signing_input + "." + b64u(sig)

# 2. Exchange the assertion for an access token.
body = urllib.parse.urlencode({
    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "assertion": assertion,
}).encode()
req = urllib.request.Request(
    key["token_uri"],
    data=body,
    headers={"Content-Type": "application/x-www-form-urlencoded"},
)
try:
    with urllib.request.urlopen(req) as resp:
        token_response_raw = resp.read().decode()
        token_response = json.loads(token_response_raw)
except urllib.error.HTTPError as e:
    print(f"FAIL: token endpoint returned HTTP {e.code}", file=sys.stderr)
    print(e.read().decode(), file=sys.stderr)
    sys.exit(1)

access_token = token_response.get("access_token")
if not access_token:
    print("FAIL: no access_token in response", file=sys.stderr)
    print(token_response_raw, file=sys.stderr)
    sys.exit(1)
print(f"    token acquired (len={len(access_token)}, expires_in={token_response.get('expires_in')})")

# 3. Validate the token via tokeninfo.
tokeninfo_url = "https://oauth2.googleapis.com/tokeninfo"
ti_body = urllib.parse.urlencode({"access_token": access_token}).encode()
ti_req = urllib.request.Request(
    tokeninfo_url,
    data=ti_body,
    headers={"Content-Type": "application/x-www-form-urlencoded"},
)
with urllib.request.urlopen(ti_req) as resp:
    tokeninfo_response_raw = resp.read().decode()
    tokeninfo_response = json.loads(tokeninfo_response_raw)
print(f"    tokeninfo: azp={tokeninfo_response.get('azp')} aud={tokeninfo_response.get('aud')} scope={tokeninfo_response.get('scope')}")

# 4. Write transcripts. The assertion that we sent embeds the signing key
#    indirectly -- safer to redact it. The captured tokens are short-lived
#    fixtures whose only purpose is as test inputs.
with open(os.path.join(out_dir, "token_endpoint.json"), "w") as f:
    json.dump({
        "method": "POST",
        "url": key["token_uri"],
        "content_type": "application/x-www-form-urlencoded",
        "request_body_redacted": "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=REDACTED",
        "status_code": 200,
        "response_body": token_response,
    }, f, indent=2, sort_keys=True)

with open(os.path.join(out_dir, "tokeninfo.json"), "w") as f:
    json.dump({
        "method": "POST",
        "url": tokeninfo_url,
        "content_type": "application/x-www-form-urlencoded",
        "request_body_redacted": "access_token=REDACTED",
        "status_code": 200,
        "response_body": tokeninfo_response,
    }, f, indent=2, sort_keys=True)

# 5. Metadata: derive what the validator will need from the actual response.
with open(os.path.join(out_dir, "metadata.json"), "w") as f:
    json.dump({
        "provider": "google",
        "service_account_email": key["client_email"],
        "project_id": key["project_id"],
        "token_endpoint": key["token_uri"],
        "tokeninfo_endpoint": tokeninfo_url,
        "captured_at": now,
        # Google returns numbers as STRINGS in tokeninfo -- coerce here so
        # the C++ test sees the same logical value.
        "tokeninfo_exp": int(tokeninfo_response.get("exp", 0)),
        "tokeninfo_aud": tokeninfo_response.get("aud", ""),
        "tokeninfo_azp": tokeninfo_response.get("azp", ""),
        "tokeninfo_sub": tokeninfo_response.get("sub", ""),
        "tokeninfo_scope": tokeninfo_response.get("scope", ""),
        "scope_requested": scope,
        "note": "Access token is opaque (not a JWT). Validation goes through tokeninfo, NOT JWKS. Tokens expire after captured_at + expires_in seconds.",
    }, f, indent=2, sort_keys=True)

print("=== written ===")
for name in ("token_endpoint.json", "tokeninfo.json", "metadata.json"):
    p = os.path.join(out_dir, name)
    print(f"    {p} ({os.path.getsize(p)} bytes)")
PY

echo
echo "Transcripts written. To verify they replay correctly, run the"
echo "ReplayHttpClient-backed Google tests once that slice lands."
