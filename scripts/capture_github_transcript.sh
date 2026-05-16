#!/usr/bin/env bash
# Capture a GitHub OAuth-App transcript for slice S-11b replay tests.
#
# Reads QUACK_OAUTH_GITHUB_* from .env.github (gitignored). Calls
# `POST https://api.github.com/applications/{client_id}/token` with
# HTTP Basic = client_id:client_secret to validate the access token
# (R-S-13). Writes the response under
# test/integration/transcripts/github/.
#
# Sensitive material is filtered before write:
#   - The HTTP Basic Authorization header is NEVER written.
#   - The request body has the live token replaced with REDACTED.
# The committed transcript holds only what GitHub sends back; by the
# time it's in git the response body's `token` echo is just a fixture
# string (the live token having long expired or been revoked).
#
# Usage:
#   cp .env.github.example .env.github && $EDITOR .env.github
#   ./scripts/capture_github_transcript.sh

set -euo pipefail

PROJ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$PROJ_DIR/.env.github"
OUT_DIR="$PROJ_DIR/test/integration/transcripts/github"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "FAIL: $ENV_FILE not found. Copy .env.github.example and fill in your OAuth App values." >&2
    exit 2
fi

# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

: "${QUACK_OAUTH_GITHUB_CLIENT_ID:?QUACK_OAUTH_GITHUB_CLIENT_ID not set in $ENV_FILE}"
: "${QUACK_OAUTH_GITHUB_CLIENT_SECRET:?QUACK_OAUTH_GITHUB_CLIENT_SECRET not set in $ENV_FILE}"
: "${QUACK_OAUTH_GITHUB_ACCESS_TOKEN:?QUACK_OAUTH_GITHUB_ACCESS_TOKEN not set in $ENV_FILE (mint via the OAuth Web Flow against your App)}"

CHECK_URL="https://api.github.com/applications/${QUACK_OAUTH_GITHUB_CLIENT_ID}/token"

mkdir -p "$OUT_DIR"

echo "=== POST $CHECK_URL ==="
# Capture the full response body and status separately so we can
# discriminate 200 vs 404 / 401 / 403.
TMP_BODY="$(mktemp)"
trap 'rm -f "$TMP_BODY"' EXIT

STATUS="$(curl -s -o "$TMP_BODY" -w '%{http_code}' \
    -u "${QUACK_OAUTH_GITHUB_CLIENT_ID}:${QUACK_OAUTH_GITHUB_CLIENT_SECRET}" \
    -H "Content-Type: application/json" \
    -H "Accept: application/vnd.github+json" \
    -X POST \
    -d "{\"access_token\":\"${QUACK_OAUTH_GITHUB_ACCESS_TOKEN}\"}" \
    "$CHECK_URL")"

echo "    HTTP $STATUS"

if [[ "$STATUS" != "200" ]]; then
    echo "WARN: non-200 -- the token may not have been issued by this App, or the App credentials are wrong." >&2
    echo "      Capturing the response anyway; it documents the negative-path shape." >&2
fi

RESPONSE_BODY="$(cat "$TMP_BODY")"
REDACTED_REQUEST_BODY="{\"access_token\":\"REDACTED\"}"

python3 - "$CHECK_URL" "$REDACTED_REQUEST_BODY" "$RESPONSE_BODY" "$STATUS" "$OUT_DIR/check_token_endpoint.json" <<'PY'
import json, sys
url, body, response_str, status, out_path = sys.argv[1:6]
try:
    parsed_body = json.loads(response_str)
except json.JSONDecodeError:
    parsed_body = {"raw": response_str}
doc = {
    "method": "POST",
    "url": url,
    "content_type": "application/json",
    "request_body_redacted": body,
    "status_code": int(status),
    "response_body": parsed_body,
}
with open(out_path, "w") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
PY

python3 - "$QUACK_OAUTH_GITHUB_CLIENT_ID" "$CHECK_URL" "$STATUS" "$OUT_DIR/metadata.json" <<'PY'
import json, sys
client_id, check_url, status, out_path = sys.argv[1:5]
doc = {
    "provider": "github",
    "client_id": client_id,
    "check_url": check_url,
    "captured_status_code": int(status),
    "note": (
        "GitHub tokens are opaque; validation goes through POST "
        "/applications/{client_id}/token with HTTP Basic. Replay tests "
        "feed the response_body back through the same code path."
    ),
}
with open(out_path, "w") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
PY

echo "=== written ==="
ls -la "$OUT_DIR"
echo
echo "Transcript written. Status was HTTP $STATUS."
