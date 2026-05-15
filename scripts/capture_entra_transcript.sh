#!/usr/bin/env bash
# Capture an Entra ID transcript for slice S-11b replay tests.
#
# Reads QUACK_OAUTH_ENTRA_* from .env.entra (gitignored), runs the
# client_credentials flow against Microsoft Graph, fetches the JWKS, and
# writes the responses to test/integration/transcripts/entra/.
#
# Sensitive material is filtered before write:
#   - request_headers (Authorization: Basic ...) are NEVER written
#   - request_body is written WITHOUT client_secret (replaced with REDACTED)
# The committed transcripts contain only what Entra sends back over the
# wire. Token bodies expire ~10 minutes after capture; tests freeze the
# clock to the capture's `iat` so signature verification still passes.
#
# Usage:
#   cp .env.entra.example .env.entra && $EDITOR .env.entra
#   ./scripts/capture_entra_transcript.sh
#
# Re-run any time. Each capture overwrites the previous fixtures.

set -euo pipefail

PROJ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$PROJ_DIR/.env.entra"
OUT_DIR="$PROJ_DIR/test/integration/transcripts/entra"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "FAIL: $ENV_FILE not found. Copy .env.entra.example and fill in your tenant values." >&2
    exit 2
fi

# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

: "${QUACK_OAUTH_ENTRA_TENANT_ID:?QUACK_OAUTH_ENTRA_TENANT_ID not set in $ENV_FILE}"
: "${QUACK_OAUTH_ENTRA_CLIENT_ID:?QUACK_OAUTH_ENTRA_CLIENT_ID not set in $ENV_FILE}"
: "${QUACK_OAUTH_ENTRA_CLIENT_SECRET:?QUACK_OAUTH_ENTRA_CLIENT_SECRET not set in $ENV_FILE}"
: "${QUACK_OAUTH_ENTRA_SCOPE:=https://graph.microsoft.com/.default}"

TENANT="$QUACK_OAUTH_ENTRA_TENANT_ID"
TOKEN_URL="https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token"
JWKS_URL="https://login.microsoftonline.com/${TENANT}/discovery/v2.0/keys"
ISSUER="https://login.microsoftonline.com/${TENANT}/v2.0"

mkdir -p "$OUT_DIR"

echo "=== capturing Entra token endpoint response ==="
TOKEN_BODY="grant_type=client_credentials&client_id=${QUACK_OAUTH_ENTRA_CLIENT_ID}&client_secret=${QUACK_OAUTH_ENTRA_CLIENT_SECRET}&scope=${QUACK_OAUTH_ENTRA_SCOPE}"
TOKEN_RESPONSE="$(curl -sf -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data "$TOKEN_BODY" \
    "$TOKEN_URL")"
if [[ -z "$TOKEN_RESPONSE" ]]; then
    echo "FAIL: empty response from $TOKEN_URL" >&2
    exit 1
fi

ACCESS_TOKEN="$(echo "$TOKEN_RESPONSE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
if [[ -z "$ACCESS_TOKEN" ]]; then
    echo "FAIL: no access_token in token response" >&2
    echo "$TOKEN_RESPONSE" >&2
    exit 1
fi
echo "    token acquired (len=${#ACCESS_TOKEN})"

# Decode iat / exp / kid / actual iss / actual aud from the JWT itself.
# Entra often returns v1.0 tokens with iss=`https://sts.windows.net/{tid}/`
# even when the v2.0 endpoint was used; aud is whatever the scope resolves
# to. Reading these from the token guarantees the transcript matches what
# the validator will see.
read IAT EXP KID TOKEN_ISS TOKEN_AUD <<<"$(printf '%s' "$ACCESS_TOKEN" | python3 -c '
import sys, base64, json
parts = sys.stdin.read().strip().split(".")
hdr = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
pl = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
aud = pl.get("aud", "")
if isinstance(aud, list): aud = aud[0] if aud else ""
print(pl.get("iat", 0), pl.get("exp", 0), hdr.get("kid", ""), pl.get("iss", ""), aud)')"
echo "    iat=$IAT exp=$EXP kid=$KID"
echo "    iss=$TOKEN_ISS aud=$TOKEN_AUD"

echo "=== capturing Entra JWKS ==="
JWKS_RESPONSE="$(curl -sf -H "Accept: application/json" "$JWKS_URL")"
if [[ -z "$JWKS_RESPONSE" ]]; then
    echo "FAIL: empty JWKS response" >&2
    exit 1
fi

# Verify the signing kid is in the JWKS the IdP just served, otherwise
# replay tests would always fail signature verification.
if ! printf '%s' "$JWKS_RESPONSE" | python3 -c "
import json, sys
keys = json.load(sys.stdin).get('keys', [])
sys.exit(0 if any(k.get('kid') == '$KID' for k in keys) else 1)
"; then
    echo "FAIL: token's kid=$KID is not in the JWKS response. Re-capture." >&2
    exit 1
fi
echo "    JWKS contains kid $KID"

# Write transcripts. The redacted request_body marker carries the body shape
# (for documentation / future reproduction) without the client_secret.
REDACTED_TOKEN_BODY="grant_type=client_credentials&client_id=${QUACK_OAUTH_ENTRA_CLIENT_ID}&client_secret=REDACTED&scope=${QUACK_OAUTH_ENTRA_SCOPE}"

TOKEN_RESPONSE_FOR_PY="$TOKEN_RESPONSE" \
JWKS_RESPONSE_FOR_PY="$JWKS_RESPONSE" \
TOKEN_URL_FOR_PY="$TOKEN_URL" \
JWKS_URL_FOR_PY="$JWKS_URL" \
REDACTED_BODY_FOR_PY="$REDACTED_TOKEN_BODY" \
python3 - <<'PY'
import json, os, pathlib
out_dir = pathlib.Path(os.environ["OUT_DIR"]) if "OUT_DIR" in os.environ else None
PY
# (The heredoc-stub above is a no-op left in for future expansion;
# the real writes happen via separate `python3 -c` invocations below to
# keep the script readable.)

python3 - "$TOKEN_URL" "$REDACTED_TOKEN_BODY" "$TOKEN_RESPONSE" "$OUT_DIR/token_endpoint.json" <<'PY'
import json, sys
url, body, response_str, out_path = sys.argv[1:5]
doc = {
    "method": "POST",
    "url": url,
    "content_type": "application/x-www-form-urlencoded",
    "request_body_redacted": body,
    "status_code": 200,
    "response_body": json.loads(response_str),
}
with open(out_path, "w") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
PY

python3 - "$JWKS_URL" "$JWKS_RESPONSE" "$OUT_DIR/jwks.json" <<'PY'
import json, sys
url, response_str, out_path = sys.argv[1:4]
doc = {
    "method": "GET",
    "url": url,
    "status_code": 200,
    "response_body": json.loads(response_str),
}
with open(out_path, "w") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
PY

python3 - "$TENANT" "$QUACK_OAUTH_ENTRA_CLIENT_ID" "$TOKEN_ISS" "$JWKS_URL" "$TOKEN_URL" "$IAT" "$EXP" "$KID" "$TOKEN_AUD" "$OUT_DIR/metadata.json" <<'PY'
import json, sys
(tenant, client_id, issuer, jwks_uri, token_url, iat, exp, kid, audience, out_path) = sys.argv[1:11]
doc = {
    "provider": "entra",
    "tenant_id": tenant,
    "client_id": client_id,
    "issuer": issuer,            # token's actual `iss`, may be v1.0 sts.windows.net or v2.0 login.microsoftonline.com
    "jwks_uri": jwks_uri,        # always the v2.0 discovery endpoint -- it serves keys for both versions
    "token_endpoint": token_url,
    "captured_iat": int(iat),
    "captured_exp": int(exp),
    "kid": kid,
    "audience": audience,        # token's actual `aud` (api://<client_id> for custom-API scope)
    "note": "Token expires ~10 min after captured_iat; replay tests freeze the clock to captured_iat + 5.",
}
with open(out_path, "w") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
PY

echo "=== written ==="
ls -la "$OUT_DIR"
echo
echo "Transcripts written. To verify they replay correctly, run the"
echo "ReplayHttpClient-backed tests once that slice lands."
