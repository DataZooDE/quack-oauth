"""Ad-hoc Entra E2E verification. Not part of the pytest suite -- run
directly:  uv run --no-project python e2e/entra_e2e.py

Mints a real Entra token via client_credentials, starts a quack server
with the Entra preset, then connects a client over the wire and
exercises the full auth + authz pipeline. Used to find bugs the
existing tests miss.
"""
from __future__ import annotations

import os
import sys
import subprocess
import pathlib

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
from helpers.server import open_client, start_server, EXTENSION_PATH  # noqa: E402

# 1. Load .env.entra
ENV_FILE = HERE.parent / ".env.entra"
env = {}
for line in ENV_FILE.read_text().splitlines():
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, _, v = line.partition("=")
    env[k.strip()] = v.strip()

TENANT = env["QUACK_OAUTH_ENTRA_TENANT_ID"]
CLIENT_ID = env["QUACK_OAUTH_ENTRA_CLIENT_ID"]
CLIENT_SECRET = env["QUACK_OAUTH_ENTRA_CLIENT_SECRET"]
SCOPE = env["QUACK_OAUTH_ENTRA_SCOPE"]
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"

# 2. Mint a fresh token via curl (well-trodden path)
print(f"[1/6] Acquiring Entra token from {TOKEN_URL} ...")
out = subprocess.check_output([
    "curl", "-sf", "-X", "POST",
    "-H", "Content-Type: application/x-www-form-urlencoded",
    "-d", f"grant_type=client_credentials&client_id={CLIENT_ID}&client_secret={CLIENT_SECRET}&scope={SCOPE}",
    TOKEN_URL,
])
import json
token = json.loads(out)["access_token"]
print(f"    got token ({len(token)} chars)")

# 3. Start a quack server with the Entra preset.
print("[2/6] Starting quack server with Entra preset ...")
# The start_server helper hard-codes audience='account' (Keycloak default).
# We need to pass the Entra audience (the client_id GUID for v2.0 tokens).
# Patch by calling start_server with provider='entra' and the right values.
server = start_server(
    realm_url=TENANT,             # for entra, this IS the tenant GUID, not a URL
    audience=CLIENT_ID,            # v2.0 audience == client_id
    provider="entra",
    seed_policy=True,
    seed_audit=True,
    bind_host="127.0.0.1",
)
print(f"    listening on {server.host}:{server.port}")

# 4. Inspect what policy / audit the helper seeded for us.
rows = server.conn.execute(
    "SELECT priority, subject, any_scope, actions, allow FROM main.policies"
).fetchall()
print(f"[3/6] Policy rules: {rows}")

# 5. Bug hunt: the helper seeded the policy for `email` scope (Keycloak default).
# Entra tokens don't have an `email` claim or scope; they have `roles=['quack.access']`.
# Patch the policy so the test isn't expecting a Keycloak-shaped principal.
print("[4/6] Patching policy for Entra role-based principal ...")
server.conn.execute("DELETE FROM main.policies")
server.conn.execute("""
    INSERT INTO main.policies VALUES
        (10, NULL, ['quack.access'], ['Scan', 'Attach'], true);
""")

# 6. Client connects.
print(f"[5/6] Client ATTACH 'quack:{server.host}:{server.port}' ...")
client = open_client()
try:
    client.execute(
        f"ATTACH 'quack:{server.host}:{server.port}' AS srv "
        f"(TYPE quack, token '{token}')"
    )
    # Pull rows over the wire. This triggers Scan on the server.
    result = client.execute("SELECT count(*) FROM srv.main.t").fetchone()
    print(f"    SELECT count(*) FROM srv.main.t -> {result}")
except Exception as e:
    print(f"    CLIENT ERROR: {e}")
finally:
    # 7. Inspect the audit trail on the server side.
    print("[6/6] Server-side audit log:")
    for ev in server.conn.execute(
        "SELECT event_type, substr(subject, 1, 18) AS sub, action, reason, token_hash "
        "FROM quack_oauth_audit_log() ORDER BY timestamp_unix_s"
    ).fetchall():
        print(f"    {ev}")
    print("    audit_table rows:")
    for ev in server.conn.execute(
        "SELECT event_type, substr(subject, 1, 18) AS sub, action, reason "
        "FROM main.audit ORDER BY timestamp_unix_s"
    ).fetchall():
        print(f"    {ev}")
    server.close()
    print("done.")
