"""Keycloak helpers for the E2E harness.

Wraps `docker compose` on the existing test/integration/keycloak realm,
acquires bearer tokens via ROPC, and exposes a JWT-tampering helper.
"""

from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

PROJ_DIR = Path(__file__).resolve().parents[2]
COMPOSE_FILE = PROJ_DIR / "test" / "integration" / "keycloak" / "docker-compose.yml"

BASE_URL = "http://localhost:8080"
REALM = "quack-test"
CLIENT_ID = "quack-client"
CLIENT_SECRET = "quack-client-test-secret"
USERNAME = "alice"
PASSWORD = "secret"


@dataclass
class KeycloakHandle:
    base_url: str
    realm: str
    issuer: str
    jwks_uri: str

    @property
    def realm_url(self) -> str:
        return f"{self.base_url}/realms/{self.realm}"


def _compose(*args: str) -> None:
    cmd = ["docker", "compose", "-f", str(COMPOSE_FILE)] + list(args)
    subprocess.run(cmd, check=True, capture_output=True)


def bring_up(timeout_s: int = 180) -> KeycloakHandle:
    """Idempotent: start Keycloak via docker compose and wait for the realm
    endpoint to serve. Returns the handle once it's ready."""
    _compose("up", "-d", "--quiet-pull")

    realm_url = f"{BASE_URL}/realms/{REALM}"
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(realm_url, timeout=2) as resp:
                if resp.status == 200:
                    return KeycloakHandle(
                        base_url=BASE_URL,
                        realm=REALM,
                        issuer=realm_url,
                        jwks_uri=f"{realm_url}/protocol/openid-connect/certs",
                    )
        except (urllib.error.URLError, urllib.error.HTTPError, ConnectionResetError):
            pass
        time.sleep(2)
    raise TimeoutError(f"Keycloak realm '{REALM}' did not become available within {timeout_s}s")


def tear_down() -> None:
    subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "down", "--remove-orphans", "--volumes"],
        check=False,
        capture_output=True,
    )


def acquire_ropc_token(handle: KeycloakHandle,
                       username: str = USERNAME,
                       password: str = PASSWORD,
                       client_id: str = CLIENT_ID,
                       client_secret: str = CLIENT_SECRET) -> str:
    """Acquire an access token via OAuth 2.0 Resource Owner Password
    Credentials. Returns the access_token (RS256 JWT)."""
    body = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": client_id,
        "client_secret": client_secret,
        "username": username,
        "password": password,
    }).encode("ascii")
    req = urllib.request.Request(
        f"{handle.realm_url}/protocol/openid-connect/token",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    return payload["access_token"]


def tamper_jwt_signature(token: str) -> str:
    """Flip a character in the middle of the signature segment so verification
    fails. Returns a new JWT string with the same header+payload but invalid
    signature. Mirrors the trick used by run_integration_keycloak.sh."""
    last_dot = token.rfind(".")
    if last_dot == -1 or last_dot >= len(token) - 16:
        raise ValueError("token does not look like a JWT with a signature segment")
    pos = last_dot + 16
    swapped = "B" if token[pos] == "A" else "A"
    return token[:pos] + swapped + token[pos + 1:]
