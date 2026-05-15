"""E2E core: server boots, client connects with a real JWT, happy path."""

from __future__ import annotations

import socket

from helpers import server


def test_server_listens(quack_server: server.QuackServer) -> None:
    """The quack listener is reachable. TCP connect probe so the test
    doesn't depend on the quack protocol -- if the listener didn't start,
    this fails fast."""
    with socket.create_connection((quack_server.host, quack_server.port), timeout=2) as s:
        assert s.fileno() > 0


def test_scan_allowed_by_policy(client, quack_server: server.QuackServer, alice_token: str) -> None:
    """alice's JWT goes in as the `token` ATTACH option. quack passes it
    to `quack_oauth_check_token(session_id, JWT, server_psk)` (args[1]),
    we validate against Keycloak's JWKS, cache the Principal, and admit
    the connection.

    The policy table grants Scan to any principal with `email` scope
    (alice's default ROPC token has it). A real wire query through the
    quack protocol returns the seeded rows."""
    client.execute(
        f"ATTACH 'quack:{quack_server.host}:{quack_server.port}' AS srv "
        f"(TYPE quack, token '{alice_token}')"
    )
    rows = client.execute("SELECT id FROM srv.main.t ORDER BY id").fetchall()
    assert rows == [(0,), (1,), (2,), (3,), (4,)]
