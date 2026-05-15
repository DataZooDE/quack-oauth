"""E2E AuthN: a tampered JWT must be rejected at connect time."""

from __future__ import annotations

import duckdb
import pytest

from helpers import keycloak, server


def test_tampered_token_rejected(client, quack_server: server.QuackServer, alice_token: str) -> None:
    """Flip a character in the JWT signature; the server's
    `quack_oauth_check_token` returns false, quack refuses the
    connection with 'Authentication failed'.
    """
    bad_token = keycloak.tamper_jwt_signature(alice_token)
    assert bad_token != alice_token

    with pytest.raises(duckdb.Error) as excinfo:
        client.execute(
            f"ATTACH 'quack:{quack_server.host}:{quack_server.port}' AS srv "
            f"(TYPE quack, token '{bad_token}')"
        )
        # ATTACH may succeed lazily; force the connect by issuing a query.
        client.execute("SELECT 1 FROM srv.main.t LIMIT 1")
    msg = str(excinfo.value).lower()
    assert "authenticat" in msg or "auth" in msg, f"unexpected error: {excinfo.value}"


def test_unsigned_garbage_rejected(client, quack_server: server.QuackServer) -> None:
    """A non-JWT token shaped like `not.a.jwt` is rejected the same way."""
    with pytest.raises(duckdb.Error) as excinfo:
        client.execute(
            f"ATTACH 'quack:{quack_server.host}:{quack_server.port}' AS srv "
            f"(TYPE quack, token 'not.a.jwt')"
        )
        client.execute("SELECT 1 FROM srv.main.t LIMIT 1")
    msg = str(excinfo.value).lower()
    assert "authenticat" in msg or "auth" in msg, f"unexpected error: {excinfo.value}"
