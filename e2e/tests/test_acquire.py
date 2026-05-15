"""E2E R-C-2: `quack_oauth_acquire(secret_name)` threaded directly into
ATTACH's `token` option.

The cached-AT path doesn't need a live IdP call -- we put alice's
already-acquired ROPC token onto the SECRET as `access_token` and let
quack_oauth_acquire short-circuit (UseCached). This proves the
operator pattern:

    ATTACH 'quack:...' AS srv
      (TYPE quack, token quack_oauth_acquire('cli'));

end-to-end through the wire.
"""

from __future__ import annotations

import duckdb

from helpers import server


def test_attach_via_acquire_cached_path(client, quack_server: server.QuackServer,
                                        alice_token: str) -> None:
    """A client SECRET carrying a pre-baked fresh AT is short-circuited
    by quack_oauth_acquire. Threading it into ATTACH gives the operator
    a single-statement reconnect-safe pattern."""
    # Put the live ROPC token onto a client SECRET with a far-future
    # expires_at, so the UseCached branch fires.
    client.execute(f"""
        CREATE SECRET cli (
            TYPE quack_oauth,
            token_endpoint 'https://idp.nonexistent.invalid/token',
            client_id 'demo',
            access_token '{alice_token}',
            expires_at '2099-01-01T00:00:00Z'
        );
    """)
    # Verify acquire returns it unchanged.
    got = client.execute("SELECT quack_oauth_acquire('cli')").fetchone()
    assert got is not None
    assert got[0] == alice_token

    # Now the operator pattern: weave it into ATTACH.
    client.execute(
        f"ATTACH 'quack:{quack_server.host}:{quack_server.port}' AS srv "
        f"(TYPE quack, token quack_oauth_acquire('cli'))"
    )
    rows = client.execute("SELECT id FROM srv.main.t ORDER BY id").fetchall()
    assert rows == [(0,), (1,), (2,), (3,), (4,)]


def test_acquire_unconfigured_fails_loudly(client, quack_server: server.QuackServer) -> None:
    """An empty SECRET raises with a message that tells the operator
    what to add. Pairs with the cached path above to prove the decision
    helper picks both branches."""
    client.execute("""
        CREATE SECRET cli_bad (
            TYPE quack_oauth,
            issuer 'https://idp.test'
        );
    """)
    import pytest
    with pytest.raises(duckdb.Error) as excinfo:
        client.execute("SELECT quack_oauth_acquire('cli_bad')")
    msg = str(excinfo.value).lower()
    assert "unconfigured" in msg, f"unexpected error: {excinfo.value}"
