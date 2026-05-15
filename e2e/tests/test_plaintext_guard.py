"""E2E R-N-4: plaintext guard. A server bound to a non-loopback host
(0.0.0.0 / public IP) must refuse to validate tokens unless the operator
explicitly sets `quack_oauth_trust_plaintext = true`."""

from __future__ import annotations

import duckdb
import pytest

from helpers import keycloak, server


@pytest.fixture()
def public_server(keycloak_handle: keycloak.KeycloakHandle):
    """A second quack server, bound to 0.0.0.0 (publicly reachable) but
    WITHOUT the trust_plaintext opt-in. Used to verify R-N-4 refusal."""
    s = server.start_server(
        realm_url=keycloak_handle.realm_url,
        bind_host="0.0.0.0",
        trust_plaintext=False,
        allow_other_hostname=True,
    )
    yield s
    s.close()


def test_public_listener_without_trust_is_refused(public_server, client, alice_token):
    """With listener on 0.0.0.0 and trust_plaintext=false, our check_token
    raises -- which quack reports back to the client as the generic
    'Authentication failed' (the rich message stays in the server log).
    Pairs with test_public_listener_with_trust_is_allowed: the SAME token
    against the SAME server passes when trust_plaintext=true, so the
    only thing blocking here is the R-N-4 guard."""
    with pytest.raises(duckdb.Error) as excinfo:
        client.execute(
            f"ATTACH 'quack:127.0.0.1:{public_server.port}' AS srv "
            f"(TYPE quack, token '{alice_token}')"
        )
        # Defensive: force a wire query if ATTACH deferred the auth.
        client.execute("SELECT 1 FROM srv.main.t LIMIT 1")
    msg = str(excinfo.value).lower()
    # Quack reports a generic message; we just verify it's an auth-class
    # error. The contrast with the trust=true sibling test proves it's
    # the R-N-4 guard, not a token-validation reject.
    assert "auth" in msg, f"unexpected error: {excinfo.value}"


@pytest.fixture()
def public_server_trusted(keycloak_handle: keycloak.KeycloakHandle):
    """Same public bind, but operator opted in via trust_plaintext."""
    s = server.start_server(
        realm_url=keycloak_handle.realm_url,
        bind_host="0.0.0.0",
        trust_plaintext=True,
        allow_other_hostname=True,
    )
    yield s
    s.close()


def test_public_listener_with_trust_is_allowed(public_server_trusted, client, alice_token):
    """When trust_plaintext=true, the same public-bound listener admits
    valid tokens. Proves the guard is opt-in-able, not blanket-deny."""
    client.execute(
        f"ATTACH 'quack:127.0.0.1:{public_server_trusted.port}' AS srv "
        f"(TYPE quack, token '{alice_token}')"
    )
    rows = client.execute("SELECT id FROM srv.main.t ORDER BY id LIMIT 1").fetchall()
    assert rows == [(0,)]
