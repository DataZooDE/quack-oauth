"""Pytest fixtures for the real-quack E2E harness."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from helpers import keycloak, server


@pytest.fixture(scope="session")
def keycloak_handle() -> Iterator[keycloak.KeycloakHandle]:
    """Bring up Keycloak via docker compose for the whole test session."""
    handle = keycloak.bring_up()
    yield handle
    keycloak.tear_down()


@pytest.fixture(scope="session")
def alice_token(keycloak_handle: keycloak.KeycloakHandle) -> str:
    """A fresh access token for alice (RS256 JWT). Reused across tests
    because tokens are valid for 10 minutes (see realm-export.json)."""
    return keycloak.acquire_ropc_token(keycloak_handle)


@pytest.fixture(scope="session")
def quack_server(keycloak_handle: keycloak.KeycloakHandle) -> Iterator[server.QuackServer]:
    """A real quack server hosted in-process. The listener runs on a
    background thread; we hold the configuring connection alive for the
    full session so the DatabaseInstance (with the principal/audit/
    policy state) outlives the tests.
    """
    s = server.start_server(realm_url=keycloak_handle.realm_url)
    yield s
    s.close()


@pytest.fixture()
def client():
    """A per-test, fresh client-side DuckDB connection with `quack` loaded.
    The test is responsible for ATTACHing to the server."""
    conn = server.open_client()
    yield conn
    conn.close()
