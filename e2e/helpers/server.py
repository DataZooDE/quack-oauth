"""Server fixture: an in-process DuckDB DatabaseInstance loaded with both
`quack` (from the public extension registry) and our locally-built
`quack_oauth` (.duckdb_extension). The `quack_serve()` table function
spawns the listener on a background thread and returns immediately, so we
can hold the server `Connection` alive while running tests against it
via a separate client connection (host:port).
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path

import duckdb

PROJ_DIR = Path(__file__).resolve().parents[2]
EXTENSION_PATH = PROJ_DIR / "build" / "release" / "extension" / "quack_oauth" / "quack_oauth.duckdb_extension"

# A short random pre-shared key. The OAuth path ignores this -- only the
# default `quack_check_token` would compare against it. We keep it stable
# so tests can refer to it if they want to demonstrate the override.
SERVER_PSK = "quack-oauth-e2e-psk-do-not-rely-on"


def find_free_port() -> int:
    """Pick an unused TCP port on localhost. Race-free for our single-runner
    use case; not safe under parallel test execution but pytest-xdist isn't
    enabled."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class QuackServer:
    conn: duckdb.DuckDBPyConnection
    host: str
    port: int

    @property
    def uri(self) -> str:
        return f"quack:{self.host}:{self.port}"

    def close(self) -> None:
        try:
            self.conn.execute(f"SELECT quack_stop('{self.uri}')")
        except Exception:
            pass
        self.conn.close()


def _new_db() -> duckdb.DuckDBPyConnection:
    """Open a fresh in-memory DB with both extensions loaded."""
    if not EXTENSION_PATH.exists():
        raise RuntimeError(
            f"quack_oauth extension not built at {EXTENSION_PATH} -- run 'make' first")

    conn = duckdb.connect(
        database=":memory:",
        config={
            "allow_unsigned_extensions": "true",
            # Keep the Python harness's DuckDB from disabling our extension
            # autoload paranoia -- we install quack from the official repo,
            # so it's signed.
            "autoinstall_known_extensions": "true",
            "autoload_known_extensions": "true",
        },
    )
    # `quack` from the public DuckDB community extension repo.
    # `quack` is expected to already be installed at
    # ~/.duckdb/extensions/v1.5.2/<platform>/quack.duckdb_extension
    # (operator runs `INSTALL quack;` once via the duckdb CLI).
    # `LOAD quack` works without re-installing.
    conn.execute("LOAD quack")
    # Our locally-built quack_oauth.
    conn.execute(f"LOAD '{EXTENSION_PATH}'")
    return conn


def start_server(
    *,
    realm_url: str,
    audience: str = "account",
    provider: str = "keycloak",
    seed_policy: bool = True,
    seed_audit: bool = True,
    bind_host: str = "127.0.0.1",
    trust_plaintext: bool = False,
    allow_other_hostname: bool = False,
) -> QuackServer:
    """Configure a server-side DuckDB and start the quack listener.

    The server SECRET uses the keycloak provider preset against `realm_url`
    (e.g. http://localhost:8080/realms/quack-test). Policy + audit tables
    are seeded if requested.
    """
    conn = _new_db()

    # 1. Server-side SECRET. Provider preset fills issuer + jwks_uri.
    audit_field = ", audit_table 'main.audit'" if seed_audit else ""
    policy_field = ", policy_table 'main.policies'" if seed_policy else ""
    conn.execute(f"""
        CREATE SECRET rs (
            TYPE quack_oauth_server,
            tenant_or_realm '{realm_url}',
            audience '{audience}'
            {policy_field}
            {audit_field}
        );
    """)
    conn.execute(f"SET quack_oauth_provider = '{provider}'")
    conn.execute("SET quack_oauth_server_secret_name = 'rs'")

    # 2. Policy table (R-S-7 / R-S-8) -- grant Scan + Attach to any token
    # with `email` scope (which Keycloak's default ROPC includes).
    if seed_policy:
        conn.execute("""
            CREATE TABLE main.policies (
                priority  INTEGER NOT NULL,
                subject   VARCHAR,
                any_scope VARCHAR[],
                actions   VARCHAR[],
                allow     BOOLEAN NOT NULL
            );
        """)
        conn.execute("""
            INSERT INTO main.policies VALUES
                (10, NULL, ['email'], ['Scan', 'Attach'], true);
        """)

    # 3. Audit table -- the extension INSERTs one row per auth decision.
    if seed_audit:
        conn.execute("""
            CREATE TABLE main.audit (
                timestamp_unix_s BIGINT,
                event_type       VARCHAR,
                subject          VARCHAR,
                issuer           VARCHAR,
                kid              VARCHAR,
                token_hash       VARCHAR,
                action           VARCHAR,
                reason           VARCHAR
            );
        """)

    # 4. Demo data the client will read.
    conn.execute("CREATE TABLE main.t AS SELECT * FROM range(0, 5) AS r(id)")

    # 5. Swap quack's auth callbacks for our extension's. These are
    # GLOBAL settings (see duckdb-quack/quack_extension.cpp), so they
    # apply to every connection on this DatabaseInstance.
    conn.execute("SET quack_authentication_function = 'quack_oauth_check_token'")
    conn.execute("SET quack_authorization_function  = 'quack_oauth_check_authorization'")

    # R-N-4 plaintext-guard opt-in. Defaults to false so a public-bound
    # listener gets refused unless the caller explicitly trusts it.
    if trust_plaintext:
        conn.execute("SET quack_oauth_trust_plaintext = true")

    # 6. Listen. quack_serve() spawns a background thread for the HTTP
    # listener and returns immediately; the connection stays open while
    # the test runs.
    port = find_free_port()
    uri = f"quack:{bind_host}:{port}"
    if allow_other_hostname:
        conn.execute(
            "SELECT * FROM quack_serve(?, token => ?, disable_ssl => true, allow_other_hostname => true)",
            [uri, SERVER_PSK],
        )
    else:
        conn.execute(
            "SELECT * FROM quack_serve(?, token => ?, disable_ssl => true)",
            [uri, SERVER_PSK],
        )

    return QuackServer(conn=conn, host=bind_host, port=port)


def open_client() -> duckdb.DuckDBPyConnection:
    """Open a fresh client-side DuckDB connection with both `quack`
    (wire protocol) and `quack_oauth` (so the client can use
    `quack_oauth_acquire(secret)` to mint a token inside ATTACH).
    """
    if not EXTENSION_PATH.exists():
        raise RuntimeError(f"quack_oauth extension not built at {EXTENSION_PATH}")
    conn = duckdb.connect(
        database=":memory:",
        config={
            "allow_unsigned_extensions": "true",
            "autoinstall_known_extensions": "true",
            "autoload_known_extensions": "true",
        },
    )
    # `quack` is expected to already be installed at
    # ~/.duckdb/extensions/v1.5.2/<platform>/quack.duckdb_extension
    # (operator runs `INSTALL quack;` once via the duckdb CLI).
    conn.execute("LOAD quack")
    conn.execute(f"LOAD '{EXTENSION_PATH}'")
    return conn
