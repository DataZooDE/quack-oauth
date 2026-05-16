"""Server boot: in-process DuckDB + quack + quack_oauth + listener +
aiohttp front end.

One process, one CLI invocation. Holds the DuckDB connection open as
long as the aiohttp event loop runs. The quack listener is a thread
spawned by `quack_serve()` inside the connection.
"""

from __future__ import annotations

import logging
import os
import secrets
import socket
import sys
from pathlib import Path

import duckdb
from dotenv import load_dotenv

from . import http_app
from . import taxi_data

log = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
EXTENSION_LOCAL_PATH = (
    PROJECT_ROOT
    / "build"
    / "release"
    / "extension"
    / "quack_oauth"
    / "quack_oauth.duckdb_extension"
)


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _open_db() -> duckdb.DuckDBPyConnection:
    """In-memory DuckDB with both extensions loaded.

    `quack` and `quack_oauth` are pulled from get.erpl.io's
    `customExtensionRepository` shape by default. If
    QUACK_OAUTH_LOCAL=1 is set, the freshly-built loadable extension
    in `build/release/...` is loaded directly -- handy for iterating
    on the extension itself.
    """
    conn = duckdb.connect(
        database=":memory:",
        config={
            "allow_unsigned_extensions": "true",
            "autoinstall_known_extensions": "true",
            "autoload_known_extensions": "true",
            "custom_extension_repository": "http://get.erpl.io",
        },
    )
    # quack comes from the official community repo; quack_oauth from get.erpl.io.
    conn.execute("INSTALL quack;")
    conn.execute("LOAD quack;")
    if os.environ.get("QUACK_OAUTH_LOCAL") == "1":
        if not EXTENSION_LOCAL_PATH.exists():
            raise SystemExit(
                f"QUACK_OAUTH_LOCAL=1 set but {EXTENSION_LOCAL_PATH} not built. "
                f"Run `GEN=ninja make` at the repo root first."
            )
        conn.execute(f"LOAD '{EXTENSION_LOCAL_PATH}'")
    else:
        conn.execute("INSTALL quack_oauth FROM 'http://get.erpl.io';")
        conn.execute("LOAD quack_oauth;")
    return conn


def _configure_oauth_server(
    conn: duckdb.DuckDBPyConnection, client_id: str, client_secret: str
) -> None:
    """Server-side SECRET + policy + audit + global callback wiring.

    `tenant_or_realm` carries the GitHub OAuth App's client_id.
    `introspect_client_id` is intentionally OMITTED -- the github
    preset (commit d5d5cb5) defaults it to `tenant_or_realm`, so the
    SECRET shape is one field shorter than the README's pre-fix form.
    """
    conn.execute(
        """
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
        """
    )
    conn.execute(
        """
        CREATE TABLE main.policies (
            priority  INTEGER NOT NULL,
            subject   VARCHAR,
            any_scope VARCHAR[],
            actions   VARCHAR[],
            allow     BOOLEAN NOT NULL
        );
        """
    )
    # User-token scope `read:user` is the one we ask for in the OAuth flow.
    conn.execute(
        "INSERT INTO main.policies VALUES "
        "(10, NULL, ['read:user'], ['Attach', 'Scan'], true);"
    )

    conn.execute(
        f"""
        CREATE SECRET rs (
            TYPE quack_oauth_server,
            tenant_or_realm          '{client_id}',
            introspect_client_secret '{client_secret}',
            audience                 'quack-oauth-demo',
            policy_table             'main.policies',
            audit_table              'main.audit'
        );
        """
    )
    conn.execute("SET quack_oauth_provider = 'github'")
    conn.execute("SET quack_oauth_server_secret_name = 'rs'")
    conn.execute("SET quack_authentication_function = 'quack_oauth_check_token'")
    conn.execute("SET quack_authorization_function  = 'quack_oauth_check_authorization'")


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s %(message)s",
    )

    # Load .env.demo (cwd or example/) -- python-dotenv tolerates absence.
    load_dotenv(Path(__file__).resolve().parents[1] / ".env.demo")
    client_id = os.environ.get("GITHUB_DEMO_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GITHUB_DEMO_CLIENT_SECRET", "").strip()
    front_port = int(os.environ.get("GITHUB_DEMO_PORT", "8000"))

    if not client_id or not client_secret:
        print(
            "FAIL: GITHUB_DEMO_CLIENT_ID and GITHUB_DEMO_CLIENT_SECRET must be set\n"
            "      Copy example/.env.demo.example to example/.env.demo and fill in",
            file=sys.stderr,
        )
        return 2

    log.info("[boot] opening DuckDB + loading quack + quack_oauth")
    conn = _open_db()

    log.info("[boot] loading NYC taxi data")
    taxi_data.ensure_loaded(conn)

    log.info("[boot] wiring github auth + policy + audit")
    _configure_oauth_server(conn, client_id, client_secret)

    quack_port = _find_free_port()
    quack_uri = f"quack:127.0.0.1:{quack_port}"
    # The quack server token is a defence-in-depth shared secret; the
    # OAuth path ignores it (only the default `quack_check_token`
    # compares against it). We pick something random anyway.
    psk = secrets.token_urlsafe(16)
    log.info("[boot] starting quack listener on %s", quack_uri)
    conn.execute(
        "SELECT * FROM quack_serve(?, token => ?, disable_ssl => true)",
        [quack_uri, psk],
    )

    redirect_uri = f"http://localhost:{front_port}/oauth/callback"
    cfg = http_app.AppConfig(
        github_client_id=client_id,
        github_client_secret=client_secret,
        redirect_uri=redirect_uri,
        quack_port=quack_port,
    )

    log.info(
        "[boot] frontend listening on http://localhost:%d  (quack proxy -> %s)",
        front_port,
        quack_uri,
    )
    log.info("[boot] open http://localhost:%d in your browser", front_port)
    try:
        http_app.run(front_port, cfg)
    except KeyboardInterrupt:
        log.info("ctrl-c received, shutting down")
    finally:
        try:
            conn.execute(f"SELECT quack_stop('{quack_uri}')")
        except Exception:
            pass
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
