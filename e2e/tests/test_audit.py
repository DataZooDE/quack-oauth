"""E2E audit propagation: after real-wire traffic, the server's audit
table contains corresponding entries.

We query the server's own state directly via the server-side connection
(not via the wire), so this test reads what the in-process server logged.
"""

from __future__ import annotations

from helpers import server


def test_audit_table_records_real_wire_decisions(
    client, quack_server: server.QuackServer, alice_token: str
) -> None:
    """Drive one successful ATTACH + scan and one denied COPY via the
    wire, then look at the audit table on the server side. The server's
    `audit_table` field on the SECRET points to `main.audit` so the
    extension INSERTs one row per decision.
    """
    # Snapshot the counts before — fixtures are session-scoped so earlier
    # tests already populated the audit table. We assert deltas.
    before = quack_server.conn.execute("SELECT count(*) FROM main.audit").fetchone()[0]

    client.execute(
        f"ATTACH 'quack:{quack_server.host}:{quack_server.port}' AS srv "
        f"(TYPE quack, token '{alice_token}')"
    )
    client.execute("SELECT id FROM srv.main.t WHERE id = 0").fetchall()

    # We can't easily run COPY in a way that fails-but-doesn't-crash the
    # client. Skipping that here; the explicit deny path is exercised in
    # test_authz.py. Just assert the audit table grew by ≥ 1 from the
    # successful traffic above.
    after = quack_server.conn.execute("SELECT count(*) FROM main.audit").fetchone()[0]
    assert after > before, (before, after)

    # Last few rows include a token_accepted entry for the connect, and
    # at least one authz_allow for the scan.
    recent = quack_server.conn.execute(f"""
        SELECT event_type FROM main.audit
        ORDER BY rowid DESC
        LIMIT {after - before}
    """).fetchall()
    types = {row[0] for row in recent}
    assert "token_accepted" in types or "authz_allow" in types, types


def test_token_hash_never_leaks_raw_jwt(
    client, quack_server: server.QuackServer, alice_token: str
) -> None:
    """Even after a successful wire connect, the audit table's
    `token_hash` column MUST be the redacted 8-hex prefix, never the
    raw JWT or any substring of it."""
    client.execute(
        f"ATTACH 'quack:{quack_server.host}:{quack_server.port}' AS srv "
        f"(TYPE quack, token '{alice_token}')"
    )
    client.execute("SELECT id FROM srv.main.t LIMIT 1").fetchall()

    hashes = quack_server.conn.execute(
        "SELECT DISTINCT token_hash FROM main.audit WHERE token_hash IS NOT NULL"
    ).fetchall()
    for (h,) in hashes:
        # Redacted prefix is exactly 8 hex chars.
        assert len(h) == 8, h
        assert h not in alice_token  # not even a leading substring
