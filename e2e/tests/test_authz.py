"""E2E AuthZ: with a valid token + a tightened policy, the wire query is
denied by `check_authorization` and the client sees an
'Authorization failed' error.

Note: the quack scan path rewrites client-side COPY/SELECT into
server-side SELECTs (see `BuildPushdownQuery` in duckdb-quack), so the
server's authz callback always classifies the action as Scan. To
exercise the deny branch we tighten the policy on the server's
in-process DB (a privileged side-channel) rather than try to send a
CopyTo over the wire.
"""

from __future__ import annotations

import duckdb
import pytest

from helpers import server


def test_scan_denied_after_subject_block(client, quack_server: server.QuackServer, alice_token: str) -> None:
    """Insert a higher-priority deny rule keyed on alice's subject, then
    issue a SELECT over the wire. The server's authz callback should
    return false (the deny rule matches first), and quack should reply
    'Authorization failed'.
    """
    # 1. Find alice's subject (the `sub` claim) -- the server already
    #    cached it after a previous successful connect in another test
    #    or we drive a fresh connect here.
    client.execute(
        f"ATTACH 'quack:{quack_server.host}:{quack_server.port}' AS srv_pre "
        f"(TYPE quack, token '{alice_token}')"
    )
    client.execute("SELECT id FROM srv_pre.main.t LIMIT 1").fetchall()

    # Grab alice's `sub` from the server-side principal cache. Easier path:
    # read it from the audit table (it's been recorded there).
    alice_sub = quack_server.conn.execute(
        "SELECT subject FROM main.audit "
        "WHERE event_type = 'token_accepted' AND subject IS NOT NULL "
        "ORDER BY rowid DESC LIMIT 1"
    ).fetchone()
    assert alice_sub is not None and alice_sub[0]
    alice_sub_str = alice_sub[0]

    # 2. Insert an explicit deny rule for alice (lower priority number
    #    => higher precedence, first match wins).
    quack_server.conn.execute(
        "INSERT INTO main.policies VALUES (?, ?, NULL, NULL, ?)",
        [1, alice_sub_str, False],
    )

    try:
        # 3. Fresh ATTACH so we get a fresh session_id. ATTACH itself
        #    issues schema-discovery queries over the wire (which the
        #    server runs through check_authorization), so the deny fires
        #    here -- which is exactly the proof we want: a denied scan
        #    over a real wire propagates back to the client.
        with pytest.raises(duckdb.Error) as excinfo:
            client.execute(
                f"ATTACH 'quack:{quack_server.host}:{quack_server.port}' AS srv_deny "
                f"(TYPE quack, token '{alice_token}')"
            )
            # Defensive: if ATTACH succeeded (some quack versions defer
            # schema-discovery), force a wire query.
            client.execute("SELECT id FROM srv_deny.main.t LIMIT 1").fetchall()
        msg = str(excinfo.value).lower()
        assert "authoriz" in msg or "denied" in msg or "rule deny" in msg, \
            f"unexpected error: {excinfo.value}"
    finally:
        # Always clean up the deny rule, even on failure -- other tests
        # share this policy table.
        quack_server.conn.execute(
            "DELETE FROM main.policies WHERE priority = 1 AND subject = ?",
            [alice_sub_str],
        )
