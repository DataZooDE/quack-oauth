"""Native host isolation regressions with a synthetic loopback IdP.

Run: python3 -m unittest discover -s test/security -v
The C++ driver seeds through the production native authentication API, while
ordinary SQL calls remain the operations under test. No quack server is involved.
"""

import json
import os
from pathlib import Path
import threading
import time
import unittest
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs
from uuid import uuid4

os.environ["DATAZOO_DISABLE_TELEMETRY"] = "1"


DRIVER = Path(os.environ.get(
    "QUACK_OAUTH_SECURITY_DRIVER",
    str(Path(__file__).resolve().parents[2] / "build/release/test/quack_oauth_security_tests"),
)).resolve()


class SessionIsolationTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(DRIVER.is_file(), f"Build native security driver first: {DRIVER}")
        marker = uuid4().hex
        self.subject = f"owner-{marker}"
        self.other_subject = f"other-{marker}"
        self.owner_token = f"synthetic-owner-{marker}"
        self.other_token = f"synthetic-other-{marker}"
        self.claims = {
            self.owner_token: (self.subject, "quack:read"),
            self.other_token: (self.other_subject, "quack:write"),
        }
        claims = self.claims

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                token = parse_qs(body.decode()).get("token", [""])[0]
                identity = claims.get(token)
                response = {"active": False}
                if identity:
                    response = {
                        "active": True, "sub": identity[0], "scope": identity[1],
                        "iss": "https://isolation.test", "aud": "isolation-test",
                        "exp": int(time.time()) + 600,
                    }
                payload = json.dumps(response).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.shutdown)

        self.endpoint = f"http://127.0.0.1:{server.server_port}/introspect"

    def run_case(self, case):
        result = subprocess.run(
            [str(DRIVER), case, self.endpoint, self.owner_token, self.other_token,
             self.subject, self.other_subject],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"PASS {case}", result.stdout)


CASES = (
    "unrelated_database_cannot_read_principal",
    "unrelated_database_cannot_read_audit",
    "unrelated_database_cannot_replace_principal",
    "same_database_unbound_connection_cannot_read_principal",
    "same_database_distinct_sessions_cannot_read_each_others_principal",
    "same_database_distinct_sessions_cannot_read_each_others_audit",
    "same_database_connection_cannot_replace_principal",
    "sql_validation_cannot_create_session_principal",
    "closing_owner_connection_revokes_session",
    "closing_owner_database_revokes_session",
    "one_argument_validation_preserves_principal",
    "invalid_token_cannot_replace_principal",
    "failed_native_reauthentication_revokes_principal",
    "native_configuration_error_revokes_principal",
    "validation_caches_are_database_local",
    "connection_cannot_be_rebound_to_another_session",
    "authorization_cannot_select_another_sessions_principal",
)


def make_test(case):
    def test(self):
        self.run_case(case)
    return test


for case in CASES:
    setattr(SessionIsolationTests, f"test_{case}", make_test(case))


if __name__ == "__main__":
    unittest.main()
