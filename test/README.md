# Testing this extension
This directory contains all the tests for this extension. The `sql` directory holds tests that are written as [SQLLogicTests](https://duckdb.org/dev/sqllogictest/intro.html). DuckDB aims to have most its tests in this format as SQL statements, so for the quack extension, this should probably be the goal too.

The root makefile contains targets to build and run all of these tests. To run the SQLLogicTests:
```bash
make test
```
or 
```bash
make test_debug
```

The native security regression suite runs separately:

```bash
cmake --build build/release --target quack_oauth_security_tests -j 4
python3 -m unittest discover -s test/security -v
```

The Python harness uses only the standard library. It starts a synthetic
loopback introspection provider and runs the C++ driver against the built
extension code. Override the driver path with `QUACK_OAUTH_SECURITY_DRIVER`.
Localhost socket permission is required; no external IdP or quack server is used.
Telemetry is disabled.

The original 12 cases retain their isolation assertions. Setup now uses the
production native authentication API instead of the SQL interface being
restricted. Each case first verifies successful authentication, the owner's
identity and scopes, an audit event, an allowed read, and a denied write.
Shared-database cases also verify a shared table. Peer authentication verifies
its distinct identity and write permission. Cleanup cases check destruction of
session state using a weak reference, in addition to authorization denial.
Five additional cases cover failed native reauthentication, configuration errors,
session rebinding, cross-session authorization lookup, and database-local caches.
No trusted SQL seeding hook is shipped.

Coverage includes cross-database and same-database disclosure, principal
replacement, ordinary SQL principal creation, lifecycle cleanup, and the
one-argument/invalid-token controls. A separate SQL regression checks audit
isolation and legacy callback denial through ordinary SQL connections.

No privileged read API is introduced: broader audit access remains the host's
responsibility through existing operator-managed sinks. Remote reachability
and the separate quack-server cross-session query-access claim are not verified
by this suite. Legacy quack E2E success tests require native integration changes;
see [the migration contract](../docs/SESSION_ISOLATION.md).
