# quack-oauth E2E harness

Real `quack` server with our extension's callbacks swapped in, exercised
by a Python DuckDB client over the quack wire protocol.

## Prerequisites

- `uv` ([install](https://github.com/astral-sh/uv))
- `docker compose` (for the Keycloak fixture)
- Project built: `make` at the repo root
- `quack` installed once via the duckdb CLI:

  ```bash
  duckdb -c "INSTALL quack;"
  ```

  This drops `quack.duckdb_extension` into `~/.duckdb/extensions/v1.5.3/<platform>/`
  where the Python `duckdb` package and our harness pick it up via `LOAD quack`.

## Run

From the project root:

```bash
make e2e
```

Or directly:

```bash
cd e2e
uv sync
uv run pytest -v
```

The first run brings the Keycloak compose up (session-scoped fixture);
subsequent runs in the same shell reuse it. Container is torn down on
test-session exit.

## Layout

```
e2e/
├── pyproject.toml           # uv project: duckdb, pytest, pytest-timeout
├── conftest.py              # keycloak / server / client fixtures
├── helpers/
│   ├── keycloak.py          # docker compose lifecycle + ROPC + JWT tamper
│   └── server.py            # in-process quack server fixture
└── tests/
    ├── test_handshake.py    # listener up + happy-path Scan
    ├── test_authn.py        # tampered + garbage tokens rejected
    ├── test_authz.py        # subject-targeted deny rule propagates
    └── test_audit.py        # audit table grows; token_hash redacted
```
