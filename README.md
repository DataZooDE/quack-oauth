# quack-oauth

[![CI](https://github.com/DataZooDE/quack-oauth/actions/workflows/MainDistributionPipeline.yml/badge.svg)](https://github.com/DataZooDE/quack-oauth/actions/workflows/MainDistributionPipeline.yml)

DuckDB extension that adds **OAuth 2.1 / OIDC** authentication and a
claims-driven authorization model to the [`duckdb-quack`][quack]
client/server protocol. Replaces quack's stub auth callbacks with real
JWKS-signature / RFC 7662 introspection / Google-style tokeninfo
validation, then applies a policy (default-scope-based, or a SQL table
inside your server's DuckDB) to gate ATTACH / SELECT / COPY operations.

[quack]: https://github.com/duckdb/duckdb-quack

> **Status**: end-to-end green against live Keycloak — including
> real-client → real-server traffic through the quack wire protocol.
> JWKS, introspection, client_credentials, refresh, device_code,
> default policy, SQL-table policy, audit. Recorded-replay coverage
> for Microsoft Entra and Google. wasm32 source-side gating in place;
> CI wasm matrix pending.

## Why

`duckdb-quack` lets one DuckDB instance serve another over a wire
protocol. The protocol exposes two callback hooks — authentication and
authorization — but ships stubs (`quack_check_token` does a shared-
secret comparison; `quack_nop_authorization` always allows). For
anything past a single-tenant homelab you need real auth: signature
verification against an IdP, claim-based decisions, audit. This
extension is that layer.

Concretely, after `LOAD quack_oauth` and a one-line callback swap:

- Clients present a normal OAuth bearer JWT on `ATTACH` (`token` option).
- The server validates it against your IdP every connect, caches the
  Principal by `session_id`, and applies a policy on every request.
- Policy rules live as **SQL rows** in your server's own DuckDB — no
  YAML, no parser, no restart. `INSERT INTO policies` and the next
  query sees the new rule.
- Every decision lands in an in-memory audit ring and (optionally) a
  SQL audit table, with the bearer token redacted to an 8-hex SHA-256
  prefix.

## Try the demo

The shortest path from `git clone` to seeing it work end-to-end:

```bash
# 1. Build (~10 min the first time; uses vcpkg).
export VCPKG_ROOT=/path/to/vcpkg
export VCPKG_TOOLCHAIN_PATH=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
GEN=ninja make

# 2. Run the demo. Brings up Keycloak via docker compose, mints a real
# token for alice, configures the server SECRET + a SQL policy table,
# exercises allow + deny paths, prints the audit log + diagnose() output,
# tears the container down.
make demo
```

What it prints in the middle — real-server behaviour, not stubs:

```
┌────────────────┬──────────────────────────────────────┬────────────┬──────────────┐
│   event_type   │               subject                │   action   │    reason    │
├────────────────┼──────────────────────────────────────┼────────────┼──────────────┤
│ authz_allow    │ 8493df4b-b692-4581-a291-7be11cd1b6bd │ Scan       │ rule allow   │
│ authz_allow    │ 8493df4b-b692-4581-a291-7be11cd1b6bd │ Attach     │ rule allow   │
│ authz_deny     │ 8493df4b-b692-4581-a291-7be11cd1b6bd │ CopyTo     │ default deny │
│ authz_deny     │ 8493df4b-b692-4581-a291-7be11cd1b6bd │ ServeAdmin │ default deny │
│ token_accepted │ 8493df4b-b692-4581-a291-7be11cd1b6bd │ NULL       │ ok           │
└────────────────┴──────────────────────────────────────┴────────────┴──────────────┘
```

## Quick start (production shape)

```sql
-- 1. Install + load (build from source today; binary distribution pending).
LOAD quack;
LOAD quack_oauth;

-- 2. Tell quack to use our callbacks.
SET quack_authentication_function = 'quack_oauth_check_token';
SET quack_authorization_function  = 'quack_oauth_check_authorization';

-- 3. Configure the resource server (IdP coordinates). Provider preset
-- fills issuer + jwks_uri for keycloak / entra / google / okta / github.
CREATE SECRET rs (
    TYPE quack_oauth_server,
    tenant_or_realm 'https://keycloak.example.com/realms/prod',
    audience        'my-quack-api',
    policy_table    'main.policies',
    audit_table     'main.audit'
);
SET quack_oauth_provider = 'keycloak';
SET quack_oauth_server_secret_name = 'rs';

-- 4. Define the policy as a SQL table.
CREATE TABLE main.policies (
    priority  INTEGER NOT NULL,
    subject   VARCHAR,
    any_scope VARCHAR[],
    actions   VARCHAR[],
    allow     BOOLEAN NOT NULL
);
INSERT INTO main.policies VALUES
    (10, NULL, ['quack:read'],  ['Attach', 'Scan'],                       true),
    (20, NULL, ['quack:write'], ['Attach', 'Scan', 'CopyTo', 'CopyFrom'], true);

-- 5. (Optional) persistent audit log.
CREATE TABLE main.audit (
    timestamp_unix_s BIGINT, event_type VARCHAR, subject VARCHAR,
    issuer VARCHAR, kid VARCHAR, token_hash VARCHAR,
    action VARCHAR, reason VARCHAR
);

-- 6. Listen.
SELECT * FROM quack_serve('quack:0.0.0.0:9494');
```

On the **client** side:

```sql
LOAD quack;

ATTACH 'quack:server.example.com:9494' AS srv (
    TYPE quack,
    token 'eyJhbGciOiJSUzI1NiIs…'    -- a real bearer JWT from your IdP
);

SELECT * FROM srv.main.t;            -- ← policy decides; audit row appended
```

## Features

- **Three validation modes**, picked per server SECRET:
  - `jwks` (default): local JWT signature check against the IdP's JWKS endpoint, per-`kid` cache, rate-limited refresh.
  - `introspect`: RFC 7662 token introspection POST, positive-decision cache capped at token `exp`. Negative decisions never cached.
  - `tokeninfo`: Google-style opaque-token endpoint (numbers-as-strings tolerated, no Basic auth, no `active` field).
- **Provider presets** for `entra`, `google`, `keycloak`, `okta`, `github`, `generic`. `tenant_or_realm` on the SECRET + `quack_oauth_provider` setting auto-fills issuer / JWKS / introspection URIs.
- **Client-side OAuth flows**: `client_credentials` (RFC 6749 §4.4), `refresh_token` (RFC 6749 §6), `device_code` (RFC 8628 with `slow_down` back-off + full §3.5 error mapping).
- **SQL-native authorization policy**:
  - Default policy from R-S-8: `quack:read` → Attach + Scan; `quack:write` → also CopyTo + CopyFrom; `ServeAdmin` always denied.
  - Optional SQL-table policy at `policy_table` on the server SECRET — rules are rows in a regular DuckDB table. First-match-wins by ascending `priority`. The `quack_oauth_policy_default` setting (`'allow'` / `'deny'`, default `'deny'`) controls the no-match fallback.
  - **Fail-closed**: if `policy_table` is set but the `SELECT` fails (missing table, wrong schema, invalid action name), every call denies.
  - **Hot updates**: `INSERT` / `UPDATE` / `DELETE` against the policy table — next request picks them up; no restart, no file watch.
- **SQL action detection**: classifies the incoming query (ATTACH / Scan / CopyTo / CopyFrom / ServeAdmin) so the policy can gate per-action.
- **Audit trail** for every decision: in-memory `quack_oauth_audit_log()` ring + DuckDB `Logger` lines (INFO for allows, WARNING for denies) + optional `audit_table` on the SECRET for SQL-queryable persistence. The bearer token is redacted to an 8-hex SHA-256 prefix; the raw JWT never appears.
- **Self-documenting**: every function carries `description`, `parameter_names`, `parameter_types`, `examples`, `categories` — visible in `duckdb_functions()`.
- **Secrets-first**: every credential lives on a typed SECRET, with redaction in trace output (`client_secret`, `access_token`, `refresh_token`, `introspect_client_secret`).
- **Diagnose**: `SELECT * FROM quack_oauth_diagnose()` reports config, JWKS / decision / session caches, and a per-event-type tally of the audit ring.

## API reference

See **[API_REFERENCE.md](API_REFERENCE.md)** for the complete reference:
all scalar / table functions, SECRET types, settings, with parameters,
return types, and examples. The same descriptions are also queryable in
DuckDB itself:

```sql
SELECT function_name, description, parameters, examples
FROM duckdb_functions()
WHERE function_name LIKE 'quack_oauth%';
```

## Building

### Prerequisites

- a C++17 toolchain (gcc 11+, clang 14+, msvc 2022)
- CMake 3.10+
- ninja (recommended — every sibling DuckDB extension uses it and `make` without it is 2–3× slower)
- a [vcpkg](https://github.com/microsoft/vcpkg) checkout

### Build

```bash
export VCPKG_ROOT=/path/to/vcpkg
export VCPKG_TOOLCHAIN_PATH=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
GEN=ninja make                 # release, the usual dev loop
GEN=ninja make debug           # debug build (ASAN, lldb, etc.)
```

The first build takes a while because vcpkg fetches + builds openssl,
jwt-cpp, picojson, and Catch2. Incremental builds are seconds with
ninja.

Artifacts:

- `build/release/duckdb` — a DuckDB shell with the extension statically linked
- `build/release/extension/quack_oauth/quack_oauth.duckdb_extension` — the loadable binary
- `build/release/test/unittest` — DuckDB SQL test runner
- `build/release/test/quack_oauth_unit_tests` — Catch2 pure-logic unit tests

## Testing

Two layers + three integration suites — see
[docs/IMPLEMENTATION.md §2](docs/IMPLEMENTATION.md) for the policy.

```bash
make unit_test            # Catch2 pure-logic tests (~580 assertions)
make test                 # SQL tests via DuckDB's unittest runner
make smoke_static         # verify static-linkage allowlist
make integration_keycloak # end-to-end against live Keycloak (docker compose)
make integration_google   # end-to-end against live Google (needs GCP service-account JSON)
make e2e                  # real-quack-in-front Python + uv harness
make demo                 # interactive quickstart (Keycloak + allow + deny + audit)
```

SQL tests are the source of truth (no mocks, real DuckDB load path).
Catch2 is restricted to pure logic with no DuckDB linkage. The Python
`e2e/` harness drives a real quack server through the wire protocol,
exercising the wiring no in-process test can.

## Documentation

- **[API_REFERENCE.md](API_REFERENCE.md)** — complete function / SECRET / setting reference.
- **[requirements.md](requirements.md)** — functional spec.
- **[architecture.md](architecture.md)** — arc42 design doc.
- **[docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md)** — TDD discipline, test layering, slice plan.
- **[e2e/README.md](e2e/README.md)** — how the Python harness is wired.
- **[CLAUDE.md](CLAUDE.md)** — local dev / workflow guide; non-obvious gotchas captured by past sessions.

## License

MIT (matching the DuckDB extension template baseline).
