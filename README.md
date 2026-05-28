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
> for Microsoft Entra and Google.

## Quick install

Install with two lines of DuckDB SQL (DuckDB must be started with the
`-unsigned` flag, since the extension binary is not signed by the
DuckDB Foundation):

```sql
INSTALL 'quack_oauth' FROM 'http://get.erpl.io';
LOAD 'quack_oauth';
```

This pulls the right binary for your platform from our public
distribution bucket (Linux amd64/arm64, macOS amd64/arm64, Windows
amd64, plus the wasm32 trio). No build toolchain, no vcpkg, no
submodules required.

[Building from source](#building-from-source) is documented at the
bottom of this file for contributors and packagers.

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

```bash
git clone https://github.com/DataZooDE/quack-oauth
cd quack-oauth
make demo
```

The demo brings up Keycloak via docker-compose, mints a real token,
configures the server SECRET + a SQL policy table, exercises allow +
deny paths, prints the audit log + `diagnose()` output, then tears the
container down.

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
-- 1. Install + load.
INSTALL 'quack_oauth' FROM 'http://get.erpl.io';
LOAD 'quack';
LOAD 'quack_oauth';

-- 2. Tell quack to use our callbacks.
SET quack_authentication_function = 'quack_oauth_check_token';
SET quack_authorization_function  = 'quack_oauth_check_authorization';

-- 3. Configure the resource server (IdP coordinates). Provider preset
-- fills issuer + jwks_uri for keycloak / entra / google / github.
CREATE SECRET rs (
    TYPE quack_oauth_server,
    tenant_or_realm 'https://keycloak.example.com/realms/prod',
    audience        'my-quack-api',
    policy_table    'main.policies',
    audit_table     'main.audit'
);
SET quack_oauth_provider           = 'keycloak';
SET quack_oauth_server_secret_name = 'rs';

-- 4. Define the policy as a SQL table. (See the Authorization section
-- below for the schema and semantics.)
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
-- One-time setup: install + create a persistent client SECRET that
-- holds the IdP coordinates. Survives DuckDB restarts.
INSTALL 'quack_oauth' FROM 'http://get.erpl.io';
LOAD 'quack';
LOAD 'quack_oauth';

CREATE PERSISTENT SECRET cli (
    TYPE quack_oauth,
    token_endpoint 'https://keycloak.example.com/realms/prod/protocol/openid-connect/token',
    client_id      'my-client-id',
    client_secret  'my-client-secret',
    scope          'openid quack:read'
);
```

```sql
-- Every connect: ATTACH calls quack_oauth_acquire() to mint (or reuse)
-- a fresh access token automatically. No JWT pasting, no manual refresh.
ATTACH 'quack:server.example.com:9494' AS srv (
    TYPE quack,
    token quack_oauth_acquire('cli')
);

SELECT * FROM srv.main.t;            -- ← policy decides; audit row appended
```

## Configuring providers

`quack_oauth` ships presets for the common IdPs. Set
`quack_oauth_provider` to the preset name and put a `tenant_or_realm`
field on the server SECRET — the extension auto-fills `issuer`,
`jwks_uri`, and (where applicable) `introspection_endpoint` from the
provider's templates. Explicit SECRET fields always win, so you can
override any single URL.

Supported presets: **`keycloak`**, **`entra`**, **`google`**,
**`github`**, **`okta`** (reserved — use `generic` today), **`generic`**.

### Keycloak (JWKS, default mode)

`tenant_or_realm` is the **full base URL of the realm**, since the
host varies per deployment.

```sql
CREATE SECRET rs (
    TYPE quack_oauth_server,
    tenant_or_realm 'https://keycloak.example.com/realms/prod',
    audience        'my-quack-api'
);
SET quack_oauth_provider           = 'keycloak';
SET quack_oauth_server_secret_name = 'rs';
```

Resolved internally to:
- `issuer = https://keycloak.example.com/realms/prod`
- `jwks_uri = https://keycloak.example.com/realms/prod/protocol/openid-connect/certs`
- `introspection_endpoint = https://keycloak.example.com/realms/prod/protocol/openid-connect/token/introspect`

### Microsoft Entra ID (JWKS)

`tenant_or_realm` is the **tenant GUID** (or `common`, `organizations`,
`consumers`).

**Two things you'll trip over:**

1. **Custom API + app role required.** Tokens with
   `scope=https://graph.microsoft.com/.default` are NOT third-party-
   verifiable — Entra signs them so only Graph can validate. Set up:
   `App registration → Expose an API → set Application ID URI` and
   `App registration → App roles → Create app role` (Allowed member
   types: **Applications**). Request tokens with
   `scope=api://<your-client-id>/.default` instead.
2. **v1.0 vs v2.0 audience format.** v2.0 access tokens (default for
   new app registrations + manifest `requestedAccessTokenVersion: 2`)
   carry `aud = <client-id-GUID>` — bare GUID, no `api://` prefix.
   v1.0 tokens carry `aud = api://<client-id-GUID>`. The `audience`
   field on the SECRET must match exactly whatever the token actually
   contains.

For v2.0 tokens (recommended):

```sql
CREATE SECRET rs (
    TYPE quack_oauth_server,
    tenant_or_realm '12345678-1234-1234-1234-123456789abc',
    audience        '22222222-2222-2222-2222-222222222222'    -- bare client_id
);
SET quack_oauth_provider           = 'entra';
SET quack_oauth_server_secret_name = 'rs';
```

For v1.0 tokens you also need to override the issuer (preset assumes
v2.0):

```sql
CREATE SECRET rs (
    TYPE quack_oauth_server,
    tenant_or_realm '12345678-1234-1234-1234-123456789abc',
    audience        'api://22222222-2222-2222-2222-222222222222',  -- with api:// prefix
    issuer          'https://sts.windows.net/12345678-1234-1234-1234-123456789abc/'
);
```

The preset (v2.0) resolves internally to:
- `issuer = https://login.microsoftonline.com/<tenant>/v2.0`
- `jwks_uri = https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys`

**App-only flows (client_credentials) populate `roles`, not `scope`.**
Policy rules for service-to-service callers therefore name the role:

```sql
INSERT INTO main.policies VALUES
    (10, NULL, ['quack.access'], ['Attach', 'Scan'], true);
    --        ^ the role's `value` from the App roles definition
```

### Google (tokeninfo, opaque tokens)

Google access tokens are **opaque** (not JWTs). The preset routes
validation through Google's `tokeninfo` endpoint. `tenant_or_realm` is
unused; just leave it off.

```sql
CREATE SECRET rs (
    TYPE quack_oauth_server,
    audience '1234567890-abc123.apps.googleusercontent.com'
);
SET quack_oauth_provider           = 'google';
SET quack_oauth_validation_mode    = 'tokeninfo';
SET quack_oauth_server_secret_name = 'rs';
```

Resolved internally to:
- `introspection_endpoint = https://oauth2.googleapis.com/tokeninfo`

### GitHub (github_check)

GitHub access tokens are **opaque** and validated against
`/applications/{client_id}/token` with the App's credentials as HTTP
Basic. `tenant_or_realm` is the **App's `client_id`**.

```sql
CREATE SECRET rs (
    TYPE quack_oauth_server,
    tenant_or_realm           'Iv1.abc123...',           -- GitHub App client_id
    introspect_client_secret  '<github-app-client-secret>',
    audience                  'my-quack-api'
);
SET quack_oauth_provider           = 'github';
SET quack_oauth_server_secret_name = 'rs';
-- The 'github' preset auto-flips validation_mode to 'github_check'
-- and auto-fills introspect_client_id from tenant_or_realm (R-S-13).
```

### Generic (no preset)

For any IdP without a preset (Auth0, Cognito, custom OIDC, …), set
`provider = 'generic'` and configure every URL on the SECRET
explicitly:

```sql
CREATE SECRET rs (
    TYPE quack_oauth_server,
    issuer                   'https://idp.example.com/',
    jwks_uri                 'https://idp.example.com/.well-known/jwks.json',
    introspection_endpoint   'https://idp.example.com/oauth2/introspect',
    introspect_client_id     'my-rs',
    introspect_client_secret 'shh',
    audience                 'my-quack-api'
);
SET quack_oauth_provider           = 'generic';
SET quack_oauth_server_secret_name = 'rs';
```

### Override the validation mode

By default the preset picks the mode (`keycloak`/`entra` → `jwks`,
`google` → `tokeninfo`, `github` → `github_check`). You can override:

```sql
SET quack_oauth_validation_mode = 'introspect';   -- force RFC 7662
```

Modes:

| `validation_mode` | What it does | Cache behaviour |
|---|---|---|
| `jwks` *(default)* | Local JWT signature check against the IdP's JWKS endpoint, per-`kid` cache, rate-limited refresh. Zero round-trip on warm cache. | JWKS cached by `kid`. |
| `introspect` | RFC 7662 POST to the introspection endpoint. Useful for confidential clients that need a hot-revocable token. | Positive decisions cached up to token `exp`. Negatives never cached. |
| `tokeninfo` | Google-style opaque-token validation. Tolerates Google's quirks (numbers-as-strings, no `active` field, no Basic auth). | Same caching as introspect. |
| `github_check` | `/applications/{client_id}/token` with HTTP Basic. Auto-selected by `provider = 'github'`. | Same caching as introspect. |

## Authorization

Authorization runs **after** authentication on every request that
quack forwards. The principal extracted from the JWT (`subject`,
`issuer`, `scopes`, `exp`) is paired with an **action** detected from
the SQL of the incoming request, and a policy decides allow / deny.

### Actions

The action is parsed from the request's SQL by DuckDB's own parser
(no regex / keyword sniffing — the same parser DuckDB itself uses
when executing the statement). The classified `Action` enum gates
the policy:

| Action | Triggered by |
|---|---|
| `Attach` | `ATTACH 'quack:…' AS …` |
| `Scan` *(default for reads)* | `SELECT`, `WITH`, `EXPLAIN`, `SHOW`, `RELATION` |
| `Insert` | `INSERT INTO …` |
| `Update` | `UPDATE … SET …` |
| `Delete` | `DELETE FROM …` |
| `Ddl` | `CREATE`, `DROP`, `ALTER`, `TRANSACTION`, `CREATE FUNCTION` |
| `CopyTo` | `COPY <t> TO '…'` |
| `CopyFrom` | `COPY <t> FROM '…'` |
| `Pragma` | `PRAGMA <not-quack>`, `SET`, `LOAD` |
| `ServeAdmin` | `PRAGMA quack_serve` / `quack_stop` / `quack_restart` |

In addition to the action, the parser walks the statement and
collects:

- **`objects`** — the schema-qualified tables / views the statement
  touches (`main.audit`, `main.trips_enriched`, …). System tables
  (`information_schema.*`, `pg_catalog.*`, `duckdb_*`) are filtered
  out. Subqueries, CTEs, and JOINs are walked recursively.
- **`columns`** — the unqualified column names a SELECT projects.
  `SELECT *` produces the sentinel `*`.

Policy rules can target these. See "SQL-table policy: schema"
below.

### Two layers of policy

There are two policies; the SECRET decides which is active:

1. **Default scope-based policy** (R-S-8) — applied when `policy_table`
   is **not** set on the active server SECRET. Hard-coded:

   | Scope on the JWT | Allowed actions |
   |---|---|
   | `quack:read` | `Attach`, `Scan` |
   | `quack:write` | `Attach`, `Scan`, `Insert`, `Update`, `Delete`, `CopyTo`, `CopyFrom` |
   | (anything else) | nothing |
   | (`Ddl` / `Pragma` / `ServeAdmin`) | **always denied** |

   Good for prototyping; locked at compile time. Object + column
   gating is not available here — that's the SQL-table policy below.

2. **SQL-table policy** — set `policy_table` on the SECRET to a
   qualified table name (e.g. `main.policies`). Rules are rows. Hot-
   reloadable. **This is the recommended production setup.**

### SQL-table policy: schema

```sql
CREATE TABLE main.policies (
    priority       INTEGER NOT NULL, -- ascending; lower = earlier
    subject        VARCHAR,          -- NULL = match any subject
    any_scope      VARCHAR[],        -- NULL/empty = match any scope set
    actions        VARCHAR[],        -- NULL/empty = match any action
    object_pattern VARCHAR,          -- NULL = match any object; glob: 'main.*'
    column_pattern VARCHAR,          -- NULL = match any column; glob: 'pii_*'
    allow          BOOLEAN NOT NULL  -- true = allow, false = deny
);
```

The **`object_pattern`** and **`column_pattern`** columns are
optional. If you skip them (5-column schema, the original shape),
all rules match any object / any column — the table behaves exactly
like before. You can `ALTER TABLE main.policies ADD COLUMN
object_pattern VARCHAR; ADD COLUMN column_pattern VARCHAR;` later
without re-inserting any rules.

A rule matches a (principal, action, object, column) **cell** when
every non-empty condition matches:

- `subject` — if set, the principal's `sub` claim must equal it
  **exactly**. NULL means "any subject".
- `any_scope` — if non-empty, the principal must hold **at least one**
  of the listed scopes. NULL/empty means "any scope set".
- `actions` — if non-empty, the request's action must be in the
  list. NULL/empty means "any action".
- `object_pattern` — if set, the touched object name must glob-match
  the pattern. `*` is the only wildcard; comparison is
  case-insensitive (`main.*` matches `main.audit`, `MAIN.AUDIT`,
  `main.trips_enriched`). NULL = match any object.
- `column_pattern` — same shape, but matches against each column
  name the SELECT projects. `*` (literal star) is treated as a name
  too — a rule with `column_pattern='*'` allows `SELECT *`, while
  a rule with `column_pattern='ssn'` only matches when the SELECT
  list includes `ssn`. NULL = match any column.

Evaluation: rules sorted by ascending `priority`, **first match
wins per cell**. The ABAC matrix walk is "every (object × column)
cell the request touches must end in allow"; first deny
short-circuits and the audit row names the failing object /
column.

Action strings: `Attach`, `Scan`, `Insert`, `Update`, `Delete`,
`Ddl`, `Pragma`, `CopyTo`, `CopyFrom`, `ServeAdmin`. Unknown names
make the load fail closed — the whole policy is rejected and every
request denies. See the **fail-closed** note below.

### Examples

The policy table is one shape; the configurations below walk from
"zero rules" through column-level PII gating. **Simple things stay
simple; complicated things become possible.**

#### Level 0 — no policy table (the default)

Skip the `policy_table` field on the SECRET entirely. The default
scope-based policy applies (`quack:read` allows reads,
`quack:write` adds writes, admin actions always deny).

#### Level 1 — one scope, blanket allow

```sql
INSERT INTO main.policies VALUES
    (10, NULL, ['analyst'], ['Attach', 'Scan'], NULL, NULL, true);
```

Anyone presenting a token with the `analyst` scope can attach and
read everything. The trailing two `NULL`s are `object_pattern` and
`column_pattern` — both unset means "any object, any column". **Old
5-column policy rows still work unchanged** — just drop those two
columns and use the 5-column form.

#### Level 2 — per-table read split

```sql
INSERT INTO main.policies VALUES
    (10, NULL, ['analyst'],    ['Attach', 'Scan'], 'main.trips_*', NULL, true),
    (20, NULL, ['audit:read'], ['Attach', 'Scan'], 'main.audit',   NULL, true);
```

Analysts can read the `trips_*` tables but not `audit`; auditors can
read `audit` but not `trips_*`. Object globs support `*` only.

#### Level 3 — read vs write split with finer DML actions

```sql
INSERT INTO main.policies VALUES
    (10, NULL, ['analyst'],       ['Scan'],            'main.*',          NULL, true),
    (20, NULL, ['etl:load'],      ['Insert'],          'main.staging.*',  NULL, true),
    (30, NULL, ['etl:transform'], ['Update','Delete'], 'main.staging.*',  NULL, true),
    (40, NULL, ['db:admin'],      ['Ddl'],             NULL,              NULL, true);
```

`Insert` / `Update` / `Delete` / `Ddl` are the new fine-grained
actions the parser produces. Previously they all collapsed into
`Scan`.

#### Level 4 — per-subject override (named superuser + role default)

```sql
INSERT INTO main.policies VALUES
    -- Specific subject: god mode regardless of scope.
    ( 1, '108273490231', NULL, ['Attach','Scan','Insert','Update','Delete','Ddl'],
         NULL, NULL, true),
    -- Everyone else: scope-gated read.
    (10, NULL, ['analyst'], ['Attach','Scan'], 'main.*', NULL, true);
```

Rules are evaluated in priority order; first match wins per cell.

#### Level 5 — column-level PII protection

```sql
INSERT INTO main.policies VALUES
    -- Override: pii:read grants the carved-out columns (high priority).
    ( 5, NULL, ['pii:read'], ['Scan'], 'main.users', 'ssn',   true),
    ( 6, NULL, ['pii:read'], ['Scan'], 'main.users', 'email', true),
    ( 7, NULL, ['pii:read'], ['Scan'], 'main.users', 'dob',   true),
    -- Carve out sensitive columns for analysts.
    (20, NULL, ['analyst'],  ['Scan'], 'main.users', 'ssn',   false),
    (21, NULL, ['analyst'],  ['Scan'], 'main.users', 'email', false),
    (22, NULL, ['analyst'],  ['Scan'], 'main.users', 'dob',   false),
    -- Baseline: analysts can Select main.users.
    (30, NULL, ['analyst'],  ['Scan'], 'main.users', NULL,    true);
```

`SELECT id, name FROM main.users` works for any analyst. `SELECT
id, email FROM main.users` requires `pii:read`. `SELECT * FROM
main.users` is denied because `*` (the sentinel) only matches a
rule with `column_pattern='*'` — add one to permit it.

#### Level 6 — row-level filtering via operator-defined views

`quack-oauth` does not rewrite queries. Row-level security is
achieved by **operator-defined views** that the policy then
targets:

```sql
-- Server admin defines (once):
CREATE VIEW main.users_safe AS
  SELECT id, name, signup_at FROM main.users WHERE is_active;

CREATE VIEW main.audit_recent AS
  SELECT * FROM main.audit WHERE timestamp_unix_s > epoch(now()) - 86400;

-- Policy:
INSERT INTO main.policies VALUES
    (10, NULL, ['analyst'],     ['Scan'], 'main.users_safe',  NULL, true),
    (11, NULL, ['ops'],         ['Scan'], 'main.audit_recent', NULL, true),
    (12, NULL, ['audit:admin'], ['Scan'], 'main.audit',        NULL, true);
```

Analysts see `users_safe` only (no inactive accounts). Ops see
24-hour-fresh audit rows via `audit_recent`. Audit admins see the
raw `main.audit`.

#### Level 7 — subject deny-list overlay

```sql
INSERT INTO main.policies VALUES
    -- Highest priority: compromised subjects locked out of writes.
    ( 1, '108273490231', NULL, ['Insert','Update','Delete','Ddl'], NULL, NULL, false),
    ( 2, '108273490299', NULL, ['Insert','Update','Delete','Ddl'], NULL, NULL, false),
    -- Everyone else with etl:writer can write to staging.
    (10, NULL, ['etl:writer'], ['Insert','Update','Delete'], 'main.staging.*',
         NULL, true);
```

`subject IS NOT NULL` with `any_scope` NULL means "this rule fires
for that subject regardless of their scopes". A deny here trumps
any later allow.

#### Migration from the 5-column schema

Existing operators don't need to migrate — the loader introspects
the policy table's column set; missing `object_pattern` /
`column_pattern` columns are read as NULL (match any). When you're
ready:

```sql
ALTER TABLE main.policies ADD COLUMN object_pattern VARCHAR;
ALTER TABLE main.policies ADD COLUMN column_pattern VARCHAR;
```

All existing rules continue to match every object / column, exactly
as before. New rules can use the new columns.

#### Open default + explicit denies

```sql
-- Anyone authenticated can do anything by default; specific denies pick
-- exceptions.
SET quack_oauth_policy_default = 'allow';

INSERT INTO main.policies VALUES
    (10, NULL, NULL, ['ServeAdmin'], NULL, NULL, false), -- nobody admins
    (20, NULL, NULL, ['CopyFrom'],   NULL, NULL, false); -- nobody bulk-loads
```

The `quack_oauth_policy_default = 'allow'` flips the no-match
fallback. Use this only when **every** principal you trust is
already filtered by the JWT validator.

#### Time-bounded grant (rolling)

`policy_table` is a regular SQL table; nothing stops you scheduling
mutations. A cron / DuckDB scheduled `INSERT` (and a matching
`DELETE`) gives you time-bounded permissions without restarts:

```sql
-- expire grant: a sidecar process runs this every minute.
-- Add your own `expires_at TIMESTAMP` column to main.policies first;
-- this `DELETE` then drops any rule whose expiry has passed.
DELETE FROM main.policies
WHERE subject = 'temp-contractor'
  AND priority = 50
  AND expires_at < now();
```

### Hot reload, fail-closed

- **Hot reload**: every request re-`SELECT`s the policy table once per
  chunk. `INSERT` / `UPDATE` / `DELETE` are picked up by the next
  request — no restart, no signal.
- **Fail-closed**: if `policy_table` is set but the `SELECT` fails
  (missing table, wrong schema, invalid action name), every request
  **denies** with `policy_table load failed`. Misconfiguration never
  results in over-permissive behaviour.
- **Principal expiry**: `check_authorization` re-evaluates token
  validity against `principal.exp` on every call. An expired session
  drops from the cache and denies.

### Inspecting decisions

Every decision lands in three sinks:

```sql
-- in-memory ring buffer (last ~64 events, lossy)
SELECT * FROM quack_oauth_audit_log() ORDER BY timestamp_unix_s DESC LIMIT 10;

-- persistent SQL table (set `audit_table` on the SECRET)
SELECT * FROM main.audit ORDER BY timestamp_unix_s DESC LIMIT 100;

-- DuckDB logger: WARNING for denies, INFO for allows
CALL enable_logging();
SET logging_level = 'INFO';

-- one-shot health report
SELECT * FROM quack_oauth_diagnose();
```

The `token_hash` column is always the first 8 hex of `sha256(token)` —
**never** the raw bearer.

## Telemetry

The extension sends anonymous usage events to a DataZoo-owned PostHog
project so we can see which OAuth flows and provider presets get
exercised in practice. Two event types ship: one `extension_load`
when DuckDB first loads `quack_oauth`, and one `function_execution`
each time a user-facing function (`quack_oauth_login`,
`quack_oauth_acquire`, `quack_oauth_diagnose`, …) is invoked. Each
event carries the extension name + version, DuckDB version, host
platform, and a stable anonymous identifier derived from the
machine's first physical MAC address. **No tokens, no claims, no
SQL, no SECRET fields, no IdP URLs are sent.**

This is on by default and can be disabled two ways — either is
enough:

```sql
-- per-database, runtime
SET quack_oauth_telemetry_enabled = false;
```

```bash
# machine-wide, env var (also honoured by ../erpl and ../erpl-web)
export DATAZOO_DISABLE_TELEMETRY=1
```

Full policy: <https://erpl.io/telemetry>.

## Features

- **Four validation modes** (`jwks` / `introspect` / `tokeninfo` /
  `github_check`), picked per server SECRET.
- **Provider presets** for `entra`, `google`, `keycloak`, `github`,
  `generic` (and reserved `okta`). `tenant_or_realm` + provider setting
  auto-fills URLs.
- **Client-side OAuth flows**: `client_credentials` (RFC 6749 §4.4),
  `refresh_token` (RFC 6749 §6), `device_code` (RFC 8628 with
  `slow_down` back-off + full §3.5 error mapping).
- **SQL-native authorization** with hot reload + fail-closed semantics.
- **Parser-driven action detection** (Attach / Scan / Insert / Update /
  Delete / Ddl / Pragma / CopyTo / CopyFrom / ServeAdmin) via DuckDB's
  own parser — handles CTEs, subqueries, JOINs, multi-statement scripts.
- **Object- and column-level policy** — rules target schema-qualified
  tables (`main.audit`, `main.trips_*`) and projected columns
  (`pii:read` to access `users.ssn`). Backward-compatible: the legacy
  5-column policy table still loads.
- **Audit trail** for every decision: in-memory ring +
  `DUCKDB_LOG_*` + optional SQL audit table. Bearer always redacted.
- **Self-documenting**: every function carries `description`,
  `parameter_names`, `parameter_types`, `examples`, `categories` —
  visible in `duckdb_functions()`.
- **Secrets-first**: every credential lives on a typed SECRET, with
  redaction in trace output.
- **Diagnose**: `SELECT * FROM quack_oauth_diagnose()` reports config,
  JWKS / decision / session caches, IdP reachability, and a per-event
  tally of the audit ring.

## API reference

See **[API_REFERENCE.md](API_REFERENCE.md)** for the complete
reference: all scalar / table functions, SECRET types, settings, with
parameters, return types, and examples. The same descriptions are
queryable in DuckDB itself:

```sql
SELECT function_name, description, parameters, examples
FROM duckdb_functions()
WHERE function_name LIKE 'quack_oauth%';
```

## Building from source

The recommended way to use `quack_oauth` is the [quick install](#quick-install)
above. Build from source only if you're contributing, packaging, or
need a debug build.

### Prerequisites

- a C++17 toolchain (gcc 11+, clang 14+, msvc 2022)
- CMake 3.10+
- ninja (recommended — every sibling DuckDB extension uses it and
  `make` without it is 2–3× slower)
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
make unit_test            # Catch2 pure-logic tests (~750 assertions)
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
