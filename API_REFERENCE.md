# quack-oauth — API reference

> Complete function, SECRET, and setting reference.

**DuckDB version:** v1.4.x LTS or v1.5.3+
**Extension target:** `quack_oauth`

The same per-function metadata (description, parameters, examples) is
also queryable inside DuckDB itself:

```sql
SELECT function_name, description, parameters, examples, function_type
FROM duckdb_functions()
WHERE function_name LIKE 'quack_oauth%';
```

---

## Contents

- [Quick reference](#quick-reference)
- [Scalar functions](#scalar-functions)
  - [`quack_oauth_check_token`](#quack_oauth_check_token)
  - [`quack_oauth_check_authorization`](#quack_oauth_check_authorization)
  - [`quack_oauth_login`](#quack_oauth_login)
  - [`quack_oauth_refresh`](#quack_oauth_refresh)
  - [`quack_oauth_device_login`](#quack_oauth_device_login)
- [Table functions](#table-functions)
  - [`quack_oauth_diagnose`](#quack_oauth_diagnose)
  - [`quack_oauth_audit_log`](#quack_oauth_audit_log)
- [SECRET types](#secret-types)
  - [`quack_oauth_server`](#secret-type-quack_oauth_server)
  - [`quack_oauth`](#secret-type-quack_oauth)
- [Settings](#settings)
- [Validation modes](#validation-modes)
- [Provider presets](#provider-presets)
- [Authorization policy](#authorization-policy)

---

## Quick reference

| Function | Kind | Purpose |
|----------|------|---------|
| `quack_oauth_check_token(token)` | scalar | Validate a bearer token via JWKS / introspection / tokeninfo |
| `quack_oauth_check_token(session_id, auth_string, token)` | scalar | quack callback shape — validates + caches Principal by session |
| `quack_oauth_check_authorization(session_id, query_string)` | scalar | Action-aware policy check against the cached Principal |
| `quack_oauth_login(secret_name)` | scalar | RFC 6749 §4.4 `client_credentials` grant |
| `quack_oauth_refresh(secret_name)` | scalar | RFC 6749 §6 `refresh_token` grant |
| `quack_oauth_device_login(secret_name)` | scalar | RFC 8628 device authorization flow |
| `quack_oauth_diagnose()` | table | Health snapshot: extension config, caches, audit-ring summary |
| `quack_oauth_audit_log()` | table | Last N auth decisions as typed rows (token redacted) |

---

## Scalar functions

### `quack_oauth_check_token`

Two overloads share this name.

#### `quack_oauth_check_token(token VARCHAR) → BOOLEAN`

| Parameter | Type    | Description |
|-----------|---------|-------------|
| `token`   | VARCHAR | The bearer access token (JWT or opaque, per validation mode). |

Validates the token against the active `quack_oauth_server` SECRET
(selected by `quack_oauth_server_secret_name`). The global setting
`quack_oauth_validation_mode` (or first-class provider preset via
`quack_oauth_provider`) picks the path:

- `jwks` — verify the JWT signature against the JWKS endpoint with
  per-`kid` cache + rate-limited refresh + clock-skew tolerance.
- `introspect` — RFC 7662 POST to `introspection_endpoint` using
  `introspect_client_id` / `introspect_client_secret` (Basic auth).
  Positive decisions cached up to `min(quack_oauth_introspect_cache_s,
  token_exp − now)`. Negative decisions are NOT cached (revocation-safe).
- `tokeninfo` — Google-style opaque-token endpoint; no Basic auth,
  numbers-as-strings tolerated.
- `github_check` — GitHub App token validation via
  `POST /applications/{client_id}/token`.


Returns `true` if the token is valid, or `false` on any token rejection. Once the
active server SECRET and listener configuration are valid, token validation
failures (expired, invalid signature, unknown kid, jwks throttled) return `false`.
At the SQL scalar interface, callers see an undifferentiated `false` across
all token rejections. The underlying reason is disambiguated in `quack_oauth_audit_log()`
(e.g. `jwks_throttled`, `invalid_signature`, `expired`) and logged to the DuckDB logger
at `WARNING` level. Setup and environment errors (e.g. missing `quack_oauth_server_secret_name`,
unrecognized secret, or plaintext guard violation without `quack_oauth_trust_plaintext`)
throw standard DuckDB exceptions.

```sql
SELECT quack_oauth_check_token('eyJhbGciOiJSUzI1NiIs...');
```

#### `quack_oauth_check_token(session_id VARCHAR, auth_string VARCHAR, token VARCHAR) → BOOLEAN`

| Parameter      | Type    | Description |
|----------------|---------|-------------|
| `session_id`   | VARCHAR | quack's per-session id; used as the key for the principal cache. |
| `auth_string`  | VARCHAR | The raw HTTP `Authorization` header value (e.g. `Bearer eyJ...`) containing the OAuth access token. The optional `Bearer ` prefix is stripped automatically before validation. |
| `token`        | VARCHAR | quack's pre-shared PSK token from `quack_serve`. Ignored by `quack_oauth` (present for callback signature compatibility with `quack`). |

Matches `quack`'s `quack_check_token(session_id, auth_string, token)`
callback signature exactly. **Side effect**: on success, the extracted
Principal (subject, scopes, audience, exp) is cached against
`session_id` in process-local state so a later
`quack_oauth_check_authorization()` call can apply the policy.

Wired into quack after `LOAD`:

```sql
SET quack_authentication_function = 'quack_oauth_check_token';
SET quack_authorization_function  = 'quack_oauth_check_authorization';
```

```sql
SELECT quack_oauth_check_token('sess-42', 'Bearer eyJhbGciOi...', '');
```

---

### `quack_oauth_check_authorization`

`quack_oauth_check_authorization(session_id VARCHAR, query_string VARCHAR) → BOOLEAN`

| Parameter      | Type    | Description |
|----------------|---------|-------------|
| `session_id`   | VARCHAR | Same key used by `quack_oauth_check_token`'s 3-arg form. |
| `query_string` | VARCHAR | The SQL about to be executed. Used to detect the action. |

Two-stage authorization in two steps:

1. **Action detection** — strips leading whitespace and `--` /
   `/* */` comments, then classifies:
   - `ATTACH …` → `Attach`
   - `COPY … TO …` → `CopyTo`
   - `COPY … FROM …` → `CopyFrom`
   - `PRAGMA quack_serve` / `quack_stop` / `quack_restart` → `ServeAdmin`
   - anything else → `Scan`
2. **Policy evaluation** against the Principal cached for `session_id`:
   - If the active `quack_oauth_server` SECRET has `policy_table` set →
     run `SELECT priority, subject, any_scope, actions, allow FROM <table> ORDER BY priority`
     against the active database and evaluate the rules first-match-wins.
     **Fail-closed**: if the query fails (missing table, wrong schema,
     unknown action name), returns `false`.
   - Otherwise → apply the default policy (R-S-8):
     - `quack:read` → `Attach`, `Scan` allowed.
     - `quack:write` → also `CopyTo`, `CopyFrom` (implies read).
     - `ServeAdmin` → always denied (no scope grants it).

Returns `false` for unknown `session_id`.

```sql
SELECT quack_oauth_check_authorization('sess-42', 'SELECT * FROM t');           -- Scan
SELECT quack_oauth_check_authorization('sess-42', 'COPY t TO ''out.csv''');     -- CopyTo
SELECT quack_oauth_check_authorization('sess-42', 'ATTACH ''quack:rs'' AS r');  -- Attach
```

---

### `quack_oauth_login`

`quack_oauth_login(secret_name VARCHAR) → VARCHAR`

| Parameter     | Type    | Description |
|---------------|---------|-------------|
| `secret_name` | VARCHAR | Name of a `quack_oauth` (client) SECRET. Must include `token_endpoint`, `client_id`, `client_secret`. |

Runs an RFC 6749 §4.4 `client_credentials` grant. POSTs the SECRET's
`token_endpoint` with `grant_type=client_credentials` (plus `scope` if
present), parses the JSON response, **persists** `access_token`,
`refresh_token` (if returned), and `expires_at` (UTC ISO 8601) back
onto the SECRET, and returns the new `expires_at` timestamp.

Use for machine-to-machine (service-account) flows.

```sql
CREATE SECRET cli (
    TYPE quack_oauth,
    token_endpoint 'https://keycloak.example.com/realms/prod/protocol/openid-connect/token',
    client_id      'my-service',
    client_secret  's3cr3t',
    scope          'openid'
);
SELECT quack_oauth_login('cli');
```

---

### `quack_oauth_refresh`

`quack_oauth_refresh(secret_name VARCHAR) → VARCHAR`

| Parameter     | Type    | Description |
|---------------|---------|-------------|
| `secret_name` | VARCHAR | Name of a `quack_oauth` SECRET. Must include `token_endpoint`, `client_id`, `refresh_token`; `client_secret` required for confidential clients. |

Runs an RFC 6749 §6 `refresh_token` grant. POSTs `grant_type=refresh_token`,
persists the rotated `access_token` + `refresh_token` (if rotated) + new
`expires_at` back onto the SECRET, and returns the new `expires_at`
timestamp.
Public and confidential clients both supported.

```sql
SELECT quack_oauth_refresh('cli');
```

---

### `quack_oauth_device_login`

`quack_oauth_device_login(secret_name VARCHAR) → VARCHAR`

| Parameter     | Type    | Description |
|---------------|---------|-------------|
| `secret_name` | VARCHAR | Name of a `quack_oauth` SECRET. Must include `device_authorization_endpoint`, `token_endpoint`, `client_id`; `scope` optional. |

Runs the full RFC 8628 device authorization flow:

1. POST `device_authorization_endpoint` to mint a `device_code` +
   `user_code` + `verification_uri[_complete]`.
2. Print the verification URL + user code to **stderr** so the operator
   can complete it on a second device.
3. Poll `token_endpoint` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`,
   honouring RFC 8628 §3.5 errors (`authorization_pending`, `slow_down`
   back-off, `access_denied`, `expired_token`).
4. On success, persist `access_token` + `refresh_token` + `expires_at`
   back onto the SECRET and return the new `expires_at` timestamp.

Use for interactive authentication on input-constrained devices.

```sql
CREATE SECRET cli (
    TYPE quack_oauth,
    device_authorization_endpoint 'https://login.example.com/oauth2/v2.0/devicecode',
    token_endpoint                'https://login.example.com/oauth2/v2.0/token',
    client_id                     'native-app'
);
SELECT quack_oauth_device_login('cli');
```

---

## Table functions

### `quack_oauth_diagnose`

`quack_oauth_diagnose() → TABLE(component VARCHAR, status VARCHAR, detail VARCHAR)`

No parameters. Returns six rows (in alphabetical order on `component`)
with a status and a `detail` string of `key=value` pairs:

| `component`           | `status`                  | typical `detail` keys |
|-----------------------|---------------------------|------------------------|
| `decision_cache`      | `empty` \| `warm`         | `entries=` |
| `extension`           | `configured` \| `unconfigured` | `enabled= secret_name= validation_mode= provider=` |
| `idp_reachability`    | `reachable` \| `unreachable` \| `unconfigured` \| `unavailable_on_wasm` | `uri= http_status=` (on wasm: `uri= reason=wasm_host_owns_network`) |
| `jwks_cache`          | `empty` \| `warm` \| `misses_only` | `entries= unknown_kids= min_refresh_s= throttled= budget_throttled= kid_throttled=` |
| `recent_decisions`    | `empty` \| `active`       | `count=N/CAP accepted= rejected= allowed= denied= refreshed= refresh_noop= refresh_failed=` |
| `session_principals`  | `empty` \| `active`       | `sessions=` |

```sql
SELECT * FROM quack_oauth_diagnose();
```

---

### `quack_oauth_audit_log`

```
quack_oauth_audit_log() → TABLE(
    timestamp_unix_s BIGINT,
    event_type       VARCHAR,    -- 'token_accepted'|'token_rejected'|'authz_allow'|'authz_deny'|'jwks_refresh'
    subject          VARCHAR,
    issuer           VARCHAR,
    kid              VARCHAR,
    token_hash       VARCHAR,    -- 8-hex-char SHA-256 prefix; never the raw token
    action           VARCHAR,    -- 'Attach'|'Scan'|'CopyTo'|'CopyFrom'|'ServeAdmin'; NULL for token events
    reason           VARCHAR     -- short stable code, e.g. 'ok', 'expired', 'rule allow', 'default deny'
)
```

Returns the in-memory audit ring (last 64 decisions) as a typed table.
Both `check_token` and `check_authorization` emit one event per row
they evaluate. The raw bearer token is never exposed — `token_hash` is
the first 8 hex characters of its SHA-256.

#### Audit reason codes

| `event_type` | `reason` | Description |
|---|---|---|
| `token_accepted` | `ok` | Token successfully verified against cached or fetched key/introspection. |
| `token_rejected` | `malformed` | Token could not be parsed as a JWT or bearer token. |
| `token_rejected` | `disallowed_algorithm` | Algorithm not in `allowed_algorithms` whitelist or forbidden (`none`, HMAC). |
| `token_rejected` | `invalid_signature` | Cryptographic signature verification failed. |
| `token_rejected` | `expired` | Token `exp` timestamp exceeded (accounting for clock skew). |
| `token_rejected` | `not_yet_valid` | Token `nbf`/`iat` timestamp is in the future (accounting for clock skew). |
| `token_rejected` | `wrong_issuer` | Token `iss` does not match configured server `issuer`. |
| `token_rejected` | `wrong_audience` | Token `aud` does not match configured server `audience`. |
| `token_rejected` | `unsupported_key_type` | Key type or size unsupported (e.g. sub-2048-bit RSA). |
| `token_rejected` | `unusable_key` | Key contents unparseable or curve unrecognised (e.g. malformed base64url or missing parameters). |
| `token_rejected` | `unknown_kid` | Token `kid` was not found in the IdP's JWKS document. |
| `token_rejected` | `no_matching_key` | Token algorithm or use did not match any active key for the `kid` in the JWKS document. |
| `token_rejected` | `jwks_fetch_failed` | Outbound HTTP request to JWKS or introspection endpoint failed. |
| `token_rejected` | `jwks_throttled` | Transient rejection: outbound JWKS fetch throttled by either global budget window (2s) on cold miss or per-kid negative-cache cooldown (`quack_oauth_jwks_min_refresh_s`, default 30s). Inspect `quack_oauth_diagnose().jwks_cache` detail counters (`budget_throttled` vs `kid_throttled`) to determine whether retry applies after the 2-second global window or after `min_refresh_s`. |
| `jwks_refresh` | `refresh_rotated` | IdP rotated key material under the same `kid`; fresh keys successfully ingested. |
| `jwks_refresh` | `refresh_revoked` | Previously cached key for kid was removed from authoritative 200 JWKS response. |
| `jwks_refresh` | `refresh_no_rotation` | JWKS re-fetched following verification failure, but contains no new key material. |
| `jwks_refresh` | `refresh_fetch_failed` | Outbound JWKS HTTP GET failed or returned non-200. |
| `jwks_refresh` | `refresh_parse_failed` | Outbound JWKS response was not valid JSON or contained no keys. |
| `jwks_refresh` | `refresh_kid_absent` | Fresh JWKS document did not contain the requested `kid` (first observation; cached key retained pending corroboration). |
| `jwks_refresh` | `refresh_kid_evicted` | Consecutive fresh JWKS documents confirmed `kid` absence; cached key authoritatively evicted (F2 corroboration). |
| `jwks_refresh` | `refresh_superseded` | Refresh discarded because a concurrent reservation committed first. |
| `authz_allow` | `rule allow` | Explicit allow rule matched in `policy_table`. |
| `authz_allow` | `default allow` | No rule matched; fallback to `quack_oauth_policy_default='allow'`. |
| `authz_deny` | `rule deny` | Explicit deny rule matched in `policy_table`. |
| `authz_deny` | `default deny` | No rule matched; fallback to `quack_oauth_policy_default='deny'`. |

> **Note on throttled refresh logging**: When a refresh attempt is suppressed by `min_refresh_s` or the 2-second global fetch budget window, internal reason codes `refresh_throttled` and `refresh_budget_throttled` are emitted directly to the DuckDB warning logger (`DUCKDB_LOG_WARNING`, deduplicated per vector chunk) rather than polluting the audit ring. The resulting token evaluation failure appears in the audit ring as `invalid_signature` (for existing cached keys) or `jwks_throttled` (for cold misses and negative-cached unknown kids). Detailed throttle breakdown is observable via `quack_oauth_diagnose().jwks_cache` (`budget_throttled` and `kid_throttled`).

For persistent audit, set `audit_table` on the server SECRET to a SQL
table with the same column shape (BIGINT + 7 × VARCHAR); the extension
also INSERTs each event there.

```sql
SELECT timestamp_unix_s, event_type, subject, action, reason
FROM quack_oauth_audit_log()
ORDER BY timestamp_unix_s DESC
LIMIT 20;
```

---

## SECRET types

### SECRET type `quack_oauth_server`

The **resource-server** side. One per IdP / realm / tenant.

| Field                       | Type    | Sensitive | Required | Description |
|-----------------------------|---------|-----------|----------|-------------|
| `issuer`                    | VARCHAR | no        | for `jwks` mode | OAuth issuer URL (the `iss` claim). |
| `audience`                  | VARCHAR | no        | recommended | Expected `aud` claim. |
| `jwks_uri`                  | VARCHAR | no        | for `jwks` mode | JWKS endpoint URL. |
| `policy_table`              | VARCHAR | no        | no       | Fully-qualified name of a SQL table holding authorization rules (see [Authorization policy](#authorization-policy)). E.g. `main.quack_oauth_policies`. |
| `audit_table`               | VARCHAR | no        | no       | Fully-qualified name of a SQL table the extension will INSERT one row into per auth decision. Schema: `(timestamp_unix_s BIGINT, event_type VARCHAR, subject VARCHAR, issuer VARCHAR, kid VARCHAR, token_hash VARCHAR, action VARCHAR, reason VARCHAR)`. The in-memory `quack_oauth_audit_log()` ring is always populated regardless of this field. |
| `introspection_endpoint`    | VARCHAR | no        | for `introspect` mode | RFC 7662 token introspection endpoint. |
| `introspect_client_id`      | VARCHAR | no        | for `introspect` mode | Client id for Basic auth on the introspection endpoint. |
| `introspect_client_secret`  | VARCHAR | **yes**   | for `introspect` mode | Client secret. Redacted in tracing. |
| `tenant_or_realm`           | VARCHAR | no        | for provider presets | Substituted into the provider preset URL templates. |

```sql
-- Manual (generic provider)
CREATE SECRET rs (
    TYPE quack_oauth_server,
    issuer    'https://keycloak.example.com/realms/prod',
    jwks_uri  'https://keycloak.example.com/realms/prod/protocol/openid-connect/certs',
    audience  'my-quack-api'
);

-- With introspection
CREATE SECRET rs_intr (
    TYPE quack_oauth_server,
    issuer                   'https://keycloak.example.com/realms/prod',
    introspection_endpoint   'https://keycloak.example.com/realms/prod/protocol/openid-connect/token/introspect',
    introspect_client_id     'my-quack-api',
    introspect_client_secret 'super-secret'
);
SET quack_oauth_validation_mode = 'introspect';

-- With a provider preset (issuer / jwks_uri / introspection auto-filled)
CREATE SECRET rs_kc (
    TYPE quack_oauth_server,
    tenant_or_realm 'prod'
);
SET quack_oauth_provider = 'keycloak';

-- With SQL-table policy. The table lives in this DuckDB database and
-- is managed with normal INSERT / UPDATE / DELETE.
CREATE TABLE main.quack_oauth_policies (
    priority  INTEGER NOT NULL,
    subject   VARCHAR,
    any_scope VARCHAR[],
    actions   VARCHAR[],
    allow     BOOLEAN NOT NULL
);
INSERT INTO main.quack_oauth_policies VALUES
    (10, NULL, ['quack:read'],  ['Attach', 'Scan'],                       true),
    (20, NULL, ['quack:write'], ['Attach', 'Scan', 'CopyTo', 'CopyFrom'], true);

CREATE SECRET rs_pol (
    TYPE quack_oauth_server,
    issuer       'https://keycloak.example.com/realms/prod',
    jwks_uri     'https://keycloak.example.com/realms/prod/protocol/openid-connect/certs',
    policy_table 'main.quack_oauth_policies'
);
```

### SECRET type `quack_oauth`

The **client** side. Holds endpoint URLs and the active tokens.

| Field                            | Type    | Sensitive | Description |
|----------------------------------|---------|-----------|-------------|
| `issuer`                         | VARCHAR | no        | OAuth issuer URL. |
| `client_id`                      | VARCHAR | no        | Client id at the IdP. |
| `client_secret`                  | VARCHAR | **yes**   | Client secret (confidential clients). Redacted in tracing. |
| `audience`                       | VARCHAR | no        | Requested audience (sent on `audience=` if the IdP supports it). |
| `scope`                          | VARCHAR | no        | Requested scope string. |
| `device_authorization_endpoint`  | VARCHAR | no        | RFC 8628 device authorization endpoint. |
| `token_endpoint`                 | VARCHAR | no        | RFC 6749 token endpoint. |
| `redirect_listener_port`         | INTEGER | no        | Reserved for the authorization-code-with-PKCE flow (future). |
| `access_token`                   | VARCHAR | **yes**   | Current access token. Filled by `quack_oauth_login` / `refresh` / `device_login`. |
| `refresh_token`                  | VARCHAR | **yes**   | Current refresh token. Same. |
| `expires_at`                     | VARCHAR | no        | UTC ISO 8601 expiry of `access_token`. |

```sql
CREATE SECRET cli (
    TYPE quack_oauth,
    token_endpoint 'https://keycloak.example.com/realms/prod/protocol/openid-connect/token',
    client_id      'my-service',
    client_secret  's3cr3t',
    scope          'openid'
);
```

---

## Settings

All settings are global (SET applies process-wide; there is no per-session override). In server mode, quack's auth thread runs authentication and authorization callbacks on fresh `ClientContext` instances per incoming wire request; global scope ensures all connections observe the configured settings.

| Setting                              | Type    | Default     | Description |
|--------------------------------------|---------|-------------|-------------|
| `quack_oauth_enabled`                | BOOLEAN | `false`     | Master switch (R-S-1). Defaults off so `LOAD` is side-effect-free. |
| `quack_oauth_validation_mode`        | VARCHAR | `'jwks'`    | `jwks` \| `introspect` \| `tokeninfo` \| `github_check` (R-S-2). |
| `quack_oauth_provider`               | VARCHAR | `'generic'` | First-class preset: `entra` \| `google` \| `keycloak` \| `okta` \| `github` \| `generic` (R-S-12). |
| `quack_oauth_clock_skew_s`           | INTEGER | `60`        | Allowable clock skew (seconds) for JWT `exp`/`nbf`/`iat` (R-S-3). |
| `quack_oauth_jwks_min_refresh_s`     | INTEGER | `30`        | Min seconds between JWKS refreshes per kid (R-S-4). Must be between the startup floor and 3600; cannot be lowered below startup floor (default 30, override via `QUACK_OAUTH_JWKS_MIN_REFRESH_S`). Process-global setting that applies across all chunk validations until reset. |
| `quack_oauth_introspect_cache_s`     | INTEGER | `30`        | Cache lifetime for `introspect`-mode decisions, capped at token `exp` (R-S-5). |
| `quack_oauth_renew_skew_s`           | INTEGER | `60`        | Client refreshes the access token this many seconds before `expires_at` (R-C-2). |
| `quack_oauth_policy_default`         | VARCHAR | `'deny'`    | Default decision when no `policy_table` rule matches: `allow` or `deny` (R-S-7). |
| `quack_oauth_trust_plaintext`        | BOOLEAN | `false`     | Allow enabling auth without a TLS terminator (R-N-4). Disabled by default. |
| `quack_oauth_server_secret_name`     | VARCHAR | `''`        | Name of the `quack_oauth_server` SECRET that `check_token` reads from. |

---

## Key rotation

When identity providers (such as Microsoft Entra ID) rotate key material while reusing the same `kid`, cached keys will fail signature verification on new tokens. The extension automatically detects this and triggers a rate-limited, synchronous on-demand JWKS refresh on the request path to recover the new key without requiring process restart or cache invalidation.

- **Multi-key cache entry**: On a successful 200 OK JWKS fetch, cached keys for the target `kid` are synchronized with the keys currently published in the document, capped at 4 keys per `kid`. If a fetch fails or times out, all existing cached keys are preserved.
- **Corroborated sibling key eviction**: To protect against transient network glitches or partial IdP responses evicting valid keys, whole-`kid` absence of sibling keys from a 200 OK response during a key rotation refresh must be observed across **2 consecutive distinct refreshes** before the cached sibling key is evicted. Cold unknown-`kid` misses passively ingest discovered keys without incrementing absence counters or evicting unrelated cached keys. Existing keys continue to verify until absence is corroborated.
- **Multi-tenant partitioning**: JWKS documents, cached keys, and per-kid cooldowns are strictly partitioned by `(jwks_uri, kid)` composite keys. Refreshing or evicting keys for Tenant A cannot mutate, invalidate, leak across, or starve the per-kid refresh window for Tenant B. (The 2-second outbound fetch budget window operates as a process-global protection to prevent network storms).
- **Request-path latency**: Refreshes happen synchronously on the request thread encountering an unusable key signature failure against currently-cached keys, bounded by `quack_oauth_jwks_min_refresh_s` (default 30 seconds) per `kid` and a process-global fetch rate limit (2 seconds).
- **Starvation & DoS resistance**: Fresh key material fetched from the IdP over TLS is committed to the cache even if the triggering token fails verification, preventing forged or corrupted tokens from starving legitimate key rotation recovery. Cold misses during a fresh document window (<2s) reject immediately as `unknown_kid` without burning the global fetch slot. Tokens signed by valid cached keys verify directly from cache without outbound HTTP requests or refresh events. When an invalid-signature request triggers a rate-limited fetch that yields no new key material, `refresh_no_rotation` is audited.
- **Troubleshooting**: If clients experience bursts of `invalid_signature` or `jwks_throttled` errors during an IdP rotation, inspect `quack_oauth_audit_log()` for `jwks_refresh` events and `quack_oauth_diagnose()` for granular throttle counters (`throttled=N`, `budget_throttled=N`, `kid_throttled=N`) on `jwks_cache`. Refresh rate-limiting is logged to the DuckDB logger as `quack_oauth: JWKS refresh rate-limited by min_refresh_s for kid='...'` or `quack_oauth: JWKS refresh throttled by global fetch budget (2s window) for kid='...'` (viewable via `SET enable_logging = true; SELECT * FROM duckdb_logs WHERE message LIKE 'quack_oauth:%';`); network failures appear as `refresh_fetch_failed`.

---

## Validation modes

| Mode           | Use when                                                                 | Cache behaviour |
|----------------|--------------------------------------------------------------------------|-----------------|
| `jwks`         | The IdP issues JWTs (RS256/384/512, ES256/384 on P-256/P-384, or EdDSA on Ed25519) and exposes a JWKS endpoint. | Per-`kid` JWKS cache + per-token decision cache. |
| `introspect`   | The IdP issues opaque tokens (or you want centralised revocation). RFC 7662. | Positive decisions cached up to `min(quack_oauth_introspect_cache_s, exp − now)`. **Negative** decisions never cached. |
| `tokeninfo`    | Google-style endpoints that return JSON claims directly for opaque tokens. | Same as `introspect`. |
| `github_check` | GitHub Apps validating user-to-server or installation tokens via GitHub REST API. | Same as `introspect`. |

---

## Provider presets

Setting `quack_oauth_provider` + the SECRET's `tenant_or_realm` field
auto-fills the issuer / JWKS / introspection URIs from a built-in
template, so the operator surface stays minimal for the common cases.

| Provider   | Tenant key       | Validation default | Notes |
|------------|------------------|--------------------|-------|
| `entra`    | tenant GUID      | `jwks`             | Microsoft Entra ID. Use a custom API scope (`api://<client_id>/.default`), **not** Microsoft Graph — Graph tokens carry a `nonce` in the JWT header and are not third-party-verifiable. |
| `google`   | (n/a)            | `tokeninfo`        | Service-account tokens have no `sub`; numbers may come back as JSON strings. |
| `keycloak` | realm name       | `jwks`             | Confidential client required for introspection. |
| `okta`     | org host         | `jwks`             | Same as keycloak otherwise. |
| `github`   | (n/a)            | `github_check`     | GitHub-flavoured token check. |
| `generic`  | (n/a)            | per setting        | Fall back to manually-set `issuer` / `jwks_uri` / etc. |


---

## Authorization policy

Two modes, picked per server SECRET.

### Default policy (no `policy_table` set)

Scope-based, per R-S-8:

| Scope         | Allowed actions                       |
|---------------|---------------------------------------|
| `quack:read`  | `Attach`, `Scan`                      |
| `quack:write` | `Attach`, `Scan`, `CopyTo`, `CopyFrom` (write implies read) |
| `ServeAdmin`  | **never** granted by any scope        |

### SQL-table policy (`policy_table` set)

The policy lives in an operator-managed SQL table in the active
DuckDB database. The extension issues one `SELECT` per chunk and
evaluates the rules first-match-wins.

**Expected schema** (operator creates the table; column names matter):

```sql
CREATE TABLE main.quack_oauth_policies (
    priority  INTEGER NOT NULL,        -- ASC, first match wins
    subject   VARCHAR,                  -- NULL = match any subject
    any_scope VARCHAR[],                -- NULL or [] = no scope filter
    actions   VARCHAR[],                -- NULL or [] = match any action
    allow     BOOLEAN NOT NULL          -- decision when this rule matches
);
```

**Example**:

```sql
-- Allow anyone with `quack:read` to Attach + Scan.
-- Allow alice@example.com to also CopyTo.
-- Block bob@example.com entirely.
-- Everything else: deny (default).
INSERT INTO main.quack_oauth_policies VALUES
    (10, 'bob@example.com',   NULL,           NULL,                       false),
    (20, 'alice@example.com', NULL,           ['Attach', 'Scan', 'CopyTo'], true),
    (30, NULL,                ['quack:read'], ['Attach', 'Scan'],          true);
```

**Per-column semantics**:

| Column      | Type      | NULL / empty means | Matching |
|-------------|-----------|--------------------|----------|
| `priority`  | INTEGER   | NOT NULL — required | Rules sorted by ASC priority; first match wins. |
| `subject`   | VARCHAR   | match any subject | Equality on `principal.subject`. |
| `any_scope` | VARCHAR[] | no scope filter | Match if **any** element is in `principal.scopes`. |
| `actions`   | VARCHAR[] | match any action | Match if `current_action` is in the list. Values must be one of `Attach` \| `Scan` \| `CopyTo` \| `CopyFrom` \| `ServeAdmin`. |
| `allow`     | BOOLEAN   | NOT NULL — required | Decision when this rule matches. |

**No-match fallback**: the `quack_oauth_policy_default` setting
(`'allow'` or `'deny'`, default `'deny'`) decides when no rule matched.

**Fail-closed**: if `policy_table` is set but the `SELECT` fails
(table missing, wrong schema, unknown action string), every call to
`quack_oauth_check_authorization` returns `false` — regardless of
principal — until the table is fixed.

**Hot updates**: an `INSERT` / `UPDATE` / `DELETE` against the policy
table takes effect on the next `check_authorization` call; no reload,
no restart. Use the host's normal transaction guarantees to make
multi-row policy changes atomic.
