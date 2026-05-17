# quack-oauth — implementation & testing approach

Status: draft v0.1 (2026-05-14)
Companion to `requirements.md` and `architecture.md` at the repo root.

This document is the *how we work* on this codebase. It is the source
of truth for the test stack, the TDD discipline, the real-world IdP
test plan, and the static-linkage policy.

## 1. TDD discipline

Strict red → green → refactor, **one slice at a time**.

- A **slice** is the smallest change that exposes a new observable
  behaviour as a passing test. Never write production code without a
  failing test that motivates it.
- **Red first.** Every new behaviour starts with a failing test that
  fails *for the right reason* (the function does not exist yet, the
  setting is unknown, the SECRET type is not registered, …).
- **Green next.** The minimum code that turns the test green. Resist
  the urge to write the next slice before the current one is green.
- **Refactor third.** Only with a green bar, and only renaming /
  extracting; no new behaviour during refactor.
- **Do not branch test types.** A single behaviour gets exactly one
  test at the right layer (see §2). If a SQL test covers it, no
  Catch2 test for the same behaviour. If a Catch2 unit covers it,
  no SQL duplicate.

## 2. Test stack

Two layers, with a strict role separation.

### 2.1 SQL tests (`test/sql/*.test`) — the source of truth

DuckDB SQLLogicTest format. These are the **only** tests that prove
the extension works as a real DuckDB extension. They run via DuckDB's
own `unittest` runner (`build/release/test/unittest`), which loads the
extension exactly as a user would.

- **No mocks**, ever. SQL tests hit real code paths.
- IdP-touching SQL tests use either a locally running Keycloak (see
  §4) or recorded HTTP transcripts (see §4) — never an in-process
  fake.
- Naming: `test/sql/oauth_<feature>.test` (e.g. `oauth_settings.test`,
  `oauth_secret_client.test`, `oauth_jwks_validation.test`).
- Header convention (sibling-extension standard):
  ```
  # name: test/sql/oauth_<feature>.test
  # description: <one line>
  # group: [sql]

  require quack_oauth
  ```
- Run all: `make test`. Run one:
  `./build/release/test/unittest test/sql/oauth_<feature>.test`.

### 2.2 Catch2 unit tests (`test/cpp/test_*.cpp`) — pure logic only

Catch2 v3 with `Catch2WithMain`. The unit-test binary
(`build/release/test/quack_oauth_unit_tests`) does **not** link DuckDB.

- Scope is limited to **pure logic** that takes inputs, returns
  outputs, and touches no I/O: JWT parsing, JWKS-cache key handling,
  decision-cache eviction, policy rule evaluation, redaction.
- Mocks are permitted **only here**. Use Catch2's `GENERATE` and
  trompeloeil/FakeIt or hand-rolled test doubles for HTTP / clock
  injection.
- Code that needs DuckDB headers (Logger, ClientContext, Catalog) is
  out of scope for Catch2 — that code is exercised by SQL tests.
- Naming: `test/cpp/test_<module>.cpp`.
- Run: `make unit_test` (builds + runs); or invoke the binary directly:
  `./build/release/test/quack_oauth_unit_tests`.

### 2.3 Module split that enables this

For any module that has both pure logic and DuckDB integration, split
into two `.cpp` files sharing one header:

```
src/include/<module>.hpp          declares the full API
src/<module>_pure.cpp             pure logic, no #include "duckdb.hpp"
src/<module>_duckdb.cpp           DuckDB integration, registration, glue
```

The Catch2 binary compiles only `<module>_pure.cpp`. The extension
compiles both.

Example (slice 1):
```
src/include/tracing.hpp
src/tracing_redact.cpp     pure: sha256-prefix, no duckdb
src/tracing_log.cpp         DuckDB Logger sink, sensitive-field hashing
```

## 3. Mocking policy

- **SQL tests: no mocks.** Period. If a SQL test needs an IdP, an IdP
  is running (Keycloak container) or being replayed (recorded
  transcript).
- **Catch2 tests: mocks allowed, isolated to the test file.** Inject
  via interface (`IHttpClient`, `IClock`, `IFileSystem`) and pass a
  test double in the test. Never alter production code paths to make
  them testable in non-realistic ways.
- **No in-process IdP fakes** that diverge from real provider
  behaviour. If we need an IdP for a SQL test, we use a real one.

## 4. Real-world testing plan

The architecture mandates a five-provider matrix (Entra, Google,
Keycloak, Okta, GitHub — requirements §5.3). Okta is **deferred** for
the initial implementation per user decision; GitHub is also deferred.
The active matrix is **Keycloak (live) + Google (recorded) + Entra
(recorded)**.

### 4.1 Keycloak — live container, primary reference

- A `test/integration/keycloak/docker-compose.yml` brings up
  Keycloak ≥ 22 with a pre-seeded realm, a confidential client for
  introspection, and a device-flow client.
- `make integration_keycloak` brings the container up, runs the
  relevant SQL tests against it, and tears it down.
- CI runs the same compose file; the realm is seeded from a JSON
  export committed to the repo.
- This is the reference platform for `jwks` mode, device-flow,
  client_credentials, refresh, and introspection.

### 4.2 Google + Entra — recorded HTTP transcripts

- Provider matrix R-S-15 / acceptance #7 requires release-blocking
  smoke tests for each first-class provider. For providers we can't
  run locally (Entra, Google), we capture transcripts once per
  release against live tenants.
- Recordings live under
  `test/integration/transcripts/{google,entra}/*.json` (key sanitised
  before commit — never commit a real refresh_token).
- An HTTP-replay shim (interface-injected, see §3) replays the
  transcript deterministically in CI.
- When the upstream provider changes a response shape, the recording
  is re-captured; this is intentional — we want CI to fail when the
  IdP contract drifts.

### 4.3 Okta + GitHub — deferred

Not in scope for the initial implementation. The provider strategy
table (architecture §8.6) leaves stubs so they can be added without
touching the rest of the codebase.

### 4.4 Manual smoke for development

`scripts/manual_keycloak.sh` brings up Keycloak, prints
`CREATE SECRET` / `quack_oauth_login` snippets, and leaves the
container running for ad-hoc poking. Not run by CI.

## 5. Tracing & logging policy

Every observable code path that handles a token or IdP response calls
the `Trace(level, event, kv...)` helper from
`src/include/tracing.hpp`.

- **Output goes through DuckDB's `Logger`** (R-S-10), not stdout, not
  spdlog, not a separate file.
- **Sensitive fields are auto-redacted.** Fields named `token`,
  `access_token`, `refresh_token`, `id_token`, `client_secret`,
  `password`, `code` are replaced by an 8-hex-char prefix of their
  SHA-256. Other fields pass through as-is.
- **Levels**: TRACE (per-request internals), DEBUG (state changes),
  INFO (auth decisions), WARN (config/policy denials), ERROR (failed
  validation).
- Tokens MUST NEVER appear in plaintext at any level — including
  TRACE. This is non-negotiable per R-S-10.
- Redaction is **pure logic** (see §2.3) so it is unit-tested.

## 6. Static-linkage policy

The shipping artefact (`quack_oauth.duckdb_extension`) is a shared
library, but its third-party dependencies are statically linked.

Dynamic-dep allowlist on Linux:
```
linux-vdso.so.1
libpthread.so.0
libdl.so.2
librt.so.1
libm.so.6
libgcc_s.so.1
libstdc++.so.6
libc.so.6
ld-linux-x86-64.so.2
libssl.so.3            # only where DuckDB itself already dynamically links
libcrypto.so.3         # ditto
```

Anything else in `ldd` output is a violation. `make smoke_static`
enforces this allowlist after every release build.

## 7. Slice plan

The implementation is divided into named slices. Each slice is a
single PR-sized change with its own red→green cycle.

| Slice | Goal | Tests added |
|---|---|---|
| **S-0 Harness** | Catch2 wired, jwt-cpp linked, tracing.Redact green, static-linkage smoke. | Catch2: `test_tracing.cpp` |
| S-1 Skeleton | Strip waddle demo. LoadInternal empty. Smoke SQL test. | SQL: `oauth_load.test` |
| S-2 Settings | Register every `quack_oauth_*` setting per R-S-11 / R-N-12. | SQL: `oauth_settings.test` |
| S-3 SECRET types | Register `quack-oauth` (client) + `quack-oauth-server` (server) per R-C-1 / R-S-11. | SQL: `oauth_secret_*.test` |
| S-4 diagnose() stub | Table function returning a typed empty result per R-N-13. | SQL: `oauth_diagnose.test` |
| S-5 JWT parse | Pure-logic JWT header/payload decode. No signature. | Catch2: `test_jwt_parse.cpp` |
| S-6 JWKS cache | Pure-logic kid→JWK cache with TTL + rate-limit. | Catch2: `test_jwks_cache.cpp` |
| **S-7a JWT verify (pure)** | ParseJwksJson + JwkRsaToPem + VerifyJwt with clock-injected RS256/384/512, R-S-3 algorithm gating. | Catch2: `test_jwks_parse.cpp`, `test_jwt_verify.cpp` |
| **S-7b.1 Validator orchestration (pure)** | IHttpClient interface + ValidateToken (cache miss → fetch → parse → re-lookup → verify) with FakeHttpClient. | Catch2: `test_validator.cpp` |
| **S-7b.2 Scalar function** | Concrete `DuckdbHttpClient` (duckdb_httplib_openssl) + per-process state + `quack_oauth_check_token` scalar. Early-fail SQL test (bind errors, malformed, HS256). | SQL: `oauth_check_token.test` |
| **S-7b.3 Live Keycloak** ✅ | docker-compose + realm seed + happy-path SQL integration test that hits a real IdP. **End-to-end green: real RS256 token from Keycloak validates through the full stack (fetch + parse + cache + verify).** | `make integration_keycloak` -> `test/integration/keycloak/oauth_jwks_keycloak.test` |
| **S-8 Decision cache** ✅ | Pure-logic LRU keyed by `sha256(token)`. TTL = `min(default_ttl_s, exp - now_s)`. R-S-9 / R-N-2. | Catch2: `test_decision_cache.cpp` (11 cases, 94 assertions) |
| **S-9 Quack callback swap** ✅ | Add a 3-arg `quack_oauth_check_token(session_id, auth_string, token)` overload matching quack's signature; activated via `SET quack_authentication_function = 'quack_oauth_check_token'` (name-based, not `REPLACE_ON_CONFLICT` -- the draft requirements doc was stale; see §8.bis). | SQL: `test/sql/oauth_quack_swap.test` |
| **S-10a Introspect (pure)** ✅ | RFC 7662 POST + parsing + IHttpClient::Post + Basic auth. | Catch2: `test_introspect.cpp` |
| **S-10b Introspect (live)** ✅ | Wired into validator (`ValidateTokenViaIntrospection`) + scalar dispatch via `quack_oauth_validation_mode`. Server SECRET extended with `introspection_endpoint` + `introspect_client_id` + `introspect_client_secret` (redacted). DecisionCache (S-8) caches positive decisions; negative not cached (revocation-safe). Keycloak `quack-client` made confidential. **End-to-end green: real Keycloak introspect returns active=true → cached; tampered token returns active=false → reject.** | `make integration_keycloak` → `oauth_introspect_keycloak.test` |
| **S-11a Provider strategy** ✅ | ProviderId enum (`entra`, `google`, `keycloak`, `okta`, `github`, `generic`) + ProviderValidation enum (`Jwks`, `Tokeninfo`, `Introspect`, `GithubCheck`) + ResolveProvider(id, tenant_or_realm) materializes issuer/jwks_uri/introspection from per-provider templates. **Wired into the scalar**: `SET quack_oauth_provider='keycloak'` + `tenant_or_realm` on the SECRET auto-fills URIs. **End-to-end green against live Keycloak.** | Catch2: `test_providers.cpp`; SQL: `oauth_provider_preset_keycloak.test` |
| **S-11b Entra (recorded)** ✅ | `scripts/capture_entra_transcript.sh` + `test/cpp/test_entra_replay.cpp` + transcripts under `test/integration/transcripts/entra/`. Replay-shim `IHttpClient` verifies live RS256 token against captured JWKS with frozen clock. Covers happy path + tampered signature + expired + wrong-issuer. | Catch2: `test_entra_replay.cpp` (4 cases, fixtures from a real Entra tenant) |
| **S-11b Google (recorded)** ✅ | `scripts/capture_google_transcript.sh` uses a service-account JSON key + RFC 7523 JWT-bearer flow to mint an opaque access token, then calls Google's `tokeninfo` to validate. `ParseTokeninfoResponse` + `QueryTokeninfo` (PURE_SOURCES) handle Google's quirks: numbers-as-strings, no `active` field (synthesized from HTTP status), no Basic auth, missing `sub` on service-account tokens. | Catch2: `test_google_replay.cpp` (11 cases, fixtures from a real GCP service account) |
| **S-12 client_credentials** ✅ | RFC 6749 §4.4 + `quack_oauth_login(secret_name)` scalar. Reads client SECRET (token_endpoint + client_id + client_secret + scope), POSTs to token endpoint, persists access_token + expires_at back on the SECRET. **End-to-end green against a Keycloak service-account client.** | Catch2: `test_token_endpoint.cpp`; SQL: `oauth_login_keycloak.test` |
| **S-12c refresh_token** ✅ | RFC 6749 §6 + `quack_oauth_refresh(secret_name)` scalar. Reads client SECRET (token_endpoint + client_id [+ client_secret] + refresh_token), POSTs grant_type=refresh_token, persists new access_token + (rotated) refresh_token + expires_at. **End-to-end green against live Keycloak** (runner extracts ROPC refresh_token, hands it to the SQL test). Public-client + confidential-client paths both supported. | Catch2: `test_token_endpoint.cpp [refresh]` (6 cases); SQL: `oauth_refresh_keycloak.test` |
| **S-12 device_code** ✅ | RFC 8628: ParseDeviceAuthorizationResponse + RequestDeviceAuthorization + ParseDevicePollResponse (full RFC 8628 §3.5 error mapping: pending/slow_down/access_denied/expired_token) + PollDeviceTokenEndpoint. `quack_oauth_device_login(secret_name)` scalar runs the full loop with `slow_down` interval back-off and stderr notice for the user_code + verification_uri. | Catch2: `test_device_code.cpp` (11 cases, 47 assertions). Live device-flow integration test deferred (would need admin-API auto-consent in parallel with the polling) |
| **S-13a Default policy (pure)** ✅ | R-S-8 default policy: quack:read → Attach + Scan; quack:write → also Insert/Update/Delete/CopyTo/CopyFrom (and implies read); Ddl / Pragma / ServeAdmin always denied. Action enum, PolicyOutcome with reason for diagnostics. (Object + column patterns landed later in S-13e; the default policy itself stays action-only.) | Catch2: `test_authz.cpp` |
| **S-13b AuthZ scalar wiring** ✅ | session_id → Principal cache in `QuackOauthState`. The 3-arg form of `quack_oauth_check_token` (the shape quack itself calls) extracts the Principal from the verified JWT and stores it keyed by session_id. New scalar `quack_oauth_check_authorization(session_id VARCHAR, query_string VARCHAR) → BOOLEAN` matches quack's expected signature; applies `EvaluateDefaultPolicy(Scan)` against the cached Principal. Unknown session_id → default-deny. Action detection from `query_string` arrives in S-13c. | SQL: `oauth_authz_keycloak.test` (9 assertions; demonstrates cache populate + policy evaluation against a real Keycloak token) |
| **Validator Tokeninfo dispatch** ✅ | `ValidateTokenViaTokeninfo` + dispatch in `check_token_function` for `validation_mode='tokeninfo'`. Google's live path now SQL-reachable. | SQL: `oauth_tokeninfo_google.test` via `make integration_google` (9 assertions against a fresh GCP service-account token) |
| **S-13c action detection** ✅ | Initially shipped as `DetectAction(query_string)` (string-matching heuristic). **Superseded by S-13e** -- the parser-driven `InspectSql()` produces an `AuthzRequest` carrying the action plus the touched objects + projected columns. The old string-matcher and `src/action_detect.{cpp,hpp}` are retired. | Catch2 (initial): retired with `test_action_detect.cpp`; live coverage via `oauth_check_authorization.test` and the e2e Keycloak suite |
| **S-13d SQL-native policy** ✅ | `src/policy.{hpp,cpp}` (PURE_SOURCES) hosts the rule + evaluator types; `src/policy_table.{hpp,cpp}` (DUCKDB_WASM_SAFE_SOURCES) loads rules from a SQL table via a short-lived `Connection`. Schema: 5-column `priority / subject / any_scope / actions / allow` originally; extended in S-13e with optional `object_pattern` + `column_pattern` columns (loader uses `pragma_table_info` introspection so the legacy 5-column shape continues to load). Rules sorted by ascending priority; first match wins per cell. `policy_table` field on the server SECRET names the table; `quack_oauth_policy_default` setting (`allow`|`deny`, default `deny`) controls the no-match fallback. **Fail-closed**: if `policy_table` is set but the query fails (missing table, wrong schema, invalid action name), denies regardless of principal. Falls back to the default scope policy when `policy_table` is unset. **No yaml-cpp dependency**. | Catch2: `test_policy.cpp` (evaluator semantics, glob, object/column, multi-object); SQL: `oauth_check_authorization.test` + `oauth_policy_table_keycloak.test` |
| **S-13e Parser-driven authz (R-S-7 expansion)** ✅ | `src/sql_inspect.{cpp,hpp}` (DUCKDB_WASM_SAFE_SOURCES) parses the incoming SQL with `duckdb::Parser`, classifies the action into the extended enum (Attach / Scan / Insert / Update / Delete / Ddl / Pragma / CopyTo / CopyFrom / ServeAdmin), and walks the parse tree (`BaseTableRef`, `JoinRef`, `SubqueryRef`, `ColumnRefExpression`, `SetOperationNode.children`, `cte_map`) to enumerate touched objects + projected columns. System tables (`information_schema.*`, `pg_catalog.*`, `duckdb_*`) are filtered. `EvaluatePolicy` rewrites to an ABAC matrix walk across (object × column) cells; first deny short-circuits with an actionable audit reason naming the failing cell. Backward-compat: 5-column policy tables load with object/column patterns as NULL (match-any). Wasm-safe (the parser is in DuckDB core; no httplib dep). Retires `src/action_detect.{cpp,hpp}`. | Catch2: `test_policy.cpp` `[glob]`, `[object]`, `[column]`, backward-compat cases; SQL: `oauth_check_authorization.test` (loader accepts 5- and 7-column schemas, parser dispatches each action shape) |
| **S-15 Audit + live diagnose() + audit_table** ✅ | New `src/audit.{hpp,cpp}` (PURE_SOURCES) with `AuditEvent` / `AuditRing` (capacity 64) / `FormatAuditLine`. New `src/audit_sink.{hpp,cpp}` (DUCKDB_WASM_SAFE_SOURCES) fans every decision out to (a) the in-memory ring, (b) DuckDB Logger via `DUCKDB_LOG_INFO` / `DUCKDB_LOG_WARNING`, and (c) optional INSERT into the SQL table named by `audit_table` on the server SECRET. `check_token` (all 3 modes, 1-arg + 3-arg) and `check_authorization` emit on every per-row decision. `quack_oauth_diagnose()` rewritten to return live state (extension config + secret_name, jwks_cache.Size(), decision_cache.Size(), session_principals.size(), audit ring counts). New `quack_oauth_audit_log()` table function returns the ring as 8-column rows. Token-redaction: `RedactSensitive(raw_token)` (first 8 hex of sha256) is the only form ever logged or written to the audit table -- never the raw token. Closes R-S-10 and R-N-13. | Catch2: `test_audit.cpp` (9 cases, 33 assertions covering wraparound, format, redaction); SQL: `oauth_diagnose.test` updated for live schema; Keycloak: `oauth_audit_keycloak.test` (15 assertions verifying audit_table INSERTs + audit_log() + diagnose() recent_decisions counts) |
| **S-16 Quickstart demo** ✅ | `make demo` → `scripts/demo.sh` brings up the Keycloak compose, acquires a real ROPC token, configures a server SECRET, creates a SQL policy table, runs allow + deny queries, prints the audit log + diagnose() output, and tears down. Pure operator-onboarding aid; no test assertions. | `make demo` (manual) |
| **S-17 Live device_code integration** ✅ | New `quack-device` public client in `realm-export.json` with `oauth2.device.authorization.grant.enabled=true` and `consentRequired=false`. `scripts/keycloak_device_consent.py` is a standard-library Python helper that drives Keycloak's verification page (GET form → POST credentials → POST consent grant) over urllib + cookies. `scripts/run_device_code_test.sh` spawns DuckDB CLI in the background running `SELECT length(quack_oauth_device_login('cli')) > 0`, tails its stderr until the `[quack_oauth_device_login] visit ...` notice appears, parses out the verification URI + user_code, runs the Python consent helper, then waits for the polling loop to return. Also fixes a side-effect bug found during this slice: `quack_oauth_device_login` (and login / refresh / check_token / check_authorization) now call `SetVolatile()` on the ScalarFunction so DuckDB's optimizer never constant-folds or double-evaluates these calls. | Live integration via `bash scripts/run_device_code_test.sh` (invoked from `make integration_keycloak`); asserts the function returns a non-empty access token after parallel consent |
| **S-18 Real-quack E2E (Python + uv)** ✅ | New `e2e/` harness (uv-managed Python 3.10+, `pytest` + `pytest-timeout`). In-process **server** fixture: a Python `duckdb.DuckDBPyConnection` loads both `quack` (from `~/.duckdb`) and our local `quack_oauth.duckdb_extension`, seeds policy + audit tables + a demo table, swaps quack's auth callbacks, and runs `quack_serve('quack:127.0.0.1:N', ...)` on a free port -- the listener runs on a background thread and the server connection stays alive for the session. **Client** fixture: a separate `duckdb.connect(':memory:')` per test with `quack` loaded, that uses `ATTACH 'quack:...' AS srv (TYPE quack, token '<JWT>')` to connect. Test matrix (7 cases, all green): TCP listener reachable; happy-path Scan returns rows; tampered JWT → AuthN reject; garbage token → AuthN reject; subject-targeted policy deny over the wire → AuthZ reject; audit table grows per real wire decision; `token_hash` never leaks the raw JWT. **Two bugs uncovered + fixed by this slice**: (a) `CheckTokenScalarFun3` was validating `args[2]` (quack's PSK) instead of `args[1]` (the client's `token` attach option, i.e. the JWT); (b) all `quack_oauth_*` settings were `SetScope::SESSION` and so invisible to quack's auth thread which runs on fresh `ClientContext`s -- flipped to `SetScope::GLOBAL` to match quack's own callback-name settings. | `make e2e` (requires `INSTALL quack;` having been run once via the duckdb CLI; brings up the same Keycloak compose as `make integration_keycloak`) |
| **S-14 Wasm gating (source-side)** ✅ | `DUCKDB_NATIVE_ONLY_SOURCES` (http_client_duckdb, check_token, login, refresh, device_login) is conditionally excluded in `CMakeLists.txt` when `EMSCRIPTEN` is set. The matching `Register*` calls in `quack_oauth_extension.cpp` are guarded by `#ifndef EMSCRIPTEN`. Wasm build retains settings, SECRET types, `diagnose()`, and `quack_oauth_check_authorization` (PURE_SOURCES + state are all wasm-safe; `policy_table.cpp` + `sql_inspect.cpp` use only DuckDB's own `Connection` / `Parser` APIs, no native deps). PURE_SOURCES (JWT verify/parse, JWKS cache, decision cache, providers, authz, policy, redact, tokeninfo/introspect parsers, token_endpoint parser, device_code parser) compile under emscripten unchanged. Live emcc build still requires the EMSDK toolchain in CI (`make wasm_mvp` via extension-ci-tools). | Native build, Catch2 (786 assertions), SQL (162), Keycloak integration (7 tests) all green; CI matrix run `6f1b649` verifies wasm_mvp / wasm_eh / wasm_threads all build the parser-driven authz path |

Deferred items (intentionally not yet sliced):

- **Policy query caching** — current loader runs the `SELECT` once per
  chunk. For small policies this is fine; if a profile ever shows the
  query on the hot path, cache the parsed `PolicyDocument` keyed by
  `(qualified_table, last-tx-id)` and invalidate on table mutation.
- **S-14 wasm CI matrix** — the source-side split is in place (see
  S-14 row above) and `make wasm_mvp` / `wasm_eh` / `wasm_threads`
  targets exist via extension-ci-tools, but the GitHub Actions matrix
  in `.github/workflows/MainDistributionPipeline.yml` doesn't yet
  exercise them. Needs an emcc-equipped runner and a vcpkg
  wasm32-emscripten install of jwt-cpp, openssl, picojson.
- **State-reset hook** — `QuackOauthState` is process-wide. Useful
  ergonomics: a `quack_oauth_reset()` PRAGMA that clears
  `session_principals`, `audit_ring`, and the caches between sessions
  or tests. Would also fix the `oauth_diagnose.test` brittleness around
  cross-test state leakage.
- **Telemetry beyond Logger** — `R-S-10` is covered by the per-decision
  `DUCKDB_LOG_*` calls, but a metrics/exporter sink (Prometheus /
  OpenTelemetry counter for `auth.deny.reason=...`) is out of scope of
  the spec but a natural follow-on for ops teams.

Slices land in order. Each PR closes its slice with green CI and a
note in `CLAUDE.md`'s `## Knowledge updates` section if anything
non-obvious surfaced.

## 8. When in doubt: ask, don't assume

This file exists because the requirements and architecture documents
leave many concrete decisions open. Whenever a slice surfaces a
decision that the docs don't already settle (e.g. exact SECRET field
type for `expires_at`, exact wording of a setting), open a question
to the user rather than picking unilaterally. Record the answered
decision in this file or in `architecture.md` as appropriate.

## 8.bis Resolved against upstream

### quack's actual callback contract (slice S-9)

`requirements.md` v0.1 (2026-05-14) describes the integration as:

> R-S-1: register replacements for `quack_check_token` and
> `quack_nop_authorization` upon LOAD, gated by `quack_oauth_enabled`
> (default false; setting it to true swaps the callbacks atomically).

Inspecting the installed `duckdb-quack` source
(`github.com/duckdb/duckdb-quack/src/quack_extension.cpp:125`), the actual
contract is:

- **Signatures**:
  - `quack_check_token(session_id VARCHAR, auth_string VARCHAR, token VARCHAR) → BOOLEAN`
  - `quack_nop_authorization(session_id VARCHAR, query_string VARCHAR) → BOOLEAN`
- **Swap mechanism**: not `OnCreateConflict::REPLACE_ON_CONFLICT`. Quack
  exposes two settings that name which function to call:
  - `quack_authentication_function` (default `'quack_check_token'`)
  - `quack_authorization_function` (default `'quack_nop_authorization'`)
- **Activation in this codebase**: register
  `quack_oauth_check_token` as a `ScalarFunctionSet` with overloads for both
  the 1-arg (CLI-friendly) and 3-arg (quack-callable) shapes, then operator
  runs `SET quack_authentication_function = 'quack_oauth_check_token'`
  after `LOAD quack`.
- **`quack_oauth_enabled` setting**: kept as a discoverable placeholder
  (R-N-12 still wants it visible) but no longer drives the swap. The actual
  toggle is the quack-side setting above. A future slice may wire a
  set-callback so `SET quack_oauth_enabled = true` also flips the quack
  setting, but that's pure ergonomics.

The corresponding requirements update is the user's call; this section
records the resolved contract so future slices use the right one.

## 9. Open questions (live)

These are not yet answered; capture answers inline as they come.

- **quack callback signatures**: the exact C++ signature of
  `quack_check_token` and `quack_nop_authorization` once we look at
  upstream `duckdb-quack`. R-S-1 names them but not their argument
  list. Pending S-9.
- **Wasm crypto backend**: `jwt-cpp` over OpenSSL (native) vs
  mbedTLS (wasm). Architecture §8.7 picks mbedTLS for size; needs a
  size measurement before commit. Pending S-14.
- **Recorded-transcript format**: home-rolled JSON vs a library
  (`vcrpy`-equivalent for C++). Pending S-11; lean home-rolled
  unless a library appears that fits in the dependency budget.
- **SECRET type names — kebab vs snake**: `requirements.md` prose
  references `TYPE quack-oauth` and `TYPE quack-oauth-server`
  (kebab-case). DuckDB's `CREATE SECRET ... TYPE <ident>` grammar
  accepts only an identifier; sibling-extension precedent is
  snake_case (e.g. `microsoft_entra` in
  `../erpl-web/src/microsoft_entra_secret.cpp:165`). Slice S-3
  registered the types as `quack_oauth` and `quack_oauth_server`.
  If the kebab form is required for spec compliance, the user
  should flag it — we'd need to either (a) quote the type name in
  every `CREATE SECRET` call site, or (b) maintain a second alias
  registration.
- **Introspection client credentials in `quack_oauth_server`**:
  R-S-5 requires POSTing to `introspection_endpoint` with client
  credentials, but R-S-11's verbatim field list for the server
  SECRET is only `issuer / audience / jwks_uri / policy_table`.
  S-3 ships exactly the R-S-11 fields and **defers** the
  introspect-creds question. Two viable resolutions when introspect
  mode is implemented (slice S-10): extend `quack_oauth_server`
  with `introspection_endpoint` / `introspect_client_id` /
  `introspect_client_secret`, or layer them via DuckDB SET. Pending
  user input.
