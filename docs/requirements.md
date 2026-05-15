# quack-oauth — Requirements Specification

Status: draft v0.1 (2026-05-14)
Scope: a DuckDB extension `quack-oauth` that adds OAuth 2.1 / OpenID
Connect authentication and authorization to the `quack` client/server
protocol extension.

## 1. Context

`duckdb-quack` exposes a DuckDB instance as a network service over
HTTP/1.1 (`POST /quack`, content-type `application/duckdb`). Today it
authenticates clients with a single shared bearer token, compared in
constant time, carried inside the in-band `ConnectionRequestMessage`.
Authorization is a no-op (`quack_nop_authorization`).

quack already exposes two pluggable callbacks as DuckDB scalar
functions and a custom secret type:

- `quack_check_token(token VARCHAR) -> BOOLEAN` — replaceable.
- `quack_nop_authorization(...) -> BOOLEAN` — replaceable.
- `SECRET TYPE quack { token: VARCHAR (redacted) }` — replaceable.

`quack-oauth` plugs into exactly these extension points. It does not
modify `quack` itself and does not change the quack wire format.

Deployment assumption: a Caddy reverse proxy terminates TLS and
forwards opaque requests to the quack process. Caddy is **not** part
of the auth path; it is a TLS terminator only. The extension must
work identically when Caddy is absent (e.g. local dev, in-process
unit tests).

A second deployment is browser-side: `quack` running inside
DuckDB-Wasm. The Wasm build of `quack-oauth` does not implement any
OAuth flow itself; the host JavaScript page performs the flow and
injects the resulting access token into the extension via a SECRET.

## 2. Glossary

- **IdP** — identity provider. Supported, first-class: **Microsoft
  Entra ID, Google, Keycloak, Okta, GitHub**. Other RFC-6749/OIDC-1.0
  providers (Auth0, Authentik, Zitadel, …) are expected to work via
  the generic OIDC path but are not part of the test matrix.
- **AT** — OAuth 2.1 access token, signed JWT in this spec.
- **JWKS** — JSON Web Key Set published by the IdP at
  `<issuer>/.well-known/jwks.json`.
- **RS** — resource server: the quack process being protected.
- **Client** — the DuckDB instance attaching to a remote quack RS.
- **Subject** — `sub` claim of a verified AT; the authenticated
  principal.

## 3. Goals / Non-goals

### 3.1 Goals

1. Replace quack's shared-secret authentication with OIDC-grade
   bearer-token authentication, with no changes to the quack wire
   protocol.
2. Provide a minimal, claims-driven authorization model that lets
   operators express "who can ATTACH, SCAN, COPY, what".
3. Build identically for Linux, macOS, Windows, and DuckDB-Wasm from
   one C++ source tree.
4. Minimum dependencies; statically linkable; the smallest amount of
   code that satisfies the goals.

### 3.2 Non-goals

- TLS termination (delegated to Caddy or platform).
- User management, consent UI, IdP implementation.
- mTLS, SPIFFE, Macaroons, custom token formats.
- Row- or column-level security beyond what claims-to-role mapping
  trivially enables.
- HA, clustering, distributed sessions. State is per-process.

## 4. Stakeholders

| Role | Concern |
|------|---------|
| Data platform operator | Single sign-on; central revocation; audit. |
| Analyst (interactive duckdb shell) | Login once, queries just work. |
| Service / ETL job | Non-interactive credentials, no human in the loop. |
| Browser/notebook user | DuckDB-Wasm in a webapp must reuse the page's session. |
| Security reviewer | Standards-compliant, auditable, no token-in-logs. |

## 5. Functional requirements

Requirements use the convention **MUST / SHOULD / MAY** (RFC 2119).

### 5.1 Server-side (resource server)

- **R-S-1** The extension MUST register replacement scalar functions
  for the two quack auth hooks (`quack_oauth_check_token` for
  authentication, `quack_oauth_check_authorization` for authorization)
  upon LOAD. Quack performs the swap by name via its own settings:
  `SET quack_authentication_function = 'quack_oauth_check_token'` and
  `SET quack_authorization_function = 'quack_oauth_check_authorization'`.
  An advisory `quack_oauth_enabled` setting (default `false`) is
  registered so deployment tooling can express intent; the actual
  callback swap is performed by the operator (or their startup script)
  through the quack settings above. Per R-N-4, when
  `quack_oauth_enabled = true` and a non-loopback listener is detected
  without `quack_oauth_trust_plaintext = true`, the extension refuses
  to validate any wire-presented token.
- **R-S-2** The extension MUST validate access tokens by **either**
  local JWT verification against a cached JWKS, **or** RFC 7662
  introspection against the IdP, selected by the
  `quack_oauth_validation_mode` setting (`jwks` | `introspect`).
  Default `jwks`.
- **R-S-3** In `jwks` mode the extension MUST verify the JWT
  signature, `iss`, `aud`, `exp`, `nbf`, and `iat` (with a
  configurable clock skew, default 60 s). It MUST reject `none` and
  symmetric algorithms; permitted algorithms are RS256, RS384, RS512,
  ES256, ES384, EdDSA (Ed25519).
- **R-S-4** The extension MUST cache JWKS by `kid`, refresh on cache
  miss, and rate-limit JWKS fetches to at most one per
  `quack_oauth_jwks_min_refresh_s` (default 30 s) per `kid` to
  prevent JWKS-poll DoS.
- **R-S-5** In `introspect` mode the extension MUST POST to
  `introspection_endpoint` with `token=<at>` and the configured
  introspection client credentials, cache the result keyed by the
  token hash for up to `quack_oauth_introspect_cache_s` (default
  30 s, capped at the token's remaining lifetime), and treat
  `active=false` as a hard reject.
- **R-S-6** The extension MUST expose a `current_principal()` table
  function returning subject, issuer, scopes, and a JSON blob of
  claims, derived from the most recently authenticated token on the
  current connection.
- **R-S-7** The extension MUST provide a default authorization
  function `quack_oauth_check_authorization` that evaluates a policy
  expressed as **a SQL table in the server's DuckDB database**. The
  table is named per resource-server via the `policy_table` field on
  the `quack_oauth_server` SECRET; the fallback decision when no rule
  matches is controlled by the `quack_oauth_policy_default` setting
  (default `'deny'`). The expected table schema is:
  ```
  CREATE TABLE <policy_table> (
      priority  INTEGER NOT NULL,        -- ASC, first match wins
      subject   VARCHAR,                 -- NULL = any subject
      any_scope VARCHAR[],               -- NULL/[] = any scope
      actions   VARCHAR[],               -- NULL/[] = any action
      allow     BOOLEAN NOT NULL
  );
  ```
  Action strings MUST be one of: `Attach`, `Scan`, `CopyTo`, `CopyFrom`,
  `ServeAdmin`. The policy MUST support, at minimum:
  - allow/deny by `sub` (via the `subject` column),
  - allow/deny by required `scope` set (via `any_scope`),
  - allow/deny by quack operation (via `actions`).
  Allow/deny by referenced object (`schema.table` glob) is reserved
  for a future schema extension.
- **R-S-8** When `policy_table` is unset on the active SECRET, the
  default policy MUST be "any token with scope `quack:read` may
  attach + scan; any token with scope `quack:write` may also
  copy_to/copy_from (and implies read); no implicit admin". When
  `policy_table` is set but the table is missing, has the wrong
  schema, or contains an invalid action name, `check_authorization`
  MUST fail closed (return false for every session).
- **R-S-9** The extension MUST re-evaluate token validity (signature
  not yet checked OR `exp` past) on each call to
  `check_authorization`, not only at connection time. Validation
  results MUST be cached against the token's `jti` (or a SHA-256 of
  the raw token when `jti` is absent) for at most 60 s.
- **R-S-10** The extension MUST log auth events (token accepted,
  rejected with reason, JWKS refresh, policy denial) at INFO/WARN
  through DuckDB's logger. Tokens, JWKS private material, and client
  secrets MUST NEVER appear in logs; only `kid`, `sub`, `iss`, `jti`,
  and a token-hash prefix (first 8 hex chars of `sha256(token)`). In
  addition, the extension MUST expose:
  - `quack_oauth_audit_log()` table function -- last N decisions as
    typed rows (timestamp, event_type, subject, issuer, kid,
    token_hash, action, reason);
  - optional `audit_table` field on `quack_oauth_server` SECRET --
    when set, the extension INSERTs one row per decision into that
    table for persistent audit (same column shape as `audit_log()`).
- **R-S-11** Configuration MUST be settable via:
  (a) DuckDB SET statements, (b) a `CREATE SECRET ... TYPE
  quack-oauth-server` carrying issuer/audience/jwks-uri/policy-table,
  (c) environment variables prefixed `QUACK_OAUTH_*`. SET > SECRET >
  env, in that precedence.

### 5.2 Client-side (DuckDB attaching to a remote quack)

- **R-C-1** The extension MUST register a SECRET type
  `quack-oauth` with parameters: `issuer`, `client_id`,
  `client_secret` (redacted), `audience`, `scope`,
  `device_authorization_endpoint`, `token_endpoint`,
  `redirect_listener_port` (unused outside auth_code+PKCE, reserved),
  `access_token` (redacted, optional, externally injected),
  `refresh_token` (redacted, optional), `expires_at` (UTC
  timestamp). Either (client_id+secret) for client_credentials, or
  client_id alone for device_code, or just access_token for
  externally-supplied tokens MUST be sufficient.
- **R-C-2** When `ATTACH 'quack:host' AS x` resolves a `quack-oauth`
  secret, the extension MUST:
  - if `access_token` is present and not within
    `quack_oauth_renew_skew_s` (default 60 s) of `expires_at`, use it;
  - else, if `refresh_token` is present, perform
    `grant_type=refresh_token`;
  - else, if `client_secret` is present, perform
    `grant_type=client_credentials`;
  - else, perform RFC 8628 device authorization, print the
    `user_code` + `verification_uri_complete` via DuckDB notice/log,
    poll `token_endpoint` until success or `expires_in` elapses.
- **R-C-3** The resulting access token MUST be passed as the `token`
  parameter to quack's `ConnectionRequestMessage` (no quack wire
  changes).
- **R-C-4** The extension MUST automatically reconnect (re-issue
  `ConnectionRequestMessage` with a fresh token) when the local
  cached AT is within `quack_oauth_renew_skew_s` of expiry, before
  the next operation that requires a server round-trip.
- **R-C-5** Refresh tokens, when issued, MUST be persisted by
  updating the secret in DuckDB's secret manager. They MUST never be
  written to a separate file by the extension.
- **R-C-6** In a DuckDB-Wasm build (`-DEMSCRIPTEN`), the extension
  MUST NOT compile any OAuth-flow code. It MUST consume only the
  `access_token` and `expires_at` fields of the secret. Acquiring
  tokens is the host page's responsibility.
- **R-C-7** A scalar function `quack_oauth_login(secret_name)` MUST
  be available in non-Wasm builds to force a flow (typically
  device_code) and update the named secret. Returns the new
  `expires_at`.
- **R-C-8** A scalar function `quack_oauth_logout(secret_name)` MUST
  clear the cached `access_token`, `refresh_token`, and `expires_at`
  fields of the named secret, and SHOULD call the IdP's
  revocation endpoint (RFC 7009) when available.

### 5.3 Supported identity providers

The extension MUST ship with first-class, tested support for the
following providers. "First-class" means: documented secret-creation
recipe, end-to-end integration test in CI, named entry in
`quack_oauth_diagnose()`, and a provider preset that sets sensible
defaults for issuer/JWKS/introspection/validation-mode.

| Provider | AT format | Default validation_mode | Notes / quirks | Flows supported |
|---|---|---|---|---|
| **Microsoft Entra ID** (v2.0) | JWT (RS256) | `jwks` | `iss` is tenant-specific (`https://login.microsoftonline.com/{tid}/v2.0`); `aud` MUST be the RS's API client ID or `api://…` URI, **never** Microsoft Graph. v1.0 endpoints are out of scope. | device_code, client_credentials, refresh_token, auth_code+PKCE (Wasm) |
| **Google** (Google Identity) | Opaque AT (+ JWT ID token) | `introspect` (uses Google's `tokeninfo` endpoint) | Google's AT is **not** a JWT; `jwks` mode is not usable for the AT. The ID token is a JWT signed via `https://www.googleapis.com/oauth2/v3/certs` and MAY be validated for identity assertions but is not the bearer used for protocol auth. | device_code (limited-input devices client), client_credentials (workload-identity / service account JWT-bearer), refresh_token, auth_code+PKCE (Wasm) |
| **Keycloak** (≥ 22) | JWT (RS256/ES256) | `jwks` | `iss` is realm URL; introspection requires confidential client. Default reference platform for integration tests. | device_code, client_credentials, refresh_token, auth_code+PKCE (Wasm) |
| **Okta** (Customer Identity / Workforce Identity) | JWT (RS256) — **only** when using a **custom authorization server**; the org-level auth server emits opaque ATs for Okta's own APIs | `jwks` for custom AS, `introspect` for org AS | The default org auth server's AT is opaque and only valid for Okta APIs; the spec requires operators to provision a **custom** authorization server with an explicit audience. Diagnose MUST warn if the resolved `iss` is `https://{org}.okta.com` (org AS) rather than `https://{org}.okta.com/oauth2/{authServerId}`. | device_code, client_credentials, refresh_token, auth_code+PKCE (Wasm) |
| **GitHub** (OAuth Apps / GitHub Apps) | Opaque (`gho_…`, `ghu_…`, `ghs_…`) | Provider-specific (see notes) | GitHub is **not** OIDC and does **not** implement RFC 7662 introspection. Validation MUST POST to `https://api.github.com/applications/{client_id}/token` with HTTP-Basic `client_id:client_secret` per [GitHub REST: Check a token]; a 200 response with `user.login`, `scopes`, `expires_at` is the principal source. The `sub` claim is synthesised as `gh:{user.id}`; `scope` claims are GitHub OAuth scopes (`repo`, `read:org`, …). Device flow is supported (RFC 8628). PKCE is **not** supported by GitHub for confidential clients; Wasm builds MUST use the GitHub App user-to-server flow via host JS. | device_code, refresh_token (GitHub Apps only), auth_code (Wasm; PKCE per provider rules). **No client_credentials**: use a GitHub App installation token minted server-side as the AT instead. |

- **R-S-12** The extension MUST expose a `quack_oauth_provider`
  setting accepting `entra | google | keycloak | okta | github |
  generic` (default `generic`). Selecting a named provider MUST
  pre-populate provider-specific defaults (validation endpoint paths,
  default scopes, `iss` regex, claim-mapping rules) such that
  configuring a typical deployment requires only `client_id`,
  `client_secret` (where applicable), `tenant_or_realm_or_org`, and
  `audience`.
- **R-S-13** The extension MUST treat **GitHub** as a special case:
  - validation MUST use the GitHub `applications/{client_id}/token`
    endpoint, not RFC 7662;
  - the principal MUST map GitHub `user.login` → `preferred_username`,
    `user.id` → `sub` (prefixed `gh:`), `scopes[]` → `scope`,
    `user.email` (verified only) → `email`;
  - policy rules that match on `scope:repo` etc. MUST work
    unchanged.
- **R-S-14** The extension MUST treat **Google** as a special case:
  the AT is validated via Google's `tokeninfo` endpoint
  (`https://oauth2.googleapis.com/tokeninfo?access_token=…`) under
  the `introspect` mode wiring. Google ID tokens MAY additionally be
  consumed when present, validated against Google's JWKS, to enrich
  the principal's `email` / `name` claims; this is best-effort.
- **R-S-15** The provider matrix above MUST be re-checked in CI on
  every release-candidate build. A provider that fails its smoke test
  MUST block the release of `quack-oauth`.

### 5.4 Compatibility

- **R-X-1** quack's binary protocol MUST NOT change.
- **R-X-2** A `quack-oauth` server MUST refuse any token that is not
  a valid JWT-or-introspectable-opaque per `validation_mode`,
  including the legacy shared-secret strings. There is no fallback
  mode.
- **R-X-3** Native and Wasm builds MUST share one source tree gated
  by `#ifdef EMSCRIPTEN`. No platform-specific source files outside
  one isolated `platform/` subtree.

## 6. Non-functional requirements

### 6.1 Security

- **R-N-1** All cryptographic verification MUST use a vetted library
  (OpenSSL ≥3.0 native; mbedTLS for Wasm where applicable). No
  hand-rolled crypto.
- **R-N-2** Token comparison and cache lookups MUST not be vulnerable
  to timing attacks: cache keys are SHA-256 hashes; equality on raw
  tokens uses constant-time comparison.
- **R-N-3** The extension MUST drop tokens from memory (zero-fill)
  when their cache entry is evicted.
- **R-N-4** The extension MUST refuse to start when both
  `quack_oauth_enabled=true` and TLS is not detectable (heuristic:
  the listener is bound to `localhost` only, OR an explicit
  `quack_oauth_trust_plaintext` setting is `true`). This guards
  against accidentally serving bearer tokens over plaintext when
  Caddy is misconfigured.
- **R-N-5** No secret values MUST be returned from any scalar/table
  function. Redaction is applied at the SECRET layer and also in
  log lines.

### 6.2 Performance

- **R-N-6** Per-request auth overhead (cached JWKS, cached
  introspection) SHOULD be < 100 µs on a modern x86 core.
- **R-N-7** JWKS refresh and token-endpoint requests SHOULD complete
  with default 5 s connect / 10 s read timeouts and one retry with
  exponential backoff (1 s, 2 s).

### 6.3 Portability

- **R-N-8** Single source build for `linux/x86_64`,
  `linux/aarch64`, `macos/x86_64`, `macos/arm64`, `windows/x86_64`,
  and `wasm32`. All produced via the standard DuckDB extension
  CMake + vcpkg template.
- **R-N-9** All third-party dependencies MUST be statically linked
  into the `.duckdb_extension` artefact. Dynamic linkage is
  forbidden except against the platform's libc / libSystem /
  ucrt and OpenSSL where DuckDB itself already dynamically
  links it.

### 6.4 Code size / complexity

- **R-N-10** Target ≤ 2,500 SLOC of hand-written C++ for the entire
  extension (excluding vendored single-header libs and generated
  protobuf/JSON helpers).
- **R-N-11** Dependency budget: at most **four** third-party
  libraries beyond what DuckDB already pulls in. Default selection:
  `jwt-cpp` (header-only), `picojson` (header-only) **or**
  duckdb's already-vendored JSON, OpenSSL (already in vcpkg),
  `duckdb_httplib` (already vendored in duckdb).

### 6.5 Operability

- **R-N-12** All extension settings discoverable via
  `SELECT * FROM duckdb_settings() WHERE name LIKE 'quack_oauth%'`.
- **R-N-13** A `quack_oauth_diagnose()` table function MUST report:
  - **idp_reachability** -- live GET probe on the active SECRET's
    `jwks_uri` (or `introspection_endpoint` for opaque-token paths);
    status ∈ `{unconfigured, reachable, unreachable}` with the
    HTTP status code in `detail`;
  - **jwks_cache** -- in-memory entry count;
  - **decision_cache** -- in-memory entry count;
  - **session_principals** -- count of cached `(session_id → Principal)`
    pairs;
  - **recent_decisions** -- a tally over the in-memory audit ring
    (`count=N/CAP accepted= rejected= allowed= denied=`); full history
    is exposed by the companion `quack_oauth_audit_log()` table
    function;
  - **extension** -- current configuration snapshot
    (`enabled` / `secret_name` / `validation_mode` / `provider`).

## 7. Out of scope (deferred)

- Audit-log shipping to syslog/OTel.
- Token binding (RFC 8473) or DPoP (RFC 9449).
- Mutual TLS / client certificate auth.
- Multi-tenant policy with per-tenant JWKS.
- Caching backed by a shared store (Redis, etc.).
- Authorization-code+PKCE flow in native builds (Wasm host JS handles
  the browser case; native CLI uses device_code).

## 8. Acceptance criteria

1. With Keycloak (or equivalent) issuing RS256 access tokens, a
   client `ATTACH 'quack:rs.example.com' AS r (TYPE quack)` succeeds
   after a `CREATE SECRET` of type `quack-oauth` and `SELECT
   quack_oauth_login('s')` running a device-code flow.
2. `SELECT * FROM r.public.t LIMIT 1` succeeds for a token with
   scope `quack:read` and is denied with a clear error for a token
   without it.
3. Killing the IdP after JWKS is cached does not break ongoing
   queries until the cached JWKS' `kid` rotates.
4. Rotating the IdP's signing key, then invalidating the JWKS cache,
   surfaces in `quack_oauth_diagnose()` within
   `quack_oauth_jwks_min_refresh_s`.
5. A DuckDB-Wasm build loaded in a browser, given a SECRET
   pre-populated by the host page with a still-valid `access_token`,
   completes an ATTACH and a scan against a Caddy-fronted RS without
   any C++ code performing an OAuth flow.
6. The compiled native `quack_oauth.duckdb_extension` artefact is
   ≤ 3 MB and has no dynamic dependencies beyond what stock duckdb
   already requires on each platform.
7. **Provider matrix smoke test.** For each of {Entra, Google,
   Keycloak, Okta-custom-AS, GitHub} a recorded-transcript integration
   test (`replayhttp` or equivalent) issues a token via the
   provider-appropriate flow, ATTACHes, scans a table allowed by the
   policy, and is denied on a scope mismatch. All five MUST pass on
   every release-candidate build.
