# quack-oauth — development guide

DuckDB extension that adds OAuth 2.1 / OIDC authentication and a
claims-driven authorization model to the `duckdb-quack` client/server
protocol. See `requirements.md` and `architecture.md` (arc42) for the
*what* and *why*. See `docs/IMPLEMENTATION.md` for the *how we build
and test it* (TDD discipline, test layering, real-world IdP plan,
static-linkage policy, slice-by-slice plan). This file is the local
dev / workflow guide — start here when you need to know *how* to
build, test, or extend.

Target name: **`quack_oauth`** (snake_case, used as `INSTALL quack_oauth`
/ `LOAD quack_oauth` and as `TARGET_NAME` in `CMakeLists.txt`).

## Knowledge updates

This file is a living document. When a session of work uncovers
something that future sessions would want to know — a persistent
error and its fix, a non-obvious DuckDB C++ API behavior, a vcpkg or
CMake quirk, a CI surprise, a working pattern for a tricky extension
feature — capture it here. A one-paragraph note under the relevant
section (`Common pitfalls` for gotchas, the appropriate topical
section for new patterns) is enough. The bar is *"would past-me have
saved an hour if this had been written down?"* If yes, write it.

## Repository layout

```
.
├── CMakeLists.txt              # explicit source list, find_package() per dep
├── Makefile                    # one-liner: include extension-ci-tools/.../duckdb_extension.Makefile
├── extension_config.cmake      # duckdb_extension_load(quack_oauth ...)
├── vcpkg.json                  # native deps (openssl today; more land per module)
├── src/
│   ├── quack_oauth_extension.cpp   # entry point: DUCKDB_CPP_EXTENSION_ENTRY → LoadInternal
│   └── include/
│       └── quack_oauth_extension.hpp
├── test/sql/                   # SQLLogicTest *.test files
├── duckdb/                     # submodule, pinned to v1.5.3
├── extension-ci-tools/         # submodule, pinned to v1.5.3
├── requirements.md             # functional spec
├── architecture.md             # arc42 design doc
└── docs/UPDATING.md            # how to bump the DuckDB target version
```

## Build

Always use ninja — every sibling extension does, and `make` without it
takes 2–3× longer:

```bash
export VCPKG_ROOT=/home/jr/.local/share/vcpkg          # or wherever your vcpkg lives
export VCPKG_TOOLCHAIN_PATH=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
GEN=ninja make                # release build, usual dev loop
GEN=ninja make debug          # debug build (needed for ASAN, lldb, etc.)
```

Artifacts:

- `build/release/duckdb` — duckdb shell with the extension statically linked
- `build/release/test/unittest` — DuckDB unit test runner (also has the
  extension linked in; the way to run SQL tests)
- `build/release/extension/quack_oauth/quack_oauth.duckdb_extension` —
  the loadable binary that ships in distribution

First build is slow: DuckDB + the vcpkg openssl fetch. Incremental
builds are seconds with ninja. `make clean` is rarely needed — only
after editing `vcpkg.json` or pulling a new DuckDB submodule SHA.

## Tests

Two layers — see `docs/IMPLEMENTATION.md` section 2 for the policy.
**SQL tests are the source of truth**; Catch2 unit tests are
restricted to pure logic with no DuckDB linkage. Mocks are allowed
in Catch2 only, never in SQL tests.

```bash
make test                                                       # all SQL tests
./build/release/test/unittest test/sql/<feature>.test           # one SQL test
./build/release/test/unittest --test-dir . "[sql]"              # all sql group
make unit_test                                                  # Catch2 unit tests
./build/release/test/quack_oauth_unit_tests "[tracing][redact]" # one Catch2 tag
```

Static-linkage smoke (asserts only platform libs are dynamic deps):

```bash
make smoke_static
```

Test file header convention (copied from anofox-context):

```
# name: test/sql/<feature>.test
# description: <one line>
# group: [sql]

statement error
SELECT some_fn();
----
Catalog Error: Scalar Function with name some_fn does not exist!

require quack_oauth

query I
SELECT some_fn('x');
----
expected output
```

Always start the live-extension part of a test with `require quack_oauth`.
Use `statement error` *before* the require to assert the extension is
genuinely not loaded by default.

## vcpkg

We use vcpkg in manifest mode (`vcpkg.json`) with the overlay-ports
and overlay-triplets shipped inside `extension-ci-tools`. Today's only
declared dep is `openssl`.

To add a dependency (jwt-cpp, cpp-httplib, spdlog, … per
architecture.md §8):

1. Add the package name to `vcpkg.json` dependencies.
2. In `CMakeLists.txt`, add a `find_package(<name> CONFIG REQUIRED)`
   and link the import target in both `target_link_libraries()` calls
   (static **and** loadable).
3. `make clean && GEN=ninja make` — vcpkg will fetch and build the
   dep into `vcpkg_installed/`.

Header-only libs (jwt-cpp, spdlog when used as header-only) only need
an `include_directories(...)` or the corresponding interface target.

## Source layout conventions

Follow the anofox-tabular / anofox-context pattern:

- One paired `.cpp` + `.hpp` per module. Header in `src/include/`,
  implementation in `src/`. No subdirectories under `src/` until a
  module grows past ~5 files.
- The entry point (`src/quack_oauth_extension.cpp`) only declares
  `LoadInternal(ExtensionLoader &loader)` and the C ABI hook
  (`DUCKDB_CPP_EXTENSION_ENTRY`). Per-module registration goes into
  module-scoped `Register<Foo>(loader)` functions called from
  `LoadInternal`.
- **Explicit source list** in `CMakeLists.txt`, never globs (sibling
  convention — globs invalidate ninja caching on file add/delete).

## C++ conventions

**Mimic upstream DuckDB style.** When in doubt about formatting,
naming, file structure, includes, or idiomatic use of DuckDB's C++
API, copy the style of one of these reference codebases — in order
of preference:

1. **DuckDB itself** — the `duckdb/` submodule. Its `src/`, `src/include/`,
   and especially `src/main/extension/` show what idiomatic
   extension-facing code looks like. The repo-root `.clang-format` and
   `.clang-tidy` are already symlinked from `duckdb/` (so the formatter
   already enforces this).
2. `https://github.com/duckdb/duckdb-quack` — small, focused
   protocol extension; pattern reference for callback-replacement
   APIs, scalar-function registration, and the SECRET type integration
   we plug into.
3. `https://github.com/duckdb/ducklake` — larger, modern extension
   with a richer surface (table functions, storage, transactions);
   pattern reference for module layout once `quack-oauth` grows past
   the single-file scaffold.

Don't invent local style. If something looks unfamiliar in a sibling
DataZoo extension (`../erpl`, `../erpl-web`, `../anofox-*`), check
DuckDB / duckdb-quack / ducklake before assuming it's the convention.

Explicit baselines (consistent with the references above):

- C++17. The flag is set in `CMakeLists.txt`; don't touch.
- File names: `snake_case.cpp` / `snake_case.hpp`.
- Types and functions: `CamelCase`.
- Prefer `duckdb::unique_ptr<T>` / `duckdb::make_uniq<T>(...)`. Avoid
  raw `new` / `delete`.
- Keep functions short (target ~30 lines; 80-line ceiling).
- Run `clang-format -i` before committing; the symlinked
  `.clang-format` is DuckDB's exact config, so output will match.
- **Linker gotcha** (from anofox-tabular): if you get a duplicate
  symbol on `duckdb::LogicalType::VARCHAR` or similar at link time,
  switch the offending call site to `LogicalTypeId::VARCHAR`. The
  `LogicalType::` constants are non-inline definitions; in the
  loadable + static dual-build they can multi-define.
- **C++ standard gotcha**: DuckDB's `build_static_extension` /
  `build_loadable_extension` macros force `-std=c++11` on extension
  targets, ignoring the project-level `CMAKE_CXX_STANDARD` setting
  (because DuckDB's parent CMake already cached the value).
  `std::string_view`, `std::optional`, and the rest of C++17 simply
  fail to compile until you add
  `target_compile_features(${EXTENSION_NAME} PRIVATE cxx_std_17)` and
  the same for `${LOADABLE_EXTENSION_NAME}`. This is also required
  on any naked `add_executable(...)` target (e.g. the Catch2 unit
  test binary), which otherwise inherits DuckDB's `-std=c++14`. See
  `../erpl-web/CMakeLists.txt:168-171` for the proven sibling
  pattern and our own `CMakeLists.txt` for the live wiring.
- **The cached `CMAKE_CXX_STANDARD=11` breaks the v1.5.3 build in two
  places; force C++17 for the WHOLE build in `extension_config.cmake`.**
  DuckDB's root CMake does `set(CMAKE_CXX_STANDARD "11" CACHE STRING ...)`,
  and a plain `set(... CACHE ...)` in our `CMakeLists.txt` is a no-op
  against an already-populated cache (see the gotcha above), so by default
  every DuckDB TU compiles below C++17. Symptoms:
    1. **Linux/GCC**: linking quack_oauth statically into DuckDB drags
       `posthog-telemetry`'s **PUBLIC** `cxx_std_17` into DuckDB's own
       `tools/plan_serializer`, so that one tool compiles as C++17 while
       `libduckdb_static` stays C++11. `BufferedFileWriter::DEFAULT_OPEN_FLAGS`
       (a `static constexpr` member *with* a deprecated out-of-line
       definition) is then COMDAT-weak on one side and a strong symbol on
       the other → `multiple definition` link error.
    2. **Windows/MSVC** (VS2026 runners): DuckDB's bundled `fmt` uses inline
       variables, rejected without `/std:c++17` (`error C7525`); at
       `CMAKE_CXX_STANDARD=11` CMake emits no `/std` flag on MSVC at all.
  (v1.4.4 LTS Linux is unaffected — the header differs.) **Fix:**
  `set(CMAKE_CXX_STANDARD 17 CACHE STRING "" FORCE)` at the top of
  `extension_config.cmake`. That file is `include()`d from
  extension-ci-tools' `extension_build_tools.cmake` (via
  `DUCKDB_EXTENSION_CONFIGS`) **before** DuckDB's `add_subdirectory(src/tools)`
  and `add_third_party(fmt)`, so the FORCE lands in time and the whole build
  agrees on C++17 (no weak/strong split; MSVC gets `/std:c++17`). Our
  `CMakeLists.txt:13` set is too late (it runs at the extension subdir, after
  src/tools are configured) — the FORCE must be in `extension_config.cmake`.
- **The C++17 FORCE fixes the Windows *inline-variable* error (C7525) but
  uncovers a second MSVC failure on the newest runners.** `windows-latest`
  now ships MSVC 19.51 (VS18/"2026"), whose STL **removed**
  `stdext::checked_array_iterator`. DuckDB v1.5.3 (and 1.4 LTS) bundle fmt
  6.1.2, whose `#ifdef _SECURE_SCL` branch
  (`duckdb/third_party/fmt/include/fmt/format.h`) uses that symbol →
  `C2653: 'stdext' is not a class or namespace name`. `_SECURE_SCL` is
  *always* defined on MSVC, so the broken branch is always taken, and
  `_SILENCE_ALL_MS_EXT_DEPRECATION_WARNINGS` can't revive a *removed*
  symbol. The runner is hardcoded in the extension-ci-tools submodule
  (`config/distribution_matrix.json`) with no override input, so you can't
  pin an older image. **Fix:** `extension_config.cmake` `include()`s
  `scripts/patch_bundled_fmt.cmake`, which flips that guard to `#if 0` at
  configure time (before `add_third_party(fmt)`), forcing fmt's portable
  `#else` (plain-pointer) branch — what every non-MSVC build already uses.
  The patch is idempotent and runs on all platforms (no-op behavior change
  off MSVC). It edits a file inside the `duckdb/` submodule working tree, so
  expect `git status` to show the submodule dirty after a configure; that's
  cosmetic. Transform is covered by `make ci_config_test`
  (`scripts/test_fmt_patch.sh`); the real MSVC compile is CI-only.
- **Google's `tokeninfo` returns numeric claims as JSON strings**, not
  numbers: `"exp": "1735689600"` rather than `"exp": 1735689600`. Any
  parser that demands `picojson::value::is<std::int64_t>()` will see
  zeros for `exp` and `expires_in`. Pattern: a `AsIntFlexible` helper
  that tries int → double → string-with-stoll. Same quirk applies to
  `expires_in`. Service-account tokens also omit `sub` entirely
  (unlike user tokens). Also note: Google's tokeninfo is
  **unauthenticated** -- adding HTTP Basic auth causes 401, unlike
  RFC 7662 introspection. See `src/tokeninfo.cpp::QueryTokeninfo`.
- **Entra access tokens for Microsoft Graph carry a `nonce` in the
  JWT header and are NOT verifiable by third parties.** When you
  request `scope=https://graph.microsoft.com/.default`, the returned
  token has `header.nonce` set to a server-side random value, and the
  signature is computed over a transformed input (not plain
  `header.payload`). Even `openssl dgst -verify` with the correct
  JWKS key reports `bad signature`. This is by design — Microsoft
  protects against cross-app replay by making Graph tokens
  Graph-only. For third-party validation (i.e. our use case), the
  app MUST expose a custom API (App registration → Expose an API →
  Application ID URI) AND define an Application app role (App roles
  → Allowed member types = Applications). The token is then
  requested with `scope=api://<client_id>/.default` and signs as a
  standard JWS. The Azure permissions cache takes 1–5 min to sync
  after creating app roles -- `Grant admin consent` fails with
  `Claim is invalid: <role> does not exist in client application's
  RequiredResourceAccess` until propagation completes. Pattern
  documented in `scripts/capture_entra_transcript.sh` and the
  fixtures under `test/integration/transcripts/entra/`.
- **`SecretManager::GetSecretByName` returns a `unique_ptr`** that owns
  the `SecretEntry`. Helpers that extract the `KeyValueSecret*` MUST
  keep the unique_ptr alive in the same scope where the `*kv` is used,
  not return-by-raw-pointer from a helper that lets the owner drop.
  The wrong shape (returning a raw `KeyValueSecret*` from a helper)
  yields a dangling pointer that DuckDB's allocator surfaces as
  `Out of Memory Error: Allocation failure`, not a segfault -- the
  pointed-to memory is reused by the next allocation. Pattern in
  `src/login_function.cpp::DoLogin`.
- **`require <ext>` vs explicit `LOAD <ext>` in SQL tests**: the
  unittest binary sets `load_extensions=false` and uses its own local
  extension repo (`build/release/repository/<version>/<platform>/`),
  not `~/.duckdb/extensions/`. So `require quack` silently *skips*
  the test if quack isn't in the build repo, even when the operator
  has it installed via `INSTALL quack;` at the shell level. `LOAD <ext>`
  on the other hand honours `allow_unsigned_extensions` (which the
  runner enables) and finds the extension at the user's default
  install path -- so it works locally but *hard-fails* in CI because
  the CI runner has no `~/.duckdb/extensions/`. **The default choice
  for tests that need quack is `require quack` -- gracefully skipping
  in CI is much better than a red build.** The canonical end-to-end
  coverage of the quack swap is `make e2e` (Python+uv harness; boots
  a real quack server in-process), which already exercises the real
  wire. Pattern in `test/sql/oauth_quack_swap.test`.
- **DuckDB's core `HTTPUtil` is HTTP-only without `httpfs`.** The default
  `HTTPLibClient` (in `duckdb/src/main/http/http_util.cpp`) wraps
  `duckdb_httplib::Client` (not `SSLClient`) and throws
  `NotImplementedException` on POST/PUT/HEAD/DELETE. HTTPS + POST support
  is provided by `httpfs` registering its own `HTTPUtil` implementation.
  So migrating `src/http_client_duckdb.cpp` to `HTTPUtil::Get(*context.db).Request(...)`
  would create a runtime dependency on `LOAD httpfs`. Since OAuth/OIDC
  endpoints are virtually always HTTPS + POST (token endpoint,
  introspection, tokeninfo), we deliberately keep our own
  `cpp-httplib`-backed `DuckdbHttpClient` and `RetryingHttpClient` rather
  than introducing the httpfs precondition. Pattern reference for the
  HTTPUtil API (when we eventually do migrate, e.g. after R-N-X "make
  httpfs a hard dep") is `duckdb/src/main/extension/extension_install.cpp`
  lines 433-449.
- **Pulling another DuckDB extension via `duckdb_extension_load(GIT_URL ...)`
  needs the target's submodules**: e.g. duckdb-quack's CMakeLists references
  `duckdb/third_party/httplib` as a relative path inside its own tree.
  When `register_external_extension` fetches via FetchContent it does
  NOT recurse into the target's submodules by default, so the include
  path is missing and compilation fails. `duckdb_extension_load` has a
  `SUBMODULES` option that *might* help, but the simpler path for
  development-only dependencies (test-only quack) is to leave it
  out-of-build and `LOAD` from the user's installed extension dir.
- **jwt-cpp's `base64url` alphabet is URL-percent-encoded**, not the
  unpadded form JWS/JWK use. `jwt::alphabet::base64url::fill()` returns
  `"%3d"` (the URL-encoded form of `=`), so jwt-cpp's encoder produces
  `...%3d` for padded base64url and its decoder *rejects* inputs that
  end with literal `=`. **For JWK n/e fields** (and any other JWS-format
  base64url) you must roll your own decoder/encoder or strip `%3d`
  before calling jwt-cpp's helpers. Live in `src/jwt_verify.cpp`'s
  `Base64UrlDecode` and `test/cpp/test_jwt_verify.cpp`'s
  `B64UrlNoPad`. Discovered when integrating with a real Keycloak.
- **Generated SQL test files must live under `test/`** to be discovered
  by DuckDB's unittest binary -- it recursively scans the `test/`
  directory at startup and registers each `.test` file as a Catch2
  test case. Passing a path outside `test/` makes the binary treat it
  as a filter pattern that matches nothing. But that means a stale
  generated `.test` file under `test/` will silently break `make test`
  on subsequent runs. Convention: integration runners delete their
  generated files in the cleanup trap; the path goes in `.gitignore`.
  See `scripts/run_integration_keycloak.sh`.
- **jwt-cpp time errors all map to `token_expired`** in 0.7.x:
  exp-in-past, nbf-in-future, and iat-in-future all surface as the
  same `token_verification_error::token_expired` code. To distinguish
  `Expired` from `NotYetValid` we re-examine the token's claims
  against the injected clock after the verifier returns. See
  `VerifyWithVerifier` in `src/jwt_verify.cpp`.
- **jwt-cpp uses two distinct `std::error_category` objects**:
  `signature_verification_error_category()` for raw RSA/ECDSA
  failures and `token_verification_error_category()` for claim
  checks. `ec.value()` is an `int` in both, and the numeric ranges
  overlap (e.g. `verifyfinal_failed` can numerically equal
  `token_expired`). **You MUST dispatch on `ec.category()` first.**
  Pattern in `src/jwt_verify.cpp`.
- **Flipping the last base64url char of an RSA signature doesn't
  invalidate it**: unpadded base64url's last char encodes only
  2 useful bits of the trailing signature byte plus 4 padding bits.
  For RSA-2048 (256-byte sig → 342-char base64url), changing the
  final character may modify only padding bits and leave the
  signature bytes unchanged. Tests that exercise "tampered
  signature" must mangle a *middle* character of the signature
  segment, not the last one.
- **jwt-cpp + picojson wiring**: vcpkg's `jwt-cpp` port sets
  `-DJWT_DISABLE_PICOJSON` in the public interface and does **not**
  ship `picojson.h`. Including `<jwt-cpp/jwt.h>` alone gives you a
  jwt-cpp without a JSON backend — the templates won't instantiate.
  Fix: add `picojson` as its own vcpkg dep (its port installs to
  `include/picojson/picojson.h`, which matches the path
  `jwt-cpp/traits/kazuho-picojson/traits.h` hard-codes) and
  `#include <jwt-cpp/traits/kazuho-picojson/defaults.h>` instead of
  the base `jwt.h`. The defaults header brings in picojson and
  defaults `jwt::decode<>` to the kazuho-picojson traits. See
  `src/jwt_parse.cpp` for the live wiring.
- **`DESCRIBE FROM <table_function()>` gotcha**: in DuckDB 1.5.x this
  returns a *single* `Describe` column with pre-formatted text
  ("`component varchar`"), not the separate `column_name` /
  `data_type` / `ordinal_position` columns that some clients expect.
  Don't write SQL tests that depend on the multi-column shape. To
  assert column types, query the function and wrap each column in
  `typeof(...)` instead — that's the pattern in
  `test/sql/oauth_diagnose.test`.
- **Running SQL from inside a scalar function callback**: construct
  `duckdb::Connection conn(*context.db);` then `conn.Query(sql)`. The
  call is fine to issue inside `BinaryExecutor::Execute<...>`'s outer
  scope (per chunk), but doing it per row would multiply the cost by
  the chunk size. Pattern in `src/policy_table.cpp` (load policy
  rules once per chunk) + the inspiration in
  `../erpl-web/src/delta_share_scan.cpp:232`. Identifiers MUST be
  quoted before substitution — see `QuoteQualifiedIdentifier` in
  `src/policy_table.cpp`; never concatenate user-influenced names
  (incl. SECRET fields) directly into SQL.

## Submodules

Both pinned to `v1.5.3` (current stable):

```
duckdb              → tag      v1.5.3   (14eca11bd9…)
extension-ci-tools  → branch   v1.5.3   (4b3b37b0c9…, tip of v1.5.3)
```

CI **also** builds against the 1.4 LTS line (currently `v1.4.4`)
in a parallel job pair. The LTS jobs override the version via
workflow inputs — submodules are not multi-pinned, so local dev
defaults to stable. To build against LTS locally, check the
submodules out to the LTS tag/branch and `make clean && GEN=ninja
make`.

Bumping the DuckDB stable target is a coordinated change — both
submodules move together, plus the `duckdb_version` /
`ci_tools_version` inputs in
`.github/workflows/MainDistributionPipeline.yml`. Bumping the LTS
pin is workflow-only. The procedure is in `docs/UPDATING.md`.

When CI breaks after a bump, check DuckDB's release notes and the
[core extension patches](https://github.com/duckdb/duckdb/commits/main/.github/patches/extensions)
for C++ API changes.

## Commit & PR style

- Short, imperative commit subjects (≤72 chars). Optional body
  explains the *why*.
- Do **not** add "Generated with Claude" / `Co-Authored-By: Claude…`
  trailers — sibling extensions explicitly forbid them.
- One logical change per commit. Don't bundle a refactor with a
  feature.

## Common pitfalls

- **`make` without `GEN=ninja`** uses the default generator (Make on
  Linux/macOS, MSBuild on Windows) and is much slower. Always export
  `GEN=ninja` locally.
- **Editing `vcpkg.json` without `make clean`** can leave stale
  dependency state in `vcpkg_installed/`. Clean and rebuild.
- **`unittest` vs `duckdb` CLI**: the unittest runner is the reliable
  way to execute extension SQL tests (the CLI loads the extension
  but sqllogictest verbs aren't available there).
- **Wasm path**: wasm is currently **excluded from CI** (issue #3 —
  `wasm_mvp;wasm_eh;wasm_threads` in every `exclude_archs` of
  `MainDistributionPipeline.yml`). The reason is a load-time failure CI
  can't see: the wasm loadable side-module (`emcc -sSIDE_MODULE=2`) links
  only the libraries named in `duckdb_extension_load(... LINKED_LIBS ...)`,
  and we declare none, so jwt-cpp's OpenSSL crypto symbols are left
  unresolved — the `.wasm` *builds* green (symbol resolution is deferred
  to load time) but won't instantiate in the browser. OAuth's
  interactive/redirect flows aren't viable in wasm anyway. The
  source-side split below is **kept** so a future `LINKED_LIBS`-based
  wasm build can be re-enabled cheaply, but no wasm artifact ships today.
  The `CMakeLists.txt` source list is split into `DUCKDB_WASM_SAFE_SOURCES`
  and `DUCKDB_NATIVE_ONLY_SOURCES`; the native-only set is conditionally
  excluded under `if(EMSCRIPTEN)`, and the matching `Register*` calls in
  `quack_oauth_extension.cpp` are wrapped in `#ifndef EMSCRIPTEN`. **When
  adding a new network-touching scalar / table function: put its `.cpp` in
  `DUCKDB_NATIVE_ONLY_SOURCES`, and wrap both its `#include` and its
  `Register*(loader)` call in the entry point's `#ifndef EMSCRIPTEN`
  block.** Don't add `#include <openssl/…>` in any of the
  `DUCKDB_WASM_SAFE_SOURCES` files. PURE_SOURCES are always
  wasm-safe (they're already free of DuckDB / httplib deps). **To
  re-enable wasm:** make the side-module self-contained by passing the
  vcpkg wasm OpenSSL archives via `LINKED_LIBS` on the
  `duckdb_extension_load(quack_oauth ...)` call in `extension_config.cmake`,
  then drop the wasm archs from `exclude_archs`. Verify with a real
  duckdb-wasm browser/node load (CI's build-green is not proof).

## Pointers

### DuckDB upstream canonical extensions

Read these when you need an authoritative example of *how* to build an
extension feature — they're maintained by the DuckDB core team and
track current best practices.

- `https://github.com/duckdb/duckdb-quack` — the protocol extension
  this one plugs into; the closest API-surface reference, and the
  source of the callbacks (`quack_check_token`,
  `quack_nop_authorization`) we replace.
- `https://github.com/duckdb/ducklake` — modern out-of-tree extension
  with rich storage/transaction surface area; good for table-function
  patterns, custom storage, and DuckDB v1.5 idioms.
- `https://github.com/duckdb/duckdb-postgres` — the postgres scanner.
  Best reference for: external HTTP/network resources, SECRET-typed
  authentication, replacement scans, ATTACH-style integration.

### DataZoo build & deployment standards

Read these for *how we do it here* — Makefile structure, vcpkg
manifest patterns, GitHub Actions distribution pipeline, custom
extension repository deployment, telemetry, internal CI conventions.

- `../erpl` — flagship SAP/enterprise data-source extension. Mature
  build + custom-repo deployment (`get.erpl.io`), multi-module
  layout, custom CI.
- `../erpl-web` — HTTP/OData/secrets stack; closest analogue to
  `quack-oauth` in surface area. Reference for OpenSSL + SECRET
  registration + cpp-httplib usage and the `make dev` fast-path.
- `../anofox-tabular` — explicit-source CMake, multi-DuckDB-version
  CI matrix, `LogicalTypeId::VARCHAR` linker-gotcha workaround,
  header-only spdlog usage.
- `../anofox-context` — minimal Makefile, paired
  `src/*.cpp` ⇄ `src/include/*.hpp` module layout, bundled httplib.

### Other

- DuckDB SQLLogicTest docs: in-tree at
  `duckdb/test/sqllogictest/README.md`.
- DuckDB extension template upstream:
  `https://github.com/duckdb/extension-template` (we bootstrapped from
  this; `docs/UPDATING.md` is its retained guidance).
- DuckDB C++ API change tracking:
  `https://github.com/duckdb/duckdb/commits/main/.github/patches/extensions`.
