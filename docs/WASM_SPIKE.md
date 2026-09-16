# Wasm spike — is the documented reason for excluding wasm still true?

*Run 2026-09-16 against `5d88a99` + the `fn:` work, DuckDB v1.5.5,
emsdk 3.1.71 (the version `extension-ci-tools` pins), Linux x86-64.*

## Why this spike ran

`CLAUDE.md` and `MainDistributionPipeline.yml` both record the same
reason for excluding `wasm_mvp` / `wasm_eh` / `wasm_threads` (issue #3):

> the wasm loadable side-module (`emcc -sSIDE_MODULE=2`) links only the
> libraries named in `duckdb_extension_load(... LINKED_LIBS ...)`, and we
> declare none, so jwt-cpp's OpenSSL crypto symbols are left unresolved —
> the `.wasm` *builds* green but won't instantiate in the browser.

That predicts a specific, checkable failure. It had never been checked.

## What was established

**1. vcpkg builds OpenSSL for wasm without complaint.**
`wasm32-emscripten` resolves to vcpkg's community triplet and produces
OpenSSL **3.6.0**: `libcrypto.a` (6.4 MB) and `libssl.a` (1.4 MB) under
`build/wasm_mvp/vcpkg_installed/wasm32-emscripten/lib/`. The availability
of a wasm OpenSSL was never the problem.

**2. All three wasm targets build, and every artifact is a well-formed
extension.** Each is accepted by `new WebAssembly.Module(...)`, exports
`quack_oauth_duckdb_cpp_init` (the C++ entry point), and is correctly
stamped in its `duckdb_signature` section:

| target | size | imports | OpenSSL imports | stamp |
|---|---|---|---|---|
| `wasm_mvp` | 176,168 B | 378 | 0 | `v1.5.5` / `wasm_mvp` |
| `wasm_eh` | 229,320 B | 468 | 0 | `v1.5.5` / `wasm_eh` |
| `wasm_threads` | 176,270 B | 377 | 0 | `v1.5.5` / `wasm_threads` |

`wasm_threads` building is itself a correction: the comment at
`CMakeLists.txt:138-145` warns that the vcpkg OpenSSL port lacks the
atomics / bulk-memory features `--shared-memory` needs. That is true, but
it only ever applied to the **Catch2 unit-test binary**, which is skipped
under Emscripten — and since OpenSSL is dropped from the extension
entirely (see below), the constraint never binds.

**3. `LINKED_LIBS` changes essentially nothing — the premise above does
not hold as written.** Built both ways and compared:

| | with `LINKED_LIBS` | without |
|---|---|---|
| size | 176,168 B | 176,146 B |
| total imports | 378 | 378 |
| **OpenSSL imports** | **0** | **0** |

All 378 imports are libc / C++ runtime (`env` 247, `GOT.func` 39,
`GOT.mem` 92) — `memcpy`, `__cxa_throw`, `getenv` and friends. Not one
OpenSSL symbol is imported *or* defined, in either build.

This is not because the sources avoid OpenSSL. `jwt_verify.cpp.o` in the
wasm build carries **42 undefined OpenSSL symbols** (`EVP_DigestVerify`,
`BN_bin2bn`, `OSSL_PARAM_BLD_*`, …), and `secure_scrub.cpp.o` has
`OPENSSL_cleanse`. The linker drops that code as unreachable: every
registration that drives JWT verification (`RegisterQuackOauthCheckToken`
and the rest of the acquire/login/refresh surface) is compiled out under
`#ifndef __EMSCRIPTEN__`. The authorization walk survives —
`InspectSql` is present in the module's exports.

So the side-module has **no unresolved OpenSSL symbols to fail on**, and
`LINKED_LIBS` has nothing to fix.

## What was NOT established

**Whether the module actually loads.** This is the one thing the spike
set out to prove and it remains open. Three harness attempts, all
inconclusive for reasons unrelated to our artifact:

- `@duckdb/duckdb-wasm@1.33.1-dev57.0` ships DuckDB **v1.5.4**, so any
  result would have been a version-mismatch artifact. `dev64.0` ships
  **v1.5.5** and matches our build — use that one.
- The **blocking** node API (`duckdb-node-blocking.cjs`) *hangs
  indefinitely* on `LOAD`, even version-matched. It also fails
  `SET allow_unsigned_extensions=true` with `_setThrew is not defined`.
  Extension loading needs asynchronous WebAssembly instantiation, which a
  synchronous query call cannot drive — the blocking API is the wrong
  harness, not evidence about the module.
- The **async worker** API crashed inside `duckdb-node-mvp.worker.cjs`.

A browser harness (or `duckdb-wasm`'s own test runner) is the credible
next step. Static evidence points toward the module loading fine, but
*points toward* is not *proves*, and the whole reason wasm was excluded is
that this failure mode is invisible to a green build.

## Recommendation

**Keep wasm excluded for now** — the exclusion stays correct, but the
*stated reason* is wrong and should be corrected so nobody re-derives a
fix for a non-problem. Note the second-order effect: with all three
targets building green and carrying no unresolved symbols, CI would
happily publish them, which is exactly the "green build, broken artifact"
trap the exclusion was meant to avoid — only now the danger is an
extension that cannot authenticate, not one that cannot instantiate.
community-extensions PR #2709, which excludes wasm, is unaffected either
way.

Before re-enabling, in order:

1. Prove `LOAD` in a browser against duckdb-wasm v1.5.5. Everything else
   is inference.
2. Decide what a wasm build should *mean*. With the native-only
   registrations compiled out, the wasm module exposes the authorization
   surface (`check_authorization`, `inspect_sql`, policy, secrets,
   settings, diagnose) but **cannot verify a JWT** — `jwt_verify` is
   stripped. Shipping a build that authorizes but cannot authenticate
   needs a deliberate answer, and ADR-5 ("Wasm build does no OAuth; host
   JS does") is the place to record it.
3. Only then touch `exclude_archs`, invert `scripts/test_ci_wasm_excluded.sh`
   (it currently asserts the opposite), and add a browser-based load leg
   to `_extension_smoke_test.yml` — whose matrix is native-only today, and
   whose `scripts/smoke_test.py` drives a native CLI.

The **mbedtls fallback is not needed.** It was contingent on wasm OpenSSL
being unbuildable or unlinkable; neither is the case.

## Build gotchas found (also in `CLAUDE.md`)

- `GEN=ninja` breaks every wasm target: the makefile configures with
  `emcmake cmake` but builds with `emmake make`, so a Ninja tree dies with
  "No targets specified and no makefile found". The stale
  `CMAKE_GENERATOR:INTERNAL=Ninja` in `build/<arch>/CMakeCache.txt`
  survives a re-run, so you must `rm -rf build/<arch>` — preserving
  `vcpkg_installed/` to avoid a 20-minute OpenSSL rebuild.
- `vcpkg.json`'s `overlay-triplets` points at
  `./extension-ci-tools/toolchains`, which no longer exists in the pinned
  submodule (deleted upstream in `cd7a046`). vcpkg ignores it silently.
