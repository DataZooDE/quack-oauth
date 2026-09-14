#!/usr/bin/env bash
#
# test_wasm_guards.sh -- assert that Wasm preprocessor guards in src/ use
# standard __EMSCRIPTEN__ (defined by emcc/em++) rather than bare EMSCRIPTEN
# (issue #14), and verify that all DUCKDB_WASM_SAFE_SOURCES compile cleanly
# with -D__EMSCRIPTEN__ without telemetry.hpp on the include path.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# 1. Assert no bare EMSCRIPTEN preprocessor checks exist in src/ or src/include/
echo "Checking for bare EMSCRIPTEN preprocessor directives in src/ and src/include/..."
if grep -rnE '(#\s*(if|ifdef|ifndef|elif)\s+EMSCRIPTEN\b|#\s*(if|elif).*defined\s*\(?\s*EMSCRIPTEN\b)' "$REPO_ROOT/src"; then
  echo "FAIL: Found bare EMSCRIPTEN preprocessor check. Use __EMSCRIPTEN__ instead." >&2
  exit 1
fi
echo "PASS: No bare EMSCRIPTEN preprocessor checks found."

# 2. Assert CMakeLists.txt does not define bare EMSCRIPTEN
echo "Checking that CMakeLists.txt does not define bare EMSCRIPTEN..."
if grep -nE 'add_compile_definitions\s*\(\s*EMSCRIPTEN\s*\)|-DEMSCRIPTEN\b' "$REPO_ROOT/CMakeLists.txt"; then
  echo "FAIL: Found bare EMSCRIPTEN compile definition in CMakeLists.txt. Rely solely on compiler-provided __EMSCRIPTEN__." >&2
  exit 1
fi
echo "PASS: CMakeLists.txt does not define bare EMSCRIPTEN."

# 3. Assert all 14 Emscripten preprocessor guards in src/ use __EMSCRIPTEN__
match_count=$(grep -rcE '#\s*(if|ifdef|ifndef|elif)\s+__EMSCRIPTEN__\b|defined\s*\(?\s*__EMSCRIPTEN__\b' "$REPO_ROOT/src" | awk -F: '{s+=$2} END {print s}')
if [ "$match_count" -lt 14 ]; then
  echo "FAIL: Expected at least 14 __EMSCRIPTEN__ guards in src/, found $match_count" >&2
  exit 1
fi
echo "PASS: Found $match_count __EMSCRIPTEN__ guards in src/."

# 4. Syntax check all DUCKDB_WASM_SAFE_SOURCES with -D__EMSCRIPTEN__ (without posthog-telemetry/include)
WASM_SAFE_SOURCES=(
  "src/audit_sink.cpp"
  "src/check_authorization_function.cpp"
  "src/diagnose.cpp"
  "src/policy_table.cpp"
  "src/quack_oauth_extension.cpp"
  "src/quack_oauth_state.cpp"
  "src/secret_accessor.cpp"
  "src/secrets.cpp"
  "src/settings.cpp"
  "src/sql_inspect.cpp"
  "src/tracing_log.cpp"
)

if command -v g++ >/dev/null 2>&1; then
  echo "Verifying all ${#WASM_SAFE_SOURCES[@]} DUCKDB_WASM_SAFE_SOURCES syntax under -D__EMSCRIPTEN__..."
  for f in "${WASM_SAFE_SOURCES[@]}"; do
    if [ ! -f "$REPO_ROOT/$f" ]; then
      echo "FAIL: Expected source file $f not found" >&2
      exit 1
    fi
    g++ -fsyntax-only -std=c++17 -D__EMSCRIPTEN__ -w \
      -I"$REPO_ROOT/src/include" \
      -I"$REPO_ROOT/duckdb/src/include" \
      -I"$REPO_ROOT/duckdb/third_party/fmt/include" \
      -I"$REPO_ROOT/datazoo-banner/include" \
      "$REPO_ROOT/$f"
  done
  echo "PASS: All ${#WASM_SAFE_SOURCES[@]} DUCKDB_WASM_SAFE_SOURCES compile cleanly under -D__EMSCRIPTEN__ without telemetry.hpp"
else
  echo "WARNING: g++ not found, skipping syntax-only compilation checks" >&2
fi

echo "ALL WASM GUARD CHECKS PASSED"

