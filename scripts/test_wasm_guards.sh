#!/usr/bin/env bash
#
# test_wasm_guards.sh -- assert that Wasm preprocessor guards in src/ use
# standard __EMSCRIPTEN__ (defined by emcc/em++) rather than bare EMSCRIPTEN
# (issue #14), and verify that all DUCKDB_WASM_SAFE_SOURCES compile cleanly
# with -D__EMSCRIPTEN__ without telemetry.hpp on the include path.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# 1. Assert no bare EMSCRIPTEN preprocessor checks exist in src/
echo "Checking for bare EMSCRIPTEN preprocessor directives in src/..."
if grep -rnE '#\s*(if|ifdef|ifndef|elif)\s+EMSCRIPTEN\b' "$REPO_ROOT/src"; then
  echo "FAIL: Found bare EMSCRIPTEN preprocessor check. Use __EMSCRIPTEN__ instead." >&2
  exit 1
fi
echo "PASS: No bare EMSCRIPTEN preprocessor checks in src/"

# 2. Assert all Emscripten preprocessor guards in src/ use __EMSCRIPTEN__
match_count=$(grep -rcE '#\s*(if|ifdef|ifndef|elif)\s+__EMSCRIPTEN__\b' "$REPO_ROOT/src" | awk -F: '{s+=$2} END {print s}')
if [ "$match_count" -lt 14 ]; then
  echo "FAIL: Expected at least 14 __EMSCRIPTEN__ guards in src/, found $match_count" >&2
  exit 1
fi
echo "PASS: Found $match_count __EMSCRIPTEN__ guards in src/"

# 3. Syntax check DUCKDB_WASM_SAFE_SOURCES with -D__EMSCRIPTEN__ (without posthog-telemetry/include)
if command -v g++ >/dev/null 2>&1; then
  echo "Verifying DUCKDB_WASM_SAFE_SOURCES syntax under -D__EMSCRIPTEN__..."
  for f in src/quack_oauth_extension.cpp src/check_authorization_function.cpp src/diagnose.cpp src/settings.cpp; do
    g++ -fsyntax-only -std=c++17 -D__EMSCRIPTEN__ \
      -I"$REPO_ROOT/src/include" \
      -I"$REPO_ROOT/duckdb/src/include" \
      -I"$REPO_ROOT/duckdb/third_party/fmt/include" \
      -I"$REPO_ROOT/datazoo-banner/include" \
      "$REPO_ROOT/$f"
  done
  echo "PASS: DUCKDB_WASM_SAFE_SOURCES compile without telemetry.hpp under -D__EMSCRIPTEN__"
fi

echo "ALL WASM GUARD CHECKS PASSED"
