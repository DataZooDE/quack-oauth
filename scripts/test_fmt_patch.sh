#!/usr/bin/env bash
#
# test_fmt_patch.sh -- verify scripts/patch_bundled_fmt.cmake neutralizes the
# `#ifdef _SECURE_SCL` guard in DuckDB's bundled fmt 6.1.2.
#
# Background: MSVC 19.51 (the VS18 windows-latest runner) removed
# stdext::checked_array_iterator, which that guarded branch uses. fmt's #else
# branch (plain pointer) compiles everywhere, so we force selection of it at
# CMake configure time. This test exercises the transform on a fixture so it
# runs anywhere (no MSVC needed); the real MSVC compile is validated in CI.
#
# RED before scripts/patch_bundled_fmt.cmake exists; GREEN after.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATCH_SCRIPT="$REPO_ROOT/scripts/patch_bundled_fmt.cmake"

command -v cmake >/dev/null || { echo "FAIL: cmake not on PATH" >&2; exit 1; }
[ -f "$PATCH_SCRIPT" ] || { echo "FAIL: missing $PATCH_SCRIPT" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fixture="$tmp/format.h"

# Minimal reproduction of fmt 6.1.2's guarded block (format.h:324-333).
cat > "$fixture" <<'EOF'
template <typename Char> inline Char* get_data(std::basic_string<Char>& s) {
  return &s[0];
}

#ifdef _SECURE_SCL
// Make a checked iterator to avoid MSVC warnings.
template <typename T> using checked_ptr = stdext::checked_array_iterator<T*>;
template <typename T> checked_ptr<T> make_checked(T* p, std::size_t size) {
  return {p, size};
}
#else
template <typename T> using checked_ptr = T*;
template <typename T> inline T* make_checked(T* p, std::size_t) { return p; }
#endif
EOF

cmake -DQO_FMT_HEADER="$fixture" -P "$PATCH_SCRIPT" >/dev/null

rc=0
if grep -q '#ifdef _SECURE_SCL' "$fixture"; then
  echo "FAIL: '#ifdef _SECURE_SCL' guard still present after patch" >&2
  rc=1
fi
if ! grep -q '#if 0' "$fixture"; then
  echo "FAIL: guard not replaced with '#if 0'" >&2
  rc=1
fi
# The portable #else branch must survive untouched.
if ! grep -q 'using checked_ptr = T\*;' "$fixture"; then
  echo "FAIL: portable #else (checked_ptr = T*) branch missing" >&2
  rc=1
fi

# Idempotent: a second run must not error or further change the file.
before="$(cat "$fixture")"
cmake -DQO_FMT_HEADER="$fixture" -P "$PATCH_SCRIPT" >/dev/null
if [ "$before" != "$(cat "$fixture")" ]; then
  echo "FAIL: patch is not idempotent" >&2
  rc=1
fi

[ "$rc" -eq 0 ] && echo "PASS: fmt _SECURE_SCL guard neutralized, #else branch intact, idempotent"
exit "$rc"
