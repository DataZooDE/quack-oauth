#!/usr/bin/env bash
#
# test_ci_wasm_excluded.sh -- assert the distribution pipeline excludes the
# wasm architectures (issue #3: the wasm side-module links no OpenSSL via
# LINKED_LIBS and fails to load; OAuth flows aren't viable in wasm anyway).
#
# This is a real behavioural test of the CI mechanism: it pulls every
# `exclude_archs:` value out of the workflow and feeds it to the *same*
# matrix generator extension-ci-tools runs (modify_distribution_matrix.py),
# then asserts the resulting wasm matrix is empty -- i.e. no wasm job is
# emitted. RED before the workflow excludes wasm, GREEN after.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$REPO_ROOT/.github/workflows/MainDistributionPipeline.yml"
MATRIX_SCRIPT="$REPO_ROOT/extension-ci-tools/scripts/modify_distribution_matrix.py"
MATRIX_JSON="$REPO_ROOT/extension-ci-tools/config/distribution_matrix.json"

for f in "$WORKFLOW" "$MATRIX_SCRIPT" "$MATRIX_JSON"; do
  [ -f "$f" ] || { echo "FAIL: missing required file: $f" >&2; exit 1; }
done

# All distinct exclude_archs values declared in the workflow (build + deploy).
mapfile -t EXCLUDES < <(grep -oE "exclude_archs:\s*'[^']*'" "$WORKFLOW" \
                          | sed -E "s/.*'([^']*)'.*/\1/" | sort -u)

if [ "${#EXCLUDES[@]}" -eq 0 ]; then
  echo "FAIL: no exclude_archs entries found in $WORKFLOW" >&2
  exit 1
fi

WASM_ARCHS=(wasm_mvp wasm_eh wasm_threads)
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
rc=0

for excl in "${EXCLUDES[@]}"; do
  out="$tmp/wasm_matrix.json"
  : > "$out"
  python3 "$MATRIX_SCRIPT" \
    --input "$MATRIX_JSON" \
    --select_os wasm \
    --output "$out" \
    --exclude "$excl" \
    --opt_in "" \
    --reduced_ci_mode disabled >/dev/null

  # Empty file or {} => no wasm jobs emitted. Anything with an "include"
  # list means wasm is still built.
  remaining="$(python3 - "$out" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as fh:
        txt = fh.read().strip()
    data = json.loads(txt) if txt else {}
except Exception:
    data = {}
print(",".join(e.get("duckdb_arch", "?") for e in data.get("include", [])))
PY
)"

  if [ -n "$remaining" ]; then
    echo "FAIL: exclude_archs='$excl' still emits wasm jobs: [$remaining]" >&2
    rc=1
  else
    echo "ok: exclude_archs='$excl' -> wasm matrix empty"
  fi

  # Belt and suspenders: the workflow string itself names every wasm arch.
  for w in "${WASM_ARCHS[@]}"; do
    case ";$excl;" in
      *";$w;"*) : ;;
      *) echo "FAIL: exclude_archs='$excl' does not list '$w'" >&2; rc=1 ;;
    esac
  done
done

if [ "$rc" -eq 0 ]; then
  echo "PASS: all exclude_archs values exclude wasm_mvp/wasm_eh/wasm_threads"
fi
exit "$rc"
