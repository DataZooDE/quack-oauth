#!/usr/bin/env bash
# Enforce that the loadable extension only dynamically links against the
# platform standard libraries. See docs/IMPLEMENTATION.md section 6.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <path-to-.duckdb_extension>" >&2
    exit 2
fi

target="$1"
if [[ ! -f "$target" ]]; then
    echo "not found: $target" >&2
    exit 2
fi

# Platform-libs allowlist. Anything else is a static-linkage violation.
allowlist_pattern='^(linux-vdso|libpthread|libdl|librt|libm|libgcc_s|libstdc\+\+|libc|ld-linux-x86-64|ld-linux-aarch64|libssl|libcrypto)\.so'

violations=$(ldd "$target" 2>/dev/null \
    | awk '{ print $1 }' \
    | awk -F/ '{ print $NF }' \
    | grep -v '^$' \
    | grep -Ev "$allowlist_pattern" \
    || true)

if [[ -n "$violations" ]]; then
    echo "FAIL: $target has disallowed dynamic dependencies:" >&2
    echo "$violations" >&2
    exit 1
fi

echo "OK: $target dynamic deps within allowlist"
ldd "$target"
