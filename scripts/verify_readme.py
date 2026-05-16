#!/usr/bin/env python3
"""Extract every ```sql block from README.md and verify it at least parses
through DuckDB with quack_oauth loaded. Blocks may reference external
resources (live IdPs, listener sockets, fictional tables) and so are
allowed to fail at *execution* with a known set of "expected" runtime
errors -- but parse errors, unknown function/option names, and unknown
SECRET fields are always treated as bugs.

Run: python3 scripts/verify_readme.py
Exit code 0 iff every block is acceptable.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

PROJ = pathlib.Path(__file__).parent.parent
README = PROJ / "README.md"
EXT = PROJ / "build" / "release" / "extension" / "quack_oauth" / "quack_oauth.duckdb_extension"
DUCKDB = PROJ / "build" / "release" / "duckdb"

# Errors we tolerate (block references something only available in a
# live setup -- IdP, listener, an as-yet-unfetched extension, etc.).
EXPECTED_OK = (
    "did not return a valid response",   # IdP not reachable
    "Connection refused",
    "Could not establish connection",
    "Unable to resolve",
    "SECRET '",                          # snippet references a SECRET we didn't create
    "Table with name",                   # references a table the snippet's prelude would have created
    "Catalog Error",
    "Could not find quack",              # ATTACH without a live server
    "Failed to install",                 # INSTALL from a URL we can't hit from CI
    "HTTP",
    "Conversion Error",                  # CAST samples on synthetic data
)

# Hard fails: parse errors, unknown options, undefined functions in our
# scalar/table surface, etc.
HARD_FAIL_MARKERS = (
    "syntax error",
    "Parser Error",
    "does not exist",        # unknown function name
    "Unknown named parameter",
    "Unknown option",
    "Unrecognized configuration",
    "Catalog Error: Setting",
)


def extract_blocks(text: str) -> list[tuple[int, str]]:
    """Returns [(line_number, sql_body), ...] for every ```sql fence."""
    blocks: list[tuple[int, str]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        if lines[i].strip() == "```sql":
            start = i + 1
            j = start
            while j < len(lines) and lines[j].strip() != "```":
                j += 1
            body = "\n".join(lines[start:j])
            blocks.append((start + 1, body))
            i = j + 1
        else:
            i += 1
    return blocks


def run_all_in_one_session(blocks: list[tuple[int, str]]) -> list[tuple[int, str, str]]:
    """Run all blocks in a single DuckDB process so state cascades:
    a CREATE TABLE in block N is visible to block N+1, mirroring how a
    reader would actually paste the examples top-to-bottom.

    Returns [(line_no, body, stderr-for-that-block), ...] in order.
    """
    # Build one big script that delimits per-block stderr via marker
    # PRAGMA echoes. The shell prefix isolates each block to its own
    # transaction so a CREATE TABLE failure in one doesn't poison later
    # blocks (we want to find ALL the bugs, not just the first).
    parts = [f"LOAD '{EXT}';"]
    for i, (_ln, body) in enumerate(blocks):
        parts.append(f"-- <<<BLOCK {i}>>>")
        parts.append(body)
        parts.append(f"-- <<<ENDBLOCK {i}>>>")
    full = "\n".join(parts) + "\n"

    proc = subprocess.run(
        [str(DUCKDB), "-unsigned", "-c", full],
        capture_output=True,
        text=True,
        timeout=60,
    )
    # DuckDB CLI prints each error to stderr but doesn't tag it by block.
    # We re-run each block individually for clean per-block stderr, but
    # carry state forward via a pre-seed script.
    return _run_individually_with_preseed(blocks)


def _run_individually_with_preseed(
    blocks: list[tuple[int, str]],
) -> list[tuple[int, str, str]]:
    results: list[tuple[int, str, str]] = []
    accumulated = f"LOAD '{EXT}';\n"
    for line_no, body in blocks:
        # Try to run this block isolated, but with everything that came
        # before as state. We append after-success so a block's errors
        # don't poison the next.
        script = accumulated + body + "\n"
        proc = subprocess.run(
            [str(DUCKDB), "-unsigned", "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
        )
        results.append((line_no, body, proc.stderr))
        if not proc.stderr.strip() or _stderr_is_expected(proc.stderr):
            accumulated += body + "\n"
    return results


def _stderr_is_expected(stderr: str) -> bool:
    return any(needle in stderr for needle in EXPECTED_OK)


def categorise(stderr: str) -> str:
    """Return 'hard', 'expected', or 'unknown'."""
    if not stderr.strip():
        return "ok"
    for needle in HARD_FAIL_MARKERS:
        if needle in stderr:
            return "hard"
    for needle in EXPECTED_OK:
        if needle in stderr:
            return "expected"
    return "unknown"


def main() -> int:
    if not EXT.exists():
        print(f"FAIL: extension not built at {EXT}", file=sys.stderr)
        return 2
    if not DUCKDB.exists():
        print(f"FAIL: duckdb not built at {DUCKDB}", file=sys.stderr)
        return 2

    text = README.read_text()
    blocks = extract_blocks(text)
    print(f"Found {len(blocks)} ```sql blocks in README.md\n")

    hard, expected, ok, unknown = [], [], [], []
    per_block_results = run_all_in_one_session(blocks)
    for line_no, body, stderr in per_block_results:
        # Skip blocks that are just the install-from-URL line (we can't
        # actually hit get.erpl.io in many environments).
        if body.strip().startswith("INSTALL '"):
            ok.append((line_no, body, "[skipped: live install]"))
            continue
        cat = categorise(stderr)
        if cat == "hard":
            hard.append((line_no, body, stderr.strip().splitlines()[0] if stderr.strip() else ""))
        elif cat == "expected":
            expected.append((line_no, body, stderr.strip().splitlines()[0]))
        elif cat == "unknown":
            unknown.append((line_no, body, stderr.strip().splitlines()[0]))
        else:
            ok.append((line_no, body, ""))

    print("=" * 72)
    print(f"OK         : {len(ok)}")
    print(f"expected   : {len(expected)}  (block fails on live resource we tolerate)")
    print(f"unknown    : {len(unknown)}  (review)")
    print(f"HARD FAIL  : {len(hard)}")
    print("=" * 72)

    if unknown:
        print("\n--- UNKNOWN (review by hand): ---")
        for ln, body, msg in unknown:
            print(f"\nREADME.md:{ln}")
            print("  body:", body[:120].replace("\n", " | "))
            print("  err :", msg)
    if hard:
        print("\n--- HARD FAILURES (must fix): ---")
        for ln, body, msg in hard:
            print(f"\nREADME.md:{ln}")
            print("  body:", body[:200].replace("\n", " | "))
            print("  err :", msg)
        return 1
    return 0 if not unknown else 1


if __name__ == "__main__":
    sys.exit(main())
