# Extension updating

The CI builds against **two** DuckDB lines in parallel:

- **Stable** — the latest v1.5.x release (currently v1.5.6). The
  `duckdb/` and `extension-ci-tools/` git submodules are pinned to this
  version. Day-to-day development happens against this checkout.
- **Next** — DuckDB 2.0 (`duckdb-next-build`), pinned to a commit on the
  `v2.0-cyanoptera` tooling branch. Built only in CI and not published.

DuckDB 1.4.x (LTS) is no longer supported.

## Bumping stable (e.g. v1.5.3 → v1.5.4)

1. **Bump submodules:**
   - `./duckdb` → new tagged release
   - `./extension-ci-tools` → the branch named after that release
     (e.g. `v1.5.4`)

   ```bash
   # edit .gitmodules: change `branch = v1.5.x` for both submodules
   git submodule sync
   git -C duckdb fetch --tags origin && git -C duckdb checkout v<new>
   git -C extension-ci-tools fetch origin v<new> && \
     git -C extension-ci-tools checkout FETCH_HEAD
   git add .gitmodules duckdb extension-ci-tools
   ```

2. **Bump versions in `.github/workflows/MainDistributionPipeline.yml`:**
   In the `duckdb-stable-build` and `duckdb-stable-deploy` jobs,
   update **all four** `v<old>` occurrences:
   - the reusable workflow ref (`@v<new>`)
   - `duckdb_version`
   - `ci_tools_version`
   - the `name:` field (display only)

# API changes
DuckDB extensions built with this extension template are built against the internal C++ API of DuckDB. This API is not guaranteed to be stable.
What this means for extension development is that when updating your extensions DuckDB target version using the above steps, you may run into the fact that your extension no longer builds properly.

Currently, DuckDB does not (yet) provide a specific change log for these API changes, but it is generally not too hard to figure out what has changed.

For figuring out how and why the C++ API changed, we recommend using the following resources:
- DuckDB's [Release Notes](https://github.com/duckdb/duckdb/releases)
- DuckDB's history of [Core extension patches](https://github.com/duckdb/duckdb/commits/main/.github/patches/extensions)
- The git history of the relevant C++ Header file of the API that has changed