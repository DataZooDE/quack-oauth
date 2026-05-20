# Extension updating

The CI builds against **two** DuckDB versions in parallel:

- **Stable** — the latest non-LTS release. The `duckdb/` and
  `extension-ci-tools/` git submodules are pinned to this version.
  Day-to-day development happens against this checkout.
- **LTS** — the latest patch on the **1.4 LTS** line. Built only in
  CI (the submodules are not multi-pinned); the LTS jobs in
  `MainDistributionPipeline.yml` pass the LTS version as a workflow
  input, and both the upstream `_extension_distribution.yml` and our
  repo-local `_extension_deploy.yml` check the submodules out to that
  version inline.

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

## Bumping the LTS pin (e.g. v1.4.4 → v1.4.5)

Submodules are not touched. In
`.github/workflows/MainDistributionPipeline.yml`, in the
`duckdb-lts-build` and `duckdb-lts-deploy` jobs, update all four
`v1.4.x` occurrences (workflow ref, `duckdb_version`,
`ci_tools_version`, `name:`).

The repo-local `_extension_deploy.yml` checks out both submodules to
the requested version inline, so the LTS deploy picks up the LTS
architecture matrix without any further edits.

# API changes
DuckDB extensions built with this extension template are built against the internal C++ API of DuckDB. This API is not guaranteed to be stable.
What this means for extension development is that when updating your extensions DuckDB target version using the above steps, you may run into the fact that your extension no longer builds properly.

Currently, DuckDB does not (yet) provide a specific change log for these API changes, but it is generally not too hard to figure out what has changed.

For figuring out how and why the C++ API changed, we recommend using the following resources:
- DuckDB's [Release Notes](https://github.com/duckdb/duckdb/releases)
- DuckDB's history of [Core extension patches](https://github.com/duckdb/duckdb/commits/main/.github/patches/extensions)
- The git history of the relevant C++ Header file of the API that has changed