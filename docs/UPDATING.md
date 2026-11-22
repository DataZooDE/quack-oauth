# Extension updating

The default local build and stable CI release line use **DuckDB v2.0.1**.
The `duckdb/` gitlink pins the release tag's commit; `extension-ci-tools/`
pins a commit from the matching `v2.0-cyanoptera` tooling branch. CI builds,
smoke-tests and publishes this line. Separate `duckdb-v1-*` jobs retain
v1.5.6 compatibility and distribution. DuckDB 1.4.x is no longer supported.

## Bumping the default release

1. Update `duckdb/` to the new stable release tag and `extension-ci-tools/`
   to a compatible tooling commit. The tooling branch need not have the
   same name as the DuckDB release tag.
2. Keep `.gitmodules` branch entries aligned with the corresponding
   upstream maintenance branches, then commit both gitlinks. Normal
   `git submodule update --init --recursive` uses the pinned commits.
3. In `.github/workflows/MainDistributionPipeline.yml`, update the
   `duckdb-stable-build`, `duckdb-stable-smoke-test`, and
   `duckdb-stable-deploy` jobs together: `duckdb_version`, display names,
   reusable build workflow ref and `ci_tools_version` (build and deploy).
   Keep compatibility jobs on their own release line.
4. Reconfigure and rebuild locally, run the SQL and security regressions,
   and verify CI smoke-tests the loadable artifact in the official release
   binary before publishing.

# API changes
DuckDB extensions built with this extension template are built against the internal C++ API of DuckDB. This API is not guaranteed to be stable.
What this means for extension development is that when updating your extensions DuckDB target version using the above steps, you may run into the fact that your extension no longer builds properly.

Currently, DuckDB does not (yet) provide a specific change log for these API changes, but it is generally not too hard to figure out what has changed.

For figuring out how and why the C++ API changed, we recommend using the following resources:
- DuckDB's [Release Notes](https://github.com/duckdb/duckdb/releases)
- DuckDB's history of [Core extension patches](https://github.com/duckdb/duckdb/commits/main/.github/patches/extensions)
- The git history of the relevant C++ Header file of the API that has changed