# This file is included by DuckDB's build system. It specifies which extension to load

# Extension from this repo
duckdb_extension_load(quack_oauth
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
)

# Note: `duckdb-quack` is NOT pulled in here. Building it inline via
# `duckdb_extension_load(quack GIT_URL ...)` fails because quack's
# CMakeLists references its own `duckdb/third_party/httplib` submodule,
# which the FetchContent path doesn't initialise. The S-9 SQL test uses
# `require quack`, which loads it from the user's installed extensions
# (populated by `make quack_prereq`). On systems where quack isn't
# installed, the test skips -- standard DuckDB sqllogictest behaviour.