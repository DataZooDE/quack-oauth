# This file is included by DuckDB's build system. It specifies which extension to load.
#
# DuckDB caches CMAKE_CXX_STANDARD=11 (duckdb/CMakeLists.txt) and a plain
# `set(... CACHE ...)` in our own CMakeLists is a no-op against an already
# populated cache, so the whole of DuckDB compiles below C++17 by default.
# That single fact breaks the v1.5.3 build in two different ways:
#
#   * Linux/GCC: linking quack_oauth statically into DuckDB drags
#     posthog_telemetry's PUBLIC cxx_std_17 requirement into DuckDB's own
#     `plan_serializer` tool, so that one tool compiles as C++17 while
#     `libduckdb_static` stays C++11. `BufferedFileWriter::DEFAULT_OPEN_FLAGS`
#     is then a COMDAT-weak symbol on one side and a strong out-of-line
#     definition on the other -> "multiple definition" link error.
#   * Windows/MSVC (VS2026 runners): DuckDB's bundled `fmt` uses inline
#     variables, which MSVC rejects without `/std:c++17` (error C7525). At
#     CMAKE_CXX_STANDARD=11 CMake emits no `/std` flag at all on MSVC.
#
# Forcing the standard to C++17 for the ENTIRE build fixes both: every TU
# (incl. plan_serializer and fmt) agrees on C++17, so the weak/strong symbol
# split disappears and MSVC gets `/std:c++17`. This must happen before DuckDB
# configures `src`/`tools`/the third-party libs -- this file is included from
# extension_build_tools.cmake (DUCKDB_EXTENSION_CONFIGS) well before those
# add_subdirectory() calls, so the FORCE lands in time.
set(CMAKE_CXX_STANDARD 17 CACHE STRING "C++ standard to enforce" FORCE)
set(CMAKE_CXX_STANDARD_REQUIRED ON CACHE BOOL "" FORCE)

# Extension from this repo.
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
