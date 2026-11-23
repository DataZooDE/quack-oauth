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
#
# Applied unconditionally. Every release line (v1.5.6 and 2.0) builds through
# its own extension-ci-tools reusable workflow (see
# .github/workflows/MainDistributionPipeline.yml), which forces the Windows
# compiler to MSVC `cl`, where C++17 is exactly what we want (fmt inline vars +
# the fmt _SECURE_SCL patch below).
set(CMAKE_CXX_STANDARD 17 CACHE STRING "C++ standard to enforce" FORCE)
set(CMAKE_CXX_STANDARD_REQUIRED ON CACHE BOOL "" FORCE)

# Patch DuckDB's bundled fmt 6.1.2 so it compiles on MSVC 19.51 (the VS18
# windows-latest runner), whose STL removed stdext::checked_array_iterator.
# Must run before DuckDB's add_third_party(fmt); this file is include()d from
# extension_build_tools.cmake well before that, same as the FORCE above. See
# scripts/patch_bundled_fmt.cmake for the full rationale.
include(${CMAKE_CURRENT_LIST_DIR}/scripts/patch_bundled_fmt.cmake)

# Extension from this repo.
#
# DuckDB v1.5.6 stamps the short commit SHA instead of the release tag: its duckdb_extension_generate_version
# passes --match '${VERSIONING_TAG_MATCH}' with literal single quotes, so no tag ever matches. Pass the version
# explicitly when HEAD is on a vX.Y.Z tag (2.0.x detects it correctly too; this keeps both lines identical).
set(QUACK_OAUTH_EXT_VERSION "")
find_package(Git QUIET)
if(Git_FOUND)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --tags --always --match "v*.*.*"
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
        RESULT_VARIABLE QUACK_OAUTH_GIT_RESULT
        OUTPUT_VARIABLE QUACK_OAUTH_GIT_DESCRIBE
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
    if(QUACK_OAUTH_GIT_RESULT EQUAL 0 AND QUACK_OAUTH_GIT_DESCRIBE MATCHES "^v[0-9]+\\.[0-9]+\\.[0-9]+(-[a-zA-Z0-9\\.]+)?$")
        set(QUACK_OAUTH_EXT_VERSION "${QUACK_OAUTH_GIT_DESCRIBE}")
    endif()
endif()
if(QUACK_OAUTH_EXT_VERSION STREQUAL "")
    duckdb_extension_load(quack_oauth
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    )
else()
    message(STATUS "quack_oauth extension version ${QUACK_OAUTH_EXT_VERSION}")
    duckdb_extension_load(quack_oauth
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
        EXTENSION_VERSION ${QUACK_OAUTH_EXT_VERSION}
    )
endif()

# Note: `duckdb-quack` is NOT pulled in here. Building it inline via
# `duckdb_extension_load(quack GIT_URL ...)` fails because quack's
# CMakeLists references its own `duckdb/third_party/httplib` submodule,
# which the FetchContent path doesn't initialise. The S-9 SQL test uses
# `require quack`, which loads it from the user's installed extensions
# (populated by `make quack_prereq`). On systems where quack isn't
# installed, the test skips -- standard DuckDB sqllogictest behaviour.
