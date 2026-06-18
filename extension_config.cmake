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
# Applied unconditionally. Both the stable (v1.5.3) and the 1.4 LTS build now
# run through the SAME v1.5.3 extension-ci-tools reusable workflow (see
# .github/workflows/MainDistributionPipeline.yml) -- only the DuckDB *source*
# version differs (LTS overrides duckdb_version=v1.4.4). That workflow forces
# the Windows compiler to MSVC `cl`, so both lines build Windows with MSVC,
# where C++17 is exactly what we want (fmt inline vars + the fmt _SECURE_SCL
# patch below) and there is no MinGW `std::byte`/`byte` ambiguity. (An earlier
# attempt built the LTS line with the @v1.4.4 workflow, which left the
# compiler to autodetect; on the new windows-latest image that picked MinGW
# g++, which both tripped the C++17 std::byte clash AND could not link the
# MSVC-built vcpkg OpenSSL -- hence the move to the v1.5.3 harness.)
set(CMAKE_CXX_STANDARD 17 CACHE STRING "C++ standard to enforce" FORCE)
set(CMAKE_CXX_STANDARD_REQUIRED ON CACHE BOOL "" FORCE)

# The 1.4 LTS build compiles DuckDB's `sqlite3_api_wrapper.cpp` (the stable
# v1.5.3 build does not), which pulls in the Win-SDK headers. At C++17 on
# MSVC, `std::byte` then clashes with the SDK's global `byte`
# (`error C2872: 'byte': ambiguous symbol` in rpcndr.h/wtypes.h/objidlbase.h).
# Disable std::byte for the LTS line -- DuckDB 1.4.x built fine before C++17
# existed and our code doesn't use std::byte, so this is safe. Scoped to
# v1.4.x via $ENV{DUCKDB_GIT_VERSION} (with a git-describe fallback) so the
# green stable build is untouched.
set(_qo_ddb_ver "$ENV{DUCKDB_GIT_VERSION}")
if(NOT _qo_ddb_ver)
  execute_process(
    COMMAND git -C "${CMAKE_CURRENT_LIST_DIR}/duckdb" describe --tags
    OUTPUT_VARIABLE _qo_ddb_ver OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
endif()
if(_qo_ddb_ver MATCHES "^v?1\\.4\\.")
  add_compile_definitions(_HAS_STD_BYTE=0)
  message(STATUS "quack-oauth: DuckDB ${_qo_ddb_ver} (1.4 LTS) -- defining _HAS_STD_BYTE=0 (avoid MSVC std::byte vs Win-SDK byte clash)")
endif()

# Patch DuckDB's bundled fmt 6.1.2 so it compiles on MSVC 19.51 (the VS18
# windows-latest runner), whose STL removed stdext::checked_array_iterator.
# Must run before DuckDB's add_third_party(fmt); this file is include()d from
# extension_build_tools.cmake well before that, same as the FORCE above. See
# scripts/patch_bundled_fmt.cmake for the full rationale.
include(${CMAKE_CURRENT_LIST_DIR}/scripts/patch_bundled_fmt.cmake)

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
