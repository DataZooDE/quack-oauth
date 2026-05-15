cmake_minimum_required(VERSION 3.5)

set(TARGET_NAME quack_oauth)

find_package(OpenSSL REQUIRED)
find_package(jwt-cpp CONFIG REQUIRED)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

set(CMAKE_CXX_STANDARD "17" CACHE STRING "C++ standard to enforce")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(src/include)

# DuckDB ships cpp-httplib (namespace `duckdb_httplib_openssl`) under its
# third_party tree. Use it directly rather than adding a separate vcpkg dep,
# matching `../erpl-web/CMakeLists.txt` precedent. Pure-logic targets
# (Catch2 unit tests) intentionally do NOT get this include path -- only
# the DUCKDB_SOURCES module `http_client_duckdb.cpp` uses it.
include_directories(./duckdb/third_party/httplib)

# Pure-logic sources (no DuckDB includes) -- compiled into BOTH the extension
# and the Catch2 unit-test binary. See docs/IMPLEMENTATION.md section 2.3.
set(PURE_SOURCES
    src/acquire_flow.cpp
    src/action_detect.cpp
    src/audit.cpp
    src/authz.cpp
    src/decision_cache.cpp
    src/device_code.cpp
    src/env_overrides.cpp
    src/github_check.cpp
    src/idp_probe.cpp
    src/introspect.cpp
    src/jwks_cache.cpp
    src/jwks_parse.cpp
    src/jwt_parse.cpp
    src/jwt_verify.cpp
    src/picojson_helpers.cpp
    src/plaintext_guard.cpp
    src/platform_time.cpp
    src/policy.cpp
    src/principal_expiry.cpp
    src/providers.cpp
    src/retry_http_client.cpp
    src/secure_scrub.cpp
    src/token_endpoint.cpp
    src/tokeninfo.cpp
    src/tracing_redact.cpp
    src/validator.cpp
)

# DuckDB-coupled sources that DO NOT touch the network -- safe on every
# target including wasm32. See architecture.md R-Q-3: wasm builds must
# still register settings, SECRET types, diagnose(), and the authz scalar.
set(DUCKDB_WASM_SAFE_SOURCES
    src/audit_sink.cpp
    src/check_authorization_function.cpp
    src/diagnose.cpp
    src/policy_table.cpp
    src/quack_oauth_extension.cpp
    src/quack_oauth_state.cpp
    src/secret_accessor.cpp
    src/secrets.cpp
    src/settings.cpp
    src/tracing_log.cpp
)

# DuckDB-coupled sources that DO touch the network (duckdb_httplib_openssl
# or rely on it via the validator). Compiled into native builds only; the
# matching Register* calls in quack_oauth_extension.cpp are guarded with
# `#ifndef EMSCRIPTEN` so the wasm build links cleanly without them.
set(DUCKDB_NATIVE_ONLY_SOURCES
    src/acquire_function.cpp
    src/check_token_function.cpp
    src/device_login_function.cpp
    src/http_client_duckdb.cpp
    src/login_function.cpp
    src/logout_function.cpp
    src/refresh_function.cpp
)

if(EMSCRIPTEN)
  set(DUCKDB_SOURCES ${DUCKDB_WASM_SAFE_SOURCES})
else()
  set(DUCKDB_SOURCES ${DUCKDB_WASM_SAFE_SOURCES} ${DUCKDB_NATIVE_ONLY_SOURCES})
endif()

set(EXTENSION_SOURCES ${PURE_SOURCES} ${DUCKDB_SOURCES})

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

# DuckDB's extension build macros default to C++11 on extension targets;
# bump to C++17 to match the project standard. Sibling-extension pattern
# (see ../erpl-web/CMakeLists.txt:168-171).
target_compile_features(${EXTENSION_NAME} PRIVATE cxx_std_17)
target_compile_features(${LOADABLE_EXTENSION_NAME} PRIVATE cxx_std_17)

target_link_libraries(${EXTENSION_NAME} OpenSSL::SSL OpenSSL::Crypto jwt-cpp::jwt-cpp)
target_link_libraries(${LOADABLE_EXTENSION_NAME} OpenSSL::SSL OpenSSL::Crypto jwt-cpp::jwt-cpp)

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")

# ---------------------------------------------------------------------------
# Catch2 unit-test binary -- pure-logic tests, no DuckDB linkage.
# Built only when Catch2 is available (i.e. when vcpkg provided it).
#
# Skipped entirely under EMSCRIPTEN: the test binary isn't runnable in
# wasm anyway, and on the wasm_threads variant linking the test binary
# fails because the vcpkg OpenSSL port wasn't compiled with the atomics
# / bulk-memory features that --shared-memory requires. The extension
# itself links fine because it's a shared library not an executable.
# ---------------------------------------------------------------------------
find_package(Catch2 3 CONFIG QUIET)
if(Catch2_FOUND AND NOT EMSCRIPTEN)
  file(GLOB QUACK_OAUTH_UNIT_TEST_SOURCES CONFIGURE_DEPENDS test/cpp/test_*.cpp)
  if(QUACK_OAUTH_UNIT_TEST_SOURCES)
    add_executable(quack_oauth_unit_tests
      ${PURE_SOURCES}
      ${QUACK_OAUTH_UNIT_TEST_SOURCES}
    )
    target_include_directories(quack_oauth_unit_tests PRIVATE src/include)
    target_compile_features(quack_oauth_unit_tests PRIVATE cxx_std_17)
    target_link_libraries(quack_oauth_unit_tests PRIVATE
      Catch2::Catch2WithMain
      OpenSSL::SSL
      OpenSSL::Crypto
      jwt-cpp::jwt-cpp
    )
    set_target_properties(quack_oauth_unit_tests PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test"
    )
  endif()
endif()
