# patch_bundled_fmt.cmake -- neutralize fmt 6.1.2's `#ifdef _SECURE_SCL` guard.
#
# DuckDB v1.5.3 (and the 1.4 LTS line) bundle fmt 6.1.2, whose `#ifdef
# _SECURE_SCL` branch in third_party/fmt/include/fmt/format.h uses
# `stdext::checked_array_iterator`. MSVC 19.51's STL (the VS18 windows-latest
# runner) removed that symbol, so the branch fails with
# `C2653: 'stdext' is not a class or namespace name`. `_SECURE_SCL` is *always*
# defined on MSVC, so the broken branch is always taken, and
# `_SILENCE_ALL_MS_EXT_DEPRECATION_WARNINGS` can't revive a removed symbol.
#
# fmt's `#else` branch (`using checked_ptr = T*`) is what every non-MSVC build
# already uses and compiles on every toolchain -- it only drops MSVC's
# debug-iterator checking, irrelevant for release. We force-select it by
# flipping the guard to `#if 0` at CMake configure time, before DuckDB's
# `add_third_party(fmt)` compiles format.cc.
#
# Usable two ways:
#   * include() from extension_config.cmake (path auto-resolved), or
#   * cmake -DQO_FMT_HEADER=<path> -P scripts/patch_bundled_fmt.cmake (tests).
# The edit is idempotent: a no-op once the guard is already flipped.

if(NOT DEFINED QO_FMT_HEADER)
  set(QO_FMT_HEADER "${CMAKE_CURRENT_LIST_DIR}/../duckdb/third_party/fmt/include/fmt/format.h")
endif()

if(EXISTS "${QO_FMT_HEADER}")
  file(READ "${QO_FMT_HEADER}" _qo_fmt_src)
  string(REPLACE
    "#ifdef _SECURE_SCL"
    "#if 0 // _SECURE_SCL neutralized (quack-oauth: MSVC 19.51 removed stdext::checked_array_iterator)"
    _qo_fmt_new "${_qo_fmt_src}")
  if(NOT _qo_fmt_src STREQUAL _qo_fmt_new)
    file(WRITE "${QO_FMT_HEADER}" "${_qo_fmt_new}")
    message(STATUS "quack-oauth: patched bundled fmt _SECURE_SCL guard (${QO_FMT_HEADER})")
  endif()
endif()
