#pragma once

#include <cstdint>
#include <string>
#include <string_view>

// picojson's int64 template specialisations are only emitted when
// PICOJSON_USE_INT64 is set BEFORE the picojson include in every TU.
// Set it here so any consumer of these helpers (including the
// implementation .cpp) gets consistent int64 support without having
// to remember the define.
#ifndef PICOJSON_USE_INT64
#define PICOJSON_USE_INT64
#endif
#include <picojson/picojson.h>

namespace quack_oauth {

// Shared picojson + URL helpers used by introspect / tokeninfo /
// github_check and any future IdP integration. PURE_SOURCES.

// RFC 3986 unreserved-only URL encoding. Suitable for application/
// x-www-form-urlencoded request bodies and query-string substitution.
std::string UrlEncode(std::string_view in);

// Returns a pointer into `obj` if `key` is a string-typed field, else
// nullptr. Caller must not outlive `obj`.
const std::string *AsString(const picojson::object &obj, const std::string &key);

// Reads a numeric claim that providers serialise inconsistently:
//   - jwt-bearer JWTs / RFC 7662 introspect: native JSON number
//   - Google tokeninfo: JSON string ("1735689600")
// Returns 0 when the field is missing or unparseable.
std::int64_t AsIntFlexible(const picojson::object &obj, const std::string &key);

// Same shape for booleans: native bool OR a "true"/"True"/"TRUE" string.
// Anything else (including missing) returns false.
bool AsBoolFlexible(const picojson::object &obj, const std::string &key);

} // namespace quack_oauth
