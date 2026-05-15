#pragma once

#include <cstdint>
#include <string>

namespace quack_oauth {

// R-S-11(c) env-variable fallback for extension settings. SET in SQL > SECRET
// > env > hardcoded default. These helpers resolve the env layer; the
// settings.cpp registrations pass the result as the AddExtensionOption
// default.
//
// Pure-logic on purpose so Catch2 covers the parsing rules. The wiring into
// DuckDB lives in settings.cpp.

// Returns the env-var value, or empty string if unset OR set to the empty
// string. Trims leading/trailing whitespace.
std::string EnvString(const char *name);

// Resolves the env-var as a bool. Truthy: "1", "true", "yes", "on" (any
// case). Falsy: "0", "false", "no", "off". Anything else, or unset, returns
// `fallback`. Empty value is treated as unset.
bool EnvBoolOrDefault(const char *name, bool fallback);

// Resolves the env-var as a signed 32-bit int. Unset, empty, or non-numeric
// returns `fallback`. Negative values and zero are valid.
std::int32_t EnvIntOrDefault(const char *name, std::int32_t fallback);

} // namespace quack_oauth
