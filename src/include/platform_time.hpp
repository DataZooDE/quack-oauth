#pragma once

#include <cstdint>
#include <string>

namespace quack_oauth {

// R-X-3: portable wrapper around the platform's thread-safe gmtime variant.
// MSVC has `gmtime_s(&tm_buf, &t)`; POSIX has `gmtime_r(&t, &tm_buf)`. This
// helper hides the `#ifdef` so call sites stay platform-agnostic.
//
// Returns RFC 3339 / ISO 8601 UTC: `YYYY-MM-DDTHH:MM:SSZ`. Negative inputs
// (before the Unix epoch) and far-future inputs are handled by the
// platform's gmtime; outputs are well-formed within `tm`'s representable
// range.
std::string FormatUtcIso8601(std::int64_t unix_seconds);

} // namespace quack_oauth
