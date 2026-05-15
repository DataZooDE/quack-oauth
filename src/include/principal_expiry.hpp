#pragma once

#include <cstdint>

#include "decision_cache.hpp" // for Principal

namespace quack_oauth {

// R-S-9: principal-expiry check applied on every `check_authorization`.
//
// Returns true iff `now_s > principal.exp + skew_s`. Semantics:
//   - `principal.exp == 0` (or negative) is treated as "unknown" -- never
//     expired. Some IdPs (opaque introspect with no `exp` claim) populate
//     a Principal with no expiry; we trust the cache layer that put it
//     there rather than refusing every such session.
//   - `now_s == principal.exp` is NOT expired (RFC 7519 §4.1.4: "the JWT
//     MUST NOT be accepted for processing" only when *after* `exp`).
//   - `skew_s` is added to `exp` to give the same leeway operators
//     already get on JWT signature verification (`quack_oauth_clock_skew_s`).
bool IsPrincipalExpired(const Principal &p, std::int64_t now_s,
                        std::int64_t skew_s);

} // namespace quack_oauth
