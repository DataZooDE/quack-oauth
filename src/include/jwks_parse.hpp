#pragma once

#include <string_view>
#include <vector>

#include "jwks_cache.hpp"

namespace quack_oauth {

// Parse a JWKS JSON document (RFC 7517 §5) into a list of JWKs.
//
// Returns an empty vector if the input is not valid JSON, lacks the top-level
// `keys` array, or `keys` is not an array. Within the `keys` array, entries
// that are missing the mandatory `kid` or `kty` fields are silently dropped
// -- IdPs occasionally publish unusable entries, and we want a usable subset
// rather than refusing the whole document.
//
// Signature verification is **not** performed here; this is a pure data
// extraction step. The returned JWKs are fed into `JwksCache::OnFetchSuccess`
// by the HTTP layer (slice S-7b).
std::vector<Jwk> ParseJwksJson(std::string_view json);

} // namespace quack_oauth
