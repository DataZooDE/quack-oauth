#pragma once

#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

// Registers `quack_oauth_check_token(token VARCHAR) -> BOOLEAN`.
//
// Reads its configuration via two pieces of per-session state:
//   1. The setting `quack_oauth_server_secret_name` names a SECRET of type
//      `quack_oauth_server`. Its fields (issuer, audience, jwks_uri) drive
//      validation.
//   2. The setting `quack_oauth_clock_skew_s` is honoured for `exp` / `nbf`.
//
// Returns `true` only for tokens that pass the full `ValidateToken` flow.
// Any failure -- malformed, disallowed alg, wrong iss/aud, expired, unknown
// kid, JWKS fetch failure -- returns `false`. Configuration errors (missing
// setting, missing SECRET, secret missing `jwks_uri`) raise an exception so
// operators see them immediately.
void RegisterQuackOauthCheckToken(ExtensionLoader &loader);

} // namespace duckdb
