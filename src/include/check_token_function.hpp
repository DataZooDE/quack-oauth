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
// Native host boundary; never register this as a SQL function. The host must
// supply its own session ID, retain this context for the session's lifetime,
// execute authorization and user queries on it, and close it on disconnect.
// Uses the normal validator. A failed reauthentication revokes the old principal.
// Legacy quack SQL callbacks do not implement this contract and fail closed.
bool AuthenticateQuackOauthSession(ClientContext &context, const string &session_id, const string &token);

void RegisterQuackOauthCheckToken(ExtensionLoader &loader);

} // namespace duckdb
