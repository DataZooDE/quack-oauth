#pragma once

#include <string>

#include "duckdb/main/client_context.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

// In-process implementation of the refresh_token grant. Returns
// `expires_at` ISO. Exposed for in-process invocation from
// `quack_oauth_acquire` (avoids the sub-Connection re-read bug; see
// login_function.hpp).
string DoRefresh(ClientContext &context, const string &secret_name);

// Registers `quack_oauth_refresh(secret_name VARCHAR) -> VARCHAR` per R-C-2 /
// R-C-5. Reads the named TYPE=quack_oauth client SECRET (must carry
// `refresh_token`, `token_endpoint`, and `client_id`; `client_secret` is
// optional for public clients), runs the RFC 6749 §6 refresh_token grant,
// and persists the resulting access_token + (rotated, if present) refresh_token
// + expires_at back on the SECRET.
//
// Returns the new ISO-8601 expires_at. Configuration errors raise
// InvalidInputException; IdP failures raise IOException.
void RegisterQuackOauthRefresh(ExtensionLoader &loader);

} // namespace duckdb
