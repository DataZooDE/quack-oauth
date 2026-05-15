#pragma once

#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

// Registers the `quack_oauth_logout(secret_name VARCHAR) -> BOOLEAN`
// scalar (R-C-8). Clears access_token / refresh_token / expires_at
// on the named TYPE=quack_oauth SECRET. Returns true on success.
//
// The RFC 7009 token-revocation endpoint call promised by R-C-8 is a
// SHOULD, not MUST, and is deferred to a follow-on slice -- this
// version only does the local field clear.
void RegisterQuackOauthLogout(ExtensionLoader &loader);

} // namespace duckdb
