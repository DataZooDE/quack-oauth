#pragma once

#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

// Registers `quack_oauth_login(secret_name VARCHAR) -> VARCHAR` per R-C-7.
//
// Reads the named TYPE=quack_oauth client SECRET, decides which grant_type
// to run (S-12: client_credentials only -- device_code and refresh_token
// are deferred to a future slice), POSTs to the token endpoint, then
// persists the resulting access_token and expires_at back onto the SECRET
// via DuckDB's SecretManager.
//
// Returns the ISO-8601-ish `expires_at` string. Errors are raised as
// `InvalidInputException` so the operator sees them immediately.
void RegisterQuackOauthLogin(ExtensionLoader &loader);

} // namespace duckdb
