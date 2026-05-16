#pragma once

#include <string>

#include "duckdb/main/client_context.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

// In-process implementation of the RFC 8628 device_code flow. Returns
// `expires_at` ISO. Exposed for in-process invocation from
// `quack_oauth_acquire` (avoids the sub-Connection re-read bug; see
// login_function.hpp).
string DoDeviceLoginImpl(ClientContext &context, const string &secret_name);

// Registers `quack_oauth_device_login(secret_name VARCHAR) -> VARCHAR` per
// RFC 8628 / R-C-2. Reads the named TYPE=quack_oauth client SECRET (must
// carry `device_authorization_endpoint`, `token_endpoint`, `client_id`,
// optionally `client_secret`, `scope`). Initiates the device flow,
// surfaces user_code + verification_uri via the DuckDB notice system,
// polls the token endpoint until the user authorizes (or the device_code
// expires / is denied), and persists the resulting access_token +
// refresh_token + expires_at on the SECRET.
//
// Returns the ISO-8601 expires_at on success; raises InvalidInputException
// on misconfiguration; raises IOException on flow failure (denied /
// expired / transport error).
void RegisterQuackOauthDeviceLogin(ExtensionLoader &loader);

} // namespace duckdb
