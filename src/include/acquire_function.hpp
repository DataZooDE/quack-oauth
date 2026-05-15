#pragma once

#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

// Registers `quack_oauth_acquire(secret_name VARCHAR) -> VARCHAR`
// (R-C-2 + R-C-4). Reads the named `quack_oauth` client SECRET, picks
// the right flow (UseCached / Refresh / ClientCredentials / DeviceCode)
// via `DecideAcquireFlow`, runs it, persists rotated tokens back onto
// the SECRET, and returns the fresh access_token.
//
// Operator pattern:
//
//     ATTACH 'quack:server.example.com:9494' AS rs
//       (TYPE quack, token quack_oauth_acquire('my_client'));
//
// Each call is idempotent: a fresh AT short-circuits (UseCached) so
// repeated invocations are cheap.
void RegisterQuackOauthAcquire(ExtensionLoader &loader);

} // namespace duckdb
