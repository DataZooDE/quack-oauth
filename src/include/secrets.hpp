#pragma once

#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

// Registers the two quack_oauth SECRET types:
//
//   - `quack_oauth`        — client-side credentials per R-C-1
//   - `quack_oauth_server` — resource-server config per R-S-11
//
// Sensitive fields (client_secret, access_token, refresh_token) are added to
// the redaction set so they never appear in `duckdb_secrets()` output, per
// R-N-5 and R-S-10.
//
// Type names use snake_case (not the kebab-case `quack-oauth` referenced in
// requirements.md prose) to match the only-allowed identifier shape for
// `CREATE SECRET ... TYPE <ident>` and the sibling-extension convention
// (../erpl-web/src/microsoft_entra_secret.cpp:165 -> "microsoft_entra").
void RegisterQuackOauthSecrets(ExtensionLoader &loader);

} // namespace duckdb
