#pragma once

#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

// Registers the `quack_oauth_diagnose()` table function per R-N-13.
//
// Long-format output: (component VARCHAR, status VARCHAR, detail VARCHAR).
// One row per diagnostic category. In slice S-4 the rows are stub constants;
// later slices replace them with live cache state, IdP reachability probes,
// and the last-16-decisions audit window.
void RegisterQuackOauthDiagnose(ExtensionLoader &loader);

} // namespace duckdb
