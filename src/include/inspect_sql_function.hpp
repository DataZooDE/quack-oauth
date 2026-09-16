#pragma once

#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

// Registers the `quack_oauth_inspect_sql(VARCHAR)` table function.
//
// Surfaces the authorization object walk (`quack_oauth::InspectSql`) so an
// operator can see exactly what a statement would be gated on before -- or
// after -- a policy denies it. One row:
//   (action VARCHAR, objects VARCHAR[], columns VARCHAR[],
//    unsafe BOOLEAN, error VARCHAR)
//
// Read-only and side-effect free: it parses the string, it never plans or
// executes it, and it consults no policy. It is also the test seam for the
// walk itself -- `InspectSql` links DuckDB's parser, so it can't be reached
// from the Catch2 binary (which is pure-logic by policy).
void RegisterQuackOauthInspectSql(ExtensionLoader &loader);

} // namespace duckdb
