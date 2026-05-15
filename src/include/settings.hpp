#pragma once

#include "duckdb.hpp"

namespace duckdb {

// Registers every `quack_oauth_*` extension setting against the DBConfig.
//
// Defaults are requirement-driven (see test/sql/oauth_settings.test for the
// authoritative mapping). Discoverability is required by R-N-12; the surface
// shape is referenced by R-S-1 / R-S-2 / R-S-3 / R-S-4 / R-S-5 / R-S-7 /
// R-S-11 / R-S-12 / R-C-2 / R-N-4.
//
// Called once from LoadInternal in `quack_oauth_extension.cpp`. Idempotency
// is not guaranteed -- DBConfig::AddExtensionOption throws on duplicate
// registration, so do not call this twice.
void RegisterQuackOauthSettings(DBConfig &config);

} // namespace duckdb
