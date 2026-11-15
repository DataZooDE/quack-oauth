#pragma once

#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

// Registers `quack_oauth_check_authorization(session_id VARCHAR,
// query_string VARCHAR) -> BOOLEAN` matching quack's expected signature
// (see `quack/src/quack_extension.cpp` line ~132).
//
// Reads only the principal bound to this ClientContext by the native host API.
// A supplied session_id must match that connection's bound identity. Applies
// the configured policy and returns BOOLEAN; unrelated contexts default-deny.
//
// Action detection from `query_string` (R-S-7's allow/deny by quack
// operation: attach / scan / copy_to / copy_from / serve_admin) is a
// future slice -- for now everything maps to Scan, which is the operation
// quack actually authorizes on every fetch.
void RegisterQuackOauthCheckAuthorization(ExtensionLoader &loader);

} // namespace duckdb
