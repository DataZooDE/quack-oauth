#pragma once

#include <optional>
#include <string>

#include "duckdb/main/client_context.hpp"

#include "policy.hpp"

namespace duckdb {

// Load a PolicyDocument from a DuckDB table in the active database. Returns
// nullopt if the query fails (table missing, wrong schema, malformed action
// names) so the caller can apply fail-closed semantics.
//
// Expected table shape (operator must create it):
//
//     CREATE TABLE <name> (
//         priority  INTEGER NOT NULL,
//         subject   VARCHAR,                     -- NULL = match any subject
//         any_scope VARCHAR[],                   -- NULL or [] = no scope filter
//         actions   VARCHAR[],                   -- NULL or [] = match any action
//         allow     BOOLEAN NOT NULL
//     );
//
// Rules are sorted by ascending `priority`; the first matching rule wins.
// Action strings must be one of: "Attach", "Scan", "CopyTo", "CopyFrom",
// "ServeAdmin" -- any other value invalidates the entire policy and the
// function returns nullopt.
//
// `default_allow` is set by the caller from the
// `quack_oauth_policy_default` setting; this loader only fills `rules`.
std::optional<quack_oauth::PolicyDocument> LoadPolicyFromTable(ClientContext &context, const string &qualified_table);

} // namespace duckdb
