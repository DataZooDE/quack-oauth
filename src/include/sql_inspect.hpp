#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "authz.hpp"

namespace quack_oauth {

// Result of parsing the incoming SQL into the bits the authz layer needs.
//
// `action` is the coarse verb the policy gates on -- backward-compatible
// with the old DetectAction model: SELECT and friends still map to
// `Action::Scan`. INSERT / UPDATE / DELETE / DDL / non-quack PRAGMA now
// surface as their own actions (carving the old "everything falls back
// to Scan" model).
//
// `objects` is the set of fully-qualified schema-objects the statement
// touches: tables, views, and table-function-references that resolve to
// a base table. Each entry is `"schema.table"` in lowercase, deduped.
// System tables (information_schema.*, pg_catalog.*, duckdb_*) are
// filtered out -- the policy doesn't gate metadata reads.
//
// `columns` is the set of *unqualified* column names the SELECT projects
// (lowercased, deduped). `SELECT *` produces the special sentinel
// `"*"` to signal "every column in the source"; column-scoped policy
// rules must match `column_pattern='*'` to allow it.
//
// `unsafe == true` means we couldn't parse the SQL (or it's a shape we
// don't handle yet). The caller MUST deny in this case to preserve the
// fail-closed invariant. `error` carries the parser detail for the audit
// row's `reason` field.
struct AuthzRequest {
	Action action = Action::Scan;
	std::vector<std::string> objects;
	std::vector<std::string> columns;
	bool unsafe = false;
	std::string error;
};

// Parse + classify a single incoming SQL string. Designed to be invoked
// from `quack_oauth_check_authorization` once per quack
// ConnectionRequestMessage. Pure: no I/O, no DuckDB connection required
// (the parser is header-only enough to run standalone, and we use it
// outside of any query lifecycle).
//
// Multi-statement SQL (`SELECT …; INSERT …;`) classifies on the FIRST
// statement and collects objects/columns from all of them -- the policy
// then evaluates each cell.
AuthzRequest InspectSql(const std::string &query);

} // namespace quack_oauth
