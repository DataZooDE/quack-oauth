#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "authz.hpp"
#include "sql_inspect.hpp"

namespace quack_oauth {

// A single rule from the policy. A rule matches when ALL of its
// non-empty conditions hold against the (principal, action, object,
// column) cell currently being evaluated:
//
//   - `subject`: if set, principal.subject MUST equal this exactly.
//   - `any_scope`: if non-empty, principal.scopes MUST include AT LEAST ONE.
//   - `actions`: if non-empty, the current action MUST be in the list.
//   - `object_pattern`: if set, the touched object name MUST glob-match.
//     Glob supports `*` (match any sequence of chars) only. Comparison
//     is lowercase. NULL / unset = match any object.
//   - `column_pattern`: if set, the touched column name MUST glob-match.
//     `*` (the SELECT-star sentinel) is treated literally: a rule whose
//     `column_pattern == "*"` allows it. NULL / unset = match any column.
//
// Rules are evaluated in `priority` order; the first matching rule's
// `allow` decides for that cell. If no rule matches a cell,
// `PolicyDocument::default_allow` decides (default: false → deny).
//
// `object_pattern` and `column_pattern` were added when the
// parser-driven AuthzRequest landed. Rules predating them load with
// NULL values and behave exactly as before (match any object / any
// column). This is the backward-compatibility contract.
struct PolicyRule {
	std::optional<std::string> subject;
	std::vector<std::string> any_scope;
	std::vector<Action> actions;
	std::optional<std::string> object_pattern;
	std::optional<std::string> column_pattern;
	bool allow = true;
};

struct PolicyDocument {
	std::vector<PolicyRule> rules;
	bool default_allow = false;
};

// Parse an `Action` from its string form (case-sensitive). Accepts the
// historical five names plus the fine-grained additions:
//   "Attach" | "Scan" | "CopyTo" | "CopyFrom" | "ServeAdmin" |
//   "Insert" | "Update" | "Delete" | "Ddl" | "Pragma"
// Returns nullopt for unknown strings. Used by the SQL-table loader to
// validate action names from the database.
std::optional<Action> ActionFromString(std::string_view s);

// Glob match `pattern` against `value`. Supports `*` wildcards only --
// no `?`, no character classes, no escaping. Case-insensitive (the
// loader has already lowercased both sides, but defensive). Empty
// pattern matches only the empty value; `*` matches anything.
bool GlobMatch(std::string_view pattern, std::string_view value);

// Evaluate the policy against a parsed AuthzRequest + the validated
// principal. Walks each (object × column) cell the request touches;
// the first cell that ends on a deny -- or a no-match when
// `default_allow == false` -- fails the whole request. The returned
// `PolicyOutcome::reason` names the failing object / column when
// applicable so the operator-facing audit row is actionable.
PolicyOutcome EvaluatePolicy(const PolicyDocument &doc, const Principal &principal,
                             const AuthzRequest &request);

} // namespace quack_oauth
