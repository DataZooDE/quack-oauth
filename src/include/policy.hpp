#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "authz.hpp"

namespace quack_oauth {

// A single rule from the policy. A rule matches when ALL of its
// non-empty conditions match the (principal, action) pair:
//
//   - `subject`: if set, principal.subject MUST equal this exactly
//   - `any_scope`: if non-empty, principal.scopes MUST include AT LEAST ONE
//   - `actions`: if non-empty, the current action MUST be in the list
//
// The first matching rule wins (rules are evaluated in document order, which
// the loader sorts by ascending `priority`). Its `allow` field decides. If
// no rule matches, `PolicyDocument::default_allow` decides (default: false
// → deny).
struct PolicyRule {
	std::optional<std::string> subject;
	std::vector<std::string> any_scope;
	std::vector<Action> actions;
	bool allow = true;
};

struct PolicyDocument {
	std::vector<PolicyRule> rules;
	bool default_allow = false;
};

// Parse an `Action` from its string form ("Attach" | "Scan" | "CopyTo" |
// "CopyFrom" | "ServeAdmin"). Returns nullopt for unknown strings. Used by
// the SQL-table loader to validate action names from the database.
std::optional<Action> ActionFromString(std::string_view s);

// Evaluate the policy against a (principal, action, object) tuple.
// `object` is unused in this slice but kept in the signature for symmetry
// with EvaluateDefaultPolicy.
PolicyOutcome EvaluatePolicy(const PolicyDocument &doc,
                             const Principal &principal, Action action,
                             std::string_view object);

} // namespace quack_oauth
