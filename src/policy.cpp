#include "policy.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <string>

namespace quack_oauth {

namespace {

bool PrincipalHasAnyScope(const Principal &p, const std::vector<std::string> &any_of) {
	if (any_of.empty())
		return true; // "no scope constraint" matches anything
	for (const auto &needle : any_of) {
		if (std::find(p.scopes.begin(), p.scopes.end(), needle) != p.scopes.end()) {
			return true;
		}
	}
	return false;
}

bool ActionMatches(Action action, const std::vector<Action> &list) {
	if (list.empty())
		return true; // unconstrained action
	return std::find(list.begin(), list.end(), action) != list.end();
}

// Stable lowercase. Done at evaluation time as a safety net even though the
// loader already lowercases identifier patterns.
char Lower(char c) {
	return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

} // namespace

std::optional<Action> ActionFromString(std::string_view s) {
	if (s == "Attach")
		return Action::Attach;
	if (s == "Scan")
		return Action::Scan;
	if (s == "CopyTo")
		return Action::CopyTo;
	if (s == "CopyFrom")
		return Action::CopyFrom;
	if (s == "ServeAdmin")
		return Action::ServeAdmin;
	if (s == "Insert")
		return Action::Insert;
	if (s == "Update")
		return Action::Update;
	if (s == "Delete")
		return Action::Delete;
	if (s == "Ddl")
		return Action::Ddl;
	if (s == "Pragma")
		return Action::Pragma;
	return std::nullopt;
}

// `*`-only glob matcher. Recursive but linearises via the standard
// "advance i; on `*` skip greedily" trick. Case-insensitive.
//
// Examples:
//   GlobMatch("*",              "anything")        -> true
//   GlobMatch("main.*",         "main.audit")      -> true
//   GlobMatch("main.audit",     "main.audit")      -> true
//   GlobMatch("main.audit",     "main.trips")      -> false
//   GlobMatch("pii_*",          "pii_email")       -> true
//   GlobMatch("*.audit",        "main.audit")      -> true
//
// Empty pattern matches the empty value only.
bool GlobMatch(std::string_view pattern, std::string_view value) {
	std::size_t pi = 0, vi = 0;
	std::size_t star_p = std::string_view::npos, star_v = 0;
	while (vi < value.size()) {
		if (pi < pattern.size() && pattern[pi] == '*') {
			star_p = pi++;
			star_v = vi;
		} else if (pi < pattern.size() && Lower(pattern[pi]) == Lower(value[vi])) {
			++pi;
			++vi;
		} else if (star_p != std::string_view::npos) {
			pi = star_p + 1;
			vi = ++star_v;
		} else {
			return false;
		}
	}
	while (pi < pattern.size() && pattern[pi] == '*') {
		++pi;
	}
	return pi == pattern.size();
}

namespace {

// Per-cell rule walk. Returns the first matching rule's outcome, or a
// `Decision::Allow`/`Deny` derived from `default_allow` if no rule
// matches.
PolicyOutcome EvaluateCell(const PolicyDocument &doc, const Principal &principal, Action action,
                           std::string_view object, std::string_view column) {
	for (const auto &rule : doc.rules) {
		if (rule.subject.has_value() && *rule.subject != principal.subject) {
			continue;
		}
		if (!PrincipalHasAnyScope(principal, rule.any_scope)) {
			continue;
		}
		if (!ActionMatches(action, rule.actions)) {
			continue;
		}
		if (rule.object_pattern.has_value() && !object.empty() &&
		    !GlobMatch(*rule.object_pattern, object)) {
			continue;
		}
		if (rule.column_pattern.has_value() && !column.empty() &&
		    !GlobMatch(*rule.column_pattern, column)) {
			continue;
		}
		// Skip rules that demand an object/column when the request has
		// none -- they're not applicable to action-only verbs like
		// ATTACH or PRAGMA. (Rule writer can still gate those via
		// actions-only rules.)
		if (rule.object_pattern.has_value() && object.empty()) {
			continue;
		}
		if (rule.column_pattern.has_value() && column.empty()) {
			continue;
		}
		std::ostringstream reason;
		reason << (rule.allow ? "rule allow" : "rule deny");
		if (!object.empty()) {
			reason << " on " << object;
		}
		if (!column.empty()) {
			reason << "." << column;
		}
		return {rule.allow ? Decision::Allow : Decision::Deny, reason.str()};
	}
	std::ostringstream reason;
	reason << (doc.default_allow ? "default allow" : "default deny");
	if (!object.empty()) {
		reason << " on " << object;
	}
	if (!column.empty()) {
		reason << "." << column;
	}
	return {doc.default_allow ? Decision::Allow : Decision::Deny, reason.str()};
}

} // namespace

PolicyOutcome EvaluatePolicy(const PolicyDocument &doc, const Principal &principal,
                             const AuthzRequest &request) {
	// Action-only verbs (ATTACH / PRAGMA / DDL with no objects) check a
	// single cell. The rule writer gates them via `actions=[…]` rules
	// without object/column constraints.
	if (request.objects.empty()) {
		return EvaluateCell(doc, principal, request.action, "", "");
	}

	// Multi-object / multi-column matrix walk. The standard ABAC
	// safety rule: ALL touched cells must be allowed for the request
	// to succeed. First deny short-circuits with an actionable reason.
	for (const auto &obj : request.objects) {
		if (request.columns.empty()) {
			auto outcome = EvaluateCell(doc, principal, request.action, obj, "");
			if (outcome.decision == Decision::Deny) {
				return outcome;
			}
		} else {
			for (const auto &col : request.columns) {
				auto outcome = EvaluateCell(doc, principal, request.action, obj, col);
				if (outcome.decision == Decision::Deny) {
					return outcome;
				}
			}
		}
	}
	return {Decision::Allow, "ok"};
}

} // namespace quack_oauth
