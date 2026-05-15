#include "policy.hpp"

#include <algorithm>
#include <string>

namespace quack_oauth {

namespace {

bool PrincipalHasAnyScope(const Principal &p,
                          const std::vector<std::string> &any_of) {
	if (any_of.empty()) return true; // "no scope constraint" matches anything
	for (const auto &needle : any_of) {
		if (std::find(p.scopes.begin(), p.scopes.end(), needle) != p.scopes.end()) {
			return true;
		}
	}
	return false;
}

bool ActionMatches(Action action, const std::vector<Action> &list) {
	if (list.empty()) return true; // unconstrained action
	return std::find(list.begin(), list.end(), action) != list.end();
}

} // namespace

std::optional<Action> ActionFromString(std::string_view s) {
	if (s == "Attach") return Action::Attach;
	if (s == "Scan") return Action::Scan;
	if (s == "CopyTo") return Action::CopyTo;
	if (s == "CopyFrom") return Action::CopyFrom;
	if (s == "ServeAdmin") return Action::ServeAdmin;
	return std::nullopt;
}

PolicyOutcome EvaluatePolicy(const PolicyDocument &doc,
                             const Principal &principal, Action action,
                             std::string_view /*object*/) {
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
		return {rule.allow ? Decision::Allow : Decision::Deny,
		        rule.allow ? "rule allow" : "rule deny"};
	}
	return {doc.default_allow ? Decision::Allow : Decision::Deny,
	        doc.default_allow ? "default allow" : "default deny"};
}

} // namespace quack_oauth
