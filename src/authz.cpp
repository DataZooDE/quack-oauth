#include "authz.hpp"

#include <algorithm>
#include <string>

namespace quack_oauth {

const char *ActionName(Action a) {
	switch (a) {
	case Action::Attach:
		return "Attach";
	case Action::Scan:
		return "Scan";
	case Action::CopyTo:
		return "CopyTo";
	case Action::CopyFrom:
		return "CopyFrom";
	case Action::ServeAdmin:
		return "ServeAdmin";
	}
	return "unknown";
}

static bool HasScope(const Principal &p, const std::string &needle) {
	return std::find(p.scopes.begin(), p.scopes.end(), needle) != p.scopes.end();
}

static PolicyOutcome Allow(const char *reason) {
	return {Decision::Allow, reason};
}

static PolicyOutcome Deny(const char *reason) {
	return {Decision::Deny, reason};
}

PolicyOutcome EvaluateDefaultPolicy(const Principal &principal, Action action, std::string_view /*object*/) {
	const bool has_read = HasScope(principal, "quack:read") || HasScope(principal, "quack:write");
	const bool has_write = HasScope(principal, "quack:write");

	switch (action) {
	case Action::Attach:
	case Action::Scan:
		return has_read ? Allow("ok") : Deny("requires quack:read");
	case Action::CopyTo:
	case Action::CopyFrom:
		return has_write ? Allow("ok") : Deny("requires quack:write");
	case Action::ServeAdmin:
		// R-S-8: "no implicit admin". The default policy never grants admin;
		// a SQL-table policy can override with an explicit allow rule.
		return Deny("default policy never permits ServeAdmin");
	}
	// Unreachable -- exhaustive switch -- but defensive.
	return Deny("unknown action");
}

} // namespace quack_oauth
