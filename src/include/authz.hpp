#pragma once

#include <string>
#include <string_view>

#include "decision_cache.hpp" // for Principal

namespace quack_oauth {

// The five quack operations the policy can gate, mirroring R-S-7's list.
enum class Action {
	Attach,
	Scan,
	CopyTo,
	CopyFrom,
	ServeAdmin,
};

// Stable string form, matching the action-string spelling expected by the
// YAML-era policy and the new SQL-table policy (case-sensitive).
const char *ActionName(Action a);

enum class Decision {
	Allow,
	Deny,
};

// Outcome of a policy evaluation. `reason` is a short stable string for
// architecture section 8.3 logging / diagnostics. On `Allow` the reason is
// typically `"ok"`; on `Deny` it names the missing requirement (e.g.
// `"requires quack:read"`).
struct PolicyOutcome {
	Decision decision = Decision::Deny;
	std::string reason;
};

// Default authorization per R-S-8 (applied when no `policy_table` field is
// set on the active quack_oauth_server SECRET):
//   - any token with scope `quack:read` may Attach + Scan;
//   - any token with scope `quack:write` may also CopyTo + CopyFrom;
//   - ServeAdmin is always denied (no implicit admin);
//   - `quack:write` implies `quack:read`.
//
// The `object` argument is reserved for future glob-based filtering (R-S-7
// "allow/deny by referenced object `schema.table` glob"). The default policy
// ignores it; a future schema extension of the policy table can use it.
PolicyOutcome EvaluateDefaultPolicy(const Principal &principal, Action action, std::string_view object);

} // namespace quack_oauth
