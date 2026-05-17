#pragma once

#include <string>
#include <string_view>

#include "decision_cache.hpp" // for Principal

namespace quack_oauth {

// Operations the policy can gate. Originally a five-element enum
// (R-S-7); extended once the SQL parser-driven AuthzRequest landed
// so policy can target finer-grained DML and DDL separately.
//
// Backward-compatibility: `Scan` remains the canonical action for
// any read (SELECT / EXPLAIN / SHOW / WITH / DESCRIBE / RELATION).
// Existing policy rows with `actions=['Scan']` continue to match
// SELECTs without modification. The new `Insert` / `Update` /
// `Delete` / `Ddl` / `Pragma` values carve writes out of the old
// "everything-falls-back-to-Scan" model that DetectAction used.
enum class Action {
	Attach,
	Scan, // SELECT / EXPLAIN / SHOW / WITH / RELATION (read)
	CopyTo,
	CopyFrom,
	ServeAdmin,
	Insert,
	Update,
	Delete,
	Ddl,    // CREATE / DROP / ALTER / TRANSACTION (any DDL)
	Pragma, // non-quack PRAGMA (e.g. PRAGMA version, PRAGMA threads=…)
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
//   - any token with scope `quack:write` may also CopyTo + CopyFrom + Insert
//     + Update + Delete;
//   - Ddl / ServeAdmin / Pragma are always denied (no implicit admin);
//   - `quack:write` implies `quack:read`.
//
// The default policy is action-only; operators who want object / column
// gating must promote to a SQL-table policy via the `policy_table` SECRET
// field (R-S-7, post-parser extension).
PolicyOutcome EvaluateDefaultPolicy(const Principal &principal, Action action);

} // namespace quack_oauth
