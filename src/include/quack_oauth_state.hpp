#pragma once

#include <mutex>
#include <string>
#include <unordered_map>

#include "duckdb/common/string.hpp"

#include "audit.hpp"
#include "decision_cache.hpp"
#include "jwks_cache.hpp"

namespace duckdb {

// Per-process state holder. Lives for the duration of the host DuckDB
// process. Architecture section 5.2 calls for per-process caches; this is
// the minimum implementation -- multi-`DatabaseInstance` isolation is a
// known gap.
//
// Single mutex protects everything. The hot path locks for the duration of
// a single chunk's validate / authz calls; cache operations are O(1) under
// the hood (unordered_map ops) so the lock is held briefly.
//
// `session_principals` is populated by the 3-arg form of
// `quack_oauth_check_token` (the shape quack calls -- (session_id,
// auth_string, token)). When a token successfully validates, we cache the
// resulting Principal keyed by quack's session_id. The companion
// `quack_oauth_check_authorization(session_id, query_string)` looks it up
// to apply the policy.
struct SessionPrincipal {
	quack_oauth::Principal principal;
	int64_t updated_at_s = 0;
};

struct QuackOauthState {
	quack_oauth::JwksCache jwks_cache;
	quack_oauth::DecisionCache decision_cache;
	std::unordered_map<string, SessionPrincipal> session_principals;
	quack_oauth::AuditRing audit_ring;
	std::mutex mu;

	QuackOauthState();
};

QuackOauthState &GetQuackOauthState();

} // namespace duckdb
