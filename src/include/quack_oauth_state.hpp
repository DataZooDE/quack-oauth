#pragma once

#include <mutex>
#include <string>
#include <unordered_map>

#include "duckdb/common/string.hpp"
#include "duckdb/common/optional_idx.hpp"
#include "duckdb/main/client_context_state.hpp"
#include "duckdb/storage/object_cache.hpp"

#include "audit.hpp"
#include "decision_cache.hpp"
#include "jwks_cache.hpp"

namespace duckdb {

// Validation caches belong to a database. Principals and in-memory audit events
// belong to one ClientContext, whose lifetime must match the host's session.
struct SessionPrincipal {
	quack_oauth::Principal principal;
	int64_t updated_at_s = 0;
};

struct QuackOauthState : public ObjectCacheEntry {
	quack_oauth::JwksCache jwks_cache;
	quack_oauth::DecisionCache decision_cache;
	std::unordered_map<string, int64_t> last_throttle_logged_s;
	std::mutex mu;

	QuackOauthState();
	static string ObjectType() {
		return "quack_oauth_state";
	}
	string GetObjectType() override {
		return ObjectType();
	}
	// No eviction: callers retain references during validation. This method also
	// compiles against older DuckDB releases without eviction accounting.
	optional_idx GetEstimatedCacheMemory() const {
		return optional_idx();
	}
};

struct QuackOauthSessionState : public ClientContextState {
	string session_id;
	std::unordered_map<string, SessionPrincipal> session_principals;
	quack_oauth::AuditRing audit_ring {64};
	std::mutex mu;
};

QuackOauthState &GetQuackOauthState(ClientContext &context);
QuackOauthSessionState &GetQuackOauthSessionState(ClientContext &context);

} // namespace duckdb
