#include "quack_oauth_state.hpp"

namespace duckdb {

namespace {

// R-S-4 default for JWKS rate-limit window.
constexpr std::int64_t kDefaultMinRefreshSeconds = 30;
// Decision-cache caps (architecture section 5.2). The default TTL is the
// hot-path cap; per-token TTL is also capped at `exp - now` inside Store.
constexpr std::size_t kDecisionCacheCapacity = 1000;
constexpr std::int64_t kDecisionCacheDefaultTtlSeconds = 30;
// R-N-13 / diagnose() audit ring: last N decisions visible to operators.
// 64 lets a brief flurry of denies stay observable without unbounded growth.
constexpr std::size_t kAuditRingCapacity = 64;

} // namespace

QuackOauthState::QuackOauthState()
    : jwks_cache(kDefaultMinRefreshSeconds),
      decision_cache(kDecisionCacheCapacity, kDecisionCacheDefaultTtlSeconds),
      audit_ring(kAuditRingCapacity) {
}

QuackOauthState &GetQuackOauthState() {
	static QuackOauthState state;
	return state;
}

} // namespace duckdb
