#include "quack_oauth_state.hpp"

#include "env_overrides.hpp"

namespace duckdb {

// R-S-4 default for JWKS rate-limit window.
static constexpr int64_t kDefaultMinRefreshSeconds = 30;
// Decision-cache caps (architecture section 5.2). The default TTL is the
// hot-path cap; per-token TTL is also capped at `exp - now` inside Store.
static constexpr std::size_t kDecisionCacheCapacity = 1000;
static constexpr int64_t kDecisionCacheDefaultTtlSeconds = 30;

QuackOauthState::QuackOauthState()
    : jwks_cache(quack_oauth::EnvIntOrDefault("QUACK_OAUTH_JWKS_MIN_REFRESH_S", kDefaultMinRefreshSeconds)),
      decision_cache(kDecisionCacheCapacity, kDecisionCacheDefaultTtlSeconds) {
}

QuackOauthState &GetQuackOauthState(ClientContext &context) {
	auto state = context.db->GetObjectCache().GetOrCreate<QuackOauthState>("quack_oauth_state");
	Value refresh;
	if (context.TryGetCurrentSetting("quack_oauth_jwks_min_refresh_s", refresh) && !refresh.IsNull()) {
		std::lock_guard<std::mutex> guard(state->mu);
		state->jwks_cache.SetMinRefreshSeconds(refresh.GetValue<int32_t>());
	}
	return *state;
}

QuackOauthSessionState &GetQuackOauthSessionState(ClientContext &context) {
	return *context.registered_state->GetOrCreate<QuackOauthSessionState>("quack_oauth_session");
}

} // namespace duckdb
