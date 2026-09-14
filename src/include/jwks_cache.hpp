#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <list>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace quack_oauth {

// Public-key material in the shape published by a JWKS endpoint.
//
// We store the raw base64url-encoded modulus / exponent / coordinates rather
// than parsed EVP_PKEY material here so the cache stays pure-logic. The
// validator (slice S-7) is responsible for materialising an OpenSSL key
// from this struct on first use.
struct Jwk {
	std::string kid;
	std::string kty; // RSA, EC, OKP
	std::string alg; // RS256, ES256, EdDSA, ...
	std::string use; // "sig" expected for our purposes
	// RSA
	std::string n;
	std::string e;
	// EC / OKP
	std::string crv; // P-256, P-384, Ed25519, ...
	std::string x;
	std::string y; // EC only
};

inline bool SameKeyMaterial(const Jwk &a, const Jwk &b) {
	if (a.kty != b.kty || a.alg != b.alg || a.use != b.use) {
		return false;
	}
	if (a.kty == "RSA") {
		return a.n == b.n && a.e == b.e;
	}
	if (a.kty == "EC" || a.kty == "OKP") {
		return a.crv == b.crv && a.x == b.x && a.y == b.y;
	}
	return false;
}

inline bool SameKeyMaterial(const std::vector<Jwk> &a, const std::vector<Jwk> &b) {
	if (a.size() != b.size()) {
		return false;
	}
	std::vector<Jwk> rem = b;
	for (const auto &ka : a) {
		auto it = std::find_if(rem.begin(), rem.end(), [&](const Jwk &kb) { return SameKeyMaterial(ka, kb); });
		if (it == rem.end()) {
			return false;
		}
		rem.erase(it);
	}
	return true;
}

enum class JwksLookupStatus {
	Hit,
	Miss,
	RateLimited,
};

inline constexpr std::int64_t kGlobalFetchBudgetWindowSeconds = 2;
inline constexpr std::int64_t kClockResetThresholdSeconds = 60;
inline constexpr std::size_t kMaxKeysPerKid = 4;

enum class ClockRel { Forward, MinorRewind, Reset };
inline ClockRel RelateClock(std::int64_t now_s, std::int64_t stamp_s) noexcept {
	if (now_s >= stamp_s) {
		return ClockRel::Forward;
	}
	if (stamp_s - now_s <= kClockResetThresholdSeconds) {
		return ClockRel::MinorRewind;
	}
	return ClockRel::Reset;
}

struct JwksLookup {
	JwksLookupStatus status = JwksLookupStatus::Miss;
	std::vector<Jwk> keys;          // populated on Hit: all cached keys for this kid
	std::int64_t retry_after_s = 0; // populated only on RateLimited
};

// Process-wide JWKS cache shared across all database instances. Thread-safety:
// the QuackOauthState mutex owns this cache. Cache lookups, reservations, and commits
// must be performed while holding that mutex. The mutex is dropped across outbound
// HTTP calls (UnlockingHttpClient), during which callers must not hold references
// or pointers into cache entries.
// Caches successful kid -> JWK lookups indefinitely (architecture section 6 IdP-outage
// scenario -- hits keep serving) and rate-limits misses and hit-refresh attempts
// to at most one fetch per `min_refresh_s` per kid (R-S-4: JWKS-poll DoS protection).
// Values of min_refresh_s are clamped to [1, 3600].
//
// Clock is caller-injected (`now_s` parameters) so the cache is fully
// deterministic in tests.
class JwksCache {
public:
	explicit JwksCache(std::int64_t min_refresh_s, std::size_t max_entries = 1000);

	void SetMinRefreshSeconds(std::int64_t min_refresh_s);
	std::int64_t GetMinRefreshSeconds() const noexcept {
		return min_refresh_s_;
	}

	// Look up a kid. Does not mutate the cache.
	JwksLookup Lookup(const std::string &kid, std::int64_t now_s, const std::string &jwks_uri = "") const;

	// Ingests key material authoritatively for kid.
	void OnFetchSuccess(const std::string &kid, const std::vector<Jwk> &keys, std::int64_t now_s,
	                    const std::string &jwks_uri = "");

	// Ingests key material passively from a multi-key document (cold miss or sibling keys).
	// Strictly additive: unions keys with existing entries and never clears active reservations (F4).
	void OnPassiveFetchSuccess(const std::string &kid, const std::vector<Jwk> &keys, std::int64_t now_s,
	                           const std::string &jwks_uri = "");

	// Record kid was absent during a reserved refresh (F2).
	// Corroborated eviction: requires two consecutive absent observations across distinct refreshes
	// before evicting. Returns true if evicted, false if preserved.
	bool RecordKidAbsent(const std::string &kid, std::uint64_t reservation_id, std::int64_t now_s,
	                     const std::string &jwks_uri = "");

	// Reconciles cached kids for jwks_uri against the set of kids present in an authoritative 200 OK JWKS document.
	// Kids present in `present_kids` have consecutive_absent_count reset to 0.
	// Cached kids for `jwks_uri` (excluding `target_kid` if specified) that are absent have consecutive_absent_count
	// incremented. If consecutive_absent_count reaches 2, the cached kid is authoritatively evicted.
	void ReconcileAbsentKids(const std::unordered_set<std::string> &present_kids, std::int64_t now_s,
	                         const std::string &jwks_uri = "", const std::string &exclude_kid = "");

	// Caller fetched JWKS but the kid was absent. Starts the rate-limit
	// timer for this kid.
	void OnFetchMiss(const std::string &kid, std::int64_t now_s, const std::string &jwks_uri = "");

	// Global fetch budget: determines whether an outbound JWKS fetch is allowed
	// at now_s (decoupled to kGlobalFetchBudgetWindowSeconds for amplification control).
	bool CanFetchJwks(std::int64_t now_s) const;
	bool HasFreshJwksDocument(std::int64_t now_s, std::int64_t window_s = kGlobalFetchBudgetWindowSeconds,
	                          const std::string &jwks_uri = "") const;
	void RecordJwksFetch(std::int64_t now_s);
	void RecordJwksFetchSuccess(std::int64_t now_s, const std::string &jwks_uri = "");

	void IncrementThrottledRefreshes(bool is_budget = false, std::int64_t now_s = 0) noexcept {
		++throttled_refreshes_;
		if (is_budget) {
			++throttled_budget_refreshes_;
		} else {
			++throttled_per_kid_refreshes_;
		}
		if (now_s > 0) {
			last_throttled_at_s_.store(now_s, std::memory_order_relaxed);
		}
	}
	void SetLastRefreshReason(std::string r) {
		last_refresh_reason_ = std::move(r);
	}
	std::string GetLastRefreshReason() const {
		return last_refresh_reason_;
	}
	std::int64_t GetLastThrottledAt() const noexcept {
		return last_throttled_at_s_.load(std::memory_order_relaxed);
	}
	std::uint64_t GetThrottledRefreshesCount() const noexcept {
		return throttled_refreshes_.load(std::memory_order_relaxed);
	}
	std::uint64_t GetThrottledBudgetCount() const noexcept {
		return throttled_budget_refreshes_.load(std::memory_order_relaxed);
	}
	std::uint64_t GetThrottledPerKidCount() const noexcept {
		return throttled_per_kid_refreshes_.load(std::memory_order_relaxed);
	}

	// Reserve one rate-limited refresh attempt for an already-cached kid.
	// Returns a non-zero reservation ID if granted, or 0 if rate-limited.
	// On clock rewinds or concurrent chunks with earlier now_s (now_s < last_attempt),
	// the call fails closed (returns 0).
	std::uint64_t TryReserveRefresh(const std::string &kid, std::int64_t now_s, const std::string &jwks_uri = "");

	// Commit verified refreshed JWKs for the reserved kid.
	// Succeeds only if `reservation_id` matches the active reservation for `kid`,
	// dropping stale out-of-order completions so they cannot overwrite newer keys.
	bool CommitRefresh(const std::string &kid, std::uint64_t reservation_id, const std::vector<Jwk> &keys,
	                   std::int64_t now_s, const std::string &jwks_uri = "");

	std::size_t Size() const noexcept;
	std::size_t MissSize() const noexcept;

private:
	struct Entry {
		std::vector<Jwk> keys;
		std::int64_t fetched_at_s = 0;
		std::int64_t last_refresh_attempt_s = 0;
		std::uint64_t current_reservation_id = 0;
		int consecutive_absent_count = 0;
		std::list<std::string>::iterator lru_it;
	};
	struct MissEntry {
		std::int64_t recorded_at_s = 0;
		std::list<std::string>::iterator lru_it;
	};

	static std::string CacheKey(const std::string &jwks_uri, const std::string &kid) {
		if (jwks_uri.empty()) {
			return kid;
		}
		return jwks_uri + "\n" + kid;
	}

	std::unordered_map<std::string, Entry>::iterator FindHit(const std::string &jwks_uri, const std::string &kid);
	std::unordered_map<std::string, Entry>::const_iterator FindHit(const std::string &jwks_uri,
	                                                               const std::string &kid) const;
	std::unordered_map<std::string, MissEntry>::const_iterator FindMiss(const std::string &jwks_uri,
	                                                                    const std::string &kid) const;

	static void TrimToCap(Entry &entry);

	std::int64_t min_refresh_s_;
	std::size_t max_entries_;
	std::int64_t last_global_fetch_s_ = 0;
	std::int64_t last_successful_fetch_s_ = 0;
	std::unordered_map<std::string, std::int64_t> last_successful_fetch_by_uri_;
	mutable std::atomic<std::uint64_t> throttled_refreshes_ {0};
	mutable std::atomic<std::uint64_t> throttled_budget_refreshes_ {0};
	mutable std::atomic<std::uint64_t> throttled_per_kid_refreshes_ {0};
	mutable std::atomic<std::int64_t> last_throttled_at_s_ {0};
	std::string last_refresh_reason_;
	std::uint64_t next_reservation_id_ = 1;
	std::list<std::string> hit_lru_;
	std::list<std::string> miss_lru_;
	std::unordered_map<std::string, Entry> hits_;
	std::unordered_map<std::string, MissEntry> misses_;
};

} // namespace quack_oauth
