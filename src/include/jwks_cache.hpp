#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <list>
#include <optional>
#include <string>
#include <unordered_map>
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
	if (a.kty != b.kty) {
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

inline bool JwkMaterialDiffers(const Jwk &a, const Jwk &b) {
	return !SameKeyMaterial(a, b);
}

enum class JwksLookupStatus {
	Hit,
	Miss,
	RateLimited,
};

struct JwksLookup {
	JwksLookupStatus status = JwksLookupStatus::Miss;
	std::vector<Jwk> keys;          // populated on Hit: all cached keys for this kid
	std::optional<Jwk> jwk;         // populated on Hit: most recently ingested key for backwards compatibility
	std::int64_t retry_after_s = 0; // populated only on RateLimited
};

// Per-process JWKS cache. Thread-safety: the QuackOauthState mutex owns this
// cache. Cache lookups, reservations, and commits must be performed while holding
// that mutex. The mutex is dropped across outbound HTTP calls (UnlockingHttpClient),
// during which callers must not hold references or pointers into cache entries.
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
	JwksLookup Lookup(const std::string &kid, std::int64_t now_s) const;

	// Ingests key material for jwk.kid. If an entry for jwk.kid already exists,
	// appends this key if not already present (material difference check),
	// preserving the existing reservation ID and refresh attempt timestamp (F1, F5).
	void OnFetchSuccess(const Jwk &jwk, std::int64_t now_s);
	void OnFetchSuccess(const std::string &kid, const std::vector<Jwk> &keys, std::int64_t now_s);

	// Caller fetched JWKS but the kid was absent. Starts the rate-limit
	// timer for this kid.
	void OnFetchMiss(const std::string &kid, std::int64_t now_s);

	// Global fetch budget: determines whether an outbound JWKS fetch is allowed
	// at now_s, or if a recent successful fetch already answered all keys.
	bool CanFetchJwks(std::int64_t now_s) const;
	void RecordJwksFetch(std::int64_t now_s, bool failed = false);

	bool WasLastFetchFailed() const noexcept {
		return last_fetch_failed_;
	}

	// Reserve one rate-limited refresh attempt for an already-cached kid.
	// Returns a non-zero reservation ID if granted, or 0 if rate-limited.
	// On clock rewinds or concurrent chunks with earlier now_s (now_s < last_attempt),
	// the call fails closed (returns 0).
	std::uint64_t TryReserveRefresh(const std::string &kid, std::int64_t now_s);

	// Commit verified refreshed JWK(s) for the reserved kid.
	// Succeeds only if `reservation_id` matches the active reservation for `kid`,
	// dropping stale out-of-order completions so they cannot overwrite newer keys.
	bool CommitRefresh(const std::string &kid, std::uint64_t reservation_id, const Jwk &jwk, std::int64_t now_s);
	bool CommitRefresh(const std::string &kid, std::uint64_t reservation_id, const std::vector<Jwk> &keys,
	                   std::int64_t now_s);

	std::size_t Size() const noexcept;
	std::size_t MissSize() const noexcept;

private:
	struct Entry {
		std::vector<Jwk> keys;
		std::int64_t fetched_at_s = 0;
		std::int64_t last_refresh_attempt_s = 0;
		std::uint64_t current_reservation_id = 0;
		std::list<std::string>::iterator lru_it;
	};
	struct MissEntry {
		std::int64_t recorded_at_s = 0;
		std::list<std::string>::iterator lru_it;
	};

	std::int64_t min_refresh_s_;
	std::size_t max_entries_;
	std::int64_t last_global_fetch_s_ = 0;
	bool last_fetch_failed_ = false;
	std::uint64_t next_reservation_id_ = 1;
	std::list<std::string> hit_lru_;
	std::list<std::string> miss_lru_;
	std::unordered_map<std::string, Entry> hits_;
	std::unordered_map<std::string, MissEntry> misses_;
};

} // namespace quack_oauth
