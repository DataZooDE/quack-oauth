#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

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

enum class JwksLookupStatus {
	Hit,
	Miss,
	RateLimited,
};

struct JwksLookup {
	JwksLookupStatus status = JwksLookupStatus::Miss;
	std::optional<Jwk> jwk;         // populated only on Hit
	std::int64_t retry_after_s = 0; // populated only on RateLimited
};

// Per-process JWKS cache: thread-safety is a higher-slice concern; this layer
// is pure logic and assumes single-threaded access. Caches successful kid →
// JWK lookups indefinitely (architecture section 6 IdP-outage scenario --
// hits keep serving) and rate-limits *misses* to at most one fetch per
// `min_refresh_s` per kid (R-S-4: JWKS-poll DoS protection).
//
// Clock is caller-injected (`now_s` parameters) so the cache is fully
// deterministic in tests.
class JwksCache {
public:
	explicit JwksCache(std::int64_t min_refresh_s);

	// Look up a kid. Does not mutate the cache.
	JwksLookup Lookup(const std::string &kid, std::int64_t now_s) const;

	// Caller learned the kid maps to this JWK at `now_s`. Replaces any prior
	// entry for the same kid (covers kid-reuse rotations).
	void OnFetchSuccess(const Jwk &jwk, std::int64_t now_s);

	// Caller fetched JWKS but the kid was absent. Starts the rate-limit
	// timer for this kid.
	void OnFetchMiss(const std::string &kid, std::int64_t now_s);

	std::size_t Size() const noexcept;

private:
	struct Entry {
		Jwk jwk;
		std::int64_t fetched_at_s = 0;
	};
	struct MissEntry {
		std::int64_t recorded_at_s = 0;
	};

	std::int64_t min_refresh_s_;
	std::unordered_map<std::string, Entry> hits_;
	std::unordered_map<std::string, MissEntry> misses_;
};

} // namespace quack_oauth
