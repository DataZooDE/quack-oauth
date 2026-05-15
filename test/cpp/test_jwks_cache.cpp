#include <catch2/catch_test_macros.hpp>

#include "jwks_cache.hpp"

using quack_oauth::Jwk;
using quack_oauth::JwksCache;
using quack_oauth::JwksLookupStatus;

namespace {

Jwk MakeRsaJwk(const std::string &kid) {
	Jwk j;
	j.kid = kid;
	j.kty = "RSA";
	j.alg = "RS256";
	j.use = "sig";
	j.n = "fake-modulus-" + kid;
	j.e = "AQAB";
	return j;
}

constexpr std::int64_t kRefresh = 30; // seconds

} // namespace

TEST_CASE("JwksCache: empty cache yields Miss", "[jwks][cache]") {
	JwksCache cache(kRefresh);
	const auto r = cache.Lookup("unknown-kid", 0);
	CHECK(r.status == JwksLookupStatus::Miss);
	CHECK_FALSE(r.jwk.has_value());
	CHECK(cache.Size() == 0);
}

TEST_CASE("JwksCache: OnFetchSuccess makes subsequent lookups Hit",
          "[jwks][cache]") {
	JwksCache cache(kRefresh);
	cache.OnFetchSuccess(MakeRsaJwk("k1"), 100);

	const auto r = cache.Lookup("k1", 200);
	REQUIRE(r.status == JwksLookupStatus::Hit);
	REQUIRE(r.jwk.has_value());
	CHECK(r.jwk->kid == "k1");
	CHECK(r.jwk->kty == "RSA");
	CHECK(r.jwk->alg == "RS256");
	CHECK(r.jwk->n == "fake-modulus-k1");
	CHECK(cache.Size() == 1);
}

TEST_CASE("JwksCache: cached entries never expire on hit", "[jwks][cache]") {
	// Architecture section 6 "IdP outage" scenario: hits keep serving
	// indefinitely; only misses are rate-limited.
	JwksCache cache(kRefresh);
	cache.OnFetchSuccess(MakeRsaJwk("k1"), 0);

	const auto far_future = cache.Lookup("k1", 365L * 24 * 3600);
	CHECK(far_future.status == JwksLookupStatus::Hit);
}

TEST_CASE("JwksCache: OnFetchMiss rate-limits subsequent fetches per R-S-4",
          "[jwks][cache][rate-limit]") {
	JwksCache cache(kRefresh);
	cache.OnFetchMiss("nope", 0);

	// 10 s later: still inside the rate-limit window.
	const auto r_inside = cache.Lookup("nope", 10);
	CHECK(r_inside.status == JwksLookupStatus::RateLimited);
	CHECK(r_inside.retry_after_s == 20);

	// At exactly the boundary: still rate-limited (strict inequality).
	const auto r_at_boundary = cache.Lookup("nope", kRefresh - 1);
	CHECK(r_at_boundary.status == JwksLookupStatus::RateLimited);

	// Past the window: caller may try again.
	const auto r_after = cache.Lookup("nope", kRefresh);
	CHECK(r_after.status == JwksLookupStatus::Miss);
}

TEST_CASE("JwksCache: rate-limit is per-kid, not global",
          "[jwks][cache][rate-limit]") {
	JwksCache cache(kRefresh);
	cache.OnFetchMiss("k1", 0);

	// k2 has no recent miss recorded -- it should not inherit k1's rate limit.
	const auto r = cache.Lookup("k2", 5);
	CHECK(r.status == JwksLookupStatus::Miss);
}

TEST_CASE("JwksCache: a later success on a previously-missed kid clears the limit",
          "[jwks][cache][rate-limit]") {
	JwksCache cache(kRefresh);
	cache.OnFetchMiss("k1", 0);
	cache.OnFetchSuccess(MakeRsaJwk("k1"), 5);

	const auto r = cache.Lookup("k1", 6);
	REQUIRE(r.status == JwksLookupStatus::Hit);
	REQUIRE(r.jwk.has_value());
	CHECK(r.jwk->kid == "k1");
}

TEST_CASE("JwksCache: Size() reflects only successful fetches",
          "[jwks][cache]") {
	JwksCache cache(kRefresh);
	cache.OnFetchMiss("absent-1", 0);
	cache.OnFetchMiss("absent-2", 0);
	cache.OnFetchSuccess(MakeRsaJwk("present"), 0);
	CHECK(cache.Size() == 1);
}

TEST_CASE("JwksCache: re-fetching the same kid overwrites the cached JWK",
          "[jwks][cache]") {
	// Models IdP key rotation that reuses a kid (rare but legal): the latest
	// JWK MUST replace the previous one.
	JwksCache cache(kRefresh);

	Jwk first = MakeRsaJwk("k1");
	first.n = "first-modulus";
	cache.OnFetchSuccess(first, 0);

	Jwk second = MakeRsaJwk("k1");
	second.n = "rotated-modulus";
	cache.OnFetchSuccess(second, 100);

	const auto r = cache.Lookup("k1", 200);
	REQUIRE(r.status == JwksLookupStatus::Hit);
	REQUIRE(r.jwk.has_value());
	CHECK(r.jwk->n == "rotated-modulus");
	CHECK(cache.Size() == 1);
}
