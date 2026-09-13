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

TEST_CASE("JwksCache: OnFetchSuccess makes subsequent lookups Hit", "[jwks][cache]") {
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

TEST_CASE("JwksCache: OnFetchMiss rate-limits subsequent fetches per R-S-4", "[jwks][cache][rate-limit]") {
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

TEST_CASE("JwksCache: rate-limit is per-kid, not global", "[jwks][cache][rate-limit]") {
	JwksCache cache(kRefresh);
	cache.OnFetchMiss("k1", 0);

	// k2 has no recent miss recorded -- it should not inherit k1's rate limit.
	const auto r = cache.Lookup("k2", 5);
	CHECK(r.status == JwksLookupStatus::Miss);
}

TEST_CASE("JwksCache: a later success on a previously-missed kid clears the limit", "[jwks][cache][rate-limit]") {
	JwksCache cache(kRefresh);
	cache.OnFetchMiss("k1", 0);
	cache.OnFetchSuccess(MakeRsaJwk("k1"), 5);

	const auto r = cache.Lookup("k1", 6);
	REQUIRE(r.status == JwksLookupStatus::Hit);
	REQUIRE(r.jwk.has_value());
	CHECK(r.jwk->kid == "k1");
}

TEST_CASE("JwksCache: Size() reflects only successful fetches", "[jwks][cache]") {
	JwksCache cache(kRefresh);
	cache.OnFetchMiss("absent-1", 0);
	cache.OnFetchMiss("absent-2", 0);
	cache.OnFetchSuccess(MakeRsaJwk("present"), 0);
	CHECK(cache.Size() == 1);
}

TEST_CASE("JwksCache: re-fetching the same kid overwrites the cached JWK", "[jwks][cache]") {
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

TEST_CASE("JwksCache: cached-key refresh attempts are rate-limited", "[jwks][cache][rate-limit]") {
	JwksCache cache(kRefresh);
	cache.OnFetchSuccess(MakeRsaJwk("k1"), 100);

	CHECK_FALSE(cache.TryBeginHitRefresh("k1", 110));
	CHECK(cache.TryBeginHitRefresh("k1", 130));
	CHECK_FALSE(cache.TryBeginHitRefresh("k1", 140));
	CHECK(cache.TryBeginHitRefresh("k1", 160));
	CHECK_FALSE(cache.TryBeginHitRefresh("missing", 200));
	CHECK(cache.Lookup("k1", 200).status == JwksLookupStatus::Hit);
}

TEST_CASE("JwksCache: min_refresh_s is clamped to at least 1 second", "[jwks][cache][rate-limit]") {
	JwksCache cache(/*min_refresh_s=*/0);
	cache.OnFetchSuccess(MakeRsaJwk("k1"), 100);

	CHECK_FALSE(cache.TryBeginHitRefresh("k1", 100));
	CHECK(cache.TryBeginHitRefresh("k1", 101));
	CHECK_FALSE(cache.TryBeginHitRefresh("k1", 101));

	JwksCache cache_neg(/*min_refresh_s=*/-5);
	cache_neg.OnFetchSuccess(MakeRsaJwk("k1"), 100);
	CHECK_FALSE(cache_neg.TryBeginHitRefresh("k1", 100));
	CHECK(cache_neg.TryBeginHitRefresh("k1", 101));
	CHECK_FALSE(cache_neg.TryBeginHitRefresh("k1", 101));
}

TEST_CASE("JwksCache: backwards clock step resets rate limit and allows hit refresh",
          "[jwks][cache][rate-limit][clock-skew]") {
	JwksCache cache(30);
	cache.OnFetchSuccess(MakeRsaJwk("k1"), 1000);

	CHECK(cache.TryBeginHitRefresh("k1", 1030));
	CHECK_FALSE(cache.TryBeginHitRefresh("k1", 1030));

	// System clock steps backwards (NTP skew) to t=900 (130s in the past).
	CHECK(cache.TryBeginHitRefresh("k1", 900));
	CHECK_FALSE(cache.TryBeginHitRefresh("k1", 905));
	CHECK(cache.TryBeginHitRefresh("k1", 930));
}

TEST_CASE("JwksCache: out-of-order fetch completion preserves the latest refresh attempt timestamp",
          "[jwks][cache][rate-limit][monotonic]") {
	JwksCache cache(30);
	cache.OnFetchSuccess(MakeRsaJwk("k1"), 100);

	CHECK(cache.TryBeginHitRefresh("k1", 150));

	// An out-of-order fetch completion arrives stamped at t=120.
	// Calling OnFetchSuccess must not move last_refresh_attempt_s backwards from 150 to 120.
	cache.OnFetchSuccess(MakeRsaJwk("k1"), 120);

	CHECK_FALSE(cache.TryBeginHitRefresh("k1", 160));
	CHECK(cache.TryBeginHitRefresh("k1", 180));
}

TEST_CASE("JwksCache: successful fetches are bounded by capacity", "[jwks][cache][capacity]") {
	JwksCache cache(kRefresh, /*max_entries=*/2);
	cache.OnFetchSuccess(MakeRsaJwk("k1"), 0);
	cache.OnFetchSuccess(MakeRsaJwk("k2"), 1);
	cache.OnFetchSuccess(MakeRsaJwk("k3"), 2);

	CHECK(cache.Size() == 2);
	CHECK(cache.Lookup("k1", 3).status == JwksLookupStatus::Miss);
	CHECK(cache.Lookup("k2", 3).status == JwksLookupStatus::Hit);
	CHECK(cache.Lookup("k3", 3).status == JwksLookupStatus::Hit);
}

TEST_CASE("JwksCache: miss rate-limit entries are bounded by capacity", "[jwks][cache][capacity]") {
	JwksCache cache(kRefresh, /*max_entries=*/2);
	cache.OnFetchMiss("k1", 0);
	cache.OnFetchMiss("k2", 1);
	cache.OnFetchMiss("k3", 2);

	CHECK(cache.MissSize() == 2);
	CHECK(cache.Lookup("k1", 3).status == JwksLookupStatus::Miss);
	CHECK(cache.Lookup("k2", 3).status == JwksLookupStatus::RateLimited);
	CHECK(cache.Lookup("k3", 3).status == JwksLookupStatus::RateLimited);
}
