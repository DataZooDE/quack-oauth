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

TEST_CASE("JwksCache: decreasing now_s sequence fails closed and enforces rate limit",
          "[jwks][cache][rate-limit][clock-skew]") {
	JwksCache cache(30);
	cache.OnFetchSuccess(MakeRsaJwk("k1"), 1000);

	// Chunk B at t=1030 reserves a refresh.
	const auto res1 = cache.TryReserveRefresh("k1", 1030);
	CHECK(res1 != 0);

	// Concurrent Chunk A with slightly earlier sampled timestamp t=1029 arrives.
	// Because 1029 < 1030, this is a backwards timestamp step.
	// It must FAIL CLOSED (return 0) rather than granting a second refresh in the window.
	CHECK(cache.TryReserveRefresh("k1", 1029) == 0);

	// Another concurrent chunk at t=1028 also fails closed.
	CHECK(cache.TryReserveRefresh("k1", 1028) == 0);

	// Only after the full window from the last stamp (1028 + 30 = 1058) is a new reservation allowed.
	CHECK(cache.TryReserveRefresh("k1", 1050) == 0);
	CHECK(cache.TryReserveRefresh("k1", 1058) != 0);
}

TEST_CASE("JwksCache: out-of-order refresh completions do not overwrite newer keys",
          "[jwks][cache][reservation][concurrency]") {
	JwksCache cache(30);
	const auto k0 = MakeRsaJwk("k1");
	cache.OnFetchSuccess(k0, 1000);

	// Request A starts at t=1030 and gets reservation id res_a
	const auto res_a = cache.TryReserveRefresh("k1", 1030);
	REQUIRE(res_a != 0);

	// Request B starts later at t=1065 (after window) and gets reservation id res_b
	const auto res_b = cache.TryReserveRefresh("k1", 1065);
	REQUIRE(res_b != 0);
	REQUIRE(res_b > res_a);

	auto k1 = MakeRsaJwk("k1");
	k1.n = "key-K1";
	auto k2 = MakeRsaJwk("k1");
	k2.n = "key-K2";

	// Request B finishes faster and commits K2
	CHECK(cache.CommitRefresh("k1", res_b, k2, 1066));
	CHECK(cache.Lookup("k1", 1066).jwk->n == "key-K2");

	// Request A finishes later (out-of-order) and tries to commit K1 using stale res_a
	CHECK_FALSE(cache.CommitRefresh("k1", res_a, k1, 1070));

	// The newer key K2 must still be in the cache!
	CHECK(cache.Lookup("k1", 1070).jwk->n == "key-K2");
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

TEST_CASE("JwksCache: CommitRefresh updates LRU order for eviction", "[jwks][cache][capacity][lru]") {
	JwksCache cache(kRefresh, /*max_entries=*/2);
	cache.OnFetchSuccess(MakeRsaJwk("k1"), 0);
	cache.OnFetchSuccess(MakeRsaJwk("k2"), 1);

	// Reserve and commit refresh for k1 at t=35.
	const auto res = cache.TryReserveRefresh("k1", 35);
	REQUIRE(res != 0);
	CHECK(cache.CommitRefresh("k1", res, MakeRsaJwk("k1"), 36));

	// Adding k3 should now evict k2 (which is now least recently used), keeping k1.
	cache.OnFetchSuccess(MakeRsaJwk("k3"), 37);
	CHECK(cache.Lookup("k1", 38).status == JwksLookupStatus::Hit);
	CHECK(cache.Lookup("k2", 38).status == JwksLookupStatus::Miss);
	CHECK(cache.Lookup("k3", 38).status == JwksLookupStatus::Hit);
}

TEST_CASE("JwksCache: SetMinRefreshSeconds updates window and clamps below 1", "[jwks][cache][settings]") {
	JwksCache cache(30);
	cache.OnFetchSuccess(MakeRsaJwk("k1"), 100);

	// At 110 (10s later), rate limited under 30s window
	CHECK_FALSE(cache.TryBeginHitRefresh("k1", 110));

	// Dynamically change min refresh to 5s
	cache.SetMinRefreshSeconds(5);
	// Now at 110, 10s >= 5s, so it should be allowed!
	CHECK(cache.TryBeginHitRefresh("k1", 110));

	// Values below 1 are clamped to 1
	cache.SetMinRefreshSeconds(0);
	CHECK_FALSE(cache.TryBeginHitRefresh("k1", 110));
	CHECK(cache.TryBeginHitRefresh("k1", 111));
}
