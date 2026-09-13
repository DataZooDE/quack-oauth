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
	CHECK(r.keys.empty());
	CHECK(cache.Size() == 0);
}

TEST_CASE("JwksCache: OnFetchSuccess makes subsequent lookups Hit", "[jwks][cache]") {
	JwksCache cache(kRefresh);
	const auto j = MakeRsaJwk("k1");
	cache.OnFetchSuccess(j.kid, {j}, 100);

	const auto r = cache.Lookup("k1", 200);
	REQUIRE(r.status == JwksLookupStatus::Hit);
	REQUIRE_FALSE(r.keys.empty());
	CHECK(r.keys[0].kid == "k1");
	CHECK(r.keys[0].kty == "RSA");
	CHECK(r.keys[0].alg == "RS256");
	CHECK(r.keys[0].n == "fake-modulus-k1");
	CHECK(cache.Size() == 1);
}

TEST_CASE("JwksCache: cached entries never expire on hit", "[jwks][cache]") {
	// Architecture section 6 "IdP outage" scenario: hits keep serving
	// indefinitely; only misses are rate-limited.
	JwksCache cache(kRefresh);
	const auto j = MakeRsaJwk("k1");
	cache.OnFetchSuccess(j.kid, {j}, 0);

	const auto far_future = cache.Lookup("k1", 365L * 24 * 3600);
	CHECK(far_future.status == JwksLookupStatus::Hit);
}

TEST_CASE("JwksCache: OnFetchMiss rate-limits subsequent fetches per R-S-4", "[jwks][cache][rate-limit]") {
	JwksCache cache(kRefresh);
	cache.OnFetchMiss("nope", 0);

	const auto r0 = cache.Lookup("nope", 0);
	CHECK(r0.status == JwksLookupStatus::RateLimited);
	CHECK(r0.retry_after_s == kRefresh);

	const auto r10 = cache.Lookup("nope", 10);
	CHECK(r10.status == JwksLookupStatus::RateLimited);
	CHECK(r10.retry_after_s == kRefresh - 10);

	const auto r30 = cache.Lookup("nope", 30);
	CHECK(r30.status == JwksLookupStatus::Miss);

	// k2 has no recent miss recorded -- it should not inherit k1's rate limit.
	const auto r = cache.Lookup("k2", 5);
	CHECK(r.status == JwksLookupStatus::Miss);
}

TEST_CASE("JwksCache: a later success on a previously-missed kid clears the limit", "[jwks][cache][rate-limit]") {
	JwksCache cache(kRefresh);
	cache.OnFetchMiss("k1", 0);
	const auto j = MakeRsaJwk("k1");
	cache.OnFetchSuccess(j.kid, {j}, 5);

	const auto r = cache.Lookup("k1", 6);
	REQUIRE(r.status == JwksLookupStatus::Hit);
	REQUIRE_FALSE(r.keys.empty());
	CHECK(r.keys[0].kid == "k1");
}

TEST_CASE("JwksCache: Size() reflects only successful fetches", "[jwks][cache]") {
	JwksCache cache(kRefresh);
	cache.OnFetchMiss("absent-1", 0);
	cache.OnFetchMiss("absent-2", 0);
	const auto j = MakeRsaJwk("present");
	cache.OnFetchSuccess(j.kid, {j}, 0);
	CHECK(cache.Size() == 1);
}

TEST_CASE("JwksCache: multi-key entry preserves multiple published JWKs", "[jwks][cache]") {
	JwksCache cache(kRefresh);

	Jwk first = MakeRsaJwk("k1");
	first.n = "first-modulus";
	Jwk second = MakeRsaJwk("k1");
	second.n = "rotated-modulus";
	cache.OnFetchSuccess("k1", {first, second}, 100);

	const auto r = cache.Lookup("k1", 200);
	REQUIRE(r.status == JwksLookupStatus::Hit);
	REQUIRE(r.keys.size() == 2);
	CHECK(r.keys[0].n == "first-modulus");
	CHECK(r.keys[1].n == "rotated-modulus");
	CHECK(cache.Size() == 1);
}

TEST_CASE("JwksCache: cached-key refresh attempts are rate-limited", "[jwks][cache][rate-limit]") {
	JwksCache cache(kRefresh);
	const auto j = MakeRsaJwk("k1");
	cache.OnFetchSuccess(j.kid, {j}, 100);

	CHECK(cache.TryReserveRefresh("k1", 110) == 0);
	CHECK(cache.TryReserveRefresh("k1", 130) != 0);
	CHECK(cache.TryReserveRefresh("k1", 140) == 0);
	CHECK(cache.TryReserveRefresh("k1", 160) != 0);
	CHECK(cache.TryReserveRefresh("missing", 200) == 0);
	CHECK(cache.Lookup("k1", 200).status == JwksLookupStatus::Hit);
}

TEST_CASE("JwksCache: min_refresh_s is clamped to at least 1 second", "[jwks][cache][rate-limit]") {
	JwksCache cache(/*min_refresh_s=*/0);
	const auto j = MakeRsaJwk("k1");
	cache.OnFetchSuccess(j.kid, {j}, 100);

	CHECK(cache.TryReserveRefresh("k1", 100) == 0);
	CHECK(cache.TryReserveRefresh("k1", 101) != 0);
	CHECK(cache.TryReserveRefresh("k1", 101) == 0);

	JwksCache cache_neg(/*min_refresh_s=*/-5);
	cache_neg.OnFetchSuccess("k1", {MakeRsaJwk("k1")}, 100);
	CHECK(cache_neg.TryReserveRefresh("k1", 100) == 0);
	CHECK(cache_neg.TryReserveRefresh("k1", 101) != 0);
	CHECK(cache_neg.TryReserveRefresh("k1", 101) == 0);
}

TEST_CASE("JwksCache: decreasing now_s sequence fails closed and enforces rate limit",
          "[jwks][cache][rate-limit][clock-skew]") {
	JwksCache cache(30);
	cache.OnFetchSuccess("k1", {MakeRsaJwk("k1")}, 1000);

	// Chunk B at t=1030 reserves a refresh.
	const auto res1 = cache.TryReserveRefresh("k1", 1030);
	CHECK(res1 != 0);

	// Concurrent Chunk A with slightly earlier sampled timestamp t=1029 arrives.
	// Because 1029 < 1030, this is a backwards timestamp step.
	// It must FAIL CLOSED (return 0) rather than granting a second refresh in the window.
	CHECK(cache.TryReserveRefresh("k1", 1029) == 0);

	// Another concurrent chunk at t=1028 also fails closed.
	CHECK(cache.TryReserveRefresh("k1", 1028) == 0);

	// Monotonicity preserves the latest attempt stamp (1030), so before 1030 + 30 = 1060
	// reservations remain rate-limited.
	CHECK(cache.TryReserveRefresh("k1", 1058) == 0);
	CHECK(cache.TryReserveRefresh("k1", 1060) != 0);
}

TEST_CASE("JwksCache: out-of-order refresh completions do not overwrite newer keys",
          "[jwks][cache][reservation][concurrency]") {
	JwksCache cache(30);
	const auto k0 = MakeRsaJwk("k1");
	cache.OnFetchSuccess(k0.kid, {k0}, 1000);

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
	CHECK(cache.CommitRefresh("k1", res_b, {k2}, 1066));
	CHECK(cache.Lookup("k1", 1066).keys.back().n == "key-K2");

	// Request A finishes later (out-of-order) and tries to commit K1 using stale res_a
	CHECK_FALSE(cache.CommitRefresh("k1", res_a, {k1}, 1070));

	// The newer key K2 must still be in the cache!
	CHECK(cache.Lookup("k1", 1070).keys.back().n == "key-K2");
}

TEST_CASE("JwksCache: out-of-order fetch completion preserves the latest refresh attempt timestamp",
          "[jwks][cache][rate-limit][monotonic]") {
	JwksCache cache(30);
	const auto j = MakeRsaJwk("k1");
	cache.OnFetchSuccess(j.kid, {j}, 100);

	CHECK(cache.TryReserveRefresh("k1", 150) != 0);

	// An out-of-order fetch completion arrives stamped at t=120.
	// Calling OnFetchSuccess must not move last_refresh_attempt_s backwards from 150 to 120.
	cache.OnFetchSuccess(j.kid, {j}, 120);

	CHECK(cache.TryReserveRefresh("k1", 160) == 0);
	CHECK(cache.TryReserveRefresh("k1", 180) != 0);
}

TEST_CASE("JwksCache: successful fetches are bounded by capacity", "[jwks][cache][capacity]") {
	JwksCache cache(kRefresh, /*max_entries=*/2);
	const auto k1 = MakeRsaJwk("k1");
	const auto k2 = MakeRsaJwk("k2");
	const auto k3 = MakeRsaJwk("k3");
	cache.OnFetchSuccess(k1.kid, {k1}, 0);
	cache.OnFetchSuccess(k2.kid, {k2}, 1);
	cache.OnFetchSuccess(k3.kid, {k3}, 2);

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
	const auto k1 = MakeRsaJwk("k1");
	const auto k2 = MakeRsaJwk("k2");
	cache.OnFetchSuccess(k1.kid, {k1}, 0);
	cache.OnFetchSuccess(k2.kid, {k2}, 1);

	// Reserve and commit refresh for k1 at t=35.
	const auto res = cache.TryReserveRefresh("k1", 35);
	REQUIRE(res != 0);
	CHECK(cache.CommitRefresh("k1", res, {MakeRsaJwk("k1")}, 36));

	// Adding k3 should now evict k2 (which is now least recently used), keeping k1.
	const auto k3 = MakeRsaJwk("k3");
	cache.OnFetchSuccess(k3.kid, {k3}, 37);
	CHECK(cache.Lookup("k1", 38).status == JwksLookupStatus::Hit);
	CHECK(cache.Lookup("k2", 38).status == JwksLookupStatus::Miss);
	CHECK(cache.Lookup("k3", 38).status == JwksLookupStatus::Hit);
}

TEST_CASE("JwksCache: SetMinRefreshSeconds updates window and clamps to [1, 3600]", "[jwks][cache][settings]") {
	JwksCache cache(30);
	const auto k1 = MakeRsaJwk("k1");
	cache.OnFetchSuccess(k1.kid, {k1}, 100);

	// At 110 (10s later), rate limited under 30s window
	CHECK(cache.TryReserveRefresh("k1", 110) == 0);

	// Dynamically change min refresh to 5s
	cache.SetMinRefreshSeconds(5);
	// Now at 110, 10s >= 5s, so it should be allowed!
	CHECK(cache.TryReserveRefresh("k1", 110) != 0);

	// Values below 1 are clamped to 1
	cache.SetMinRefreshSeconds(0);
	CHECK(cache.TryReserveRefresh("k1", 110) == 0);
	CHECK(cache.TryReserveRefresh("k1", 111) != 0);

	// Values above 3600 are clamped to 3600
	cache.SetMinRefreshSeconds(5000);
	CHECK(cache.TryReserveRefresh("k1", 3700) == 0);
	CHECK(cache.TryReserveRefresh("k1", 3711) != 0);
}

TEST_CASE("JwksCache: multi-key entry preserves multiple keys under same kid", "[jwks][cache][multi-key]") {
	JwksCache cache(kRefresh);
	auto k1_a = MakeRsaJwk("k1");
	k1_a.n = "modulus-a";
	auto k1_b = MakeRsaJwk("k1");
	k1_b.n = "modulus-b";

	cache.OnFetchSuccess("k1", {k1_a, k1_b}, 100);

	const auto r = cache.Lookup("k1", 200);
	REQUIRE(r.status == JwksLookupStatus::Hit);
	REQUIRE(r.keys.size() == 2);
	CHECK(r.keys[0].n == "modulus-a");
	CHECK(r.keys[1].n == "modulus-b");
	CHECK(cache.Size() == 1);
}

TEST_CASE("JwksCache: duplicate identical key material does not duplicate or invalidate reservation",
          "[jwks][cache][multi-key]") {
	JwksCache cache(kRefresh);
	auto k1 = MakeRsaJwk("k1");
	cache.OnFetchSuccess(k1.kid, {k1}, 100);

	const auto res = cache.TryReserveRefresh("k1", 200);
	REQUIRE(res != 0);

	// Ingesting the identical key material again (e.g., from sibling ingest or repeated fetch)
	// should not duplicate the key, nor should it invalidate the active reservation ID.
	cache.OnFetchSuccess(k1.kid, {k1}, 201);

	const auto r = cache.Lookup("k1", 202);
	REQUIRE(r.keys.size() == 1);

	// Reservation must still be valid!
	auto k1_new = MakeRsaJwk("k1");
	k1_new.n = "modulus-new";
	CHECK(cache.CommitRefresh("k1", res, {k1, k1_new}, 203));

	const auto r2 = cache.Lookup("k1", 204);
	REQUIRE(r2.keys.size() == 2);
	CHECK(r2.keys[0].n == k1.n);
	CHECK(r2.keys[1].n == "modulus-new");
}

TEST_CASE("JwksCache: global fetch budget rate-limits fetches across unknown kids", "[jwks][cache][budget]") {
	JwksCache cache(30);
	CHECK(cache.CanFetchJwks(100));

	cache.RecordJwksFetch(100);
	// Within 2s window, cannot fetch again
	CHECK_FALSE(cache.CanFetchJwks(100));
	CHECK_FALSE(cache.CanFetchJwks(101));

	// At or past 2s window, can fetch again
	CHECK(cache.CanFetchJwks(102));
}

TEST_CASE("JwksCache: CanFetchJwks fails closed on clock rewind and RecordJwksFetch is monotonic",
          "[jwks][cache][budget][clock][f13]") {
	JwksCache cache(30);
	cache.RecordJwksFetch(100);

	// Clock step backward (now_s < 100) must fail closed (cannot fetch)
	CHECK_FALSE(cache.CanFetchJwks(90));
	CHECK_FALSE(cache.CanFetchJwks(50));

	// RecordJwksFetch on backwards timestamp must be monotonic (does not move timestamp backward)
	cache.RecordJwksFetch(80);
	CHECK_FALSE(cache.CanFetchJwks(90));
	CHECK_FALSE(cache.CanFetchJwks(101));
	CHECK(cache.CanFetchJwks(102));
}

TEST_CASE("JwksCache: Hard cap on Entry::keys preserves at most 4 keys", "[jwks][cache][cap][f1]") {
	JwksCache cache(30);
	std::vector<Jwk> keys;
	for (int i = 0; i < 6; ++i) {
		auto k = MakeRsaJwk("k1");
		k.n = "modulus-" + std::to_string(i);
		keys.push_back(k);
	}
	cache.OnFetchSuccess("k1", keys, 100);

	const auto r = cache.Lookup("k1", 200);
	REQUIRE(r.status == JwksLookupStatus::Hit);
	REQUIRE(r.keys.size() == 4);
	// Should contain the last 4: modulus-2, modulus-3, modulus-4, modulus-5
	CHECK(r.keys[0].n == "modulus-2");
	CHECK(r.keys[3].n == "modulus-5");
}

TEST_CASE("JwksCache: Unknown kty is rejected and does not append unbounded duplicate keys",
          "[jwks][cache][kty][f11]") {
	JwksCache cache(30);
	Jwk bad;
	bad.kid = "k1";
	bad.kty = "oct";
	bad.n = "secret";

	cache.OnFetchSuccess("k1", {bad}, 100);
	const auto r = cache.Lookup("k1", 100);
	// Unknown kty should be rejected from hits_
	CHECK(r.status == JwksLookupStatus::Miss);
}
