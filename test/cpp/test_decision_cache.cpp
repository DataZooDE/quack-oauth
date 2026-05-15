#include <catch2/catch_test_macros.hpp>

#include <string>

#include "decision_cache.hpp"

using quack_oauth::DecisionCache;
using quack_oauth::Principal;

namespace {

Principal MakePrincipal(const std::string &sub, std::int64_t exp_s = 0) {
	Principal p;
	p.subject = sub;
	p.issuer = "https://idp.test";
	p.exp = exp_s;
	return p;
}

} // namespace

TEST_CASE("DecisionCache::KeyOf returns a 64-hex SHA-256",
          "[decision-cache][key]") {
	const auto k1 = DecisionCache::KeyOf("any-token");
	REQUIRE(k1.size() == 64);
	for (char c : k1) {
		REQUIRE(((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
	}
}

TEST_CASE("DecisionCache::KeyOf is deterministic and discriminating",
          "[decision-cache][key]") {
	CHECK(DecisionCache::KeyOf("a") == DecisionCache::KeyOf("a"));
	CHECK(DecisionCache::KeyOf("a") != DecisionCache::KeyOf("b"));
	// Known SHA-256 vector: "hello" -> 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	CHECK(DecisionCache::KeyOf("hello") ==
	      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}

TEST_CASE("DecisionCache: empty cache returns nullopt",
          "[decision-cache][lookup]") {
	DecisionCache cache(/*max_entries=*/1000, /*default_ttl_s=*/60);
	CHECK_FALSE(cache.Lookup(DecisionCache::KeyOf("absent"), 0).has_value());
	CHECK(cache.Size() == 0);
}

TEST_CASE("DecisionCache: Store then Lookup returns the stored Principal",
          "[decision-cache]") {
	DecisionCache cache(1000, 60);
	const auto key = DecisionCache::KeyOf("t1");
	cache.Store(key, MakePrincipal("alice", /*exp=*/2000), /*now=*/1000);

	const auto p = cache.Lookup(key, 1010);
	REQUIRE(p.has_value());
	CHECK(p->subject == "alice");
	CHECK(p->issuer == "https://idp.test");
	CHECK(p->exp == 2000);
	CHECK(cache.Size() == 1);
}

TEST_CASE("DecisionCache: TTL elapses after default_ttl_s",
          "[decision-cache][ttl]") {
	// exp is far in the future, so the TTL cap binds at 60s.
	DecisionCache cache(1000, /*default_ttl_s=*/60);
	const auto key = DecisionCache::KeyOf("t1");
	cache.Store(key, MakePrincipal("alice", /*exp=*/1'000'000), /*now=*/1000);

	CHECK(cache.Lookup(key, 1059).has_value());  // 59s after store
	CHECK_FALSE(cache.Lookup(key, 1061).has_value()); // 61s after store
}

TEST_CASE("DecisionCache: TTL is capped at min(default_ttl_s, exp - now)",
          "[decision-cache][ttl]") {
	DecisionCache cache(1000, /*default_ttl_s=*/60);
	const auto key = DecisionCache::KeyOf("t1");
	// Token expires 10s after store -> effective TTL is 10s, not 60.
	cache.Store(key, MakePrincipal("alice", /*exp=*/1010), /*now=*/1000);

	CHECK(cache.Lookup(key, 1009).has_value());
	CHECK_FALSE(cache.Lookup(key, 1011).has_value());
}

TEST_CASE("DecisionCache: already-expired tokens are NOT stored",
          "[decision-cache][ttl]") {
	DecisionCache cache(1000, 60);
	const auto key = DecisionCache::KeyOf("expired");
	cache.Store(key, MakePrincipal("alice", /*exp=*/500), /*now=*/1000);
	// exp < now; effective TTL <= 0; nothing inserted.
	CHECK(cache.Size() == 0);
	CHECK_FALSE(cache.Lookup(key, 1000).has_value());
}

TEST_CASE("DecisionCache: tokens without exp (exp=0) still get default TTL",
          "[decision-cache][ttl]") {
	DecisionCache cache(1000, /*default_ttl_s=*/60);
	const auto key = DecisionCache::KeyOf("no-exp");
	cache.Store(key, MakePrincipal("alice", /*exp=*/0), /*now=*/1000);
	CHECK(cache.Lookup(key, 1059).has_value());
	CHECK_FALSE(cache.Lookup(key, 1061).has_value());
}

TEST_CASE("DecisionCache: LRU evicts the least-recently-used entry on overflow",
          "[decision-cache][lru]") {
	DecisionCache cache(/*max_entries=*/2, /*default_ttl_s=*/60);
	const auto k_a = DecisionCache::KeyOf("a");
	const auto k_b = DecisionCache::KeyOf("b");
	const auto k_c = DecisionCache::KeyOf("c");

	cache.Store(k_a, MakePrincipal("alice"), 1000);
	cache.Store(k_b, MakePrincipal("bob"), 1001);
	cache.Store(k_c, MakePrincipal("carol"), 1002);

	CHECK(cache.Size() == 2);
	CHECK_FALSE(cache.Lookup(k_a, 1003).has_value()); // evicted
	CHECK(cache.Lookup(k_b, 1003).has_value());
	CHECK(cache.Lookup(k_c, 1003).has_value());
}

TEST_CASE("DecisionCache: Lookup on a hit moves the entry to the front",
          "[decision-cache][lru]") {
	DecisionCache cache(/*max_entries=*/2, /*default_ttl_s=*/60);
	const auto k_a = DecisionCache::KeyOf("a");
	const auto k_b = DecisionCache::KeyOf("b");
	const auto k_c = DecisionCache::KeyOf("c");

	cache.Store(k_a, MakePrincipal("alice"), 1000);
	cache.Store(k_b, MakePrincipal("bob"), 1001);

	// Touch `a` so it's now MRU.
	REQUIRE(cache.Lookup(k_a, 1002).has_value());

	// Insert `c` -- `b` should be evicted (it's now LRU), not `a`.
	cache.Store(k_c, MakePrincipal("carol"), 1003);

	CHECK(cache.Lookup(k_a, 1004).has_value());
	CHECK_FALSE(cache.Lookup(k_b, 1004).has_value());
	CHECK(cache.Lookup(k_c, 1004).has_value());
}

TEST_CASE("DecisionCache: Store on existing key updates the value (and refreshes TTL)",
          "[decision-cache]") {
	DecisionCache cache(1000, 60);
	const auto key = DecisionCache::KeyOf("t1");
	cache.Store(key, MakePrincipal("alice", /*exp=*/2000), 1000);

	// Same key, different principal, later now.
	cache.Store(key, MakePrincipal("bob", /*exp=*/3000), 1500);

	const auto p = cache.Lookup(key, 1510);
	REQUIRE(p.has_value());
	CHECK(p->subject == "bob");
	CHECK(cache.Size() == 1);
}
