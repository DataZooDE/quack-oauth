#include <catch2/catch_test_macros.hpp>

#include "authz.hpp"
#include "decision_cache.hpp"   // for Principal
#include "principal_expiry.hpp"

using quack_oauth::IsPrincipalExpired;
using quack_oauth::Principal;

namespace {

Principal MakeP(std::int64_t exp_s) {
	Principal p;
	p.subject = "alice";
	p.exp = exp_s;
	return p;
}

} // namespace

TEST_CASE("IsPrincipalExpired: now before exp → not expired",
          "[principal-expiry]") {
	const auto p = MakeP(1700001000);
	CHECK_FALSE(IsPrincipalExpired(p, 1700000000, /*skew=*/0));
}

TEST_CASE("IsPrincipalExpired: now equals exp → not expired (exp is exclusive)",
          "[principal-expiry]") {
	const auto p = MakeP(1700001000);
	CHECK_FALSE(IsPrincipalExpired(p, 1700001000, 0));
}

TEST_CASE("IsPrincipalExpired: now after exp → expired",
          "[principal-expiry]") {
	const auto p = MakeP(1700001000);
	CHECK(IsPrincipalExpired(p, 1700001001, 0));
	CHECK(IsPrincipalExpired(p, 1700009999, 0));
}

TEST_CASE("IsPrincipalExpired: clock-skew gives leeway past exp",
          "[principal-expiry]") {
	const auto p = MakeP(1700001000);
	// 60s skew → still valid up to exp + 60.
	CHECK_FALSE(IsPrincipalExpired(p, 1700001050, 60));
	CHECK_FALSE(IsPrincipalExpired(p, 1700001060, 60));
	CHECK(IsPrincipalExpired(p, 1700001061, 60));
}

TEST_CASE("IsPrincipalExpired: exp=0 means 'unknown' -- treat as not expired",
          "[principal-expiry]") {
	// Some IdP responses (e.g. opaque introspect with no exp) yield
	// principal.exp == 0. The check_authorization caller already trusts
	// the principal cache; an unknown exp shouldn't force a deny.
	const auto p = MakeP(0);
	CHECK_FALSE(IsPrincipalExpired(p, 1700000000, 0));
	CHECK_FALSE(IsPrincipalExpired(p, 9999999999, 0));
}

TEST_CASE("IsPrincipalExpired: negative exp treated like 0 (unknown)",
          "[principal-expiry]") {
	const auto p = MakeP(-1);
	CHECK_FALSE(IsPrincipalExpired(p, 1700000000, 0));
}
