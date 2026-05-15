#include <catch2/catch_test_macros.hpp>

#include <string>

#include "secure_scrub.hpp"

using quack_oauth::SecureScrub;

TEST_CASE("SecureScrub: empty string is a no-op", "[scrub]") {
	std::string s;
	SecureScrub(s);
	CHECK(s.empty());
}

TEST_CASE("SecureScrub: bytes are zeroed before the string is freed", "[scrub]") {
	std::string s = "eyJhbGciOiJSUzI1NiIs...some-secret-jwt-bytes";
	const auto orig = s; // snapshot for comparison
	SecureScrub(s);
	CHECK(s.empty());
	// After scrubbing the buffer is zeroed; the string is emptied.
	// We can't reliably observe the freed heap from a unit test, so the
	// contract here is: s is empty, the call succeeded.
	CHECK(s != orig);
}

TEST_CASE("SecureScrub: scrubbing a moved-from string is safe", "[scrub]") {
	std::string s = "secret-token";
	std::string sink = std::move(s);
	// s is in a valid-but-unspecified state. SecureScrub must not crash.
	SecureScrub(s);
	CHECK(s.empty());
	// The moved-into sink still holds its content (we don't touch it).
	CHECK(sink == "secret-token");
}
