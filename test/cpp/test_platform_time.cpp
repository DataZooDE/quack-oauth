#include <catch2/catch_test_macros.hpp>

#include <string>

#include "platform_time.hpp"

using quack_oauth::FormatUtcIso8601;

TEST_CASE("FormatUtcIso8601: epoch zero", "[platform-time]") {
	CHECK(FormatUtcIso8601(0) == "1970-01-01T00:00:00Z");
}

TEST_CASE("FormatUtcIso8601: known wall-clock instant", "[platform-time]") {
	// epoch 1700000000 = 2023-11-14T22:13:20Z  (verified via `date -u -d`).
	CHECK(FormatUtcIso8601(1700000000) == "2023-11-14T22:13:20Z");
}

TEST_CASE("FormatUtcIso8601: end of year", "[platform-time]") {
	// 2025-12-31T23:59:59 UTC = 1767225599.
	CHECK(FormatUtcIso8601(1767225599) == "2025-12-31T23:59:59Z");
}
