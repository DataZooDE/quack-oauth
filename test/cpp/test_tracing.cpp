#include <catch2/catch_test_macros.hpp>

#include "tracing.hpp"

using quack_oauth::IsSensitiveField;
using quack_oauth::RedactSensitive;

TEST_CASE("RedactSensitive returns an 8-char hex prefix", "[tracing][redact]") {
	const auto out = RedactSensitive("some-secret-value");
	REQUIRE(out.size() == 8);
	for (char c : out) {
		REQUIRE(((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
	}
}

TEST_CASE("RedactSensitive never returns the raw input", "[tracing][redact]") {
	const std::string raw = "eyJhbGciOiJSUzI1NiJ9.tokenpayload";
	const auto redacted = RedactSensitive(raw);
	REQUIRE(redacted != raw);
	REQUIRE(redacted.find("token") == std::string::npos);
	REQUIRE(redacted.find("payload") == std::string::npos);
}

TEST_CASE("RedactSensitive is deterministic", "[tracing][redact]") {
	REQUIRE(RedactSensitive("abc") == RedactSensitive("abc"));
	REQUIRE(RedactSensitive("abc") != RedactSensitive("abd"));
}

TEST_CASE("RedactSensitive matches a known SHA-256 prefix", "[tracing][redact]") {
	// sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	REQUIRE(RedactSensitive("hello") == "2cf24dba");
}

TEST_CASE("RedactSensitive returns empty for empty input", "[tracing][redact]") {
	REQUIRE(RedactSensitive("").empty());
}

TEST_CASE("IsSensitiveField recognises the documented field names", "[tracing][redact]") {
	REQUIRE(IsSensitiveField("token"));
	REQUIRE(IsSensitiveField("access_token"));
	REQUIRE(IsSensitiveField("refresh_token"));
	REQUIRE(IsSensitiveField("id_token"));
	REQUIRE(IsSensitiveField("client_secret"));
	REQUIRE(IsSensitiveField("password"));
	REQUIRE(IsSensitiveField("code"));
}

TEST_CASE("IsSensitiveField is case-insensitive", "[tracing][redact]") {
	REQUIRE(IsSensitiveField("TOKEN"));
	REQUIRE(IsSensitiveField("Access_Token"));
	REQUIRE(IsSensitiveField("Client_Secret"));
}

TEST_CASE("IsSensitiveField rejects non-sensitive field names", "[tracing][redact]") {
	REQUIRE_FALSE(IsSensitiveField("sub"));
	REQUIRE_FALSE(IsSensitiveField("iss"));
	REQUIRE_FALSE(IsSensitiveField("kid"));
	REQUIRE_FALSE(IsSensitiveField("aud"));
	REQUIRE_FALSE(IsSensitiveField(""));
}
