#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

#include "jwt_parse.hpp"

using quack_oauth::JwtParsed;
using quack_oauth::ParseJwt;

namespace {

// Header  : {"alg":"RS256","typ":"JWT","kid":"key-1"}
// Payload : {"sub":"alice","iss":"https://idp.example","aud":"api://quack",
//            "exp":1735689600,"iat":1735686000,"nbf":1735685940,
//            "scope":"openid quack:read"}
// Signature: arbitrary -- parse-only path does not verify.
constexpr const char *kFixtureStringAud =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0xIn0."
    "eyJzdWIiOiJhbGljZSIsImlzcyI6Imh0dHBzOi8vaWRwLmV4YW1wbGUiLCJhdWQiOiJhcGk6Ly9xdWFjayIs"
    "ImV4cCI6MTczNTY4OTYwMCwiaWF0IjoxNzM1Njg2MDAwLCJuYmYiOjE3MzU2ODU5NDAsInNjb3BlIjoib3Bl"
    "bmlkIHF1YWNrOnJlYWQifQ.sig";

// Header  : {"alg":"RS256","typ":"JWT","kid":"key-2"}
// Payload : {"sub":"bob","iss":"https://login.microsoftonline.com/tid/v2.0",
//            "aud":["api://quack","api://other"],
//            "exp":1735689600,"scp":["quack.read","quack.write"]}
constexpr const char *kFixtureArrayAudEntra =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0yIn0."
    "eyJzdWIiOiJib2IiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vdGlkL3YyLjAi"
    "LCJhdWQiOlsiYXBpOi8vcXVhY2siLCJhcGk6Ly9vdGhlciJdLCJleHAiOjE3MzU2ODk2MDAsInNjcCI6WyJx"
    "dWFjay5yZWFkIiwicXVhY2sud3JpdGUiXX0.sig";

bool ContainsAudience(const JwtParsed &p, const std::string &needle) {
	return std::find(p.audience.begin(), p.audience.end(), needle) != p.audience.end();
}

bool ContainsScope(const JwtParsed &p, const std::string &needle) {
	return std::find(p.scp.begin(), p.scp.end(), needle) != p.scp.end();
}

} // namespace

TEST_CASE("ParseJwt extracts header claims (alg, kid, typ)", "[jwt][parse]") {
	const auto p = ParseJwt(kFixtureStringAud);
	REQUIRE(p.has_value());
	CHECK(p->alg == "RS256");
	CHECK(p->kid == "key-1");
	CHECK(p->typ == "JWT");
}

TEST_CASE("ParseJwt extracts payload claims (sub, iss, exp, iat, nbf, scope)", "[jwt][parse]") {
	const auto p = ParseJwt(kFixtureStringAud);
	REQUIRE(p.has_value());
	CHECK(p->subject == "alice");
	CHECK(p->issuer == "https://idp.example");
	CHECK(p->exp == 1735689600);
	CHECK(p->iat == 1735686000);
	CHECK(p->nbf == 1735685940);
	CHECK(p->scope == "openid quack:read");
}

TEST_CASE("ParseJwt handles single-string audience", "[jwt][parse][aud]") {
	const auto p = ParseJwt(kFixtureStringAud);
	REQUIRE(p.has_value());
	REQUIRE(p->audience.size() == 1);
	CHECK(p->audience[0] == "api://quack");
}

TEST_CASE("ParseJwt handles array-shaped audience (Entra-style)", "[jwt][parse][aud]") {
	const auto p = ParseJwt(kFixtureArrayAudEntra);
	REQUIRE(p.has_value());
	REQUIRE(p->audience.size() == 2);
	CHECK(ContainsAudience(*p, "api://quack"));
	CHECK(ContainsAudience(*p, "api://other"));
}

TEST_CASE("ParseJwt extracts Entra-style scp[] array", "[jwt][parse][scope]") {
	const auto p = ParseJwt(kFixtureArrayAudEntra);
	REQUIRE(p.has_value());
	REQUIRE(p->scp.size() == 2);
	CHECK(ContainsScope(*p, "quack.read"));
	CHECK(ContainsScope(*p, "quack.write"));
	// scope (space-delimited) is absent on the Entra fixture.
	CHECK(p->scope.empty());
}

TEST_CASE("ParseJwt returns nullopt for malformed tokens", "[jwt][parse][error]") {
	CHECK_FALSE(ParseJwt("").has_value());
	CHECK_FALSE(ParseJwt("not-a-jwt").has_value());
	CHECK_FALSE(ParseJwt("only.two").has_value());
	CHECK_FALSE(ParseJwt("a.b.c.d").has_value());
	// Three segments but header is not base64url of valid JSON.
	CHECK_FALSE(ParseJwt("!!!.bbb.ccc").has_value());
}

TEST_CASE("ParseJwt returns nullopt when header is not JSON", "[jwt][parse][error]") {
	// "notjson" base64url-encoded
	CHECK_FALSE(ParseJwt("bm90anNvbg.eyJzdWIiOiJhIn0.sig").has_value());
}
