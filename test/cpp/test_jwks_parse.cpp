#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

#include "jwks_parse.hpp"

using quack_oauth::Jwk;
using quack_oauth::ParseJwksJson;

namespace {

bool HasKid(const std::vector<Jwk> &keys, const std::string &kid) {
	return std::any_of(keys.begin(), keys.end(), [&](const Jwk &k) { return k.kid == kid; });
}

const Jwk *FindKid(const std::vector<Jwk> &keys, const std::string &kid) {
	for (const auto &k : keys) {
		if (k.kid == kid)
			return &k;
	}
	return nullptr;
}

constexpr const char *kValidKeycloakJwks = R"({
  "keys": [
    {
      "kid": "rsa-1",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86z",
      "e": "AQAB"
    },
    {
      "kid": "rsa-2",
      "kty": "RSA",
      "alg": "RS384",
      "use": "sig",
      "n": "another-modulus-base64url",
      "e": "AQAB"
    }
  ]
})";

constexpr const char *kEcKeyJwks = R"({
  "keys": [
    {
      "kid": "ec-1",
      "kty": "EC",
      "alg": "ES256",
      "use": "sig",
      "crv": "P-256",
      "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    }
  ]
})";

} // namespace

TEST_CASE("ParseJwksJson extracts every key in a valid document", "[jwks][parse]") {
	const auto keys = ParseJwksJson(kValidKeycloakJwks);
	REQUIRE(keys.size() == 2);
	CHECK(HasKid(keys, "rsa-1"));
	CHECK(HasKid(keys, "rsa-2"));
}

TEST_CASE("ParseJwksJson preserves RSA fields", "[jwks][parse]") {
	const auto keys = ParseJwksJson(kValidKeycloakJwks);
	const auto *k = FindKid(keys, "rsa-1");
	REQUIRE(k != nullptr);
	CHECK(k->kty == "RSA");
	CHECK(k->alg == "RS256");
	CHECK(k->use == "sig");
	CHECK(k->n == "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86z");
	CHECK(k->e == "AQAB");
}

TEST_CASE("ParseJwksJson preserves EC fields", "[jwks][parse]") {
	const auto keys = ParseJwksJson(kEcKeyJwks);
	REQUIRE(keys.size() == 1);
	const auto &k = keys[0];
	CHECK(k.kty == "EC");
	CHECK(k.alg == "ES256");
	CHECK(k.crv == "P-256");
	CHECK(k.x == "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU");
	CHECK(k.y == "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0");
}

TEST_CASE("ParseJwksJson returns empty on malformed JSON", "[jwks][parse][error]") {
	CHECK(ParseJwksJson("").empty());
	CHECK(ParseJwksJson("not json at all").empty());
	CHECK(ParseJwksJson("{").empty());
	CHECK(ParseJwksJson("[]").empty());
}

TEST_CASE("ParseJwksJson tolerates missing keys array", "[jwks][parse][error]") {
	// Well-formed JSON but no `keys` -- the response shape is wrong.
	CHECK(ParseJwksJson(R"({"unrelated":"field"})").empty());
	// `keys` exists but is not an array.
	CHECK(ParseJwksJson(R"({"keys":"not-an-array"})").empty());
}

TEST_CASE("ParseJwksJson skips entries missing required fields", "[jwks][parse]") {
	// A key without `kid` is unusable for signature verification (we look up
	// by kid). A key without `kty` has no algorithm family. Both are silently
	// dropped from the output -- it's OK for an IdP doc to mix usable and
	// unusable entries.
	constexpr const char *mixed = R"({
	  "keys": [
	    {"kty": "RSA", "n": "no-kid"},
	    {"kid": "no-kty", "n": "abc", "e": "AQAB"},
	    {"kid": "good", "kty": "RSA", "n": "good-modulus", "e": "AQAB"}
	  ]
	})";
	const auto keys = ParseJwksJson(mixed);
	REQUIRE(keys.size() == 1);
	CHECK(keys[0].kid == "good");
}
