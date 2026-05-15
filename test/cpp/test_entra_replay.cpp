#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <fstream>
#include <map>
#include <optional>
#include <sstream>
#include <string>

#ifndef PICOJSON_USE_INT64
#define PICOJSON_USE_INT64
#endif
#include <picojson/picojson.h>

#include "http_client.hpp"
#include "jwks_cache.hpp"
#include "jwt_verify.hpp"
#include "validator.hpp"

using quack_oauth::IHttpClient;
using quack_oauth::JwksCache;
using quack_oauth::ValidateContext;
using quack_oauth::ValidateToken;
using quack_oauth::VerifyOptions;
using quack_oauth::VerifyResult;

namespace {

// Read the entire contents of a file -- used to load fixture transcripts.
// We don't bail with REQUIRE here because the test SHOULD skip cleanly when
// the transcripts don't exist (a fresh check-out before someone runs the
// capture script).
std::optional<std::string> ReadFile(const std::string &path) {
	std::ifstream f(path);
	if (!f.is_open()) {
		return std::nullopt;
	}
	std::stringstream ss;
	ss << f.rdbuf();
	return ss.str();
}

std::optional<picojson::value> ParseJsonFile(const std::string &path) {
	const auto raw = ReadFile(path);
	if (!raw.has_value()) {
		return std::nullopt;
	}
	picojson::value root;
	std::string err;
	picojson::parse(root, raw->begin(), raw->end(), &err);
	if (!err.empty()) {
		return std::nullopt;
	}
	return root;
}

// ReplayHttpClient -- pure-logic IHttpClient that returns canned responses
// keyed by URL. Kept in this test TU so it doesn't sneak into production.
class ReplayHttpClient : public IHttpClient {
public:
	std::map<std::string, Response> get_responses;

	std::optional<Response> Get(std::string_view url) override {
		const auto it = get_responses.find(std::string(url));
		if (it == get_responses.end()) {
			return std::nullopt;
		}
		return it->second;
	}
	std::optional<Response> Post(const PostRequest &) override {
		return std::nullopt;
	}
};

struct EntraFixtures {
	std::string issuer;
	std::string jwks_uri;
	std::string jwks_response_body;
	std::string access_token;
	std::int64_t captured_iat;
	std::int64_t captured_exp;
};

std::optional<EntraFixtures> LoadEntraFixtures() {
	const auto meta = ParseJsonFile("test/integration/transcripts/entra/metadata.json");
	const auto jwks = ParseJsonFile("test/integration/transcripts/entra/jwks.json");
	const auto tok = ParseJsonFile("test/integration/transcripts/entra/token_endpoint.json");
	if (!meta || !jwks || !tok) {
		return std::nullopt;
	}
	const auto &m = meta->get<picojson::object>();
	const auto &j = jwks->get<picojson::object>();
	const auto &t = tok->get<picojson::object>();

	EntraFixtures f;
	f.issuer = m.at("issuer").get<std::string>();
	f.jwks_uri = m.at("jwks_uri").get<std::string>();
	f.captured_iat = m.at("captured_iat").get<std::int64_t>();
	f.captured_exp = m.at("captured_exp").get<std::int64_t>();
	// Serialise the response_body object as JSON so ParseJwksJson sees what
	// the live JWKS endpoint would have returned.
	f.jwks_response_body = j.at("response_body").serialize();
	f.access_token = t.at("response_body").get<picojson::object>().at("access_token").get<std::string>();
	return f;
}

VerifyOptions OptsAtCapture(const EntraFixtures &f) {
	VerifyOptions opts;
	opts.expected_issuer = f.issuer;
	// Audience deliberately left empty -- Entra tokens against Graph carry
	// aud = "00000003-0000-0000-c000-000000000000" (Graph's appID), which
	// is fine but not load-bearing for proving the JWKS path works.
	opts.clock_skew_s = 60;
	// Freeze clock at iat+5s -- inside the 1-hour token lifetime.
	opts.now_s = f.captured_iat + 5;
	opts.allowed_algorithms = {"RS256", "RS384", "RS512"};
	return opts;
}

} // namespace

TEST_CASE("Entra replay: live Entra token validates against captured JWKS", "[entra][replay]") {
	const auto fixtures = LoadEntraFixtures();
	if (!fixtures.has_value()) {
		WARN("Entra transcripts not found under test/integration/transcripts/entra/."
		     " Run ./scripts/capture_entra_transcript.sh once with .env.entra populated.");
		return;
	}

	ReplayHttpClient http;
	http.get_responses[fixtures->jwks_uri] = IHttpClient::Response {200, fixtures->jwks_response_body};

	JwksCache cache(30);
	ValidateContext ctx {http, cache, fixtures->jwks_uri};

	const auto result = ValidateToken(fixtures->access_token, OptsAtCapture(*fixtures), ctx);
	CHECK(result == VerifyResult::Ok);
}

TEST_CASE("Entra replay: tampered signature rejected", "[entra][replay][sig]") {
	const auto fixtures = LoadEntraFixtures();
	if (!fixtures.has_value()) {
		return;
	}
	auto token = fixtures->access_token;
	// Flip a middle character of the signature segment (last `.`-delimited).
	const auto last_dot = token.rfind('.');
	REQUIRE(last_dot != std::string::npos);
	REQUIRE(last_dot + 32 < token.size());
	for (std::size_t i = last_dot + 16; i < last_dot + 24; ++i) {
		token[i] = (token[i] == 'A') ? 'B' : 'A';
	}

	ReplayHttpClient http;
	http.get_responses[fixtures->jwks_uri] = IHttpClient::Response {200, fixtures->jwks_response_body};

	JwksCache cache(30);
	ValidateContext ctx {http, cache, fixtures->jwks_uri};

	const auto result = ValidateToken(token, OptsAtCapture(*fixtures), ctx);
	CHECK(result == VerifyResult::InvalidSignature);
}

TEST_CASE("Entra replay: expired clock rejects the captured token", "[entra][replay][exp]") {
	const auto fixtures = LoadEntraFixtures();
	if (!fixtures.has_value()) {
		return;
	}
	ReplayHttpClient http;
	http.get_responses[fixtures->jwks_uri] = IHttpClient::Response {200, fixtures->jwks_response_body};

	JwksCache cache(30);
	ValidateContext ctx {http, cache, fixtures->jwks_uri};

	auto opts = OptsAtCapture(*fixtures);
	// One hour past the token's exp.
	opts.now_s = fixtures->captured_exp + 3600;

	const auto result = ValidateToken(fixtures->access_token, opts, ctx);
	CHECK(result == VerifyResult::Expired);
}

TEST_CASE("Entra replay: wrong expected_issuer rejects the captured token", "[entra][replay][iss]") {
	const auto fixtures = LoadEntraFixtures();
	if (!fixtures.has_value()) {
		return;
	}
	ReplayHttpClient http;
	http.get_responses[fixtures->jwks_uri] = IHttpClient::Response {200, fixtures->jwks_response_body};

	JwksCache cache(30);
	ValidateContext ctx {http, cache, fixtures->jwks_uri};

	auto opts = OptsAtCapture(*fixtures);
	opts.expected_issuer = "https://login.microsoftonline.com/wrong-tid/v2.0";

	const auto result = ValidateToken(fixtures->access_token, opts, ctx);
	CHECK(result == VerifyResult::WrongIssuer);
}
