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
#include "tokeninfo.hpp"

using quack_oauth::IHttpClient;
using quack_oauth::ParseTokeninfoResponse;
using quack_oauth::QueryTokeninfo;
using quack_oauth::TokeninfoResponse;

namespace {

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

// Replay HTTP client keyed by POST URL. Get is not used by tokeninfo.
class ReplayHttpClient : public IHttpClient {
public:
	std::map<std::string, Response> post_responses;
	std::optional<PostRequest> last_post;

	std::optional<Response> Get(std::string_view) override { return std::nullopt; }
	std::optional<Response> Post(const PostRequest &req) override {
		last_post = req;
		const auto it = post_responses.find(req.url);
		if (it == post_responses.end()) {
			return std::nullopt;
		}
		return it->second;
	}
};

struct GoogleFixtures {
	std::string tokeninfo_endpoint;
	std::string tokeninfo_response_body;
	std::string access_token;
	std::int64_t tokeninfo_exp;
	std::string tokeninfo_aud;
	std::string tokeninfo_azp;
	std::string tokeninfo_scope;
};

std::optional<GoogleFixtures> LoadGoogleFixtures() {
	const auto meta = ParseJsonFile("test/integration/transcripts/google/metadata.json");
	const auto ti = ParseJsonFile("test/integration/transcripts/google/tokeninfo.json");
	const auto tok = ParseJsonFile("test/integration/transcripts/google/token_endpoint.json");
	if (!meta || !ti || !tok) {
		return std::nullopt;
	}
	const auto &m = meta->get<picojson::object>();
	const auto &t = ti->get<picojson::object>();
	const auto &k = tok->get<picojson::object>();

	GoogleFixtures f;
	f.tokeninfo_endpoint = m.at("tokeninfo_endpoint").get<std::string>();
	f.tokeninfo_exp = m.at("tokeninfo_exp").get<std::int64_t>();
	f.tokeninfo_aud = m.at("tokeninfo_aud").get<std::string>();
	f.tokeninfo_azp = m.at("tokeninfo_azp").get<std::string>();
	f.tokeninfo_scope = m.at("tokeninfo_scope").get<std::string>();
	f.tokeninfo_response_body = t.at("response_body").serialize();
	f.access_token =
	    k.at("response_body").get<picojson::object>().at("access_token").get<std::string>();
	return f;
}

} // namespace

TEST_CASE("Google: ParseTokeninfoResponse handles Google's number-as-string quirk",
          "[google][parse]") {
	// `exp` and `expires_in` are strings -- the canonical Google quirk.
	const auto r = ParseTokeninfoResponse(R"({
	  "azp": "12345.apps.googleusercontent.com",
	  "aud": "12345.apps.googleusercontent.com",
	  "scope": "openid email",
	  "exp": "1735689600",
	  "expires_in": "3599",
	  "email": "alice@example.com",
	  "email_verified": "true",
	  "access_type": "online"
	})", /*active=*/true);
	REQUIRE(r.has_value());
	CHECK(r->active);
	CHECK(r->azp == "12345.apps.googleusercontent.com");
	CHECK(r->aud == "12345.apps.googleusercontent.com");
	CHECK(r->scope == "openid email");
	CHECK(r->exp == 1735689600);
	CHECK(r->expires_in == 3599);
	CHECK(r->email == "alice@example.com");
	CHECK(r->email_verified == true);
}

TEST_CASE("Google: ParseTokeninfoResponse tolerates absent `sub` (service-account tokens)",
          "[google][parse]") {
	const auto r = ParseTokeninfoResponse(R"({
	  "azp": "105406064300261473362",
	  "aud": "105406064300261473362",
	  "scope": "https://www.googleapis.com/auth/cloud-platform.read-only"
	})", /*active=*/true);
	REQUIRE(r.has_value());
	CHECK(r->subject.empty());
}

TEST_CASE("Google: ParseTokeninfoResponse: empty / non-JSON → nullopt",
          "[google][parse][error]") {
	CHECK_FALSE(ParseTokeninfoResponse("", true).has_value());
	CHECK_FALSE(ParseTokeninfoResponse("not json", true).has_value());
	CHECK_FALSE(ParseTokeninfoResponse("[]", true).has_value());
}

TEST_CASE("Google: ParseTokeninfoResponse: also tolerates int-shaped exp",
          "[google][parse]") {
	// If Google ever fixes the string-quoting quirk, our parser still works.
	const auto r = ParseTokeninfoResponse(R"({
	  "azp": "x", "aud": "x", "exp": 1735689600, "expires_in": 3599
	})", /*active=*/true);
	REQUIRE(r.has_value());
	CHECK(r->exp == 1735689600);
	CHECK(r->expires_in == 3599);
}

TEST_CASE("Google: QueryTokeninfo POSTs with access_token in body",
          "[google][http]") {
	ReplayHttpClient http;
	http.post_responses["https://oauth2.googleapis.com/tokeninfo"] =
	    IHttpClient::Response{200, R"({"azp": "abc", "aud": "abc"})"};

	const auto r = QueryTokeninfo(http, "https://oauth2.googleapis.com/tokeninfo",
	                              "the-opaque-token");
	REQUIRE(r.has_value());
	CHECK(r->active);
	CHECK(r->azp == "abc");
	REQUIRE(http.last_post.has_value());
	CHECK(http.last_post->body == "access_token=the-opaque-token");
	CHECK(http.last_post->content_type == "application/x-www-form-urlencoded");
	// Tokeninfo is unauthenticated -- NO Basic auth header.
	CHECK(http.last_post->basic_user.empty());
	CHECK(http.last_post->basic_pass.empty());
}

TEST_CASE("Google: QueryTokeninfo: HTTP 400 surfaces as active=false",
          "[google][http]") {
	ReplayHttpClient http;
	http.post_responses["https://oauth2.googleapis.com/tokeninfo"] =
	    IHttpClient::Response{400, R"({"error_description": "Invalid Value"})"};

	const auto r = QueryTokeninfo(http, "https://oauth2.googleapis.com/tokeninfo",
	                              "revoked-token");
	REQUIRE(r.has_value());
	CHECK_FALSE(r->active);
}

TEST_CASE("Google: QueryTokeninfo: transport error → nullopt",
          "[google][http][error]") {
	ReplayHttpClient http;
	// no response configured
	CHECK_FALSE(QueryTokeninfo(http, "https://oauth2.googleapis.com/tokeninfo", "t")
	                .has_value());
}

TEST_CASE("Google: QueryTokeninfo: empty endpoint / token short-circuits",
          "[google][http]") {
	ReplayHttpClient http;
	CHECK_FALSE(QueryTokeninfo(http, "", "t").has_value());
	CHECK_FALSE(QueryTokeninfo(http, "https://oauth2.googleapis.com/tokeninfo", "")
	                .has_value());
	CHECK_FALSE(http.last_post.has_value());
}

TEST_CASE("Google replay: live tokeninfo response from a real service-account flow",
          "[google][replay]") {
	const auto fixtures = LoadGoogleFixtures();
	if (!fixtures.has_value()) {
		WARN("Google transcripts not found. Run ./scripts/capture_google_transcript.sh");
		return;
	}

	ReplayHttpClient http;
	http.post_responses[fixtures->tokeninfo_endpoint] =
	    IHttpClient::Response{200, fixtures->tokeninfo_response_body};

	const auto r = QueryTokeninfo(http, fixtures->tokeninfo_endpoint,
	                              fixtures->access_token);
	REQUIRE(r.has_value());
	CHECK(r->active);
	CHECK(r->azp == fixtures->tokeninfo_azp);
	CHECK(r->aud == fixtures->tokeninfo_aud);
	CHECK(r->scope == fixtures->tokeninfo_scope);
	CHECK(r->exp == fixtures->tokeninfo_exp);
}

TEST_CASE("Google replay: request shape matches what Google's tokeninfo expects",
          "[google][replay]") {
	const auto fixtures = LoadGoogleFixtures();
	if (!fixtures.has_value()) {
		return;
	}
	ReplayHttpClient http;
	http.post_responses[fixtures->tokeninfo_endpoint] =
	    IHttpClient::Response{200, fixtures->tokeninfo_response_body};
	QueryTokeninfo(http, fixtures->tokeninfo_endpoint, fixtures->access_token);

	REQUIRE(http.last_post.has_value());
	CHECK(http.last_post->url == fixtures->tokeninfo_endpoint);
	// access_token in the body, URL-encoded if needed.
	CHECK(http.last_post->body.rfind("access_token=", 0) == 0);
	// No HTTP Basic auth on the tokeninfo endpoint -- Google rejects it.
	CHECK(http.last_post->basic_user.empty());
}
