#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>

#include "http_client.hpp"
#include "introspect.hpp"

using quack_oauth::IHttpClient;
using quack_oauth::IntrospectionResponse;
using quack_oauth::IntrospectToken;
using quack_oauth::ParseIntrospectionResponse;

namespace {

class FakeHttpClient : public IHttpClient {
public:
	int get_calls = 0;
	int post_calls = 0;
	std::optional<Response> next_post_response;
	std::optional<PostRequest> last_post;

	std::optional<Response> Get(std::string_view) override {
		++get_calls;
		return std::nullopt;
	}
	std::optional<Response> Post(const PostRequest &req) override {
		++post_calls;
		last_post = req;
		return next_post_response;
	}
};

} // namespace

TEST_CASE("ParseIntrospectionResponse: active=true with full claim set", "[introspect][parse]") {
	const auto r = ParseIntrospectionResponse(R"({
	  "active": true,
	  "sub": "alice",
	  "iss": "https://idp.test",
	  "aud": "api://quack",
	  "scope": "openid profile",
	  "client_id": "quack-client",
	  "username": "alice",
	  "exp": 1735689600,
	  "iat": 1735686000,
	  "nbf": 1735685940
	})");
	REQUIRE(r.has_value());
	CHECK(r->active);
	CHECK(r->subject == "alice");
	CHECK(r->issuer == "https://idp.test");
	REQUIRE(r->audience.size() == 1);
	CHECK(r->audience[0] == "api://quack");
	CHECK(r->scope == "openid profile");
	CHECK(r->client_id == "quack-client");
	CHECK(r->username == "alice");
	CHECK(r->exp == 1735689600);
	CHECK(r->iat == 1735686000);
	CHECK(r->nbf == 1735685940);
}

TEST_CASE("ParseIntrospectionResponse: active=false stays parseable", "[introspect][parse]") {
	const auto r = ParseIntrospectionResponse(R"({"active": false})");
	REQUIRE(r.has_value());
	CHECK_FALSE(r->active);
	CHECK(r->subject.empty());
}

TEST_CASE("ParseIntrospectionResponse: array-shaped audience (Entra)", "[introspect][parse][aud]") {
	const auto r = ParseIntrospectionResponse(R"({
	  "active": true,
	  "aud": ["api://quack", "api://other"]
	})");
	REQUIRE(r.has_value());
	REQUIRE(r->audience.size() == 2);
	CHECK(r->audience[0] == "api://quack");
	CHECK(r->audience[1] == "api://other");
}

TEST_CASE("ParseIntrospectionResponse: scp[] array (Entra)", "[introspect][parse][scope]") {
	const auto r = ParseIntrospectionResponse(R"({
	  "active": true,
	  "scp": ["quack.read", "quack.write"]
	})");
	REQUIRE(r.has_value());
	REQUIRE(r->scp.size() == 2);
	CHECK(r->scp[0] == "quack.read");
	CHECK(r->scp[1] == "quack.write");
}

TEST_CASE("ParseIntrospectionResponse: missing `active` is malformed", "[introspect][parse][error]") {
	CHECK_FALSE(ParseIntrospectionResponse(R"({"sub": "alice"})").has_value());
	CHECK_FALSE(ParseIntrospectionResponse(R"({"active": "yes"})").has_value());
}

TEST_CASE("ParseIntrospectionResponse: malformed JSON / empty", "[introspect][parse][error]") {
	CHECK_FALSE(ParseIntrospectionResponse("").has_value());
	CHECK_FALSE(ParseIntrospectionResponse("not json").has_value());
	CHECK_FALSE(ParseIntrospectionResponse("[]").has_value());
}

TEST_CASE("IntrospectToken: happy path POSTs with form body + Basic auth", "[introspect][http]") {
	FakeHttpClient http;
	http.next_post_response = IHttpClient::Response {200, R"({"active": true, "sub": "alice"})"};

	const auto r = IntrospectToken(http, "https://idp.test/introspect", "quack-client", "shh", "raw.token.value");
	REQUIRE(r.has_value());
	CHECK(r->active);
	CHECK(r->subject == "alice");
	REQUIRE(http.last_post.has_value());
	CHECK(http.last_post->url == "https://idp.test/introspect");
	CHECK(http.last_post->content_type == "application/x-www-form-urlencoded");
	CHECK(http.last_post->basic_user == "quack-client");
	CHECK(http.last_post->basic_pass == "shh");
	// Body is `token=<urlencoded>&token_type_hint=access_token`. The dots in
	// our test token are unreserved per RFC 3986 -- pass through.
	CHECK(http.last_post->body == "token=raw.token.value&token_type_hint=access_token");
}

TEST_CASE("IntrospectToken: URL-encodes tokens that contain reserved chars", "[introspect][http]") {
	FakeHttpClient http;
	http.next_post_response = IHttpClient::Response {200, R"({"active": false})"};

	IntrospectToken(http, "https://idp.test/introspect", "c", "s", "weird+token/with=chars");
	REQUIRE(http.last_post.has_value());
	// `+`, `/`, `=` MUST be percent-encoded -- form values aren't URL-safe.
	CHECK(http.last_post->body.find("weird%2Btoken%2Fwith%3Dchars") != std::string::npos);
}

TEST_CASE("IntrospectToken: transport error returns nullopt", "[introspect][http][error]") {
	FakeHttpClient http;
	http.next_post_response = std::nullopt;
	CHECK_FALSE(IntrospectToken(http, "https://idp.test/x", "c", "s", "t").has_value());
}

TEST_CASE("IntrospectToken: non-200 HTTP returns nullopt", "[introspect][http][error]") {
	FakeHttpClient http;
	http.next_post_response = IHttpClient::Response {401, "Unauthorized"};
	CHECK_FALSE(IntrospectToken(http, "https://idp.test/x", "c", "s", "t").has_value());

	http.next_post_response = IHttpClient::Response {500, "oops"};
	CHECK_FALSE(IntrospectToken(http, "https://idp.test/x", "c", "s", "t").has_value());
}

TEST_CASE("IntrospectToken: 200 with malformed body returns nullopt", "[introspect][http][error]") {
	FakeHttpClient http;
	http.next_post_response = IHttpClient::Response {200, "not json"};
	CHECK_FALSE(IntrospectToken(http, "https://idp.test/x", "c", "s", "t").has_value());
}

TEST_CASE("IntrospectToken: empty endpoint or token short-circuits without HTTP", "[introspect][http]") {
	FakeHttpClient http;
	CHECK_FALSE(IntrospectToken(http, "", "c", "s", "t").has_value());
	CHECK_FALSE(IntrospectToken(http, "https://idp.test/x", "c", "s", "").has_value());
	CHECK(http.post_calls == 0);
}

TEST_CASE("IntrospectToken: active=false is surfaced as a populated Response", "[introspect][http]") {
	// Distinguishing "definitively inactive" (POST succeeded, IdP said no)
	// from "couldn't ask" (transport error / 5xx) matters for diagnostics:
	// the caller can decide to log differently.
	FakeHttpClient http;
	http.next_post_response = IHttpClient::Response {200, R"({"active": false})"};
	const auto r = IntrospectToken(http, "https://idp.test/x", "c", "s", "t");
	REQUIRE(r.has_value());
	CHECK_FALSE(r->active);
}
