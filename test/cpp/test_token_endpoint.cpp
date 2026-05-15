#include <catch2/catch_test_macros.hpp>

#include "http_client.hpp"
#include "token_endpoint.hpp"

using quack_oauth::AcquireTokenClientCredentials;
using quack_oauth::AcquireTokenRefreshToken;
using quack_oauth::IHttpClient;
using quack_oauth::ParseTokenResponse;
using quack_oauth::TokenResponse;

namespace {

class FakeHttpClient : public IHttpClient {
public:
	std::optional<Response> next_post_response;
	std::optional<PostRequest> last_post;
	std::optional<Response> Get(std::string_view) override { return std::nullopt; }
	std::optional<Response> Post(const PostRequest &r) override {
		last_post = r;
		return next_post_response;
	}
};

} // namespace

TEST_CASE("ParseTokenResponse: full body", "[token-endpoint][parse]") {
	const auto r = ParseTokenResponse(R"({
	  "access_token": "eyJ.access.token",
	  "refresh_token": "eyJ.refresh.token",
	  "token_type": "Bearer",
	  "scope": "openid profile",
	  "expires_in": 3600
	})");
	REQUIRE(r.has_value());
	CHECK(r->access_token == "eyJ.access.token");
	CHECK(r->refresh_token == "eyJ.refresh.token");
	CHECK(r->token_type == "Bearer");
	CHECK(r->scope == "openid profile");
	CHECK(r->expires_in == 3600);
}

TEST_CASE("ParseTokenResponse: minimum (access_token only)", "[token-endpoint][parse]") {
	const auto r = ParseTokenResponse(R"({"access_token": "abc"})");
	REQUIRE(r.has_value());
	CHECK(r->access_token == "abc");
	CHECK(r->expires_in == 0);
	CHECK(r->refresh_token.empty());
}

TEST_CASE("ParseTokenResponse: missing access_token is malformed",
          "[token-endpoint][parse][error]") {
	CHECK_FALSE(ParseTokenResponse(R"({"token_type": "Bearer"})").has_value());
	CHECK_FALSE(ParseTokenResponse(R"({"access_token": ""})").has_value());
}

TEST_CASE("ParseTokenResponse: error responses are nullopt",
          "[token-endpoint][parse][error]") {
	// RFC 6749 §5.2 error response. We treat it as parse-failure -- the caller
	// only cares about success vs not-success.
	CHECK_FALSE(ParseTokenResponse(R"({"error": "invalid_client"})").has_value());
}

TEST_CASE("ParseTokenResponse: malformed JSON", "[token-endpoint][parse][error]") {
	CHECK_FALSE(ParseTokenResponse("").has_value());
	CHECK_FALSE(ParseTokenResponse("not json").has_value());
	CHECK_FALSE(ParseTokenResponse("[]").has_value());
}

TEST_CASE("AcquireTokenClientCredentials: happy path POSTs form body + Basic auth",
          "[token-endpoint][http]") {
	FakeHttpClient http;
	http.next_post_response = IHttpClient::Response{
	    200,
	    R"({"access_token": "the-token", "token_type": "Bearer", "expires_in": 600})"};
	const auto r = AcquireTokenClientCredentials(
	    http, "https://idp.test/token", "client-1", "secret-1", "api:read");
	REQUIRE(r.has_value());
	CHECK(r->access_token == "the-token");
	CHECK(r->expires_in == 600);
	REQUIRE(http.last_post.has_value());
	CHECK(http.last_post->url == "https://idp.test/token");
	CHECK(http.last_post->content_type == "application/x-www-form-urlencoded");
	CHECK(http.last_post->body == "grant_type=client_credentials&scope=api%3Aread");
	CHECK(http.last_post->basic_user == "client-1");
	CHECK(http.last_post->basic_pass == "secret-1");
}

TEST_CASE("AcquireTokenClientCredentials: empty scope is omitted from body",
          "[token-endpoint][http]") {
	FakeHttpClient http;
	http.next_post_response =
	    IHttpClient::Response{200, R"({"access_token": "t"})"};
	AcquireTokenClientCredentials(http, "https://idp.test/token", "c", "s", "");
	REQUIRE(http.last_post.has_value());
	CHECK(http.last_post->body == "grant_type=client_credentials");
}

TEST_CASE("AcquireTokenClientCredentials: transport error → nullopt",
          "[token-endpoint][http][error]") {
	FakeHttpClient http;
	http.next_post_response = std::nullopt;
	CHECK_FALSE(AcquireTokenClientCredentials(http, "https://idp.test/x", "c", "s", "")
	                .has_value());
}

TEST_CASE("AcquireTokenClientCredentials: 401 → nullopt",
          "[token-endpoint][http][error]") {
	FakeHttpClient http;
	http.next_post_response = IHttpClient::Response{
	    401, R"({"error": "invalid_client"})"};
	CHECK_FALSE(AcquireTokenClientCredentials(http, "https://idp.test/x", "c", "s", "")
	                .has_value());
}

TEST_CASE("AcquireTokenClientCredentials: empty endpoint / client_id short-circuit",
          "[token-endpoint][http]") {
	FakeHttpClient http;
	CHECK_FALSE(AcquireTokenClientCredentials(http, "", "c", "s", "").has_value());
	CHECK_FALSE(
	    AcquireTokenClientCredentials(http, "https://idp.test/x", "", "s", "")
	        .has_value());
	CHECK_FALSE(http.last_post.has_value());
}

TEST_CASE("AcquireTokenRefreshToken: happy path posts grant_type=refresh_token",
          "[token-endpoint][refresh]") {
	FakeHttpClient http;
	http.next_post_response = IHttpClient::Response{
	    200,
	    R"({"access_token": "new-at", "refresh_token": "new-rt", "expires_in": 600, "token_type": "Bearer"})"};
	const auto r = AcquireTokenRefreshToken(
	    http, "https://idp.test/token", "c", "s", "old-refresh-token", "");
	REQUIRE(r.has_value());
	CHECK(r->access_token == "new-at");
	CHECK(r->refresh_token == "new-rt");
	CHECK(r->expires_in == 600);
	REQUIRE(http.last_post.has_value());
	CHECK(http.last_post->basic_user == "c");
	CHECK(http.last_post->basic_pass == "s");
	// Body contains grant_type, the refresh_token (URL-encoded), and the
	// client_id (some IdPs require it even with Basic auth).
	CHECK(http.last_post->body.find("grant_type=refresh_token") != std::string::npos);
	CHECK(http.last_post->body.find("refresh_token=old-refresh-token") != std::string::npos);
	CHECK(http.last_post->body.find("client_id=c") != std::string::npos);
}

TEST_CASE("AcquireTokenRefreshToken: public client (no secret) omits Basic auth",
          "[token-endpoint][refresh]") {
	FakeHttpClient http;
	http.next_post_response = IHttpClient::Response{
	    200, R"({"access_token": "x", "token_type": "Bearer"})"};
	AcquireTokenRefreshToken(http, "https://idp.test/token", "public-client",
	                         /*client_secret=*/"", "rt", "");
	REQUIRE(http.last_post.has_value());
	CHECK(http.last_post->basic_user.empty());
	CHECK(http.last_post->basic_pass.empty());
	// client_id still appears in the body -- mandatory for public clients
	// per RFC 6749 §3.2.1.
	CHECK(http.last_post->body.find("client_id=public-client") != std::string::npos);
}

TEST_CASE("AcquireTokenRefreshToken: scope is optional and URL-encoded",
          "[token-endpoint][refresh]") {
	FakeHttpClient http;
	http.next_post_response = IHttpClient::Response{
	    200, R"({"access_token": "x"})"};
	AcquireTokenRefreshToken(http, "https://idp.test/x", "c", "s", "rt",
	                         "openid api:read");
	REQUIRE(http.last_post.has_value());
	CHECK(http.last_post->body.find("scope=openid%20api%3Aread") != std::string::npos);
}

TEST_CASE("AcquireTokenRefreshToken: empty endpoint / refresh_token short-circuit",
          "[token-endpoint][refresh]") {
	FakeHttpClient http;
	CHECK_FALSE(AcquireTokenRefreshToken(http, "", "c", "s", "rt", "").has_value());
	CHECK_FALSE(AcquireTokenRefreshToken(http, "https://idp.test/x", "c", "s", "", "")
	                .has_value());
	CHECK_FALSE(http.last_post.has_value());
}

TEST_CASE("AcquireTokenRefreshToken: non-200 → nullopt", "[token-endpoint][refresh]") {
	FakeHttpClient http;
	http.next_post_response = IHttpClient::Response{
	    400, R"({"error": "invalid_grant", "error_description": "Token is not active"})"};
	CHECK_FALSE(AcquireTokenRefreshToken(http, "https://idp.test/x", "c", "s", "rt", "")
	                .has_value());
}

TEST_CASE("AcquireTokenRefreshToken: response that omits a new refresh_token works",
          "[token-endpoint][refresh]") {
	// Some IdPs don't rotate refresh_tokens. The caller keeps using the
	// original one in that case.
	FakeHttpClient http;
	http.next_post_response = IHttpClient::Response{
	    200, R"({"access_token": "new-at", "expires_in": 600})"};
	const auto r = AcquireTokenRefreshToken(
	    http, "https://idp.test/x", "c", "s", "rt", "");
	REQUIRE(r.has_value());
	CHECK(r->access_token == "new-at");
	CHECK(r->refresh_token.empty()); // caller falls back to the original
}
