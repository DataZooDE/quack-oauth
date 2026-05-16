#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include "decision_cache.hpp"
#include "github_check.hpp"
#include "http_client.hpp"
#include "jwt_verify.hpp"

using quack_oauth::DecisionCache;
using quack_oauth::GithubContext;
using quack_oauth::IHttpClient;
using quack_oauth::ParseGithubCheckResponse;
using quack_oauth::Principal;
using quack_oauth::ValidateTokenViaGithubCheck;
using quack_oauth::VerifyOptions;
using quack_oauth::VerifyResult;

namespace {

// FakeHttpClient that records the last POST and returns a canned response.
struct FakeHttp : public IHttpClient {
	std::optional<Response> next_get;
	std::optional<Response> next_post;
	PostRequest last_post;
	int post_calls = 0;

	std::optional<Response> Get(std::string_view) override {
		return next_get;
	}
	std::optional<Response> Post(const PostRequest &req) override {
		++post_calls;
		last_post = req;
		return next_post;
	}
};

// Minimal sample of the documented GitHub response shape.
constexpr const char *kHappyResponse = R"({
  "id": 1,
  "scopes": ["repo", "read:org"],
  "token": "gho_redacted",
  "user": {
    "id": 5645645,
    "login": "octocat",
    "email": "octocat@github.com"
  },
  "expires_at": "2026-12-31T00:00:00Z"
})";

} // namespace

TEST_CASE("ParseGithubCheckResponse: happy path extracts sub/login/scopes/email", "[github]") {
	const auto p = ParseGithubCheckResponse(kHappyResponse);
	REQUIRE(p.has_value());
	CHECK(p->subject == "gh:5645645");
	// scopes are space-split into the principal's scope vector
	CHECK(std::find(p->scopes.begin(), p->scopes.end(), "repo") != p->scopes.end());
	CHECK(std::find(p->scopes.begin(), p->scopes.end(), "read:org") != p->scopes.end());
}

TEST_CASE("ParseGithubCheckResponse: missing user.id returns nullopt", "[github][error]") {
	const auto p = ParseGithubCheckResponse(R"({"scopes": ["repo"]})");
	CHECK_FALSE(p.has_value());
}

TEST_CASE("ParseGithubCheckResponse: malformed JSON returns nullopt", "[github][error]") {
	CHECK_FALSE(ParseGithubCheckResponse("not json").has_value());
	CHECK_FALSE(ParseGithubCheckResponse("").has_value());
}

TEST_CASE("ValidateTokenViaGithubCheck: 200 OK populates Principal", "[github]") {
	FakeHttp http;
	http.next_post = IHttpClient::Response {200, kHappyResponse};
	DecisionCache cache(64, 30);
	VerifyOptions opts;
	opts.now_s = 1000;
	GithubContext ctx {http, cache, "https://api.github.com/applications/Iv1.client/token", "Iv1.client",
	                   "github_app_secret"};

	Principal out;
	const auto r = ValidateTokenViaGithubCheck("gho_xyz", opts, ctx, &out);
	CHECK(r == VerifyResult::Ok);
	CHECK(out.subject == "gh:5645645");

	// Body must be JSON with the access_token in it.
	CHECK(http.last_post.body.find("access_token") != std::string::npos);
	CHECK(http.last_post.body.find("gho_xyz") != std::string::npos);
	CHECK(http.last_post.content_type == "application/json");
	// HTTP Basic with client_id:client_secret.
	CHECK(http.last_post.basic_user == "Iv1.client");
	CHECK(http.last_post.basic_pass == "github_app_secret");

	// Second call hits the decision cache -- no additional POST.
	const int posts_before = http.post_calls;
	const auto r2 = ValidateTokenViaGithubCheck("gho_xyz", opts, ctx, &out);
	CHECK(r2 == VerifyResult::Ok);
	CHECK(http.post_calls == posts_before);
}

TEST_CASE("ValidateTokenViaGithubCheck: 404 -> token invalid", "[github]") {
	FakeHttp http;
	http.next_post = IHttpClient::Response {404, R"({"message": "Not Found"})"};
	DecisionCache cache(64, 30);
	VerifyOptions opts;
	opts.now_s = 1000;
	GithubContext ctx {http, cache, "https://api.github.com/applications/Iv1.client/token", "Iv1.client",
	                   "github_app_secret"};

	const auto r = ValidateTokenViaGithubCheck("not-a-real-token", opts, ctx, nullptr);
	CHECK(r == VerifyResult::InvalidSignature);

	// Negative outcomes are never cached -- a re-issued token after
	// revocation must surface, so the next call re-POSTs.
	const int posts_before = http.post_calls;
	const auto r2 = ValidateTokenViaGithubCheck("not-a-real-token", opts, ctx, nullptr);
	CHECK(r2 == VerifyResult::InvalidSignature);
	CHECK(http.post_calls == posts_before + 1);
}

TEST_CASE("ValidateTokenViaGithubCheck: 401/403 -> JwksFetchFailed (operator config error)", "[github]") {
	// 401 / 403 from GitHub means the App's introspect_client_id /
	// introspect_client_secret are wrong -- an operator-side
	// configuration bug, not a token-level rejection. Surfacing it as
	// JwksFetchFailed (audit reason `jwks_fetch_failed`) points the
	// operator at their App credentials, matching the introspect
	// path's handling of the same failure mode.
	FakeHttp http;
	DecisionCache cache(64, 30);
	VerifyOptions opts;
	opts.now_s = 1000;
	GithubContext ctx {http, cache, "https://api.github.com/applications/c/token", "c", "s"};

	http.next_post = IHttpClient::Response {401, ""};
	CHECK(ValidateTokenViaGithubCheck("t1", opts, ctx, nullptr) == VerifyResult::JwksFetchFailed);

	http.next_post = IHttpClient::Response {403, ""};
	CHECK(ValidateTokenViaGithubCheck("t2", opts, ctx, nullptr) == VerifyResult::JwksFetchFailed);
}

TEST_CASE("ValidateTokenViaGithubCheck: 5xx -> JwksFetchFailed (retry hint)", "[github]") {
	FakeHttp http;
	http.next_post = IHttpClient::Response {503, ""};
	DecisionCache cache(64, 30);
	VerifyOptions opts;
	opts.now_s = 1000;
	GithubContext ctx {http, cache, "https://api.github.com/applications/c/token", "c", "s"};
	CHECK(ValidateTokenViaGithubCheck("t", opts, ctx, nullptr) == VerifyResult::JwksFetchFailed);
}

TEST_CASE("ValidateTokenViaGithubCheck: transport failure -> JwksFetchFailed", "[github]") {
	FakeHttp http;
	http.next_post = std::nullopt;
	DecisionCache cache(64, 30);
	VerifyOptions opts;
	opts.now_s = 1000;
	GithubContext ctx {http, cache, "https://api.github.com/applications/c/token", "c", "s"};
	CHECK(ValidateTokenViaGithubCheck("t", opts, ctx, nullptr) == VerifyResult::JwksFetchFailed);
}

TEST_CASE("ValidateTokenViaGithubCheck: empty token -> Malformed without HTTP", "[github]") {
	FakeHttp http;
	DecisionCache cache(64, 30);
	VerifyOptions opts;
	opts.now_s = 1000;
	GithubContext ctx {http, cache, "https://api.github.com/applications/c/token", "c", "s"};
	CHECK(ValidateTokenViaGithubCheck("", opts, ctx, nullptr) == VerifyResult::Malformed);
	CHECK(http.post_calls == 0);
}
