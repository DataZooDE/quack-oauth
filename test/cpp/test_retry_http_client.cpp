#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <optional>
#include <string>
#include <vector>

#include "http_client.hpp"
#include "retry_http_client.hpp"

using quack_oauth::IHttpClient;
using quack_oauth::RetryingHttpClient;

namespace {

// Test double: returns a configured sequence of responses (one per call).
struct ScriptedHttpClient : public IHttpClient {
	std::vector<std::optional<Response>> get_script;
	std::vector<std::optional<Response>> post_script;
	std::size_t get_calls = 0;
	std::size_t post_calls = 0;

	std::optional<Response> Get(std::string_view) override {
		REQUIRE(get_calls < get_script.size());
		return get_script[get_calls++];
	}
	std::optional<Response> Post(const PostRequest &) override {
		REQUIRE(post_calls < post_script.size());
		return post_script[post_calls++];
	}
};

struct SleepRecorder {
	std::vector<std::chrono::milliseconds> sleeps;
	void operator()(std::chrono::milliseconds d) {
		sleeps.push_back(d);
	}
};

} // namespace

TEST_CASE("RetryingHttpClient: no retry on 200", "[retry][http]") {
	ScriptedHttpClient inner;
	inner.get_script = {IHttpClient::Response {200, "ok"}};
	SleepRecorder slept;
	RetryingHttpClient client(inner, /*max_retries=*/1, std::chrono::milliseconds(1000), std::ref(slept));
	const auto r = client.Get("https://x");
	REQUIRE(r.has_value());
	CHECK(r->status_code == 200);
	CHECK(inner.get_calls == 1);
	CHECK(slept.sleeps.empty());
}

TEST_CASE("RetryingHttpClient: retries once on 5xx, sleeps 1s, succeeds", "[retry][http]") {
	ScriptedHttpClient inner;
	inner.get_script = {
	    IHttpClient::Response {503, "transient"},
	    IHttpClient::Response {200, "now ok"},
	};
	SleepRecorder slept;
	RetryingHttpClient client(inner, 1, std::chrono::milliseconds(1000), std::ref(slept));
	const auto r = client.Get("https://x");
	REQUIRE(r.has_value());
	CHECK(r->status_code == 200);
	CHECK(inner.get_calls == 2);
	REQUIRE(slept.sleeps.size() == 1);
	CHECK(slept.sleeps[0] == std::chrono::milliseconds(1000));
}

TEST_CASE("RetryingHttpClient: retries on transport failure (nullopt)", "[retry][http]") {
	ScriptedHttpClient inner;
	inner.get_script = {std::nullopt, IHttpClient::Response {200, "ok"}};
	SleepRecorder slept;
	RetryingHttpClient client(inner, 1, std::chrono::milliseconds(1000), std::ref(slept));
	const auto r = client.Get("https://x");
	REQUIRE(r.has_value());
	CHECK(r->status_code == 200);
	CHECK(inner.get_calls == 2);
}

TEST_CASE("RetryingHttpClient: does NOT retry on 4xx (client error)", "[retry][http]") {
	ScriptedHttpClient inner;
	inner.get_script = {IHttpClient::Response {401, "Unauthorized"}};
	SleepRecorder slept;
	RetryingHttpClient client(inner, 1, std::chrono::milliseconds(1000), std::ref(slept));
	const auto r = client.Get("https://x");
	REQUIRE(r.has_value());
	CHECK(r->status_code == 401);
	CHECK(inner.get_calls == 1);
	CHECK(slept.sleeps.empty());
}

TEST_CASE("RetryingHttpClient: after exhausting retries, returns last result", "[retry][http]") {
	ScriptedHttpClient inner;
	inner.get_script = {
	    IHttpClient::Response {502, "first"},
	    IHttpClient::Response {503, "second"},
	};
	SleepRecorder slept;
	RetryingHttpClient client(inner, 1, std::chrono::milliseconds(1000), std::ref(slept));
	const auto r = client.Get("https://x");
	REQUIRE(r.has_value());
	CHECK(r->status_code == 503);
	CHECK(inner.get_calls == 2);
}

TEST_CASE("RetryingHttpClient: with max_retries=2 honours doubling backoff", "[retry][http]") {
	ScriptedHttpClient inner;
	inner.get_script = {
	    std::nullopt,
	    IHttpClient::Response {503, "still bad"},
	    IHttpClient::Response {200, "third time lucky"},
	};
	SleepRecorder slept;
	RetryingHttpClient client(inner, /*max_retries=*/2, std::chrono::milliseconds(1000), std::ref(slept));
	const auto r = client.Get("https://x");
	REQUIRE(r.has_value());
	CHECK(r->status_code == 200);
	CHECK(inner.get_calls == 3);
	REQUIRE(slept.sleeps.size() == 2);
	CHECK(slept.sleeps[0] == std::chrono::milliseconds(1000));
	CHECK(slept.sleeps[1] == std::chrono::milliseconds(2000));
}

TEST_CASE("RetryingHttpClient: Post path uses the same policy", "[retry][http]") {
	ScriptedHttpClient inner;
	inner.post_script = {
	    IHttpClient::Response {500, "boom"},
	    IHttpClient::Response {200, "ok"},
	};
	SleepRecorder slept;
	RetryingHttpClient client(inner, 1, std::chrono::milliseconds(1000), std::ref(slept));
	IHttpClient::PostRequest req;
	req.url = "https://x";
	const auto r = client.Post(req);
	REQUIRE(r.has_value());
	CHECK(r->status_code == 200);
	CHECK(inner.post_calls == 2);
}
