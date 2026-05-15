#include <catch2/catch_test_macros.hpp>

#include <queue>

#include "device_code.hpp"
#include "http_client.hpp"

using quack_oauth::DeviceAuthorizationResponse;
using quack_oauth::DevicePollOutcome;
using quack_oauth::DevicePollResult;
using quack_oauth::IHttpClient;
using quack_oauth::ParseDeviceAuthorizationResponse;
using quack_oauth::ParseDevicePollResponse;
using quack_oauth::PollDeviceTokenEndpoint;
using quack_oauth::RequestDeviceAuthorization;

namespace {

class FakeHttpClient : public IHttpClient {
public:
	std::queue<Response> next_responses;
	std::optional<PostRequest> last_post;
	std::optional<Response> Get(std::string_view) override {
		return std::nullopt;
	}
	std::optional<Response> Post(const PostRequest &r) override {
		last_post = r;
		if (next_responses.empty())
			return std::nullopt;
		auto out = next_responses.front();
		next_responses.pop();
		return out;
	}
};

} // namespace

TEST_CASE("ParseDeviceAuthorizationResponse: full body", "[device-code][parse]") {
	const auto r = ParseDeviceAuthorizationResponse(R"({
	  "device_code": "DC-abc-123",
	  "user_code": "WGYJ-NBCM",
	  "verification_uri": "https://idp.test/device",
	  "verification_uri_complete": "https://idp.test/device?code=WGYJ-NBCM",
	  "expires_in": 600,
	  "interval": 5
	})");
	REQUIRE(r.has_value());
	CHECK(r->device_code == "DC-abc-123");
	CHECK(r->user_code == "WGYJ-NBCM");
	CHECK(r->verification_uri == "https://idp.test/device");
	CHECK(r->verification_uri_complete == "https://idp.test/device?code=WGYJ-NBCM");
	CHECK(r->expires_in == 600);
	CHECK(r->interval == 5);
}

TEST_CASE("ParseDeviceAuthorizationResponse: missing required fields → nullopt", "[device-code][parse][error]") {
	CHECK_FALSE(ParseDeviceAuthorizationResponse(R"({"device_code": "x", "user_code": "y"})").has_value());
	CHECK_FALSE(ParseDeviceAuthorizationResponse(R"({"user_code": "y", "verification_uri": "z"})").has_value());
	CHECK_FALSE(ParseDeviceAuthorizationResponse("not json").has_value());
}

TEST_CASE("ParseDeviceAuthorizationResponse: defaults interval to 5s", "[device-code][parse]") {
	const auto r = ParseDeviceAuthorizationResponse(R"({
	  "device_code": "x", "user_code": "y", "verification_uri": "z",
	  "expires_in": 600
	})");
	REQUIRE(r.has_value());
	CHECK(r->interval == 5);
}

TEST_CASE("ParseDevicePollResponse: 200 with valid body → Success + tokens", "[device-code][poll]") {
	const auto r = ParseDevicePollResponse(200, R"({"access_token": "AT", "expires_in": 3600})");
	CHECK(r.outcome == DevicePollOutcome::Success);
	REQUIRE(r.tokens.has_value());
	CHECK(r.tokens->access_token == "AT");
	CHECK(r.tokens->expires_in == 3600);
}

TEST_CASE("ParseDevicePollResponse: maps each RFC 8628 error code correctly", "[device-code][poll]") {
	CHECK(ParseDevicePollResponse(400, R"({"error": "authorization_pending"})").outcome == DevicePollOutcome::Pending);
	CHECK(ParseDevicePollResponse(400, R"({"error": "slow_down"})").outcome == DevicePollOutcome::SlowDown);
	CHECK(ParseDevicePollResponse(400, R"({"error": "access_denied"})").outcome == DevicePollOutcome::Denied);
	CHECK(ParseDevicePollResponse(400, R"({"error": "expired_token"})").outcome == DevicePollOutcome::Expired);
	CHECK(ParseDevicePollResponse(400, R"({"error": "invalid_grant"})").outcome == DevicePollOutcome::Error);
	CHECK(ParseDevicePollResponse(500, "").outcome == DevicePollOutcome::Error);
}

TEST_CASE("ParseDevicePollResponse: 200 with junk body → Error", "[device-code][poll][error]") {
	const auto r = ParseDevicePollResponse(200, "not json");
	CHECK(r.outcome == DevicePollOutcome::Error);
	CHECK_FALSE(r.tokens.has_value());
}

TEST_CASE("RequestDeviceAuthorization: happy path POSTs client_id + scope", "[device-code][http]") {
	FakeHttpClient http;
	http.next_responses.push(IHttpClient::Response {200, R"({"device_code": "DC", "user_code": "UC",
	            "verification_uri": "https://idp.test/d",
	            "expires_in": 600, "interval": 5})"});
	const auto r = RequestDeviceAuthorization(http, "https://idp.test/device", "the-client", "", "openid");
	REQUIRE(r.has_value());
	CHECK(r->device_code == "DC");
	REQUIRE(http.last_post.has_value());
	CHECK(http.last_post->url == "https://idp.test/device");
	CHECK(http.last_post->body == "client_id=the-client&scope=openid");
}

TEST_CASE("RequestDeviceAuthorization: confidential client adds Basic auth", "[device-code][http]") {
	FakeHttpClient http;
	http.next_responses.push(IHttpClient::Response {200, R"({"device_code": "DC", "user_code": "UC",
	            "verification_uri": "https://idp.test/d"})"});
	RequestDeviceAuthorization(http, "https://idp.test/device", "c", "s", "");
	REQUIRE(http.last_post.has_value());
	CHECK(http.last_post->basic_user == "c");
	CHECK(http.last_post->basic_pass == "s");
}

TEST_CASE("PollDeviceTokenEndpoint: body shape (urn grant + device_code)", "[device-code][http]") {
	FakeHttpClient http;
	http.next_responses.push(IHttpClient::Response {400, R"({"error": "authorization_pending"})"});
	const auto r = PollDeviceTokenEndpoint(http, "https://idp.test/token", "c", "", "DC-xyz");
	CHECK(r.outcome == DevicePollOutcome::Pending);
	REQUIRE(http.last_post.has_value());
	CHECK(http.last_post->body.find("grant_type=urn:ietf:params:oauth:grant-type:device_code") != std::string::npos);
	CHECK(http.last_post->body.find("device_code=DC-xyz") != std::string::npos);
	CHECK(http.last_post->body.find("client_id=c") != std::string::npos);
}

TEST_CASE("PollDeviceTokenEndpoint: simulated full polling loop", "[device-code][http]") {
	// Simulates: pending → pending → slow_down → success.
	FakeHttpClient http;
	http.next_responses.push(IHttpClient::Response {400, R"({"error": "authorization_pending"})"});
	http.next_responses.push(IHttpClient::Response {400, R"({"error": "authorization_pending"})"});
	http.next_responses.push(IHttpClient::Response {400, R"({"error": "slow_down"})"});
	http.next_responses.push(
	    IHttpClient::Response {200, R"({"access_token": "AT", "refresh_token": "RT", "expires_in": 3600})"});

	auto step = [&]() {
		return PollDeviceTokenEndpoint(http, "https://idp.test/token", "c", "", "DC");
	};
	CHECK(step().outcome == DevicePollOutcome::Pending);
	CHECK(step().outcome == DevicePollOutcome::Pending);
	CHECK(step().outcome == DevicePollOutcome::SlowDown);
	const auto last = step();
	REQUIRE(last.outcome == DevicePollOutcome::Success);
	REQUIRE(last.tokens.has_value());
	CHECK(last.tokens->access_token == "AT");
	CHECK(last.tokens->refresh_token == "RT");
}

TEST_CASE("RequestDeviceAuthorization: empty endpoint / client_id short-circuit", "[device-code][http]") {
	FakeHttpClient http;
	CHECK_FALSE(RequestDeviceAuthorization(http, "", "c", "", "").has_value());
	CHECK_FALSE(RequestDeviceAuthorization(http, "https://idp.test/d", "", "", "").has_value());
	CHECK_FALSE(http.last_post.has_value());
}
