#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>

#include "http_client.hpp"
#include "idp_probe.hpp"

using quack_oauth::IdpProbeResult;
using quack_oauth::IHttpClient;
using quack_oauth::ProbeIdpReachability;

namespace {

struct FakeHttp : public IHttpClient {
	std::optional<Response> next_get;
	std::string last_url;
	int get_calls = 0;

	std::optional<Response> Get(std::string_view url) override {
		last_url = std::string(url);
		++get_calls;
		return next_get;
	}
};

} // namespace

TEST_CASE("ProbeIdpReachability: empty URI returns Unconfigured", "[idp-probe]") {
	FakeHttp http;
	const auto r = ProbeIdpReachability(http, "");
	CHECK(r.status == IdpProbeResult::Status::Unconfigured);
	CHECK(http.get_calls == 0);
}

TEST_CASE("ProbeIdpReachability: 200 → Reachable", "[idp-probe]") {
	FakeHttp http;
	http.next_get = IHttpClient::Response {200, "{}"};
	const auto r = ProbeIdpReachability(http, "https://idp/jwks");
	CHECK(r.status == IdpProbeResult::Status::Reachable);
	CHECK(r.http_status == 200);
	CHECK(http.last_url == "https://idp/jwks");
}

TEST_CASE("ProbeIdpReachability: 2xx → Reachable", "[idp-probe]") {
	FakeHttp http;
	for (int code : {200, 201, 204, 299}) {
		http.next_get = IHttpClient::Response {code, ""};
		const auto r = ProbeIdpReachability(http, "https://idp/jwks");
		INFO("status=" << code);
		CHECK(r.status == IdpProbeResult::Status::Reachable);
	}
}

TEST_CASE("ProbeIdpReachability: 4xx → Unreachable", "[idp-probe]") {
	FakeHttp http;
	http.next_get = IHttpClient::Response {404, "not found"};
	const auto r = ProbeIdpReachability(http, "https://idp/jwks");
	CHECK(r.status == IdpProbeResult::Status::Unreachable);
	CHECK(r.http_status == 404);
}

TEST_CASE("ProbeIdpReachability: 5xx → Unreachable", "[idp-probe]") {
	FakeHttp http;
	http.next_get = IHttpClient::Response {503, ""};
	const auto r = ProbeIdpReachability(http, "https://idp/jwks");
	CHECK(r.status == IdpProbeResult::Status::Unreachable);
	CHECK(r.http_status == 503);
}

TEST_CASE("ProbeIdpReachability: transport failure → Unreachable, status=0", "[idp-probe]") {
	FakeHttp http;
	http.next_get = std::nullopt;
	const auto r = ProbeIdpReachability(http, "https://idp/jwks");
	CHECK(r.status == IdpProbeResult::Status::Unreachable);
	CHECK(r.http_status == 0);
}
