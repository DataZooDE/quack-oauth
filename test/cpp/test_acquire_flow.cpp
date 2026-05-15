#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>

#include "acquire_flow.hpp"

using quack_oauth::AcquireFlow;
using quack_oauth::ClientSecretView;
using quack_oauth::DecideAcquireFlow;

namespace {

ClientSecretView Empty() { return {}; }

ClientSecretView WithAccessToken(const std::string &at, std::int64_t exp) {
	ClientSecretView v;
	v.access_token = at;
	v.expires_at_unix_s = exp;
	return v;
}

} // namespace

TEST_CASE("DecideAcquireFlow: fresh AT → UseCached", "[acquire-flow]") {
	auto v = WithAccessToken("eyJ...", 1700001000);
	const auto d = DecideAcquireFlow(v, /*now=*/1700000000, /*skew=*/60);
	CHECK(d.flow == AcquireFlow::UseCached);
}

TEST_CASE("DecideAcquireFlow: AT within skew of expiry → falls through to refresh",
          "[acquire-flow]") {
	auto v = WithAccessToken("eyJ...", 1700000050);
	v.refresh_token = "rt-xyz";
	v.token_endpoint = "https://idp/token";
	v.client_id = "cli";
	// now=1700000000, skew=60 → token expires within 50s, less than 60s skew.
	const auto d = DecideAcquireFlow(v, 1700000000, 60);
	CHECK(d.flow == AcquireFlow::RefreshToken);
}

TEST_CASE("DecideAcquireFlow: AT past expiry → falls through to refresh",
          "[acquire-flow]") {
	auto v = WithAccessToken("eyJ...", 1699999000);
	v.refresh_token = "rt-xyz";
	v.token_endpoint = "https://idp/token";
	v.client_id = "cli";
	const auto d = DecideAcquireFlow(v, 1700000000, 60);
	CHECK(d.flow == AcquireFlow::RefreshToken);
}

TEST_CASE("DecideAcquireFlow: no AT but client_credentials available → ClientCredentials",
          "[acquire-flow]") {
	ClientSecretView v;
	v.token_endpoint = "https://idp/token";
	v.client_id = "cli";
	v.client_secret = "shh";
	const auto d = DecideAcquireFlow(v, 1700000000, 60);
	CHECK(d.flow == AcquireFlow::ClientCredentials);
}

TEST_CASE("DecideAcquireFlow: refresh_token wins over client_credentials when both exist",
          "[acquire-flow]") {
	ClientSecretView v;
	v.token_endpoint = "https://idp/token";
	v.client_id = "cli";
	v.client_secret = "shh";
	v.refresh_token = "rt-xyz";
	const auto d = DecideAcquireFlow(v, 1700000000, 60);
	CHECK(d.flow == AcquireFlow::RefreshToken);
}

TEST_CASE("DecideAcquireFlow: only device_authorization_endpoint → DeviceCode",
          "[acquire-flow]") {
	ClientSecretView v;
	v.token_endpoint = "https://idp/token";
	v.client_id = "cli";
	v.device_authorization_endpoint = "https://idp/device";
	const auto d = DecideAcquireFlow(v, 1700000000, 60);
	CHECK(d.flow == AcquireFlow::DeviceCode);
}

TEST_CASE("DecideAcquireFlow: nothing usable → Unconfigured",
          "[acquire-flow]") {
	ClientSecretView v; // all empty
	const auto d = DecideAcquireFlow(v, 1700000000, 60);
	CHECK(d.flow == AcquireFlow::Unconfigured);
}

TEST_CASE("DecideAcquireFlow: AT with expires_at=0 (unknown) → falls through to refresh",
          "[acquire-flow]") {
	auto v = WithAccessToken("eyJ...", 0); // expires_at not set
	v.refresh_token = "rt-xyz";
	v.token_endpoint = "https://idp/token";
	v.client_id = "cli";
	// An AT with no expires_at is treated as expired (we don't trust it
	// to last long enough). Refresh + re-mint instead.
	const auto d = DecideAcquireFlow(v, 1700000000, 60);
	CHECK(d.flow == AcquireFlow::RefreshToken);
}

TEST_CASE("DecideAcquireFlow: fresh AT but only access_token field → UseCached",
          "[acquire-flow]") {
	// Operator injected an AT externally (R-C-1 explicitly allows this).
	// No client_id, no token_endpoint -- we should still use the AT.
	auto v = WithAccessToken("eyJ-injected", 1700009999);
	const auto d = DecideAcquireFlow(v, 1700000000, 60);
	CHECK(d.flow == AcquireFlow::UseCached);
}
