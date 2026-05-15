#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "http_client.hpp"
#include "token_endpoint.hpp"

namespace quack_oauth {

// RFC 8628 §3.2 device authorization response.
struct DeviceAuthorizationResponse {
	std::string device_code;
	std::string user_code;
	std::string verification_uri;
	std::string verification_uri_complete; // optional per RFC; many IdPs include
	std::int64_t expires_in = 0;
	std::int64_t interval = 5; // default per RFC 8628 §3.2
};

// Outcome of a single poll of the token endpoint during a device flow.
enum class DevicePollOutcome {
	Pending,  // authorization_pending -- keep polling at the current interval
	SlowDown, // slow_down -- increase the interval by 5s per RFC 8628 §3.5
	Success,  // got an access token (look at `tokens`)
	Denied,   // access_denied -- user rejected
	Expired,  // expired_token -- device_code is dead
	Error,    // any other 4xx/5xx -- treat as terminal
};

struct DevicePollResult {
	DevicePollOutcome outcome = DevicePollOutcome::Error;
	std::optional<TokenResponse> tokens; // populated only on Success
};

// Parse the JSON body of a device-authorization response (RFC 8628 §3.2).
// Returns nullopt on malformed input or missing required fields
// (`device_code`, `user_code`, `verification_uri`).
std::optional<DeviceAuthorizationResponse> ParseDeviceAuthorizationResponse(std::string_view json);

// Parse a single token-endpoint poll response. RFC 8628 §3.5 spec:
//   200          → success (token response in body)
//   400 + error: pending     → Pending
//   400 + error: slow_down   → SlowDown
//   400 + error: access_denied  → Denied
//   400 + error: expired_token → Expired
//   anything else            → Error
DevicePollResult ParseDevicePollResponse(int http_status, std::string_view body);

// POST to a device_authorization endpoint. Returns nullopt on transport
// failure, non-200, or malformed body.
std::optional<DeviceAuthorizationResponse>
RequestDeviceAuthorization(IHttpClient &http, const std::string &device_authorization_endpoint,
                           const std::string &client_id, const std::string &client_secret, const std::string &scope);

// POST one poll of the token endpoint for an in-progress device flow.
DevicePollResult PollDeviceTokenEndpoint(IHttpClient &http, const std::string &token_endpoint,
                                         const std::string &client_id, const std::string &client_secret,
                                         const std::string &device_code);

} // namespace quack_oauth
