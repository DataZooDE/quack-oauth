#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "http_client.hpp"

namespace quack_oauth {

// Successful response from an RFC 6749 §5.1 token endpoint. Fields not
// present in the response are left at their default.
struct TokenResponse {
	std::string access_token;
	std::string refresh_token;   // present for code/refresh grants, optional
	std::string token_type;      // "Bearer" in practice
	std::string scope;           // sometimes echoed back
	std::int64_t expires_in = 0; // seconds; 0 if absent
};

// Parse a token-endpoint response. Returns `nullopt` when the body isn't JSON
// or `access_token` (the only RFC-required field) is missing.
std::optional<TokenResponse> ParseTokenResponse(std::string_view json);

// Acquire a token via RFC 6749 §4.4 client_credentials. POSTs
// `grant_type=client_credentials[&scope=...]` to the token endpoint with
// HTTP Basic auth (`client_id:client_secret`). Returns `nullopt` on transport
// error, non-200, or malformed body.
std::optional<TokenResponse> AcquireTokenClientCredentials(IHttpClient &http, const std::string &token_endpoint,
                                                           const std::string &client_id,
                                                           const std::string &client_secret, const std::string &scope);

// Acquire a fresh access token via RFC 6749 §6 refresh_token grant. POSTs
// `grant_type=refresh_token&refresh_token=<urlencoded>[&scope=...]`. Public
// clients omit `client_secret` (empty -> no Basic auth header); confidential
// clients pass it. The response may include a new `refresh_token` (some
// IdPs rotate, others don't); the original SHOULD continue to work either
// way per R-C-5 (we persist whatever the IdP returned).
std::optional<TokenResponse> AcquireTokenRefreshToken(IHttpClient &http, const std::string &token_endpoint,
                                                      const std::string &client_id, const std::string &client_secret,
                                                      const std::string &refresh_token, const std::string &scope);

} // namespace quack_oauth
