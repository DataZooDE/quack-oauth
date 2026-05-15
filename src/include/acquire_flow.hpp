#pragma once

#include <cstdint>
#include <string>

namespace quack_oauth {

// R-C-2: which OAuth flow to run when an operator calls
// `quack_oauth_acquire(secret_name)`. The decision is purely a function
// of the SECRET's current state + the wall clock + the renew-skew
// setting -- no I/O. The actual HTTP-bound work happens in the four
// path-specific scalars (login_function / refresh_function /
// device_login_function); this enum tells the dispatcher which.
enum class AcquireFlow {
	UseCached,         // SECRET already has a fresh access_token; nothing to do
	RefreshToken,      // RFC 6749 §6 -- refresh_token grant
	ClientCredentials, // RFC 6749 §4.4
	DeviceCode,        // RFC 8628
	Unconfigured,      // nothing in the SECRET supports any flow
};

// Plain-data view of the relevant `quack_oauth` SECRET fields. Filled
// by the DuckDB-coupled caller from KeyValueSecret; kept SQL-free here
// so DecideAcquireFlow is Catch2-testable.
struct ClientSecretView {
	std::string access_token;
	std::int64_t expires_at_unix_s = 0; // 0 = unknown
	std::string refresh_token;
	std::string client_id;
	std::string client_secret;
	std::string token_endpoint;
	std::string device_authorization_endpoint;
	std::string scope;
};

struct AcquireDecision {
	AcquireFlow flow = AcquireFlow::Unconfigured;
	const char *reason = "";
};

// Picks the flow per the R-C-2 ladder:
//   1. fresh access_token AND not within `renew_skew_s` of expiry → UseCached
//   2. refresh_token present + token_endpoint + client_id           → RefreshToken
//   3. client_id + client_secret + token_endpoint                   → ClientCredentials
//   4. client_id + device_authorization_endpoint + token_endpoint   → DeviceCode
//   5. otherwise                                                    → Unconfigured
//
// "Fresh" means `access_token` non-empty AND `expires_at_unix_s > now_s + renew_skew_s`.
// expires_at_unix_s = 0 means "unknown" and is treated as expired.
AcquireDecision DecideAcquireFlow(const ClientSecretView &v, std::int64_t now_s, std::int64_t renew_skew_s);

// Stable string form of the enum, used by the DUCKDB-side dispatcher
// for logging / error messages.
const char *AcquireFlowName(AcquireFlow f);

} // namespace quack_oauth
