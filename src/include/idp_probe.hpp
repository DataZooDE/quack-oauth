#pragma once

#include <string>
#include <string_view>

#include "http_client.hpp"

namespace quack_oauth {

// R-N-13: synchronous reachability probe for the operator's IdP. The
// result feeds into `quack_oauth_diagnose()`'s `idp_reachability` row.
struct IdpProbeResult {
	enum class Status {
		Unconfigured, // no jwks_uri set on the active SECRET
		Reachable,    // 2xx response
		Unreachable,  // 4xx, 5xx, or transport error
	};
	Status status = Status::Unconfigured;
	int http_status = 0;     // 0 if transport error
	std::string probed_uri;  // for `detail` formatting
};

// Issue a GET on `jwks_uri` and classify the outcome. Empty `jwks_uri`
// short-circuits to Unconfigured -- no HTTP call.
IdpProbeResult ProbeIdpReachability(IHttpClient &http, std::string_view jwks_uri);

// Stable string form for the Status enum, used by diagnose() row formatting.
const char *StatusName(IdpProbeResult::Status s);

} // namespace quack_oauth
