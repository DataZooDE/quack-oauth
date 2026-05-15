#include "idp_probe.hpp"

namespace quack_oauth {

const char *StatusName(IdpProbeResult::Status s) {
	switch (s) {
	case IdpProbeResult::Status::Unconfigured: return "unconfigured";
	case IdpProbeResult::Status::Reachable:    return "reachable";
	case IdpProbeResult::Status::Unreachable:  return "unreachable";
	}
	return "unknown";
}

IdpProbeResult ProbeIdpReachability(IHttpClient &http, std::string_view jwks_uri) {
	IdpProbeResult out;
	out.probed_uri = std::string(jwks_uri);
	if (jwks_uri.empty()) {
		out.status = IdpProbeResult::Status::Unconfigured;
		return out;
	}
	const auto resp = http.Get(jwks_uri);
	if (!resp.has_value()) {
		out.status = IdpProbeResult::Status::Unreachable;
		out.http_status = 0;
		return out;
	}
	out.http_status = resp->status_code;
	if (resp->status_code >= 200 && resp->status_code < 300) {
		out.status = IdpProbeResult::Status::Reachable;
	} else {
		out.status = IdpProbeResult::Status::Unreachable;
	}
	return out;
}

} // namespace quack_oauth
