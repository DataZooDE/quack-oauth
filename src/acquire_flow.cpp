#include "acquire_flow.hpp"

namespace quack_oauth {

const char *AcquireFlowName(AcquireFlow f) {
	switch (f) {
	case AcquireFlow::UseCached:
		return "use_cached";
	case AcquireFlow::RefreshToken:
		return "refresh_token";
	case AcquireFlow::ClientCredentials:
		return "client_credentials";
	case AcquireFlow::DeviceCode:
		return "device_code";
	case AcquireFlow::Unconfigured:
		return "unconfigured";
	}
	return "unknown";
}

static bool AccessTokenIsFresh(const ClientSecretView &v, std::int64_t now_s, std::int64_t renew_skew_s) {
	if (v.access_token.empty())
		return false;
	if (v.expires_at_unix_s <= 0)
		return false; // unknown expiry = treat as stale
	return v.expires_at_unix_s > now_s + renew_skew_s;
}

static bool CanRefresh(const ClientSecretView &v) {
	return !v.refresh_token.empty() && !v.token_endpoint.empty() && !v.client_id.empty();
}

static bool CanClientCredentials(const ClientSecretView &v) {
	return !v.client_id.empty() && !v.client_secret.empty() && !v.token_endpoint.empty();
}

static bool CanDeviceCode(const ClientSecretView &v) {
	return !v.client_id.empty() && !v.token_endpoint.empty() && !v.device_authorization_endpoint.empty();
}

AcquireDecision DecideAcquireFlow(const ClientSecretView &v, std::int64_t now_s, std::int64_t renew_skew_s) {
	if (AccessTokenIsFresh(v, now_s, renew_skew_s)) {
		return {AcquireFlow::UseCached, "fresh access_token on SECRET"};
	}
	if (CanRefresh(v)) {
		return {AcquireFlow::RefreshToken, "refresh_token on SECRET"};
	}
	if (CanClientCredentials(v)) {
		return {AcquireFlow::ClientCredentials, "client_id + client_secret on SECRET"};
	}
	if (CanDeviceCode(v)) {
		return {AcquireFlow::DeviceCode, "client_id + device_authorization_endpoint on SECRET"};
	}
	return {AcquireFlow::Unconfigured, "SECRET has no usable credentials: need either a fresh access_token, "
	                                   "or refresh_token + token_endpoint + client_id, "
	                                   "or client_id + client_secret + token_endpoint, "
	                                   "or client_id + token_endpoint + device_authorization_endpoint"};
}

} // namespace quack_oauth
