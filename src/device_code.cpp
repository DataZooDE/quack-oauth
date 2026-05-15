#include "device_code.hpp"

#include <sstream>
#include <string>

#ifndef PICOJSON_USE_INT64
#define PICOJSON_USE_INT64
#endif
#include <picojson/picojson.h>

namespace quack_oauth {

static std::string UrlEncode(std::string_view in) {
	std::ostringstream out;
	for (unsigned char c : in) {
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
		    c == '.' || c == '~') {
			out << static_cast<char>(c);
		} else {
			out << '%';
			static constexpr char kHex[] = "0123456789ABCDEF";
			out << kHex[(c >> 4) & 0x0F];
			out << kHex[c & 0x0F];
		}
	}
	return out.str();
}

static const std::string *AsString(const picojson::object &obj, const std::string &key) {
	const auto it = obj.find(key);
	if (it == obj.end() || !it->second.is<std::string>()) {
		return nullptr;
	}
	return &it->second.get<std::string>();
}

static std::int64_t AsInt(const picojson::object &obj, const std::string &key, std::int64_t fallback) {
	const auto it = obj.find(key);
	if (it == obj.end())
		return fallback;
	if (it->second.is<std::int64_t>())
		return it->second.get<std::int64_t>();
	if (it->second.is<double>())
		return static_cast<std::int64_t>(it->second.get<double>());
	return fallback;
}

std::optional<DeviceAuthorizationResponse> ParseDeviceAuthorizationResponse(std::string_view json) {
	if (json.empty())
		return std::nullopt;
	picojson::value root;
	std::string err;
	picojson::parse(root, json.begin(), json.end(), &err);
	if (!err.empty() || !root.is<picojson::object>())
		return std::nullopt;
	const auto &obj = root.get<picojson::object>();

	const auto *device_code = AsString(obj, "device_code");
	const auto *user_code = AsString(obj, "user_code");
	const auto *verification_uri = AsString(obj, "verification_uri");
	if (!device_code || !user_code || !verification_uri) {
		return std::nullopt;
	}

	DeviceAuthorizationResponse out;
	out.device_code = *device_code;
	out.user_code = *user_code;
	out.verification_uri = *verification_uri;
	if (const auto *s = AsString(obj, "verification_uri_complete")) {
		out.verification_uri_complete = *s;
	}
	out.expires_in = AsInt(obj, "expires_in", 0);
	out.interval = AsInt(obj, "interval", 5);
	return out;
}

DevicePollResult ParseDevicePollResponse(int http_status, std::string_view body) {
	if (http_status == 200) {
		DevicePollResult r;
		r.outcome = DevicePollOutcome::Success;
		r.tokens = ParseTokenResponse(body);
		if (!r.tokens.has_value()) {
			// 200 but unparseable -- treat as terminal error.
			r.outcome = DevicePollOutcome::Error;
		}
		return r;
	}
	// Non-200: look for the OAuth error code.
	picojson::value root;
	std::string err;
	picojson::parse(root, body.begin(), body.end(), &err);
	if (!err.empty() || !root.is<picojson::object>()) {
		return {DevicePollOutcome::Error, std::nullopt};
	}
	const auto *code = AsString(root.get<picojson::object>(), "error");
	if (!code) {
		return {DevicePollOutcome::Error, std::nullopt};
	}
	if (*code == "authorization_pending")
		return {DevicePollOutcome::Pending, std::nullopt};
	if (*code == "slow_down")
		return {DevicePollOutcome::SlowDown, std::nullopt};
	if (*code == "access_denied")
		return {DevicePollOutcome::Denied, std::nullopt};
	if (*code == "expired_token")
		return {DevicePollOutcome::Expired, std::nullopt};
	return {DevicePollOutcome::Error, std::nullopt};
}

std::optional<DeviceAuthorizationResponse>
RequestDeviceAuthorization(IHttpClient &http, const std::string &device_authorization_endpoint,
                           const std::string &client_id, const std::string &client_secret, const std::string &scope) {
	if (device_authorization_endpoint.empty() || client_id.empty()) {
		return std::nullopt;
	}
	IHttpClient::PostRequest req;
	req.url = device_authorization_endpoint;
	req.content_type = "application/x-www-form-urlencoded";
	req.body = "client_id=" + UrlEncode(client_id);
	if (!scope.empty()) {
		req.body += "&scope=" + UrlEncode(scope);
	}
	if (!client_secret.empty()) {
		req.basic_user = client_id;
		req.basic_pass = client_secret;
	}
	const auto resp = http.Post(req);
	if (!resp.has_value() || resp->status_code != 200) {
		return std::nullopt;
	}
	return ParseDeviceAuthorizationResponse(resp->body);
}

DevicePollResult PollDeviceTokenEndpoint(IHttpClient &http, const std::string &token_endpoint,
                                         const std::string &client_id, const std::string &client_secret,
                                         const std::string &device_code) {
	if (token_endpoint.empty() || client_id.empty() || device_code.empty()) {
		return {DevicePollOutcome::Error, std::nullopt};
	}
	IHttpClient::PostRequest req;
	req.url = token_endpoint;
	req.content_type = "application/x-www-form-urlencoded";
	req.body = "grant_type=urn:ietf:params:oauth:grant-type:device_code";
	req.body += "&device_code=" + UrlEncode(device_code);
	req.body += "&client_id=" + UrlEncode(client_id);
	if (!client_secret.empty()) {
		req.basic_user = client_id;
		req.basic_pass = client_secret;
	}
	const auto resp = http.Post(req);
	if (!resp.has_value()) {
		return {DevicePollOutcome::Error, std::nullopt};
	}
	return ParseDevicePollResponse(resp->status_code, resp->body);
}

} // namespace quack_oauth
