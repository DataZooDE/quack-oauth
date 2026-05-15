#include "token_endpoint.hpp"

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

static std::int64_t AsInt(const picojson::object &obj, const std::string &key) {
	const auto it = obj.find(key);
	if (it == obj.end()) {
		return 0;
	}
	if (it->second.is<std::int64_t>()) {
		return it->second.get<std::int64_t>();
	}
	if (it->second.is<double>()) {
		return static_cast<std::int64_t>(it->second.get<double>());
	}
	return 0;
}

std::optional<TokenResponse> ParseTokenResponse(std::string_view json) {
	if (json.empty()) {
		return std::nullopt;
	}
	picojson::value root;
	std::string err;
	picojson::parse(root, json.begin(), json.end(), &err);
	if (!err.empty() || !root.is<picojson::object>()) {
		return std::nullopt;
	}
	const auto &obj = root.get<picojson::object>();

	const auto *at = AsString(obj, "access_token");
	if (at == nullptr || at->empty()) {
		// RFC 6749 §5.1: `access_token` is REQUIRED on success.
		return std::nullopt;
	}

	TokenResponse out;
	out.access_token = *at;
	if (const auto *s = AsString(obj, "refresh_token"))
		out.refresh_token = *s;
	if (const auto *s = AsString(obj, "token_type"))
		out.token_type = *s;
	if (const auto *s = AsString(obj, "scope"))
		out.scope = *s;
	out.expires_in = AsInt(obj, "expires_in");
	return out;
}

std::optional<TokenResponse> AcquireTokenClientCredentials(IHttpClient &http, const std::string &token_endpoint,
                                                           const std::string &client_id,
                                                           const std::string &client_secret, const std::string &scope) {
	if (token_endpoint.empty() || client_id.empty()) {
		return std::nullopt;
	}
	IHttpClient::PostRequest req;
	req.url = token_endpoint;
	req.content_type = "application/x-www-form-urlencoded";
	req.body = "grant_type=client_credentials";
	if (!scope.empty()) {
		req.body += "&scope=" + UrlEncode(scope);
	}
	req.basic_user = client_id;
	req.basic_pass = client_secret;

	const auto resp = http.Post(req);
	if (!resp.has_value() || resp->status_code != 200) {
		return std::nullopt;
	}
	return ParseTokenResponse(resp->body);
}

std::optional<TokenResponse> AcquireTokenRefreshToken(IHttpClient &http, const std::string &token_endpoint,
                                                      const std::string &client_id, const std::string &client_secret,
                                                      const std::string &refresh_token, const std::string &scope) {
	if (token_endpoint.empty() || refresh_token.empty()) {
		return std::nullopt;
	}
	IHttpClient::PostRequest req;
	req.url = token_endpoint;
	req.content_type = "application/x-www-form-urlencoded";
	req.body = "grant_type=refresh_token&refresh_token=" + UrlEncode(refresh_token);
	if (!scope.empty()) {
		req.body += "&scope=" + UrlEncode(scope);
	}
	// Public clients (no secret) need to send `client_id` in the body
	// instead of HTTP Basic. Confidential clients use Basic auth and may
	// also include `client_id` in the body -- Keycloak / Entra / Google
	// all tolerate both. To keep the request shape consistent we ALWAYS
	// include `client_id` in the body and additionally set Basic auth
	// when a client_secret is supplied.
	if (!client_id.empty()) {
		req.body += "&client_id=" + UrlEncode(client_id);
	}
	if (!client_secret.empty()) {
		req.basic_user = client_id;
		req.basic_pass = client_secret;
	}

	const auto resp = http.Post(req);
	if (!resp.has_value() || resp->status_code != 200) {
		return std::nullopt;
	}
	return ParseTokenResponse(resp->body);
}

} // namespace quack_oauth
