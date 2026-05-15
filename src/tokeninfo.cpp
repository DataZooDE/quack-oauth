#include "tokeninfo.hpp"

#include <sstream>
#include <string>

#ifndef PICOJSON_USE_INT64
#define PICOJSON_USE_INT64
#endif
#include <picojson/picojson.h>

namespace quack_oauth {

namespace {

std::string UrlEncode(std::string_view in) {
	std::ostringstream out;
	for (unsigned char c : in) {
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		    (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
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

const std::string *AsString(const picojson::object &obj, const std::string &key) {
	const auto it = obj.find(key);
	if (it == obj.end() || !it->second.is<std::string>()) {
		return nullptr;
	}
	return &it->second.get<std::string>();
}

// Google returns numeric claims (`exp`, `expires_in`) as JSON STRINGS, not
// numbers. Some other providers may return them as numbers if they ever
// switch -- handle both shapes.
std::int64_t AsIntFlexible(const picojson::object &obj, const std::string &key) {
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
	if (it->second.is<std::string>()) {
		const auto &s = it->second.get<std::string>();
		if (s.empty()) return 0;
		try {
			return std::stoll(s);
		} catch (...) {
			return 0;
		}
	}
	return 0;
}

bool AsBoolFlexible(const picojson::object &obj, const std::string &key) {
	const auto it = obj.find(key);
	if (it == obj.end()) {
		return false;
	}
	if (it->second.is<bool>()) {
		return it->second.get<bool>();
	}
	if (it->second.is<std::string>()) {
		const auto &s = it->second.get<std::string>();
		return s == "true" || s == "True" || s == "TRUE";
	}
	return false;
}

} // namespace

std::optional<TokeninfoResponse> ParseTokeninfoResponse(std::string_view json,
                                                       bool active) {
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

	TokeninfoResponse out;
	out.active = active;
	if (const auto *s = AsString(obj, "azp")) out.azp = *s;
	if (const auto *s = AsString(obj, "aud")) out.aud = *s;
	if (const auto *s = AsString(obj, "sub")) out.subject = *s;
	if (const auto *s = AsString(obj, "scope")) out.scope = *s;
	if (const auto *s = AsString(obj, "email")) out.email = *s;
	out.exp = AsIntFlexible(obj, "exp");
	out.expires_in = AsIntFlexible(obj, "expires_in");
	out.email_verified = AsBoolFlexible(obj, "email_verified");
	return out;
}

std::optional<TokeninfoResponse>
QueryTokeninfo(IHttpClient &http, const std::string &endpoint,
               std::string_view token) {
	if (endpoint.empty() || token.empty()) {
		return std::nullopt;
	}
	IHttpClient::PostRequest req;
	req.url = endpoint;
	req.content_type = "application/x-www-form-urlencoded";
	req.body = "access_token=" + UrlEncode(token);
	// Tokeninfo is unauthenticated (Google rejects Basic auth here).
	// Leave basic_user / basic_pass empty.

	const auto resp = http.Post(req);
	if (!resp.has_value()) {
		return std::nullopt;
	}
	if (resp->status_code == 200) {
		return ParseTokeninfoResponse(resp->body, /*active=*/true);
	}
	if (resp->status_code == 400) {
		// Inactive / revoked / malformed token. Body looks like
		// `{"error_description": "Invalid Value"}` -- we don't parse it,
		// just synthesise an inactive response.
		TokeninfoResponse out;
		out.active = false;
		return out;
	}
	// 5xx or anything else: transport failure semantics.
	return std::nullopt;
}

} // namespace quack_oauth
