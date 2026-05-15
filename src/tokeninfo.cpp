#include "tokeninfo.hpp"

#include <string>

#ifndef PICOJSON_USE_INT64
#define PICOJSON_USE_INT64
#endif
#include <picojson/picojson.h>

#include "picojson_helpers.hpp"

namespace quack_oauth {

std::optional<TokeninfoResponse> ParseTokeninfoResponse(std::string_view json, bool active) {
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
	if (const auto *s = AsString(obj, "azp"))
		out.azp = *s;
	if (const auto *s = AsString(obj, "aud"))
		out.aud = *s;
	if (const auto *s = AsString(obj, "sub"))
		out.subject = *s;
	if (const auto *s = AsString(obj, "scope"))
		out.scope = *s;
	if (const auto *s = AsString(obj, "email"))
		out.email = *s;
	out.exp = AsIntFlexible(obj, "exp");
	out.expires_in = AsIntFlexible(obj, "expires_in");
	out.email_verified = AsBoolFlexible(obj, "email_verified");
	return out;
}

std::optional<TokeninfoResponse> QueryTokeninfo(IHttpClient &http, const std::string &endpoint,
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
