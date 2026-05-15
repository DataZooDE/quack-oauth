#include "introspect.hpp"

#include <string>

#ifndef PICOJSON_USE_INT64
#define PICOJSON_USE_INT64
#endif
#include <picojson/picojson.h>

#include "picojson_helpers.hpp"

namespace quack_oauth {

static void ExtractAudience(const picojson::object &obj, IntrospectionResponse &out) {
	const auto it = obj.find("aud");
	if (it == obj.end()) {
		return;
	}
	if (it->second.is<std::string>()) {
		out.audience.push_back(it->second.get<std::string>());
		return;
	}
	if (it->second.is<picojson::array>()) {
		for (const auto &v : it->second.get<picojson::array>()) {
			if (v.is<std::string>()) {
				out.audience.push_back(v.get<std::string>());
			}
		}
	}
}

static void ExtractScp(const picojson::object &obj, IntrospectionResponse &out) {
	const auto it = obj.find("scp");
	if (it == obj.end() || !it->second.is<picojson::array>()) {
		return;
	}
	for (const auto &v : it->second.get<picojson::array>()) {
		if (v.is<std::string>()) {
			out.scp.push_back(v.get<std::string>());
		}
	}
}

std::optional<IntrospectionResponse> ParseIntrospectionResponse(std::string_view json) {
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

	// `active` is the one MUST per RFC 7662 §2.2.
	const auto active_it = obj.find("active");
	if (active_it == obj.end() || !active_it->second.is<bool>()) {
		return std::nullopt;
	}

	IntrospectionResponse out;
	out.active = active_it->second.get<bool>();

	if (const auto *s = AsString(obj, "sub"))
		out.subject = *s;
	if (const auto *s = AsString(obj, "iss"))
		out.issuer = *s;
	if (const auto *s = AsString(obj, "scope"))
		out.scope = *s;
	if (const auto *s = AsString(obj, "client_id"))
		out.client_id = *s;
	if (const auto *s = AsString(obj, "username"))
		out.username = *s;

	out.exp = AsIntFlexible(obj, "exp");
	out.iat = AsIntFlexible(obj, "iat");
	out.nbf = AsIntFlexible(obj, "nbf");

	ExtractAudience(obj, out);
	ExtractScp(obj, out);
	return out;
}

std::optional<IntrospectionResponse> IntrospectToken(IHttpClient &http, const std::string &endpoint,
                                                     const std::string &client_id, const std::string &client_secret,
                                                     std::string_view token) {
	if (endpoint.empty() || token.empty()) {
		return std::nullopt;
	}

	IHttpClient::PostRequest req;
	req.url = endpoint;
	req.content_type = "application/x-www-form-urlencoded";
	req.body = "token=" + UrlEncode(token) + "&token_type_hint=access_token";
	req.basic_user = client_id;
	req.basic_pass = client_secret;

	const auto resp = http.Post(req);
	if (!resp.has_value() || resp->status_code != 200) {
		return std::nullopt;
	}
	return ParseIntrospectionResponse(resp->body);
}

} // namespace quack_oauth
