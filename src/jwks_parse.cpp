#include "jwks_parse.hpp"

#include <string>

#ifndef PICOJSON_USE_INT64
#define PICOJSON_USE_INT64
#endif
#include <picojson/picojson.h>

namespace quack_oauth {

static const std::string *GetString(const picojson::object &obj, const std::string &field) {
	const auto it = obj.find(field);
	if (it == obj.end() || !it->second.is<std::string>()) {
		return nullptr;
	}
	return &it->second.get<std::string>();
}

static std::string GetStringOrEmpty(const picojson::object &obj, const std::string &field) {
	const auto *p = GetString(obj, field);
	return p ? *p : std::string();
}

static std::optional<Jwk> ParseSingleJwk(const picojson::value &v) {
	if (!v.is<picojson::object>()) {
		return std::nullopt;
	}
	const auto &obj = v.get<picojson::object>();
	const auto *kid = GetString(obj, "kid");
	const auto *kty = GetString(obj, "kty");
	if (!kid || !kty) {
		// kid is the cache lookup key; kty defines the algorithm family.
		// Either missing → unusable.
		return std::nullopt;
	}

	Jwk j;
	j.kid = *kid;
	j.kty = *kty;
	j.alg = GetStringOrEmpty(obj, "alg");
	j.use = GetStringOrEmpty(obj, "use");
	j.n = GetStringOrEmpty(obj, "n");
	j.e = GetStringOrEmpty(obj, "e");
	j.crv = GetStringOrEmpty(obj, "crv");
	j.x = GetStringOrEmpty(obj, "x");
	j.y = GetStringOrEmpty(obj, "y");
	return j;
}

std::vector<Jwk> ParseJwksJson(std::string_view json) {
	if (json.empty()) {
		return {};
	}

	picojson::value root;
	std::string parse_err;
	picojson::parse(root, json.begin(), json.end(), &parse_err);
	if (!parse_err.empty() || !root.is<picojson::object>()) {
		return {};
	}

	const auto &obj = root.get<picojson::object>();
	const auto keys_it = obj.find("keys");
	if (keys_it == obj.end() || !keys_it->second.is<picojson::array>()) {
		return {};
	}

	std::vector<Jwk> out;
	for (const auto &v : keys_it->second.get<picojson::array>()) {
		if (auto parsed = ParseSingleJwk(v); parsed.has_value()) {
			out.push_back(std::move(*parsed));
		}
	}
	return out;
}

} // namespace quack_oauth
