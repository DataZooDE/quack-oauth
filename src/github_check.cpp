#include "github_check.hpp"

#include <cstdint>
#include <sstream>
#include <string>

#define PICOJSON_USE_INT64
#include <picojson/picojson.h>

namespace quack_oauth {

static std::string JsonEscape(std::string_view s) {
	std::string out;
	out.reserve(s.size() + 2);
	for (char c : s) {
		switch (c) {
		case '"':
			out += "\\\"";
			break;
		case '\\':
			out += "\\\\";
			break;
		case '\b':
			out += "\\b";
			break;
		case '\f':
			out += "\\f";
			break;
		case '\n':
			out += "\\n";
			break;
		case '\r':
			out += "\\r";
			break;
		case '\t':
			out += "\\t";
			break;
		default:
			if (static_cast<unsigned char>(c) < 0x20) {
				char buf[8];
				std::snprintf(buf, sizeof(buf), "\\u%04x", c);
				out += buf;
			} else {
				out += c;
			}
		}
	}
	return out;
}

std::optional<Principal> ParseGithubCheckResponse(std::string_view json) {
	if (json.empty())
		return std::nullopt;
	picojson::value v;
	const std::string err = picojson::parse(v, std::string(json));
	if (!err.empty() || !v.is<picojson::object>())
		return std::nullopt;
	const auto &obj = v.get<picojson::object>();

	// `user.id` is the only mandatory field per R-S-13's mapping.
	const auto user_it = obj.find("user");
	if (user_it == obj.end() || !user_it->second.is<picojson::object>()) {
		return std::nullopt;
	}
	const auto &user = user_it->second.get<picojson::object>();
	const auto id_it = user.find("id");
	if (id_it == user.end())
		return std::nullopt;

	Principal p;
	if (id_it->second.is<std::int64_t>()) {
		p.subject = "gh:" + std::to_string(id_it->second.get<std::int64_t>());
	} else if (id_it->second.is<double>()) {
		p.subject = "gh:" + std::to_string(static_cast<std::int64_t>(id_it->second.get<double>()));
	} else if (id_it->second.is<std::string>()) {
		p.subject = "gh:" + id_it->second.get<std::string>();
	} else {
		return std::nullopt;
	}

	// issuer is conceptually "github"; we tag it with the API host so
	// the audit log distinguishes GitHub from other IdPs.
	p.issuer = "https://api.github.com";

	// scopes: a JSON array of strings.
	const auto scopes_it = obj.find("scopes");
	if (scopes_it != obj.end() && scopes_it->second.is<picojson::array>()) {
		for (const auto &s : scopes_it->second.get<picojson::array>()) {
			if (s.is<std::string>()) {
				p.scopes.push_back(s.get<std::string>());
			}
		}
	}

	// `expires_at` is ISO 8601 -- we don't parse it into p.exp here (the
	// existing pipeline expects unix seconds; GitHub's expiry is best
	// surfaced via the audit_table rather than the principal-expiry path).
	return p;
}

VerifyResult ValidateTokenViaGithubCheck(std::string_view token, GithubContext &ctx, Principal *out_principal) {
	if (token.empty())
		return VerifyResult::Malformed;

	IHttpClient::PostRequest req;
	req.url = ctx.check_url;
	req.content_type = "application/json";
	req.basic_user = ctx.client_id;
	req.basic_pass = ctx.client_secret;
	{
		std::ostringstream body;
		body << R"({"access_token":")" << JsonEscape(token) << R"("})";
		req.body = body.str();
	}

	const auto resp = ctx.http.Post(req);
	if (!resp.has_value())
		return VerifyResult::JwksFetchFailed;
	if (resp->status_code >= 500)
		return VerifyResult::JwksFetchFailed;
	if (resp->status_code == 404)
		return VerifyResult::InvalidSignature;
	if (resp->status_code != 200)
		return VerifyResult::InvalidSignature;

	const auto principal = ParseGithubCheckResponse(resp->body);
	if (!principal.has_value())
		return VerifyResult::Malformed;
	if (out_principal != nullptr)
		*out_principal = *principal;
	return VerifyResult::Ok;
}

} // namespace quack_oauth
