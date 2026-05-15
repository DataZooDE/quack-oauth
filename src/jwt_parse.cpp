#include "jwt_parse.hpp"

#include <chrono>
#include <cstdint>
#include <string>

#include <jwt-cpp/traits/kazuho-picojson/defaults.h>

namespace quack_oauth {

using TraitsT = jwt::traits::kazuho_picojson;

static std::int64_t ToUnixSeconds(const std::chrono::system_clock::time_point &tp) {
	return std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
}

static void ExtractHeader(const jwt::decoded_jwt<TraitsT> &decoded, JwtParsed &out) {
	if (decoded.has_algorithm()) {
		out.alg = decoded.get_algorithm();
	}
	if (decoded.has_key_id()) {
		out.kid = decoded.get_key_id();
	}
	if (decoded.has_type()) {
		out.typ = decoded.get_type();
	}
}

static void ExtractStandardPayload(const jwt::decoded_jwt<TraitsT> &decoded, JwtParsed &out) {
	if (decoded.has_subject()) {
		out.subject = decoded.get_subject();
	}
	if (decoded.has_issuer()) {
		out.issuer = decoded.get_issuer();
	}
	if (decoded.has_audience()) {
		// jwt-cpp normalises {aud:"x"} and {aud:["x","y"]} into the same set.
		for (const auto &a : decoded.get_audience()) {
			out.audience.push_back(a);
		}
	}
	if (decoded.has_expires_at()) {
		out.exp = ToUnixSeconds(decoded.get_expires_at());
	}
	if (decoded.has_not_before()) {
		out.nbf = ToUnixSeconds(decoded.get_not_before());
	}
	if (decoded.has_issued_at()) {
		out.iat = ToUnixSeconds(decoded.get_issued_at());
	}
}

static void ExtractScopes(const jwt::decoded_jwt<TraitsT> &decoded, JwtParsed &out) {
	// `scope` (RFC 6749 §3.3): single space-delimited string.
	if (decoded.has_payload_claim("scope")) {
		const auto claim = decoded.get_payload_claim("scope");
		if (claim.get_type() == jwt::json::type::string) {
			out.scope = claim.as_string();
		}
	}
	// `scp` (Microsoft Entra): array of strings.
	if (decoded.has_payload_claim("scp")) {
		const auto claim = decoded.get_payload_claim("scp");
		if (claim.get_type() == jwt::json::type::array) {
			for (const auto &v : claim.as_array()) {
				if (v.is<std::string>()) {
					out.scp.push_back(v.get<std::string>());
				}
			}
		}
	}
}

std::optional<JwtParsed> ParseJwt(std::string_view token) {
	if (token.empty()) {
		return std::nullopt;
	}
	try {
		auto decoded = jwt::decode<TraitsT>(std::string(token));
		JwtParsed out;
		ExtractHeader(decoded, out);
		ExtractStandardPayload(decoded, out);
		ExtractScopes(decoded, out);
		return out;
	} catch (...) {
		// jwt-cpp throws on malformed input (wrong segment count, bad
		// base64url, non-JSON content). We map all of those to nullopt so
		// callers can treat parse failure uniformly.
		return std::nullopt;
	}
}

} // namespace quack_oauth
