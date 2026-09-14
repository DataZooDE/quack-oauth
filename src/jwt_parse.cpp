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

static bool ExtractHeader(const jwt::decoded_jwt<TraitsT> &decoded, JwtParsed &out) {
	if (decoded.has_algorithm()) {
		out.alg = decoded.get_algorithm();
	}
	if (decoded.has_key_id()) {
		out.kid = decoded.get_key_id();
		if (out.kid.size() > 256) {
			return false;
		}
		for (char c : out.kid) {
			const auto uc = static_cast<unsigned char>(c);
			if (uc < 32 || uc == 127) {
				return false;
			}
		}
	}
	if (decoded.has_type()) {
		out.typ = decoded.get_type();
	}
	return true;
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
	// `roles` (Entra app roles, Auth0 RBAC): array of strings. Required
	// for client_credentials flows -- those tokens carry NO `scope`/`scp`,
	// only `roles` from the App registration's "App roles" definitions.
	if (decoded.has_payload_claim("roles")) {
		const auto claim = decoded.get_payload_claim("roles");
		if (claim.get_type() == jwt::json::type::array) {
			for (const auto &v : claim.as_array()) {
				if (v.is<std::string>()) {
					out.roles.push_back(v.get<std::string>());
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
		if (!ExtractHeader(decoded, out)) {
			return std::nullopt;
		}
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

static inline bool IsAsciiSpace(char c) noexcept {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

std::string_view StripBearerPrefix(std::string_view auth) noexcept {
	while (!auth.empty() && IsAsciiSpace(auth.front())) {
		auth.remove_prefix(1);
	}
	if (auth.size() >= 6) {
		const char b[] = {'b', 'e', 'a', 'r', 'e', 'r'};
		bool matches = true;
		for (size_t i = 0; i < 6; ++i) {
			if (static_cast<char>(tolower(static_cast<unsigned char>(auth[i]))) != b[i]) {
				matches = false;
				break;
			}
		}
		if (matches && (auth.size() == 6 || IsAsciiSpace(auth[6]))) {
			auth.remove_prefix(6);
			while (!auth.empty() && IsAsciiSpace(auth.front())) {
				auth.remove_prefix(1);
			}
		}
	}
	while (!auth.empty() && IsAsciiSpace(auth.back())) {
		auth.remove_suffix(1);
	}
	return auth;
}

} // namespace quack_oauth
