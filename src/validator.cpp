#include "validator.hpp"

#include <algorithm>
#include <string>

#include "decision_cache.hpp"
#include "introspect.hpp"
#include "jwks_parse.hpp"
#include "jwt_parse.hpp"
#include "tokeninfo.hpp"

namespace quack_oauth {

static bool StartsWith(const std::string &s, const std::string &prefix) {
	return s.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), s.begin());
}

static bool IsForbiddenAlgorithm(const std::string &alg) {
	return alg.empty() || alg == "none" || StartsWith(alg, "HS");
}

static bool IsAllowed(const std::string &alg, const std::vector<std::string> &whitelist) {
	static const std::vector<std::string> kDefault = {"RS256", "RS384", "RS512"};
	const auto &use = whitelist.empty() ? kDefault : whitelist;
	return std::find(use.begin(), use.end(), alg) != use.end();
}

static VerifyResult VerifyWithCachedKey(std::string_view token, const Jwk &jwk, const VerifyOptions &opts) {
	return VerifyJwt(token, jwk, opts);
}

// Returns true iff the kid landed in the cache after a fetch + parse.
static bool IngestJwks(const std::string &kid, const std::string &body, std::int64_t now_s, JwksCache &cache) {
	const auto keys = ParseJwksJson(body);
	if (keys.empty()) {
		return false;
	}
	bool found = false;
	for (const auto &k : keys) {
		cache.OnFetchSuccess(k, now_s);
		if (k.kid == kid) {
			found = true;
		}
	}
	return found;
}

static bool AudienceMatches(const std::vector<std::string> &actual, const std::string &expected) {
	if (expected.empty()) {
		return true;
	}
	return std::find(actual.begin(), actual.end(), expected) != actual.end();
}

VerifyResult ValidateToken(std::string_view token, const VerifyOptions &opts, ValidateContext &ctx) {
	const auto parsed = ParseJwt(token);
	if (!parsed) {
		return VerifyResult::Malformed;
	}

	// Reject forbidden algorithms before any cache or HTTP work (R-S-3).
	if (IsForbiddenAlgorithm(parsed->alg) || !IsAllowed(parsed->alg, opts.allowed_algorithms)) {
		return VerifyResult::DisallowedAlgorithm;
	}

	if (parsed->kid.empty()) {
		// We require `kid` to look up the right JWK. Tokens without a kid
		// cannot be served deterministically against a rotating IdP key set.
		return VerifyResult::UnknownKid;
	}

	const auto first_lookup = ctx.jwks_cache.Lookup(parsed->kid, opts.now_s);
	if (first_lookup.status == JwksLookupStatus::Hit) {
		return VerifyWithCachedKey(token, *first_lookup.jwk, opts);
	}
	if (first_lookup.status == JwksLookupStatus::RateLimited) {
		// Within the per-kid rate-limit window (R-S-4) -- do not refetch.
		return VerifyResult::UnknownKid;
	}

	// Cache miss: try to fetch the JWKS.
	const auto resp = ctx.http.Get(ctx.jwks_uri);
	if (!resp.has_value() || resp->status_code != 200) {
		return VerifyResult::JwksFetchFailed;
	}

	const bool kid_present = IngestJwks(parsed->kid, resp->body, opts.now_s, ctx.jwks_cache);
	if (!kid_present) {
		ctx.jwks_cache.OnFetchMiss(parsed->kid, opts.now_s);
		return VerifyResult::UnknownKid;
	}

	const auto second_lookup = ctx.jwks_cache.Lookup(parsed->kid, opts.now_s);
	if (second_lookup.status != JwksLookupStatus::Hit) {
		// Defensive: IngestJwks reported the kid landed, but the cache
		// disagrees. Treat as UnknownKid rather than crashing.
		return VerifyResult::UnknownKid;
	}
	return VerifyWithCachedKey(token, *second_lookup.jwk, opts);
}

VerifyResult ValidateTokenViaTokeninfo(std::string_view token, const VerifyOptions &opts, TokeninfoContext &ctx,
                                       Principal *out_principal) {
	if (token.empty()) {
		return VerifyResult::Malformed;
	}

	const auto key = DecisionCache::KeyOf(std::string(token));
	if (const auto cached = ctx.decision_cache.Lookup(key, opts.now_s)) {
		if (out_principal != nullptr) {
			*out_principal = *cached;
		}
		return VerifyResult::Ok;
	}

	const auto resp = QueryTokeninfo(ctx.http, ctx.endpoint, token);
	if (!resp.has_value()) {
		// Transport failure / 5xx -- treat as fetch failure.
		return VerifyResult::JwksFetchFailed;
	}
	if (!resp->active) {
		// Google's tokeninfo returns HTTP 400 for invalid/revoked tokens;
		// our QueryTokeninfo surfaces those as active=false.
		return VerifyResult::InvalidSignature;
	}

	// Audience check: for Google service-account tokens, `aud == azp` and
	// both equal the service account's unique numeric id. Accept a match
	// against either.
	if (!ctx.expected_audience.empty()) {
		if (resp->aud != ctx.expected_audience && resp->azp != ctx.expected_audience) {
			return VerifyResult::WrongAudience;
		}
	}

	// Exp check with clock skew.
	if (resp->exp > 0 && opts.now_s > resp->exp + opts.clock_skew_s) {
		return VerifyResult::Expired;
	}

	Principal p;
	p.subject = resp->subject.empty() ? resp->azp : resp->subject;
	if (!resp->scope.empty()) {
		std::size_t start = 0;
		while (start < resp->scope.size()) {
			auto end = resp->scope.find(' ', start);
			if (end == std::string::npos)
				end = resp->scope.size();
			if (end > start) {
				p.scopes.emplace_back(resp->scope.substr(start, end - start));
			}
			start = end + 1;
		}
	}
	p.exp = resp->exp;
	ctx.decision_cache.Store(key, p, opts.now_s);
	if (out_principal != nullptr) {
		*out_principal = p;
	}
	return VerifyResult::Ok;
}

VerifyResult ValidateTokenViaIntrospection(std::string_view token, const VerifyOptions &opts, IntrospectContext &ctx,
                                           Principal *out_principal) {
	if (token.empty()) {
		return VerifyResult::Malformed;
	}

	// Decision cache short-circuits the IdP round-trip (R-S-5, R-N-6 hot
	// path target). Keyed on sha256(token); TTL was capped at exp on Store.
	const auto key = DecisionCache::KeyOf(std::string(token));
	if (const auto cached = ctx.decision_cache.Lookup(key, opts.now_s)) {
		if (out_principal != nullptr) {
			*out_principal = *cached;
		}
		return VerifyResult::Ok;
	}

	const auto resp = IntrospectToken(ctx.http, ctx.endpoint, ctx.client_id, ctx.client_secret, token);
	if (!resp.has_value()) {
		// Transport, non-200, malformed -- treat as fetch failure rather
		// than InvalidSignature (we couldn't determine signature validity).
		return VerifyResult::JwksFetchFailed;
	}
	if (!resp->active) {
		// Hard reject per R-S-5. We deliberately don't cache negative
		// decisions: a token may flip active=true→false during its
		// lifetime (revocation) but not the other direction, so caching
		// a no would risk locking out a revoked-then-reissued token. The
		// positive cache is enough for the perf target.
		return VerifyResult::InvalidSignature;
	}

	// iss / aud checks against the introspect response. They're advisory
	// when the IdP doesn't return them.
	if (!ctx.expected_issuer.empty() && !resp->issuer.empty() && resp->issuer != ctx.expected_issuer) {
		return VerifyResult::WrongIssuer;
	}
	if (!ctx.expected_audience.empty() && !resp->audience.empty() &&
	    !AudienceMatches(resp->audience, ctx.expected_audience)) {
		return VerifyResult::WrongAudience;
	}

	Principal p;
	p.subject = resp->subject;
	p.issuer = resp->issuer;
	if (!resp->scope.empty()) {
		// Split space-delimited per RFC 6749 §3.3.
		std::size_t start = 0;
		while (start < resp->scope.size()) {
			auto end = resp->scope.find(' ', start);
			if (end == std::string::npos)
				end = resp->scope.size();
			if (end > start) {
				p.scopes.emplace_back(resp->scope.substr(start, end - start));
			}
			start = end + 1;
		}
	}
	for (const auto &s : resp->scp) {
		p.scopes.push_back(s);
	}
	p.exp = resp->exp;

	ctx.decision_cache.Store(key, p, opts.now_s);
	if (out_principal != nullptr) {
		*out_principal = p;
	}
	return VerifyResult::Ok;
}

} // namespace quack_oauth
