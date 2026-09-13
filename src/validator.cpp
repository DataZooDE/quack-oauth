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

static bool AudienceMatches(const std::vector<std::string> &actual, const std::string &expected) {
	if (expected.empty()) {
		return true;
	}
	return std::find(actual.begin(), actual.end(), expected) != actual.end();
}

static bool SignatureMatchesCandidate(VerifyResult res) noexcept {
	return res == VerifyResult::Ok || res == VerifyResult::Expired || res == VerifyResult::NotYetValid ||
	       res == VerifyResult::WrongIssuer || res == VerifyResult::WrongAudience;
}

static bool JwkMatchesTokenHeader(const Jwk &k, const std::string &token_alg) noexcept {
	if (!k.use.empty() && k.use != "sig") {
		return false;
	}
	if (!k.alg.empty() && k.alg != token_alg) {
		return false;
	}
	return true;
}

static bool JwkMaterialDiffers(const Jwk &a, const Jwk &b) noexcept {
	if (a.kty != b.kty) {
		return true;
	}
	if (a.kty == "RSA") {
		return a.n != b.n || a.e != b.e;
	}
	return a.crv != b.crv || a.x != b.x || a.y != b.y;
}

static bool IsCachedKeyUnusable(VerifyResult res) noexcept {
	return res == VerifyResult::InvalidSignature || res == VerifyResult::Malformed ||
	       res == VerifyResult::UnsupportedKeyType;
}

static std::optional<VerifyResult> TryRefreshRotatedKid(std::string_view token, const std::string &kid,
                                                        const std::string &token_alg, const Jwk &cached_key,
                                                        const VerifyOptions &opts, ValidateContext &ctx) {
	const auto reservation_id = ctx.jwks_cache.TryReserveRefresh(kid, opts.now_s);
	if (reservation_id == 0) {
		if (ctx.on_refresh) {
			ctx.on_refresh(kid, "refresh_throttled", token);
		}
		return std::nullopt;
	}

	// A provider may rotate key material while reusing the same kid. One
	// rate-limited refresh lets a valid token recover without allowing
	// forged tokens to turn every verification into a JWKS request.
	const auto refresh = ctx.http.Get(ctx.jwks_uri);
	if (!refresh.has_value() || refresh->status_code != 200) {
		if (ctx.on_refresh) {
			ctx.on_refresh(kid, "refresh_fetch_failed", token);
		}
		return std::nullopt;
	}

	const auto keys = ParseJwksJson(refresh->body);
	if (keys.empty()) {
		if (ctx.on_refresh) {
			ctx.on_refresh(kid, "refresh_parse_failed", token);
		}
		return std::nullopt;
	}

	std::vector<const Jwk *> candidates;
	for (const auto &k : keys) {
		if (k.kid == kid && JwkMatchesTokenHeader(k, token_alg)) {
			candidates.push_back(&k);
		}
	}
	if (candidates.empty()) {
		if (ctx.on_refresh) {
			ctx.on_refresh(kid, "refresh_kid_absent", token);
		}
		return std::nullopt;
	}

	const Jwk *verified_jwk = nullptr;
	VerifyResult verified_result = VerifyResult::InvalidSignature;
	const Jwk *new_valid_key = nullptr;

	for (const auto *cand : candidates) {
		const auto cand_result = VerifyWithCachedKey(token, *cand, opts);
		if (SignatureMatchesCandidate(cand_result)) {
			verified_jwk = cand;
			verified_result = cand_result;
			break;
		}
		if (cand_result == VerifyResult::InvalidSignature && JwkMaterialDiffers(*cand, cached_key)) {
			if (new_valid_key == nullptr) {
				new_valid_key = cand;
			}
		}
	}

	if (verified_jwk != nullptr) {
		const bool committed = ctx.jwks_cache.CommitRefresh(kid, reservation_id, *verified_jwk, opts.now_s);
		if (ctx.on_refresh) {
			ctx.on_refresh(kid, committed ? "rotated_key_refreshed" : "refresh_superseded", token);
		}
		return verified_result;
	}

	// Even if the presenting token didn't verify (e.g. forged or stale token),
	// if the IdP served new valid key material for this kid over TLS, commit it to prevent
	// forged tokens from starving rotation recovery (resolving F2 / F-A).
	if (new_valid_key != nullptr) {
		const bool committed = ctx.jwks_cache.CommitRefresh(kid, reservation_id, *new_valid_key, opts.now_s);
		if (ctx.on_refresh) {
			ctx.on_refresh(kid, committed ? "rotated_key_refreshed" : "refresh_superseded", token);
		}
		return VerifyWithCachedKey(token, *new_valid_key, opts);
	}

	if (ctx.on_refresh) {
		ctx.on_refresh(kid, "refresh_no_candidate", token);
	}
	return std::nullopt;
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
		const auto cached_result = VerifyWithCachedKey(token, *first_lookup.jwk, opts);
		if (!IsCachedKeyUnusable(cached_result)) {
			return cached_result;
		}
		if (const auto refreshed =
		        TryRefreshRotatedKid(token, parsed->kid, parsed->alg, *first_lookup.jwk, opts, ctx)) {
			return *refreshed;
		}
		return cached_result;
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

	const auto keys = ParseJwksJson(resp->body);
	if (keys.empty()) {
		ctx.jwks_cache.OnFetchMiss(parsed->kid, opts.now_s);
		return VerifyResult::UnknownKid;
	}

	std::vector<const Jwk *> candidates;
	for (const auto &k : keys) {
		if (k.kid == parsed->kid && JwkMatchesTokenHeader(k, parsed->alg)) {
			candidates.push_back(&k);
		}
	}
	if (candidates.empty()) {
		for (const auto &k : keys) {
			if (!k.use.empty() && k.use != "sig") {
				continue;
			}
			ctx.jwks_cache.OnFetchSuccess(k, opts.now_s);
		}
		ctx.jwks_cache.OnFetchMiss(parsed->kid, opts.now_s);
		return VerifyResult::UnknownKid;
	}

	for (const auto &k : keys) {
		if (k.kid != parsed->kid) {
			if (!k.use.empty() && k.use != "sig") {
				continue;
			}
			ctx.jwks_cache.OnFetchSuccess(k, opts.now_s);
		}
	}

	const Jwk *verified_jwk = nullptr;
	VerifyResult verified_result = VerifyResult::InvalidSignature;
	for (const auto *cand : candidates) {
		const auto cand_result = VerifyWithCachedKey(token, *cand, opts);
		if (SignatureMatchesCandidate(cand_result)) {
			verified_jwk = cand;
			verified_result = cand_result;
			break;
		}
	}
	if (verified_jwk != nullptr) {
		ctx.jwks_cache.OnFetchSuccess(*verified_jwk, opts.now_s);
		return verified_result;
	}

	// Do NOT cache unverified candidates.front() on cache miss (F3).
	ctx.jwks_cache.OnFetchMiss(parsed->kid, opts.now_s);
	return VerifyResult::InvalidSignature;
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
