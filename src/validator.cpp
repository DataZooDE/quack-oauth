// Trust policy for JWKS key caching and validation:
// 1. TLS-fetched JWKS material is authoritative and synchronizes cached keys per kid (F1).
// 2. Multi-key verification supports overlapping keys during IdP rotation (F1).
// 3. A (kid, alg) pair with a usable candidate in the fetched JWKS is never negative-cached (F3, F4).
// 4. Outbound JWKS HTTP fetches are rate-limited per kid and bounded globally across all paths (F2, F3, F7).

#include "validator.hpp"

#include <algorithm>
#include <string>
#include <unordered_map>

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

static bool IsCachedKeyUnusable(VerifyResult res) noexcept {
	return res == VerifyResult::InvalidSignature || res == VerifyResult::UnusableKey;
}

static VerifyResult VerifyWithCachedKeys(std::string_view token, const std::vector<Jwk> &keys,
                                         const VerifyOptions &opts) {
	if (keys.empty()) {
		return VerifyResult::UnknownKid;
	}
	bool all_unsupported = true;
	bool saw_invalid_sig = false;
	VerifyResult fallback_failure = VerifyResult::InvalidSignature;
	for (const auto &k : keys) {
		const auto res = VerifyJwt(token, k, opts);
		if (SignatureMatchesCandidate(res)) {
			return res;
		}
		if (res == VerifyResult::InvalidSignature) {
			saw_invalid_sig = true;
		} else if (res != VerifyResult::UnsupportedKeyType) {
			all_unsupported = false;
			fallback_failure = res;
		}
	}
	if (saw_invalid_sig) {
		return VerifyResult::InvalidSignature;
	}
	if (all_unsupported) {
		return VerifyResult::UnsupportedKeyType;
	}
	return fallback_failure;
}

static std::vector<Jwk> MatchingKeys(const std::vector<Jwk> &keys, const std::string &alg) {
	std::vector<Jwk> matching;
	for (const auto &k : keys) {
		if (JwkMatchesTokenHeader(k, alg)) {
			matching.push_back(k);
		}
	}
	return matching;
}

static VerifyResult VerifyAgainstCachedKid(std::string_view token, const std::string &alg,
                                           const std::vector<Jwk> &cached_keys, const VerifyOptions &opts) {
	const auto matching = MatchingKeys(cached_keys, alg);
	if (matching.empty()) {
		return VerifyResult::InvalidSignature;
	}
	return VerifyWithCachedKeys(token, matching, opts);
}

static std::unordered_map<std::string, std::vector<Jwk>> GroupSigningKeysByKid(const std::vector<Jwk> &keys) {
	std::unordered_map<std::string, std::vector<Jwk>> keys_by_kid;
	for (const auto &k : keys) {
		if (k.use.empty() || k.use == "sig") {
			keys_by_kid[k.kid].push_back(k);
		}
	}
	return keys_by_kid;
}

static std::vector<Jwk> ScreenUsableKeys(const std::vector<Jwk> &raw_keys) {
	std::vector<Jwk> valid;
	for (const auto &cand : raw_keys) {
		if (IsUsableSigningKey(cand)) {
			valid.push_back(cand);
		}
	}
	return valid;
}

static std::optional<VerifyResult> SelectAndVerify(std::string_view token, const std::string &token_alg,
                                                   const std::vector<Jwk> &candidates, const VerifyOptions &opts) {
	for (const auto &cand : candidates) {
		if (JwkMatchesTokenHeader(cand, token_alg)) {
			const auto res = VerifyJwt(token, cand, opts);
			if (SignatureMatchesCandidate(res)) {
				return res;
			}
		}
	}
	return std::nullopt;
}

static bool CommitAndAudit(const std::string &kid, uint64_t reservation_id, const std::vector<Jwk> &candidates,
                           const std::vector<Jwk> &cached_keys, int64_t now_s, ValidateContext &ctx,
                           RefreshEvent *out_refresh) {
	bool has_new_material = false;
	for (const auto &cand : candidates) {
		bool matches_existing = false;
		for (const auto &cached : cached_keys) {
			if (SameKeyMaterial(cand, cached)) {
				matches_existing = true;
				break;
			}
		}
		if (!matches_existing) {
			has_new_material = true;
			break;
		}
	}
	bool has_removed_material = false;
	for (const auto &cached : cached_keys) {
		bool matches_candidate = false;
		for (const auto &cand : candidates) {
			if (SameKeyMaterial(cand, cached)) {
				matches_candidate = true;
				break;
			}
		}
		if (!matches_candidate) {
			has_removed_material = true;
			break;
		}
	}

	const bool committed = ctx.jwks_cache.CommitRefresh(kid, reservation_id, candidates, now_s);
	if (out_refresh) {
		out_refresh->kid = kid;
		if (committed) {
			if (has_new_material) {
				out_refresh->reason = kReasonRefreshRotated;
			} else if (has_removed_material) {
				out_refresh->reason = kReasonRefreshRevoked;
			} else {
				out_refresh->reason = kReasonRefreshNoRotation;
			}
		} else {
			out_refresh->reason = kReasonRefreshSuperseded;
		}
	}
	return committed;
}

static void IngestSiblingKeys(const std::unordered_map<std::string, std::vector<Jwk>> &keys_by_kid,
                              const std::string &target_kid, int64_t now_s, ValidateContext &ctx) {
	for (const auto &[s_kid, s_keys] : keys_by_kid) {
		if (s_kid != target_kid) {
			const auto usable = ScreenUsableKeys(s_keys);
			if (!usable.empty()) {
				ctx.jwks_cache.OnPassiveFetchSuccess(s_kid, usable, now_s);
			}
		}
	}
}

static std::optional<VerifyResult> TryRefreshRotatedKid(std::string_view token, const std::string &kid,
                                                        const std::string &token_alg,
                                                        const std::vector<Jwk> &cached_keys, const VerifyOptions &opts,
                                                        ValidateContext &ctx, RefreshEvent *out_refresh) {
	if (!ctx.jwks_cache.CanFetchJwks(opts.now_s)) {
		ctx.jwks_cache.IncrementThrottledRefreshes();
		if (out_refresh) {
			out_refresh->kid = kid;
			out_refresh->reason = kReasonRefreshBudgetThrottled;
		}
		return std::nullopt;
	}

	const auto reservation_id = ctx.jwks_cache.TryReserveRefresh(kid, opts.now_s);
	if (reservation_id == 0) {
		ctx.jwks_cache.IncrementThrottledRefreshes();
		if (out_refresh) {
			out_refresh->kid = kid;
			out_refresh->reason = kReasonRefreshThrottled;
		}
		return std::nullopt;
	}

	ctx.jwks_cache.RecordJwksFetch(opts.now_s);

	const auto refresh = ctx.http.Get(ctx.jwks_uri);
	if (!refresh.has_value() || refresh->status_code != 200) {
		if (out_refresh) {
			out_refresh->kid = kid;
			out_refresh->reason = kReasonRefreshFetchFailed;
		}
		return std::nullopt;
	}

	const auto keys = ParseJwksJson(refresh->body);
	if (keys.empty()) {
		if (out_refresh) {
			out_refresh->kid = kid;
			out_refresh->reason = kReasonRefreshParseFailed;
		}
		return std::nullopt;
	}

	const auto keys_by_kid = GroupSigningKeysByKid(keys);
	const auto cand_it = keys_by_kid.find(kid);

	// Target kid commit under active reservation MUST happen before sibling ingest (F7)
	bool target_committed = false;
	std::vector<Jwk> candidates_for_kid;
	if (cand_it != keys_by_kid.end()) {
		candidates_for_kid = ScreenUsableKeys(cand_it->second);
		if (!candidates_for_kid.empty()) {
			// If there are multiple candidates, prioritize any candidate that verifies this token (F8)
			if (candidates_for_kid.size() > 1) {
				for (std::size_t i = 0; i < candidates_for_kid.size(); ++i) {
					std::vector<Jwk> single = {candidates_for_kid[i]};
					if (SelectAndVerify(token, token_alg, single, opts) == VerifyResult::Ok) {
						if (i > 0) {
							std::swap(candidates_for_kid[0], candidates_for_kid[i]);
						}
						break;
					}
				}
			}
			target_committed =
			    CommitAndAudit(kid, reservation_id, candidates_for_kid, cached_keys, opts.now_s, ctx, out_refresh);
		} else if (out_refresh) {
			out_refresh->kid = kid;
			out_refresh->reason = kReasonRefreshParseFailed;
		}
	} else {
		// Target kid is completely absent from 200 OK document: authoritatively evict (F2)
		ctx.jwks_cache.EvictReserved(kid, reservation_id);
		if (out_refresh) {
			out_refresh->kid = kid;
			out_refresh->reason = kReasonRefreshKidAbsent;
		}
	}

	IngestSiblingKeys(keys_by_kid, kid, opts.now_s, ctx);

	// Recheck cache for kid and verify ONLY against keys actually committed (F1, F8)
	const auto recheck = ctx.jwks_cache.Lookup(kid, opts.now_s);
	if (recheck.status == JwksLookupStatus::Hit && !recheck.keys.empty()) {
		const auto verified_result = SelectAndVerify(token, token_alg, recheck.keys, opts);
		if (verified_result.has_value()) {
			return *verified_result;
		}
	}

	// Presenting token did not verify with committed keys (or commit was refused/superseded).
	return VerifyResult::InvalidSignature;
}

VerifyResult ValidateToken(std::string_view token, const VerifyOptions &opts, ValidateContext &ctx,
                           RefreshEvent *out_refresh) {
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
		const auto matching = MatchingKeys(first_lookup.keys, parsed->alg);
		VerifyResult cached_result = VerifyResult::InvalidSignature;
		if (!matching.empty()) {
			cached_result = VerifyWithCachedKeys(token, matching, opts);
			if (!IsCachedKeyUnusable(cached_result)) {
				return cached_result;
			}
		}
		if (const auto refreshed =
		        TryRefreshRotatedKid(token, parsed->kid, parsed->alg, first_lookup.keys, opts, ctx, out_refresh)) {
			return *refreshed;
		}
		return cached_result;
	}
	if (first_lookup.status == JwksLookupStatus::RateLimited) {
		// Within the per-kid rate-limit window (R-S-4) -- do not refetch.
		return VerifyResult::UnknownKid;
	}

	// Global fetch budget check (F4, F7, F-G):
	if (!ctx.jwks_cache.CanFetchJwks(opts.now_s)) {
		ctx.jwks_cache.IncrementThrottledRefreshes();
		if (out_refresh) {
			out_refresh->kid = parsed->kid;
			out_refresh->reason = kReasonRefreshBudgetThrottled;
		}
		return VerifyResult::JwksThrottled;
	}

	// Cache miss: record attempt before network call (F2).
	ctx.jwks_cache.RecordJwksFetch(opts.now_s);
	const auto resp = ctx.http.Get(ctx.jwks_uri);
	if (!resp.has_value() || resp->status_code != 200) {
		return VerifyResult::JwksFetchFailed;
	}

	const auto keys = ParseJwksJson(resp->body);
	if (keys.empty()) {
		ctx.jwks_cache.OnFetchMiss(parsed->kid, opts.now_s);
		return VerifyResult::UnknownKid;
	}

	const auto keys_by_kid = GroupSigningKeysByKid(keys);

	for (const auto &[k_kid, k_keys] : keys_by_kid) {
		const auto usable = ScreenUsableKeys(k_keys);
		if (!usable.empty()) {
			ctx.jwks_cache.OnPassiveFetchSuccess(k_kid, usable, opts.now_s);
		}
	}

	const auto second_lookup = ctx.jwks_cache.Lookup(parsed->kid, opts.now_s);
	if (second_lookup.status != JwksLookupStatus::Hit || second_lookup.keys.empty()) {
		ctx.jwks_cache.OnFetchMiss(parsed->kid, opts.now_s);
		return VerifyResult::UnknownKid;
	}

	return VerifyAgainstCachedKid(token, parsed->alg, second_lookup.keys, opts);
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
