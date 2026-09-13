#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "decision_cache.hpp"
#include "http_client.hpp"
#include "jwks_cache.hpp"
#include "jwt_verify.hpp"

namespace quack_oauth {

inline constexpr const char *kReasonRefreshRotated = "refresh_rotated";
inline constexpr const char *kReasonRefreshNoRotation = "refresh_no_rotation";
inline constexpr const char *kReasonRefreshThrottled = "refresh_throttled";
inline constexpr const char *kReasonRefreshBudgetThrottled = "refresh_budget_throttled";
inline constexpr const char *kReasonRefreshFetchFailed = "refresh_fetch_failed";
inline constexpr const char *kReasonRefreshParseFailed = "refresh_parse_failed";
inline constexpr const char *kReasonRefreshKidAbsent = "refresh_kid_absent";
inline constexpr const char *kReasonRefreshSuperseded = "refresh_superseded";

struct RefreshEvent {
	std::string kid;
	std::string reason;
};

// Externally-owned dependencies for `ValidateToken`. The validator does not
// own the cache or the HTTP client -- the caller passes references so the
// same cache can be reused across many `ValidateToken` calls (the whole
// point of caching).
struct ValidateContext {
	IHttpClient &http;
	JwksCache &jwks_cache;
	std::string jwks_uri;
};

// Dependencies for the introspection path. Shape parallels ValidateContext
// so the two modes look symmetric at the call site.
struct IntrospectContext {
	IHttpClient &http;
	DecisionCache &decision_cache;
	std::string endpoint;
	std::string client_id;
	std::string client_secret;
	// Expected issuer to enforce when the IdP response includes `iss`.
	// Empty disables the check.
	std::string expected_issuer;
	// Expected audience to enforce when the IdP response includes `aud`.
	// Empty disables the check.
	std::string expected_audience;
};

// Validate a JWT end-to-end via JWKS-local verification:
//   1. Parse the token, extract `kid`.
//   2. Look up the `kid` in the cache.
//      - Hit: verify against the cached JWK. On InvalidSignature, reserve one
//        rate-limited refresh, fetch JWKS, test candidates for `kid` before
//        mutating the cache, and commit on success. Concurrent valid tokens
//        arriving while a refresh is in flight see InvalidSignature until the
//        refresh commits.
//      - Miss: fetch the JWKS via `ctx.http.Get(ctx.jwks_uri)`, parse it into
//        the cache, then verify against the newly-cached JWK.
//      - RateLimited: do not fetch; return `UnknownKid` so the caller's
//        rate-limit window (R-S-4) is honoured.
//   3. The token's `alg` is rejected early per R-S-3 (`none` / HS*); the
//      `JwksFetchFailed` path is only taken when the cache says Miss and the
//      HTTP call cannot be completed or returns non-200.
//
// Side effects: on initial cache miss, `ctx.jwks_cache` ingests keys from the
// fetched JWKS. On hit-refresh for a rotated key, the verified candidate for
// the target `kid` is committed via its active reservation ID first, and
// sibling keys present in the IdP document are authoritatively synchronized.
// When an IdP fetch succeeds (200 OK), keys for the target `kid` are synchronized
// with the document. On a fetch that does not contain the target `kid`, the cache
// records a miss so subsequent calls within the rate-limit window short-circuit.
// Refresh failure or network error preserves the last-good cached keys without
// mutating the cache.
VerifyResult ValidateToken(std::string_view token, const VerifyOptions &opts, ValidateContext &ctx,
                           RefreshEvent *out_refresh = nullptr);

// Dependencies for the Google-style tokeninfo path. Parallel to
// IntrospectContext but without HTTP Basic auth (Google's tokeninfo is
// unauthenticated and rejects Basic auth headers).
struct TokeninfoContext {
	IHttpClient &http;
	DecisionCache &decision_cache;
	std::string endpoint;
	// Google's access tokens have `aud == azp == service_account_unique_id`
	// for service-account flows. Empty disables the check.
	std::string expected_audience;
};

// Validate an opaque Google-style access token via the tokeninfo endpoint:
//   1. Hash the token; look up the decision cache. Hit → Ok.
//   2. Miss → POST `access_token=<urlencoded>` to `ctx.endpoint`.
//   3. HTTP 200 with parseable body → active=true; cross-check aud / azp
//      against `ctx.expected_audience` (if set); check exp against
//      `opts.now_s` (with clock_skew); cache; return Ok.
//   4. HTTP 400 (revoked / invalid_token) → return InvalidSignature.
//   5. Transport error or other non-200 → return JwksFetchFailed.
VerifyResult ValidateTokenViaTokeninfo(std::string_view token, const VerifyOptions &opts, TokeninfoContext &ctx,
                                       Principal *out_principal = nullptr);

// Validate a JWT end-to-end via RFC 7662 introspection:
//   1. Hash the token (sha256-hex); look up the decision cache. Hit (and
//      not expired) → `Ok`.
//   2. Miss → POST to `ctx.endpoint` with HTTP Basic
//      (`ctx.client_id:ctx.client_secret`) and body
//      `token=<urlencoded token>&token_type_hint=access_token`.
//   3. `active=false` (or transport error / non-200) → return without
//      caching. `active=true` → optionally cross-check iss/aud against
//      `opts` / `ctx`, then cache for `min(default_ttl, exp - now)` and
//      return `Ok`.
VerifyResult ValidateTokenViaIntrospection(std::string_view token, const VerifyOptions &opts, IntrospectContext &ctx,
                                           Principal *out_principal = nullptr);

} // namespace quack_oauth
