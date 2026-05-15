#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "decision_cache.hpp"
#include "http_client.hpp"
#include "jwks_cache.hpp"
#include "jwt_verify.hpp"

namespace quack_oauth {

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
	std::string expected_audience;
};

// Validate a JWT end-to-end via JWKS-local verification:
//   1. Parse the token, extract `kid`.
//   2. Look up the `kid` in the cache.
//      - Hit: verify against the cached JWK.
//      - Miss: fetch the JWKS via `ctx.http.Get(ctx.jwks_uri)`, parse it into
//        the cache, then verify against the newly-cached JWK.
//      - RateLimited: do not fetch; return `UnknownKid` so the caller's
//        rate-limit window (R-S-4) is honoured.
//   3. The token's `alg` is rejected early per R-S-3 (`none` / HS*); the
//      `JwksFetchFailed` path is only taken when the cache says Miss and the
//      HTTP call cannot be completed or returns non-200.
//
// Side effects: on success, `ctx.jwks_cache` is updated with every key from
// the fetched JWKS. On a fetch that does not contain the target `kid`, the
// cache records a miss so subsequent calls within the rate-limit window
// short-circuit.
VerifyResult ValidateToken(std::string_view token, const VerifyOptions &opts, ValidateContext &ctx);

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
