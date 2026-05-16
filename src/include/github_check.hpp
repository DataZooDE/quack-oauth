#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "decision_cache.hpp" // Principal
#include "http_client.hpp"
#include "jwt_verify.hpp" // VerifyResult

namespace quack_oauth {

// R-S-13: GitHub is not OIDC and does not implement RFC 7662 introspection.
// Validation goes through GitHub's bespoke "Check a token" endpoint:
//
//   POST {check_url}                                e.g. https://api.github.com/applications/{client_id}/token
//   Authorization: Basic base64(client_id:client_secret)
//   Content-Type: application/json
//   { "access_token": "<the token to validate>" }
//
// 200 → token is valid, body has the user record + scopes.
// 404 → token is unknown / revoked. Mapped to InvalidSignature (the
//       token was rejected by GitHub for this App).
// 401 / 403 → the App's introspect credentials are wrong. Mapped to
//       JwksFetchFailed -- this is an operator-config error, not a
//       token-level rejection, so the audit reason
//       (`jwks_fetch_failed`) points the operator at their config
//       instead of blaming the client. Matches how the RFC 7662
//       introspect path reports the same failure mode.
// 5xx or transport error → JwksFetchFailed (retryable).
//
// Principal mapping (per R-S-13):
//   user.id    → subject (prefixed `gh:`)
//   user.login → preferred_username       (-- not surfaced as a Principal
//                                            field; stored as a separate
//                                            entry in extra claims if needed)
//   scopes[]   → scopes
//   user.email → email                    (-- same caveat as login)

struct GithubContext {
	IHttpClient &http;
	DecisionCache &decision_cache;
	std::string check_url; // https://api.github.com/applications/{client_id}/token
	std::string client_id; // for HTTP Basic
	std::string client_secret;
};

// Parse the JSON body of a successful GitHub "check a token" response.
// Returns nullopt for malformed JSON or a missing `user.id`.
std::optional<Principal> ParseGithubCheckResponse(std::string_view json);

// Make the HTTP call and map its outcome to a VerifyResult. When
// `out_principal` is non-null AND the result is Ok, it is filled from the
// parsed response.
//
// Positive decisions are cached in `ctx.decision_cache` keyed on SHA-256 of
// the token, just like the tokeninfo / introspect paths. Negative outcomes
// are never cached -- a revoked token may flip back to valid only after
// re-issue, but caching a 404 would lock out the new token for the cache's
// TTL.
VerifyResult ValidateTokenViaGithubCheck(std::string_view token, const VerifyOptions &opts, GithubContext &ctx,
                                         Principal *out_principal);

} // namespace quack_oauth
