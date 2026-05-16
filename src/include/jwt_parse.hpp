#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace quack_oauth {

// Result of a parse-only JWT decode. Pure data; safe to copy, no I/O.
//
// Times are unix seconds (so we can compare against `std::time(nullptr)` in
// later slices without dragging chrono types across module boundaries).
// A claim that is absent in the source token leaves its field at its
// default value (empty string, empty vector, or 0).
struct JwtParsed {
	// Header.
	std::string alg;
	std::string kid;
	std::string typ;

	// Payload (standard OIDC / OAuth 2.0 claims).
	std::string subject;               // sub
	std::string issuer;                // iss
	std::vector<std::string> audience; // aud (single string or array)
	std::int64_t exp = 0;
	std::int64_t nbf = 0;
	std::int64_t iat = 0;

	// Scope expressions: `scope` is space-delimited per RFC 6749; `scp` is
	// Microsoft Entra-style array. A token may carry one, the other, or
	// neither -- we surface both so the provider strategy table (slice S-11)
	// can normalise without re-parsing.
	std::string scope;
	std::vector<std::string> scp;

	// App-role claims from the `roles` array. Used by Entra client_credentials
	// flows (where the JWT carries no `scope`/`scp` -- only `roles`) and by
	// Auth0-style RBAC. The Principal builder merges these into `scopes` so
	// policy rules can match either delegated scopes or app roles uniformly.
	std::vector<std::string> roles;
};

// Decode a compact-serialized JWT (`header.payload.signature`).
//
// **Does not verify the signature.** Signature verification is the JWKS
// validator's job (slice S-7); this function is pure logic and is the
// foundation for both the JWKS validator and Catch2 unit testing of claim
// extraction.
//
// Returns `std::nullopt` if `token` is not a well-formed compact JWT
// (wrong segment count, non-base64url payload, non-JSON header/payload).
std::optional<JwtParsed> ParseJwt(std::string_view token);

} // namespace quack_oauth
