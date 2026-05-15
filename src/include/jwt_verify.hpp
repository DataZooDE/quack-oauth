#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "jwks_cache.hpp"

namespace quack_oauth {

// Outcome of `VerifyJwt`. A single enum value is enough for the caller to
// produce a stable diagnostic reason code per architecture section 8.3 error
// taxonomy (`invalid_signature`, `expired`, `wrong_audience`, ...).
enum class VerifyResult {
	Ok,
	Malformed,
	DisallowedAlgorithm,
	InvalidSignature,
	Expired,
	NotYetValid,
	WrongIssuer,
	WrongAudience,
	UnsupportedKeyType,
	// Reported by the validator orchestration (slice S-7b.1); never produced
	// by the standalone `VerifyJwt` call.
	UnknownKid,
	JwksFetchFailed,
};

struct VerifyOptions {
	// When set, the token's `iss` claim MUST equal this exactly.
	std::string expected_issuer;
	// When set, the token's `aud` set MUST contain this value.
	std::string expected_audience;
	// Per R-S-3, default 60 s.
	std::int64_t clock_skew_s = 60;
	// Caller-provided wall clock in unix seconds. Required (no implicit
	// `std::chrono::system_clock::now()` -- the verifier must be deterministic
	// under Catch2).
	std::int64_t now_s = 0;
	// Allowed `alg` values. Empty means use the architecture default
	// {RS256, RS384, RS512}. `none` and HS* are rejected unconditionally per
	// R-S-3 regardless of this list.
	std::vector<std::string> allowed_algorithms;
};

// Verify a compact-serialized JWT against a JWK, applying R-S-3 algorithm
// allowlisting, claim checks (`iss`, `aud`), and time checks (`exp`, `nbf`)
// with caller-injected `now_s`.
//
// Pure logic: no I/O, no globals, no `std::chrono::system_clock::now()`.
// Supports the algorithms in R-S-3:
//   - RSA (kty=RSA): RS256 / RS384 / RS512
//   - EC  (kty=EC):  ES256 (P-256) / ES384 (P-384)
//   - OKP (kty=OKP): EdDSA (Ed25519)
VerifyResult VerifyJwt(std::string_view token, const Jwk &jwk, const VerifyOptions &opts);

// Convert an RSA JWK (`n`, `e` base64url-encoded) to a PEM-encoded
// SubjectPublicKeyInfo. Returns `std::nullopt` if `n` or `e` is empty or not
// valid base64url. Exposed publicly to keep it Catch2-testable.
std::optional<std::string> JwkRsaToPem(const Jwk &jwk);

// Convert an EC JWK (`crv` ∈ {P-256, P-384}, `x`, `y` base64url-encoded) to
// a PEM-encoded SubjectPublicKeyInfo. Returns nullopt for unsupported
// curves or malformed fields.
std::optional<std::string> JwkEcToPem(const Jwk &jwk);

// Convert an OKP JWK (`crv == "Ed25519"`, `x` base64url-encoded) to a PEM-
// encoded SubjectPublicKeyInfo. Returns nullopt for unsupported curves or
// malformed fields.
std::optional<std::string> JwkOkpToPem(const Jwk &jwk);

} // namespace quack_oauth
