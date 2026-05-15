#pragma once

#include <string>
#include <string_view> // IWYU pragma: keep

namespace quack_oauth {

// Sensitive-field redaction for structured logging.
//
// Returns an 8-hex-character prefix of the SHA-256 of `value`, used in
// log output anywhere we would otherwise leak a token, client secret,
// authorization code, or similar credential.
//
// The full token is never returned. An empty input yields an empty
// string (so log lines remain compact when a field is genuinely absent
// rather than redacted).
//
// See docs/IMPLEMENTATION.md section 5 for the surrounding policy and
// architecture.md section 8.2 for the design rationale.
std::string RedactSensitive(std::string_view value);

// Field-name allowlist: returns true if logging a field with this name
// MUST first be passed through RedactSensitive.
//
// Names are compared case-insensitively. The current set is:
//   token, access_token, refresh_token, id_token,
//   client_secret, password, code.
bool IsSensitiveField(std::string_view field_name);

} // namespace quack_oauth
