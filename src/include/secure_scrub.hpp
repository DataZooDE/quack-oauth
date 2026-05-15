#pragma once

#include <string>

namespace quack_oauth {

// R-N-3: zero out the storage backing `s` so the bytes don't linger in
// freed heap after the std::string is reused. Uses OPENSSL_cleanse so the
// compiler can't optimise the write away. Empties `s` on return.
//
// Architectural note: our DecisionCache stores SHA-256 *hashes* of tokens
// as keys, never raw tokens. The places where a raw token actually lives
// in memory are short-lived per-row locals inside check_token's
// ValidateChunk lambdas (and inside introspect/tokeninfo HTTP request
// bodies). This helper exists for defence-in-depth on those locals.
void SecureScrub(std::string &s);

} // namespace quack_oauth
