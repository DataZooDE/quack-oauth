#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "http_client.hpp"

namespace quack_oauth {

// Parsed Google `tokeninfo` response. Distinct from `IntrospectionResponse`
// because Google's tokeninfo is NOT RFC 7662 -- there's no `active` field
// (presence/absence is signalled by HTTP status), numeric claims come back
// as JSON strings, and the field set is Google-specific.
//
// `active` is synthesised by the caller: true when tokeninfo returns 200,
// false on 400 (invalid_token).
struct TokeninfoResponse {
	bool active = false;
	std::string azp;     // service-account or OAuth client unique id
	std::string aud;     // for service-account tokens, equals `azp`
	std::string subject; // `sub`; empty for service-account tokens
	std::string scope;   // space-delimited
	std::int64_t exp = 0;
	std::int64_t expires_in = 0;
	std::string email;
	bool email_verified = false;
};

// Parse the JSON body of a Google tokeninfo response. The `active` argument
// is synthesised by the caller from the HTTP status -- this parser doesn't
// look at status itself.
//
// Returns nullopt only if the input isn't JSON. Google's tokeninfo MUST
// return at least `aud` and `azp` on success; we don't enforce field
// presence here -- the caller decides.
std::optional<TokeninfoResponse> ParseTokeninfoResponse(std::string_view json, bool active);

// Validate an opaque Google access token via the tokeninfo endpoint. POSTs
// `access_token=<urlencoded>` (no Basic auth -- Google's tokeninfo is
// open). Returns the parsed response with `active` derived from HTTP status:
//   200 → active=true, fields populated
//   400 → active=false, fields empty
//   else → nullopt (transport failure)
std::optional<TokeninfoResponse> QueryTokeninfo(IHttpClient &http, const std::string &endpoint, std::string_view token);

} // namespace quack_oauth
