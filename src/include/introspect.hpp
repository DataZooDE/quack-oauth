#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "http_client.hpp"

namespace quack_oauth {

// Parsed RFC 7662 token-introspection response. The IdP returns at least
// `active`; remaining fields are populated when present.
struct IntrospectionResponse {
	bool active = false;
	std::string subject;                // sub
	std::string issuer;                 // iss
	std::vector<std::string> audience;  // aud (string or array)
	std::string scope;                  // RFC 7662 §2.2 -- space-delimited
	std::vector<std::string> scp;       // some IdPs (Entra) use array form
	std::int64_t exp = 0;
	std::int64_t iat = 0;
	std::int64_t nbf = 0;
	std::string client_id;
	std::string username;
};

// Parse the JSON body of an RFC 7662 response. Returns `nullopt` only if the
// input isn't JSON or `active` is missing/non-boolean -- those are the only
// schema requirements RFC 7662 imposes.
std::optional<IntrospectionResponse>
ParseIntrospectionResponse(std::string_view json);

// POST to a token-introspection endpoint per RFC 7662. Returns the parsed
// response (which may carry `active=false`), or `nullopt` if the call could
// not complete (transport error, non-200, malformed JSON, missing `active`).
//
// Body shape: `token=<urlencoded token>` (+ optional
// `token_type_hint=access_token`), content-type
// `application/x-www-form-urlencoded`. Confidential-client auth via HTTP
// Basic with the supplied `client_id` / `client_secret`.
std::optional<IntrospectionResponse>
IntrospectToken(IHttpClient &http, const std::string &endpoint,
                const std::string &client_id, const std::string &client_secret,
                std::string_view token);

} // namespace quack_oauth
