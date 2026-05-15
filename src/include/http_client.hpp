#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace quack_oauth {

// Abstract HTTP client used by the validator orchestration. The concrete
// native implementation lives in a separate translation unit so this header
// stays Catch2-testable (no DuckDB / httplib / OpenSSL transitive includes).
//
// Method coverage is intentionally minimal: the validator only needs GET for
// JWKS retrieval in S-7b. POST (introspection, token endpoint) will be added
// to this interface when slice S-10 lands.
class IHttpClient {
public:
	struct Response {
		int status_code = 0;
		std::string body;
	};

	// Request shape for `Post`. We keep this struct-based rather than a
	// param-explosion so adding optional headers later doesn't break callers.
	struct PostRequest {
		std::string url;
		std::string body;
		std::string content_type;
		// HTTP Basic credentials. Both empty = no Authorization header.
		// RFC 7662 confidential clients authenticate to the introspection
		// endpoint with `client_id:client_secret` in HTTP Basic.
		std::string basic_user;
		std::string basic_pass;
	};

	virtual ~IHttpClient() = default;

	// Issue a GET. Returns `nullopt` if the request could not be sent at all
	// (DNS failure, connection refused, TLS handshake error, …). A non-2xx
	// HTTP response is returned as a populated `Response` with the
	// corresponding `status_code` -- callers decide what to do with it.
	virtual std::optional<Response> Get(std::string_view url) = 0;

	// Issue a POST. Same error semantics as `Get`. The default returns
	// `nullopt` so legacy callers that don't override compile; concrete
	// implementations should provide a real implementation.
	virtual std::optional<Response> Post(const PostRequest &) { return std::nullopt; }
};

} // namespace quack_oauth
