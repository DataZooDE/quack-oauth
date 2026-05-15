#pragma once

#include <chrono>
#include <functional>
#include <optional>
#include <string_view>

#include "http_client.hpp"

namespace quack_oauth {

// R-N-7: IHttpClient decorator that retries on transient failure.
//
// "Transient" = either nullopt (transport-layer error: DNS, connect refused,
// TLS handshake) or a 5xx HTTP response. 4xx is treated as a client-side
// error and returned as-is; retrying it would just keep failing.
//
// Backoff doubles each retry: `initial_delay`, then 2x, then 4x, … . With
// the default `max_retries=1` and `initial_delay=1s`, the sequence matches
// R-N-7's "one retry with exponential backoff (1 s, 2 s)" -- the 2s would
// apply only if a *second* retry were enabled.
//
// `sleep_fn` is injectable so unit tests don't actually wait.
class RetryingHttpClient : public IHttpClient {
public:
	using SleepFn = std::function<void(std::chrono::milliseconds)>;

	RetryingHttpClient(IHttpClient &inner, int max_retries, std::chrono::milliseconds initial_delay, SleepFn sleep_fn);

	// Default-construct uses real std::this_thread::sleep_for.
	RetryingHttpClient(IHttpClient &inner, int max_retries = 1,
	                   std::chrono::milliseconds initial_delay = std::chrono::milliseconds(1000));

	std::optional<Response> Get(std::string_view url) override;
	std::optional<Response> Post(const PostRequest &req) override;

	// Returns true iff the outcome warrants another attempt.
	static bool ShouldRetry(const std::optional<Response> &r);

private:
	template <typename CallFn>
	std::optional<Response> RunWithRetries(CallFn &&call);

	IHttpClient &inner_;
	int max_retries_;
	std::chrono::milliseconds initial_delay_;
	SleepFn sleep_fn_;
};

} // namespace quack_oauth
