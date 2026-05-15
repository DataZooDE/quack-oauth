#include "retry_http_client.hpp"

#include <thread>

namespace quack_oauth {

static void DefaultSleeper(std::chrono::milliseconds d) {
	std::this_thread::sleep_for(d);
}

RetryingHttpClient::RetryingHttpClient(IHttpClient &inner, int max_retries, std::chrono::milliseconds initial_delay,
                                       SleepFn sleep_fn)
    : inner_(inner), max_retries_(max_retries), initial_delay_(initial_delay), sleep_fn_(std::move(sleep_fn)) {
}

RetryingHttpClient::RetryingHttpClient(IHttpClient &inner, int max_retries, std::chrono::milliseconds initial_delay)
    : RetryingHttpClient(inner, max_retries, initial_delay, DefaultSleeper) {
}

bool RetryingHttpClient::ShouldRetry(const std::optional<Response> &r) {
	if (!r.has_value())
		return true; // transport failure
	return r->status_code >= 500 && r->status_code <= 599;
}

template <typename CallFn>
std::optional<IHttpClient::Response> RetryingHttpClient::RunWithRetries(CallFn &&call) {
	auto delay = initial_delay_;
	auto result = call();
	for (int i = 0; i < max_retries_; ++i) {
		if (!ShouldRetry(result)) {
			return result;
		}
		if (sleep_fn_)
			sleep_fn_(delay);
		delay *= 2;
		result = call();
	}
	return result;
}

std::optional<IHttpClient::Response> RetryingHttpClient::Get(std::string_view url) {
	return RunWithRetries([&]() { return inner_.Get(url); });
}

std::optional<IHttpClient::Response> RetryingHttpClient::Post(const PostRequest &req) {
	return RunWithRetries([&]() { return inner_.Post(req); });
}

} // namespace quack_oauth
