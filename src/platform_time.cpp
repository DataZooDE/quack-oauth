#include "platform_time.hpp"

#include <ctime>
#include <iomanip>
#include <sstream>

namespace quack_oauth {

std::string FormatUtcIso8601(std::int64_t unix_seconds) {
	std::time_t t = static_cast<std::time_t>(unix_seconds);
	std::tm tm_buf {};
#ifdef _WIN32
	// MSVC: argument-reversed `gmtime_s(struct tm *result, const time_t *time)`.
	gmtime_s(&tm_buf, &t);
#else
	// POSIX: `gmtime_r(const time_t *time, struct tm *result)`.
	gmtime_r(&t, &tm_buf);
#endif
	std::ostringstream out;
	out << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
	return out.str();
}

} // namespace quack_oauth
