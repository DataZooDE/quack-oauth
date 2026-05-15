#include "principal_expiry.hpp"

namespace quack_oauth {

bool IsPrincipalExpired(const Principal &p, std::int64_t now_s, std::int64_t skew_s) {
	if (p.exp <= 0) {
		return false; // unknown expiry -- trust the cache.
	}
	return now_s > p.exp + skew_s;
}

} // namespace quack_oauth
