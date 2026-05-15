#include "jwks_cache.hpp"

namespace quack_oauth {

JwksCache::JwksCache(std::int64_t min_refresh_s) : min_refresh_s_(min_refresh_s) {
}

JwksLookup JwksCache::Lookup(const std::string &kid, std::int64_t now_s) const {
	if (const auto hit = hits_.find(kid); hit != hits_.end()) {
		JwksLookup result;
		result.status = JwksLookupStatus::Hit;
		result.jwk = hit->second.jwk;
		return result;
	}

	JwksLookup result;
	const auto miss = misses_.find(kid);
	if (miss != misses_.end()) {
		const auto elapsed = now_s - miss->second.recorded_at_s;
		if (elapsed < min_refresh_s_) {
			result.status = JwksLookupStatus::RateLimited;
			result.retry_after_s = min_refresh_s_ - elapsed;
			return result;
		}
	}
	result.status = JwksLookupStatus::Miss;
	return result;
}

void JwksCache::OnFetchSuccess(const Jwk &jwk, std::int64_t now_s) {
	// A successful fetch supersedes any prior miss-rate-limit on this kid.
	misses_.erase(jwk.kid);
	hits_[jwk.kid] = Entry{jwk, now_s};
}

void JwksCache::OnFetchMiss(const std::string &kid, std::int64_t now_s) {
	misses_[kid] = MissEntry{now_s};
}

std::size_t JwksCache::Size() const noexcept {
	return hits_.size();
}

} // namespace quack_oauth
