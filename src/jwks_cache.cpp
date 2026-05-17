#include "jwks_cache.hpp"

namespace quack_oauth {

JwksCache::JwksCache(std::int64_t min_refresh_s, std::size_t max_entries)
    : min_refresh_s_(min_refresh_s), max_entries_(max_entries == 0 ? 1 : max_entries) {
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
	if (const auto miss = misses_.find(jwk.kid); miss != misses_.end()) {
		miss_lru_.erase(miss->second.lru_it);
		misses_.erase(miss);
	}
	if (const auto hit = hits_.find(jwk.kid); hit != hits_.end()) {
		hit_lru_.erase(hit->second.lru_it);
		hits_.erase(hit);
	}
	hit_lru_.push_front(jwk.kid);
	hits_[jwk.kid] = Entry {jwk, now_s, hit_lru_.begin()};
	while (hits_.size() > max_entries_) {
		const auto victim = hit_lru_.back();
		hit_lru_.pop_back();
		hits_.erase(victim);
	}
}

void JwksCache::OnFetchMiss(const std::string &kid, std::int64_t now_s) {
	if (const auto miss = misses_.find(kid); miss != misses_.end()) {
		miss_lru_.erase(miss->second.lru_it);
		misses_.erase(miss);
	}
	miss_lru_.push_front(kid);
	misses_[kid] = MissEntry {now_s, miss_lru_.begin()};
	while (misses_.size() > max_entries_) {
		const auto victim = miss_lru_.back();
		miss_lru_.pop_back();
		misses_.erase(victim);
	}
}

std::size_t JwksCache::Size() const noexcept {
	return hits_.size();
}

std::size_t JwksCache::MissSize() const noexcept {
	return misses_.size();
}

} // namespace quack_oauth
