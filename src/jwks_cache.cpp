#include "jwks_cache.hpp"

namespace quack_oauth {

JwksCache::JwksCache(std::int64_t min_refresh_s, std::size_t max_entries)
    : min_refresh_s_(min_refresh_s < 1 ? 1 : min_refresh_s), max_entries_(max_entries == 0 ? 1 : max_entries) {
}

void JwksCache::SetMinRefreshSeconds(std::int64_t min_refresh_s) {
	min_refresh_s_ = min_refresh_s < 1 ? 1 : min_refresh_s;
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
	std::int64_t last_refresh = now_s;
	if (const auto hit = hits_.find(jwk.kid); hit != hits_.end()) {
		last_refresh = std::max(hit->second.last_refresh_attempt_s, now_s);
		hit_lru_.erase(hit->second.lru_it);
		hits_.erase(hit);
	}
	hit_lru_.push_front(jwk.kid);
	Entry entry;
	entry.jwk = jwk;
	entry.fetched_at_s = now_s;
	entry.last_refresh_attempt_s = last_refresh;
	entry.current_reservation_id = next_reservation_id_++;
	entry.lru_it = hit_lru_.begin();
	hits_[jwk.kid] = std::move(entry);
	while (hits_.size() > max_entries_) {
		const auto victim = hit_lru_.back();
		hit_lru_.pop_back();
		hits_.erase(victim);
	}
}

std::uint64_t JwksCache::TryReserveRefresh(const std::string &kid, std::int64_t now_s) {
	if (min_refresh_s_ <= 0) {
		return 0;
	}
	const auto hit = hits_.find(kid);
	if (hit == hits_.end()) {
		return 0;
	}
	if (now_s < hit->second.last_refresh_attempt_s) {
		// Clock rewind or concurrent chunk with earlier now_s:
		// Fail closed to prevent rate-limit bypass, and update the stamp to now_s.
		hit->second.last_refresh_attempt_s = now_s;
		return 0;
	}
	const auto elapsed = now_s - hit->second.last_refresh_attempt_s;
	if (elapsed < min_refresh_s_) {
		return 0;
	}
	hit->second.last_refresh_attempt_s = now_s;
	const auto res_id = next_reservation_id_++;
	hit->second.current_reservation_id = res_id;
	return res_id;
}

bool JwksCache::TryBeginHitRefresh(const std::string &kid, std::int64_t now_s) {
	return TryReserveRefresh(kid, now_s) != 0;
}

bool JwksCache::CommitRefresh(const std::string &kid, std::uint64_t reservation_id, const Jwk &jwk,
                              std::int64_t now_s) {
	if (reservation_id == 0) {
		return false;
	}
	const auto hit = hits_.find(kid);
	if (hit == hits_.end()) {
		return false;
	}
	if (hit->second.current_reservation_id != reservation_id) {
		// A newer reservation has occurred or a newer key was already committed.
		// Drop this stale completion to avoid overwriting a newer key.
		return false;
	}
	hit->second.jwk = jwk;
	hit->second.fetched_at_s = now_s;
	hit_lru_.erase(hit->second.lru_it);
	hit_lru_.push_front(kid);
	hit->second.lru_it = hit_lru_.begin();
	return true;
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
