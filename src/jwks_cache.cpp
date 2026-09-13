#include "jwks_cache.hpp"

#include <algorithm>

namespace quack_oauth {

JwksCache::JwksCache(std::int64_t min_refresh_s, std::size_t max_entries)
    : min_refresh_s_(std::clamp<std::int64_t>(min_refresh_s, 1, 3600)),
      max_entries_(max_entries == 0 ? 1 : max_entries) {
}

void JwksCache::SetMinRefreshSeconds(std::int64_t min_refresh_s) {
	min_refresh_s_ = std::clamp<std::int64_t>(min_refresh_s, 1, 3600);
}

void JwksCache::TrimToCap(Entry &entry) {
	if (entry.keys.size() > kMaxKeysPerKid) {
		entry.keys.resize(kMaxKeysPerKid);
	}
}

JwksLookup JwksCache::Lookup(const std::string &kid, std::int64_t now_s) const {
	if (const auto hit = hits_.find(kid); hit != hits_.end()) {
		JwksLookup result;
		result.status = JwksLookupStatus::Hit;
		result.keys = hit->second.keys;
		return result;
	}

	JwksLookup result;
	const auto miss = misses_.find(kid);
	if (miss != misses_.end()) {
		if (now_s < miss->second.recorded_at_s - kClockResetThresholdSeconds) {
			// Clock rewind larger than reset threshold: treat as expired miss (F3)
		} else if (now_s < miss->second.recorded_at_s) {
			result.status = JwksLookupStatus::RateLimited;
			result.retry_after_s = min_refresh_s_;
			return result;
		} else {
			const auto elapsed = now_s - miss->second.recorded_at_s;
			if (elapsed < min_refresh_s_) {
				result.status = JwksLookupStatus::RateLimited;
				result.retry_after_s = min_refresh_s_ - elapsed;
				return result;
			}
		}
	}
	result.status = JwksLookupStatus::Miss;
	return result;
}

void JwksCache::OnFetchSuccess(const std::string &kid, const std::vector<Jwk> &keys, std::int64_t now_s) {
	if (keys.empty()) {
		return;
	}

	last_successful_fetch_s_ = now_s;

	if (const auto miss = misses_.find(kid); miss != misses_.end()) {
		miss_lru_.erase(miss->second.lru_it);
		misses_.erase(miss);
	}

	if (const auto hit = hits_.find(kid); hit != hits_.end()) {
		if (!SameKeyMaterial(hit->second.keys, keys)) {
			hit->second.current_reservation_id = 0;
		}
		hit->second.keys = keys;
		TrimToCap(hit->second);
		hit->second.fetched_at_s = now_s;
		hit_lru_.erase(hit->second.lru_it);
		hit_lru_.push_front(kid);
		hit->second.lru_it = hit_lru_.begin();
		return;
	}

	hit_lru_.push_front(kid);
	Entry entry;
	entry.keys = keys;
	TrimToCap(entry);
	entry.fetched_at_s = now_s;
	entry.last_refresh_attempt_s = now_s;
	entry.current_reservation_id = 0;
	entry.lru_it = hit_lru_.begin();
	hits_[kid] = std::move(entry);
	while (hits_.size() > max_entries_) {
		const auto victim = hit_lru_.back();
		hit_lru_.pop_back();
		hits_.erase(victim);
	}
}

void JwksCache::OnPassiveFetchSuccess(const std::string &kid, const std::vector<Jwk> &keys, std::int64_t now_s) {
	if (const auto hit = hits_.find(kid); hit != hits_.end()) {
		if (now_s >= hit->second.fetched_at_s && (now_s - hit->second.fetched_at_s) < min_refresh_s_) {
			// Kid was already refreshed recently; do not mutate it from passive ingest (F4)
			return;
		}
	}
	OnFetchSuccess(kid, keys, now_s);
}

bool JwksCache::Evict(const std::string &kid) {
	const auto hit = hits_.find(kid);
	if (hit == hits_.end()) {
		return false;
	}
	hit_lru_.erase(hit->second.lru_it);
	hits_.erase(hit);
	return true;
}

bool JwksCache::EvictReserved(const std::string &kid, std::uint64_t reservation_id) {
	const auto hit = hits_.find(kid);
	if (hit == hits_.end()) {
		return false;
	}
	if (reservation_id != 0 && hit->second.current_reservation_id != reservation_id) {
		return false;
	}
	hit_lru_.erase(hit->second.lru_it);
	hits_.erase(hit);
	return true;
}

bool JwksCache::CanFetchJwks(std::int64_t now_s) const {
	if (last_global_fetch_s_ <= 0) {
		return true;
	}
	if (now_s < last_global_fetch_s_ - kClockResetThresholdSeconds) {
		// Clock rewind larger than reset threshold: treat as reset (F3)
		return true;
	}
	if (now_s < last_global_fetch_s_ || (now_s - last_global_fetch_s_) < kGlobalFetchBudgetWindowSeconds) {
		return false;
	}
	return true;
}

bool JwksCache::HasFreshJwksDocument(std::int64_t now_s) const {
	if (last_successful_fetch_s_ <= 0) {
		return false;
	}
	if (now_s < last_successful_fetch_s_ - kClockResetThresholdSeconds) {
		return false;
	}
	if (now_s < last_successful_fetch_s_) {
		return false;
	}
	return (now_s - last_successful_fetch_s_) < kGlobalFetchBudgetWindowSeconds;
}

void JwksCache::RecordJwksFetch(std::int64_t now_s) {
	if (last_global_fetch_s_ > 0 && now_s < last_global_fetch_s_ - kClockResetThresholdSeconds) {
		last_global_fetch_s_ = now_s;
	} else {
		last_global_fetch_s_ = std::max(last_global_fetch_s_, now_s);
	}
}

std::uint64_t JwksCache::TryReserveRefresh(const std::string &kid, std::int64_t now_s) {
	const auto hit = hits_.find(kid);
	if (hit == hits_.end()) {
		return 0;
	}
	if (now_s < hit->second.last_refresh_attempt_s - kClockResetThresholdSeconds) {
		// Clock rewind larger than reset threshold: re-base and grant reservation (F3)
		hit->second.last_refresh_attempt_s = now_s;
		const auto res_id = next_reservation_id_++;
		hit->second.current_reservation_id = res_id;
		return res_id;
	}
	if (now_s < hit->second.last_refresh_attempt_s) {
		// Clock rewind or concurrent chunk with earlier now_s:
		// Fail closed; the existing stamp is already newer.
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

bool JwksCache::CommitRefresh(const std::string &kid, std::uint64_t reservation_id, const std::vector<Jwk> &keys,
                              std::int64_t now_s) {
	if (reservation_id == 0 || keys.empty()) {
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
	if (now_s < hit->second.fetched_at_s) {
		if (now_s < hit->second.fetched_at_s - kClockResetThresholdSeconds) {
			// Clock rewind larger than reset threshold: allow commit and re-base (F3)
		} else {
			// Time inversion within window: newer material was already ingested.
			return false;
		}
	}

	hit->second.current_reservation_id = 0;
	hit->second.keys = keys;
	TrimToCap(hit->second);
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
