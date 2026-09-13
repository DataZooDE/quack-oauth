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

std::unordered_map<std::string, JwksCache::Entry>::iterator JwksCache::FindHit(const std::string &jwks_uri,
                                                                               const std::string &kid) {
	return hits_.find(CacheKey(jwks_uri, kid));
}

std::unordered_map<std::string, JwksCache::Entry>::const_iterator JwksCache::FindHit(const std::string &jwks_uri,
                                                                                     const std::string &kid) const {
	return hits_.find(CacheKey(jwks_uri, kid));
}

std::unordered_map<std::string, JwksCache::MissEntry>::const_iterator
JwksCache::FindMiss(const std::string &jwks_uri, const std::string &kid) const {
	return misses_.find(CacheKey(jwks_uri, kid));
}

JwksLookup JwksCache::Lookup(const std::string &kid, std::int64_t now_s, const std::string &jwks_uri) const {
	if (const auto hit = FindHit(jwks_uri, kid); hit != hits_.end()) {
		JwksLookup result;
		result.status = JwksLookupStatus::Hit;
		result.keys = hit->second.keys;
		return result;
	}

	JwksLookup result;
	const auto miss = FindMiss(jwks_uri, kid);
	if (miss != misses_.end()) {
		const auto rel = RelateClock(now_s, miss->second.recorded_at_s);
		if (rel == ClockRel::Forward) {
			const auto elapsed = now_s - miss->second.recorded_at_s;
			if (elapsed < min_refresh_s_) {
				result.status = JwksLookupStatus::RateLimited;
				result.retry_after_s = min_refresh_s_ - elapsed;
				return result;
			}
		} else if (rel == ClockRel::MinorRewind) {
			result.status = JwksLookupStatus::RateLimited;
			result.retry_after_s = min_refresh_s_;
			return result;
		}
		// ClockRel::Reset: treat as expired miss
	}
	result.status = JwksLookupStatus::Miss;
	return result;
}

void JwksCache::RecordJwksFetchSuccess(std::int64_t now_s, const std::string &jwks_uri) {
	if (!jwks_uri.empty()) {
		last_successful_fetch_by_uri_[jwks_uri] = now_s;
	} else {
		last_successful_fetch_s_ = now_s;
	}
}

void JwksCache::OnFetchSuccess(const std::string &kid, const std::vector<Jwk> &keys, std::int64_t now_s,
                               const std::string &jwks_uri) {
	if (keys.empty()) {
		return;
	}

	RecordJwksFetchSuccess(now_s, jwks_uri);
	const auto cache_key = CacheKey(jwks_uri, kid);

	if (const auto miss = misses_.find(cache_key); miss != misses_.end()) {
		miss_lru_.erase(miss->second.lru_it);
		misses_.erase(miss);
	}
	if (!jwks_uri.empty()) {
		if (const auto miss = misses_.find(kid); miss != misses_.end()) {
			miss_lru_.erase(miss->second.lru_it);
			misses_.erase(miss);
		}
	}

	if (const auto hit = FindHit(jwks_uri, kid); hit != hits_.end()) {
		if (!SameKeyMaterial(hit->second.keys, keys)) {
			hit->second.current_reservation_id = 0;
		}
		hit->second.keys = keys;
		TrimToCap(hit->second);
		hit->second.fetched_at_s = now_s;
		hit->second.consecutive_absent_count = 0;
		hit_lru_.erase(hit->second.lru_it);
		hit_lru_.push_front(hit->first);
		hit->second.lru_it = hit_lru_.begin();
		return;
	}

	hit_lru_.push_front(cache_key);
	Entry entry;
	entry.keys = keys;
	TrimToCap(entry);
	entry.fetched_at_s = now_s;
	entry.last_refresh_attempt_s = now_s;
	entry.current_reservation_id = 0;
	entry.consecutive_absent_count = 0;
	entry.lru_it = hit_lru_.begin();
	hits_[cache_key] = std::move(entry);
	while (hits_.size() > max_entries_) {
		const auto victim = hit_lru_.back();
		hit_lru_.pop_back();
		hits_.erase(victim);
	}
}

void JwksCache::OnPassiveFetchSuccess(const std::string &kid, const std::vector<Jwk> &keys, std::int64_t now_s,
                                      const std::string &jwks_uri) {
	if (keys.empty()) {
		return;
	}
	const auto hit = FindHit(jwks_uri, kid);
	if (hit != hits_.end()) {
		// Strictly additive: union new keys into existing entry without clearing reservation or changing fetched_at_s
		// (F4)
		for (const auto &k : keys) {
			bool exists = false;
			for (const auto &existing : hit->second.keys) {
				if (SameKeyMaterial(existing, k)) {
					exists = true;
					break;
				}
			}
			if (!exists) {
				hit->second.keys.push_back(k);
			}
		}
		TrimToCap(hit->second);
		hit->second.consecutive_absent_count = 0;
		return;
	}
	OnFetchSuccess(kid, keys, now_s, jwks_uri);
}

bool JwksCache::RecordKidAbsent(const std::string &kid, std::uint64_t reservation_id, std::int64_t now_s,
                                const std::string &jwks_uri) {
	const auto hit = FindHit(jwks_uri, kid);
	if (hit == hits_.end()) {
		return false;
	}
	if (reservation_id != 0 && hit->second.current_reservation_id != reservation_id) {
		return false;
	}
	hit->second.current_reservation_id = 0;
	hit->second.last_refresh_attempt_s = now_s;
	hit->second.consecutive_absent_count++;
	if (hit->second.consecutive_absent_count >= 2) {
		hit_lru_.erase(hit->second.lru_it);
		hits_.erase(hit);
		return true;
	}
	return false;
}

bool JwksCache::CanFetchJwks(std::int64_t now_s) const {
	if (last_global_fetch_s_ <= 0) {
		return true;
	}
	const auto rel = RelateClock(now_s, last_global_fetch_s_);
	if (rel == ClockRel::Reset) {
		return true;
	}
	if (rel == ClockRel::MinorRewind || (now_s - last_global_fetch_s_) < kGlobalFetchBudgetWindowSeconds) {
		return false;
	}
	return true;
}

bool JwksCache::HasFreshJwksDocument(std::int64_t now_s, std::int64_t window_s, const std::string &jwks_uri) const {
	std::int64_t last_s = 0;
	if (!jwks_uri.empty()) {
		const auto it = last_successful_fetch_by_uri_.find(jwks_uri);
		if (it != last_successful_fetch_by_uri_.end()) {
			last_s = it->second;
		}
	}
	if (last_s <= 0) {
		last_s = last_successful_fetch_s_;
	}
	if (last_s <= 0) {
		return false;
	}
	const auto rel = RelateClock(now_s, last_s);
	if (rel != ClockRel::Forward) {
		return false;
	}
	return (now_s - last_s) < window_s;
}

void JwksCache::RecordJwksFetch(std::int64_t now_s) {
	if (last_global_fetch_s_ > 0) {
		const auto rel = RelateClock(now_s, last_global_fetch_s_);
		if (rel == ClockRel::Reset) {
			last_global_fetch_s_ = now_s;
			return;
		}
	}
	last_global_fetch_s_ = std::max(last_global_fetch_s_, now_s);
}

std::uint64_t JwksCache::TryReserveRefresh(const std::string &kid, std::int64_t now_s, const std::string &jwks_uri) {
	const auto hit = FindHit(jwks_uri, kid);
	if (hit == hits_.end()) {
		return 0;
	}
	const auto rel = RelateClock(now_s, hit->second.last_refresh_attempt_s);
	if (rel == ClockRel::Reset) {
		hit->second.last_refresh_attempt_s = now_s;
		const auto res_id = next_reservation_id_++;
		hit->second.current_reservation_id = res_id;
		return res_id;
	}
	if (rel == ClockRel::MinorRewind) {
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
                              std::int64_t now_s, const std::string &jwks_uri) {
	if (reservation_id == 0 || keys.empty()) {
		return false;
	}
	const auto hit = FindHit(jwks_uri, kid);
	if (hit == hits_.end()) {
		return false;
	}
	if (hit->second.current_reservation_id != reservation_id) {
		return false;
	}
	const auto rel = RelateClock(now_s, hit->second.fetched_at_s);
	if (rel == ClockRel::MinorRewind) {
		return false;
	}

	hit->second.current_reservation_id = 0;
	hit->second.consecutive_absent_count = 0;
	hit->second.keys = keys;
	TrimToCap(hit->second);
	hit->second.fetched_at_s = now_s;
	hit_lru_.erase(hit->second.lru_it);
	hit_lru_.push_front(hit->first);
	hit->second.lru_it = hit_lru_.begin();
	return true;
}

void JwksCache::OnFetchMiss(const std::string &kid, std::int64_t now_s, const std::string &jwks_uri) {
	const auto cache_key = CacheKey(jwks_uri, kid);
	if (const auto miss = misses_.find(cache_key); miss != misses_.end()) {
		miss_lru_.erase(miss->second.lru_it);
		misses_.erase(miss);
	}
	miss_lru_.push_front(cache_key);
	misses_[cache_key] = MissEntry {now_s, miss_lru_.begin()};
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
