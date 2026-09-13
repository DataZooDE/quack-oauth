#include "jwks_cache.hpp"

#include <algorithm>

namespace quack_oauth {

namespace {

bool SameKeyMaterial(const Jwk &a, const Jwk &b) {
	if (a.kty != b.kty) {
		return false;
	}
	if (a.kty == "RSA") {
		return a.n == b.n && a.e == b.e;
	}
	if (a.kty == "EC" || a.kty == "OKP") {
		return a.crv == b.crv && a.x == b.x && a.y == b.y;
	}
	return false;
}

} // namespace

JwksCache::JwksCache(std::int64_t min_refresh_s, std::size_t max_entries)
    : min_refresh_s_(std::clamp<std::int64_t>(min_refresh_s, 1, 3600)),
      max_entries_(max_entries == 0 ? 1 : max_entries) {
}

void JwksCache::SetMinRefreshSeconds(std::int64_t min_refresh_s) {
	min_refresh_s_ = std::clamp<std::int64_t>(min_refresh_s, 1, 3600);
}

JwksLookup JwksCache::Lookup(const std::string &kid, std::int64_t now_s) const {
	if (const auto hit = hits_.find(kid); hit != hits_.end()) {
		JwksLookup result;
		result.status = JwksLookupStatus::Hit;
		result.keys = hit->second.keys;
		if (!hit->second.keys.empty()) {
			result.jwk = hit->second.keys.back();
		}
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
		// If identical key material already exists, preserve current reservation ID
		// and timestamps to prevent sibling ingest from invalidating in-flight refreshes (F5).
		for (const auto &existing : hit->second.keys) {
			if (SameKeyMaterial(existing, jwk)) {
				hit_lru_.erase(hit->second.lru_it);
				hit_lru_.push_front(jwk.kid);
				hit->second.lru_it = hit_lru_.begin();
				return;
			}
		}
		// Additive ingest: append new key material without evicting existing working keys (F1).
		hit->second.keys.push_back(jwk);
		hit->second.fetched_at_s = now_s;
		hit_lru_.erase(hit->second.lru_it);
		hit_lru_.push_front(jwk.kid);
		hit->second.lru_it = hit_lru_.begin();
		return;
	}

	hit_lru_.push_front(jwk.kid);
	Entry entry;
	entry.keys.push_back(jwk);
	entry.fetched_at_s = now_s;
	entry.last_refresh_attempt_s = now_s;
	entry.current_reservation_id = next_reservation_id_++;
	entry.lru_it = hit_lru_.begin();
	hits_[jwk.kid] = std::move(entry);
	while (hits_.size() > max_entries_) {
		const auto victim = hit_lru_.back();
		hit_lru_.pop_back();
		hits_.erase(victim);
	}
}

bool JwksCache::CanFetchJwks(std::int64_t now_s) const {
	if (last_global_fetch_s_ > 0 && now_s >= last_global_fetch_s_ && (now_s - last_global_fetch_s_) < min_refresh_s_) {
		return false;
	}
	return true;
}

void JwksCache::RecordJwksFetch(std::int64_t now_s) {
	last_global_fetch_s_ = now_s;
}

std::uint64_t JwksCache::TryReserveRefresh(const std::string &kid, std::int64_t now_s) {
	const auto hit = hits_.find(kid);
	if (hit == hits_.end()) {
		return 0;
	}
	if (now_s < hit->second.last_refresh_attempt_s) {
		// Clock rewind or concurrent chunk with earlier now_s:
		// Fail closed; the existing stamp is already newer (F13).
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

bool JwksCache::CommitRefresh(const std::string &kid, std::uint64_t reservation_id, const Jwk &jwk,
                              std::int64_t now_s) {
	return CommitRefresh(kid, reservation_id, std::vector<Jwk> {jwk}, now_s);
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
