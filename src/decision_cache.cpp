#include "decision_cache.hpp"

#include <algorithm>
#include <array>
#include <cstdint>

#include <openssl/evp.h>

namespace quack_oauth {

static constexpr char kHex[] = "0123456789abcdef";

static std::string HexEncode(const std::uint8_t *bytes, std::size_t n) {
	std::string out;
	out.resize(n * 2);
	for (std::size_t i = 0; i < n; ++i) {
		out[2 * i] = kHex[(bytes[i] >> 4) & 0x0F];
		out[2 * i + 1] = kHex[bytes[i] & 0x0F];
	}
	return out;
}

DecisionCache::DecisionCache(std::size_t max_entries, std::int64_t default_ttl_s)
    : max_entries_(max_entries == 0 ? 1 : max_entries), default_ttl_s_(default_ttl_s) {
}

std::string DecisionCache::KeyOf(std::string_view token) {
	std::array<std::uint8_t, EVP_MAX_MD_SIZE> digest {};
	unsigned int digest_len = 0;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (ctx == nullptr) {
		return {};
	}
	std::string out;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 && EVP_DigestUpdate(ctx, token.data(), token.size()) == 1 &&
	    EVP_DigestFinal_ex(ctx, digest.data(), &digest_len) == 1 && digest_len == 32) {
		out = HexEncode(digest.data(), digest_len);
	}
	EVP_MD_CTX_free(ctx);
	return out;
}

std::optional<Principal> DecisionCache::Lookup(const std::string &key, std::int64_t now_s) {
	const auto it = index_.find(key);
	if (it == index_.end()) {
		return std::nullopt;
	}
	if (it->second->expires_at_s <= now_s) {
		// Expired -- evict in passing.
		entries_.erase(it->second);
		index_.erase(it);
		return std::nullopt;
	}
	// Move to front (most-recently-used).
	entries_.splice(entries_.begin(), entries_, it->second);
	return it->second->principal;
}

void DecisionCache::Store(const std::string &key, const Principal &principal, std::int64_t now_s) {
	std::int64_t ttl = default_ttl_s_;
	if (principal.exp > 0) {
		const auto remaining = principal.exp - now_s;
		ttl = std::min<std::int64_t>(ttl, remaining);
	}
	if (ttl <= 0) {
		// Already expired -- don't store.
		return;
	}

	const auto existing = index_.find(key);
	if (existing != index_.end()) {
		existing->second->principal = principal;
		existing->second->expires_at_s = now_s + ttl;
		entries_.splice(entries_.begin(), entries_, existing->second);
		return;
	}

	entries_.push_front(Entry {key, principal, now_s + ttl});
	index_[key] = entries_.begin();

	while (entries_.size() > max_entries_) {
		const auto &victim = entries_.back();
		index_.erase(victim.key);
		entries_.pop_back();
	}
}

std::size_t DecisionCache::Size() const noexcept {
	return entries_.size();
}

} // namespace quack_oauth
