#pragma once

#include <cstddef>
#include <cstdint>
#include <list>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace quack_oauth {

// In-memory representation of the authenticated principal that the validator
// (S-7) produces and the authorizer (S-13) consumes.
//
// Architecture section 5.2 names this. Kept minimal for S-8: the fields the
// current code paths actually need. `claims` (raw provider blob) is added
// when a slice needs it.
struct Principal {
	std::string subject;             // sub
	std::string issuer;              // iss
	std::vector<std::string> scopes; // scope (space-split) ∪ scp[]
	std::int64_t exp = 0;            // unix seconds
};

// Per-process decision cache keyed by SHA-256 of the raw token (R-N-2:
// timing-safe; we never compare raw tokens). TTL is `min(default_ttl_s,
// exp - now_s)` per R-S-9 / architecture section 5.2. LRU eviction once
// `max_entries` is reached.
//
// Pure-logic: no I/O, clock injected via `now_s` on every method. Thread
// safety is a higher-slice concern (architecture section 8.4 wraps the
// per-process caches in a mutex when wiring into the live extension).
class DecisionCache {
public:
	DecisionCache(std::size_t max_entries, std::int64_t default_ttl_s);

	// Hex-encoded SHA-256 of `token`. 64 lowercase hex characters. Exposed so
	// callers can hash once and pass the key to both `Lookup` and `Store`,
	// and so the hashing itself is unit-testable.
	static std::string KeyOf(std::string_view token);

	// Returns the cached Principal if `key` is present and its TTL window
	// covers `now_s`; otherwise `nullopt` (and the expired entry, if any, is
	// evicted as a side effect). On a hit the entry is moved to the front
	// of the LRU.
	std::optional<Principal> Lookup(const std::string &key, std::int64_t now_s);

	// Cache a positive decision. The effective TTL is `min(default_ttl_s,
	// principal.exp - now_s)` when `principal.exp > 0`, else `default_ttl_s`.
	// Non-positive TTLs short-circuit -- nothing is inserted.
	void Store(const std::string &key, const Principal &principal, std::int64_t now_s);

	std::size_t Size() const noexcept;

private:
	struct Entry {
		std::string key;
		Principal principal;
		std::int64_t expires_at_s;
	};

	using List = std::list<Entry>;
	using Map = std::unordered_map<std::string, List::iterator>;

	std::size_t max_entries_;
	std::int64_t default_ttl_s_;
	List entries_; // front = most-recently-used
	Map index_;
};

} // namespace quack_oauth
