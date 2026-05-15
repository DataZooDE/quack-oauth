#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace quack_oauth {

enum class AuditEventType {
	TokenAccepted, // check_token returned true
	TokenRejected, // check_token returned false / threw
	AuthzAllow,    // check_authorization returned true
	AuthzDeny,     // check_authorization returned false
	JwksRefresh,   // JWKS endpoint fetched (per-kid cache miss)
};

const char *AuditEventTypeName(AuditEventType t);

// Outcome of one auth step. `subject` / `issuer` / `kid` may be empty if
// they were not extractable (e.g. tampered token, no Principal). `token_hash`
// is the 8-hex-char SHA-256 prefix from RedactSensitive() -- never the raw
// token. `action` only set for authz events.
struct AuditEvent {
	int64_t timestamp_unix_s = 0;
	AuditEventType event_type = AuditEventType::TokenRejected;
	std::string subject;
	std::string issuer;
	std::string kid;
	std::string token_hash; // RedactSensitive(raw_token)
	std::string action;     // "Scan"|"Attach"|...; empty for TokenAccepted/Rejected
	std::string reason;     // short stable code: "ok", "expired", "rule allow", ...
};

// Bounded ring buffer of recent events. Thread-unsafe by itself -- the
// caller is expected to hold a mutex (the QuackOauthState mutex).
class AuditRing {
public:
	explicit AuditRing(std::size_t capacity = 16);
	void Push(AuditEvent event);
	std::vector<AuditEvent> Snapshot() const;
	std::size_t size() const noexcept {
		return count_;
	}
	std::size_t capacity() const noexcept {
		return ring_.size();
	}

private:
	std::vector<AuditEvent> ring_;
	std::size_t head_ = 0;  // next write index
	std::size_t count_ = 0; // valid entries
};

// Format an event into a single log line. Safe to pass to a logger that
// prints the message verbatim; never contains the raw token.
//
// Example:
//   ts=1715000000 event=authz_allow sub=alice@example.com action=Scan
//   reason="rule allow" token=ab12cd34
std::string FormatAuditLine(const AuditEvent &e);

} // namespace quack_oauth
