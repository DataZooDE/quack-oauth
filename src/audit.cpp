#include "audit.hpp"

#include <sstream>

namespace quack_oauth {

const char *AuditEventTypeName(AuditEventType t) {
	switch (t) {
	case AuditEventType::TokenAccepted: return "token_accepted";
	case AuditEventType::TokenRejected: return "token_rejected";
	case AuditEventType::AuthzAllow:    return "authz_allow";
	case AuditEventType::AuthzDeny:     return "authz_deny";
	case AuditEventType::JwksRefresh:   return "jwks_refresh";
	}
	return "unknown";
}

AuditRing::AuditRing(std::size_t capacity)
    : ring_(capacity > 0 ? capacity : 1) {}

void AuditRing::Push(AuditEvent event) {
	ring_[head_] = std::move(event);
	head_ = (head_ + 1) % ring_.size();
	if (count_ < ring_.size()) {
		++count_;
	}
}

std::vector<AuditEvent> AuditRing::Snapshot() const {
	std::vector<AuditEvent> out;
	out.reserve(count_);
	// Walk from oldest (head - count) to newest (head - 1), wrapping.
	const auto cap = ring_.size();
	const auto start = (head_ + cap - count_) % cap;
	for (std::size_t i = 0; i < count_; ++i) {
		out.push_back(ring_[(start + i) % cap]);
	}
	return out;
}

namespace {

// Quote a value if it contains spaces or `=`, to keep log lines parseable
// as key=value pairs. Backslash and quote inside the value get escaped.
std::string MaybeQuote(const std::string &v) {
	bool needs_quoting = v.empty();
	for (char c : v) {
		if (c == ' ' || c == '=' || c == '"' || c == '\\') {
			needs_quoting = true;
			break;
		}
	}
	if (!needs_quoting) return v;
	std::string out;
	out.reserve(v.size() + 2);
	out.push_back('"');
	for (char c : v) {
		if (c == '"' || c == '\\') out.push_back('\\');
		out.push_back(c);
	}
	out.push_back('"');
	return out;
}

void Field(std::ostringstream &os, const char *key, const std::string &value) {
	if (value.empty()) return;
	os << ' ' << key << '=' << MaybeQuote(value);
}

} // namespace

std::string FormatAuditLine(const AuditEvent &e) {
	std::ostringstream os;
	os << "ts=" << e.timestamp_unix_s << " event=" << AuditEventTypeName(e.event_type);
	Field(os, "sub", e.subject);
	Field(os, "iss", e.issuer);
	Field(os, "kid", e.kid);
	Field(os, "action", e.action);
	Field(os, "reason", e.reason);
	Field(os, "token", e.token_hash);
	return os.str();
}

} // namespace quack_oauth
