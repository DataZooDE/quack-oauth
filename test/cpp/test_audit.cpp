#include <catch2/catch_test_macros.hpp>

#include "audit.hpp"
#include "tracing.hpp"

using quack_oauth::AuditEvent;
using quack_oauth::AuditEventType;
using quack_oauth::AuditEventTypeName;
using quack_oauth::AuditRing;
using quack_oauth::FormatAuditLine;
using quack_oauth::RedactSensitive;

namespace {

AuditEvent MakeEvent(AuditEventType type, std::int64_t ts, const std::string &sub = "",
                     const std::string &reason = "ok") {
	AuditEvent e;
	e.timestamp_unix_s = ts;
	e.event_type = type;
	e.subject = sub;
	e.reason = reason;
	return e;
}

} // namespace

TEST_CASE("AuditRing: push + snapshot returns oldest-first", "[audit]") {
	AuditRing r(4);
	r.Push(MakeEvent(AuditEventType::TokenAccepted, 1));
	r.Push(MakeEvent(AuditEventType::TokenAccepted, 2));
	r.Push(MakeEvent(AuditEventType::TokenAccepted, 3));
	const auto snap = r.Snapshot();
	REQUIRE(snap.size() == 3);
	CHECK(snap[0].timestamp_unix_s == 1);
	CHECK(snap[1].timestamp_unix_s == 2);
	CHECK(snap[2].timestamp_unix_s == 3);
}

TEST_CASE("AuditRing: wraparound drops oldest", "[audit]") {
	AuditRing r(3);
	for (std::int64_t i = 1; i <= 5; ++i) {
		r.Push(MakeEvent(AuditEventType::TokenAccepted, i));
	}
	const auto snap = r.Snapshot();
	REQUIRE(snap.size() == 3);
	// After 5 pushes into capacity-3, we keep ts=3,4,5.
	CHECK(snap[0].timestamp_unix_s == 3);
	CHECK(snap[1].timestamp_unix_s == 4);
	CHECK(snap[2].timestamp_unix_s == 5);
}

TEST_CASE("AuditRing: size + capacity track correctly", "[audit]") {
	AuditRing r(2);
	CHECK(r.size() == 0);
	CHECK(r.capacity() == 2);
	r.Push(MakeEvent(AuditEventType::TokenRejected, 10));
	CHECK(r.size() == 1);
	r.Push(MakeEvent(AuditEventType::TokenRejected, 11));
	CHECK(r.size() == 2);
	r.Push(MakeEvent(AuditEventType::TokenRejected, 12)); // drops ts=10
	CHECK(r.size() == 2);
	CHECK(r.Snapshot()[0].timestamp_unix_s == 11);
}

TEST_CASE("AuditEventTypeName: stable strings", "[audit]") {
	CHECK(AuditEventTypeName(AuditEventType::TokenAccepted) == std::string("token_accepted"));
	CHECK(AuditEventTypeName(AuditEventType::TokenRejected) == std::string("token_rejected"));
	CHECK(AuditEventTypeName(AuditEventType::AuthzAllow) == std::string("authz_allow"));
	CHECK(AuditEventTypeName(AuditEventType::AuthzDeny) == std::string("authz_deny"));
	CHECK(AuditEventTypeName(AuditEventType::JwksRefresh) == std::string("jwks_refresh"));
}

TEST_CASE("FormatAuditLine: includes ts and event type", "[audit]") {
	const auto line =
	    FormatAuditLine(MakeEvent(AuditEventType::AuthzAllow, 1715000000, "alice@example.com", "rule allow"));
	CHECK(line.find("ts=1715000000") != std::string::npos);
	CHECK(line.find("event=authz_allow") != std::string::npos);
	CHECK(line.find("sub=alice@example.com") != std::string::npos);
	// `reason` contains a space, so it must be quoted.
	CHECK(line.find("reason=\"rule allow\"") != std::string::npos);
}

TEST_CASE("FormatAuditLine: empty fields are omitted", "[audit]") {
	const auto line = FormatAuditLine(MakeEvent(AuditEventType::TokenRejected, 1715000001));
	CHECK(line.find("sub=") == std::string::npos);
	CHECK(line.find("iss=") == std::string::npos);
	CHECK(line.find("kid=") == std::string::npos);
	CHECK(line.find("action=") == std::string::npos);
	CHECK(line.find("event=token_rejected") != std::string::npos);
}

TEST_CASE("FormatAuditLine: never leaks raw token (uses token_hash field)", "[audit][security]") {
	AuditEvent e = MakeEvent(AuditEventType::TokenAccepted, 1715000002);
	const std::string secret_token = "eyJhbGciOiJSUzI1NiJ9.payload.sig.SECRET";
	e.token_hash = RedactSensitive(secret_token);
	const auto line = FormatAuditLine(e);
	CHECK(line.find(secret_token) == std::string::npos);
	CHECK(line.find("SECRET") == std::string::npos);
	// The hash prefix MUST be present and 8 hex chars.
	const auto pos = line.find("token=");
	REQUIRE(pos != std::string::npos);
	CHECK(line.substr(pos + 6, 8).size() == 8);
}

TEST_CASE("FormatAuditLine: quoted values escape backslash + quote", "[audit]") {
	AuditEvent e = MakeEvent(AuditEventType::AuthzDeny, 1, "user");
	e.reason = "rule says \"no\" \\ end";
	const auto line = FormatAuditLine(e);
	// The escaped form on the wire: reason="rule says \"no\" \\ end"
	// (Use a plain-escaped string instead of a raw string here -- MSVC's
	// preprocessor mishandles raw strings nested inside Catch2's CHECK
	// macro expansion.)
	const std::string expected = "reason=\"rule says \\\"no\\\" \\\\ end\"";
	CHECK(line.find(expected) != std::string::npos);
}
