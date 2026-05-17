#include <catch2/catch_test_macros.hpp>

#include "authz.hpp"

using quack_oauth::Action;
using quack_oauth::Decision;
using quack_oauth::EvaluateDefaultPolicy;
using quack_oauth::PolicyOutcome;
using quack_oauth::Principal;

namespace {

Principal WithScopes(std::initializer_list<std::string> scopes) {
	Principal p;
	p.subject = "alice";
	p.issuer = "https://idp.test";
	p.scopes.assign(scopes);
	return p;
}

} // namespace

TEST_CASE("Default policy: quack:read allows Attach + Scan, denies writes / admin",
          "[authz][default-policy]") {
	const auto p = WithScopes({"quack:read"});
	CHECK(EvaluateDefaultPolicy(p, Action::Attach).decision == Decision::Allow);
	CHECK(EvaluateDefaultPolicy(p, Action::Scan).decision == Decision::Allow);
	CHECK(EvaluateDefaultPolicy(p, Action::CopyTo).decision == Decision::Deny);
	CHECK(EvaluateDefaultPolicy(p, Action::CopyFrom).decision == Decision::Deny);
	CHECK(EvaluateDefaultPolicy(p, Action::Insert).decision == Decision::Deny);
	CHECK(EvaluateDefaultPolicy(p, Action::Update).decision == Decision::Deny);
	CHECK(EvaluateDefaultPolicy(p, Action::Delete).decision == Decision::Deny);
	CHECK(EvaluateDefaultPolicy(p, Action::Ddl).decision == Decision::Deny);
	CHECK(EvaluateDefaultPolicy(p, Action::Pragma).decision == Decision::Deny);
	CHECK(EvaluateDefaultPolicy(p, Action::ServeAdmin).decision == Decision::Deny);
}

TEST_CASE("Default policy: quack:write implies quack:read + all data-plane DML",
          "[authz][default-policy]") {
	const auto p = WithScopes({"quack:write"});
	CHECK(EvaluateDefaultPolicy(p, Action::Attach).decision == Decision::Allow);
	CHECK(EvaluateDefaultPolicy(p, Action::Scan).decision == Decision::Allow);
	CHECK(EvaluateDefaultPolicy(p, Action::CopyTo).decision == Decision::Allow);
	CHECK(EvaluateDefaultPolicy(p, Action::CopyFrom).decision == Decision::Allow);
	CHECK(EvaluateDefaultPolicy(p, Action::Insert).decision == Decision::Allow);
	CHECK(EvaluateDefaultPolicy(p, Action::Update).decision == Decision::Allow);
	CHECK(EvaluateDefaultPolicy(p, Action::Delete).decision == Decision::Allow);
	// R-S-8: no implicit admin / DDL / raw PRAGMAs.
	CHECK(EvaluateDefaultPolicy(p, Action::Ddl).decision == Decision::Deny);
	CHECK(EvaluateDefaultPolicy(p, Action::Pragma).decision == Decision::Deny);
	CHECK(EvaluateDefaultPolicy(p, Action::ServeAdmin).decision == Decision::Deny);
}

TEST_CASE("Default policy: no scopes denies everything", "[authz][default-policy]") {
	const auto p = WithScopes({});
	CHECK(EvaluateDefaultPolicy(p, Action::Attach).decision == Decision::Deny);
	CHECK(EvaluateDefaultPolicy(p, Action::Scan).decision == Decision::Deny);
	CHECK(EvaluateDefaultPolicy(p, Action::CopyTo).decision == Decision::Deny);
	CHECK(EvaluateDefaultPolicy(p, Action::CopyFrom).decision == Decision::Deny);
	CHECK(EvaluateDefaultPolicy(p, Action::Insert).decision == Decision::Deny);
	CHECK(EvaluateDefaultPolicy(p, Action::Ddl).decision == Decision::Deny);
	CHECK(EvaluateDefaultPolicy(p, Action::ServeAdmin).decision == Decision::Deny);
}

TEST_CASE("Default policy: unrelated scopes do not unlock data-plane access",
          "[authz][default-policy]") {
	const auto p = WithScopes({"openid", "profile", "email"});
	CHECK(EvaluateDefaultPolicy(p, Action::Scan).decision == Decision::Deny);
	CHECK(EvaluateDefaultPolicy(p, Action::CopyTo).decision == Decision::Deny);
}

TEST_CASE("Default policy: deny reasons cite the missing scope",
          "[authz][default-policy][reason]") {
	const Principal anonymous = WithScopes({});
	CHECK(EvaluateDefaultPolicy(anonymous, Action::Scan).reason == "requires quack:read");
	CHECK(EvaluateDefaultPolicy(anonymous, Action::CopyTo).reason == "requires quack:write");
	CHECK(EvaluateDefaultPolicy(anonymous, Action::Insert).reason == "requires quack:write");

	const Principal reader = WithScopes({"quack:read"});
	CHECK(EvaluateDefaultPolicy(reader, Action::CopyFrom).reason == "requires quack:write");
	CHECK(EvaluateDefaultPolicy(reader, Action::ServeAdmin).reason ==
	      "default policy never permits administrative actions");
	CHECK(EvaluateDefaultPolicy(reader, Action::Ddl).reason ==
	      "default policy never permits administrative actions");
}
