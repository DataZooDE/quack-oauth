#include <catch2/catch_test_macros.hpp>

#include "authz.hpp"
#include "policy.hpp"

using quack_oauth::Action;
using quack_oauth::ActionFromString;
using quack_oauth::Decision;
using quack_oauth::EvaluatePolicy;
using quack_oauth::PolicyDocument;
using quack_oauth::PolicyRule;
using quack_oauth::Principal;

namespace {

Principal MakePrincipal(const std::string &sub, std::initializer_list<std::string> scopes) {
	Principal p;
	p.subject = sub;
	p.scopes.assign(scopes);
	return p;
}

} // namespace

TEST_CASE("ActionFromString: known names", "[policy]") {
	CHECK(*ActionFromString("Attach") == Action::Attach);
	CHECK(*ActionFromString("Scan") == Action::Scan);
	CHECK(*ActionFromString("CopyTo") == Action::CopyTo);
	CHECK(*ActionFromString("CopyFrom") == Action::CopyFrom);
	CHECK(*ActionFromString("ServeAdmin") == Action::ServeAdmin);
}

TEST_CASE("ActionFromString: unknown name → nullopt", "[policy]") {
	CHECK_FALSE(ActionFromString("attach").has_value()); // case sensitive
	CHECK_FALSE(ActionFromString("Vandalise").has_value());
	CHECK_FALSE(ActionFromString("").has_value());
}

TEST_CASE("EvaluatePolicy: empty document, default deny", "[policy]") {
	PolicyDocument d; // no rules, default_allow = false
	const auto p = MakePrincipal("alice", {"quack:read"});
	CHECK(EvaluatePolicy(d, p, Action::Scan, "").decision == Decision::Deny);
}

TEST_CASE("EvaluatePolicy: empty document, default allow", "[policy]") {
	PolicyDocument d;
	d.default_allow = true;
	const auto p = MakePrincipal("alice", {});
	CHECK(EvaluatePolicy(d, p, Action::Scan, "").decision == Decision::Allow);
	CHECK(EvaluatePolicy(d, p, Action::ServeAdmin, "").decision == Decision::Allow);
}

TEST_CASE("EvaluatePolicy: scope-gated rule allows the right principal", "[policy]") {
	PolicyDocument d;
	{
		PolicyRule r;
		r.any_scope = {"quack:read"};
		r.actions = {Action::Scan, Action::Attach};
		r.allow = true;
		d.rules.push_back(r);
	}
	const auto reader = MakePrincipal("alice", {"quack:read"});
	CHECK(EvaluatePolicy(d, reader, Action::Scan, "").decision == Decision::Allow);
	CHECK(EvaluatePolicy(d, reader, Action::Attach, "").decision == Decision::Allow);
	CHECK(EvaluatePolicy(d, reader, Action::CopyTo, "").decision == Decision::Deny);
}

TEST_CASE("EvaluatePolicy: subject-gated rule", "[policy]") {
	PolicyDocument d;
	{
		PolicyRule r;
		r.subject = "admin@example.com";
		r.actions = {Action::ServeAdmin, Action::Scan, Action::Attach, Action::CopyTo, Action::CopyFrom};
		r.allow = true;
		d.rules.push_back(r);
	}
	const auto admin = MakePrincipal("admin@example.com", {});
	const auto regular = MakePrincipal("alice@example.com", {});
	CHECK(EvaluatePolicy(d, admin, Action::ServeAdmin, "").decision == Decision::Allow);
	CHECK(EvaluatePolicy(d, regular, Action::Scan, "").decision == Decision::Deny);
}

TEST_CASE("EvaluatePolicy: rule order matters -- first match wins", "[policy]") {
	PolicyDocument d;
	{
		PolicyRule block;
		block.subject = "bob";
		block.allow = false;
		d.rules.push_back(block);
	}
	{
		PolicyRule allow;
		allow.any_scope = {"quack:read"};
		allow.allow = true;
		d.rules.push_back(allow);
	}
	const auto bob_reader = MakePrincipal("bob", {"quack:read"});
	const auto alice_reader = MakePrincipal("alice", {"quack:read"});
	CHECK(EvaluatePolicy(d, bob_reader, Action::Scan, "").decision == Decision::Deny);
	CHECK(EvaluatePolicy(d, alice_reader, Action::Scan, "").decision == Decision::Allow);
}

TEST_CASE("EvaluatePolicy: default allow + explicit deny", "[policy]") {
	PolicyDocument d;
	d.default_allow = true;
	{
		PolicyRule block;
		block.subject = "blocked-user";
		block.allow = false;
		d.rules.push_back(block);
	}
	CHECK(EvaluatePolicy(d, MakePrincipal("blocked-user", {}), Action::Scan, "").decision == Decision::Deny);
	CHECK(EvaluatePolicy(d, MakePrincipal("anyone-else", {}), Action::Scan, "").decision == Decision::Allow);
}

TEST_CASE("EvaluatePolicy: rule with no constraints matches everything", "[policy]") {
	PolicyDocument d;
	{
		PolicyRule r;
		r.allow = true;
		d.rules.push_back(r);
	}
	const auto p = MakePrincipal("alice", {});
	CHECK(EvaluatePolicy(d, p, Action::Scan, "").decision == Decision::Allow);
	CHECK(EvaluatePolicy(d, p, Action::ServeAdmin, "").decision == Decision::Allow);
}
