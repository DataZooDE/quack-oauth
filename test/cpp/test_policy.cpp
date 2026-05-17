#include <catch2/catch_test_macros.hpp>

#include "authz.hpp"
#include "policy.hpp"
#include "sql_inspect.hpp"

using quack_oauth::Action;
using quack_oauth::ActionFromString;
using quack_oauth::AuthzRequest;
using quack_oauth::Decision;
using quack_oauth::EvaluatePolicy;
using quack_oauth::GlobMatch;
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

// Pure helper: build an AuthzRequest with no objects/columns (the
// "action-only" shape, e.g. ATTACH / PRAGMA). Used by the legacy
// suite to keep test cases simple.
AuthzRequest ReqAction(Action a) {
	AuthzRequest r;
	r.action = a;
	return r;
}

// Build an AuthzRequest that touches a single object + (optionally)
// a list of column names.
AuthzRequest ReqObj(Action a, const std::string &object,
                    std::initializer_list<std::string> columns = {}) {
	AuthzRequest r;
	r.action = a;
	r.objects.push_back(object);
	for (const auto &c : columns) {
		r.columns.push_back(c);
	}
	return r;
}

} // namespace

TEST_CASE("ActionFromString: known names", "[policy]") {
	CHECK(*ActionFromString("Attach") == Action::Attach);
	CHECK(*ActionFromString("Scan") == Action::Scan);
	CHECK(*ActionFromString("CopyTo") == Action::CopyTo);
	CHECK(*ActionFromString("CopyFrom") == Action::CopyFrom);
	CHECK(*ActionFromString("ServeAdmin") == Action::ServeAdmin);
	// Parser-driven additions:
	CHECK(*ActionFromString("Insert") == Action::Insert);
	CHECK(*ActionFromString("Update") == Action::Update);
	CHECK(*ActionFromString("Delete") == Action::Delete);
	CHECK(*ActionFromString("Ddl") == Action::Ddl);
	CHECK(*ActionFromString("Pragma") == Action::Pragma);
}

TEST_CASE("ActionFromString: unknown name → nullopt", "[policy]") {
	CHECK_FALSE(ActionFromString("attach").has_value()); // case sensitive
	CHECK_FALSE(ActionFromString("Vandalise").has_value());
	CHECK_FALSE(ActionFromString("").has_value());
}

TEST_CASE("GlobMatch: literals and stars", "[policy][glob]") {
	CHECK(GlobMatch("main.audit", "main.audit"));
	CHECK_FALSE(GlobMatch("main.audit", "main.trips"));
	CHECK(GlobMatch("*", "anything"));
	CHECK(GlobMatch("*", ""));
	CHECK(GlobMatch("main.*", "main.audit"));
	CHECK(GlobMatch("main.*", "main.trips_enriched"));
	CHECK_FALSE(GlobMatch("main.*", "other.audit"));
	CHECK(GlobMatch("*.audit", "main.audit"));
	CHECK(GlobMatch("pii_*", "pii_email"));
	CHECK_FALSE(GlobMatch("pii_*", "email"));
	CHECK(GlobMatch("a*b*c", "axbyc"));
	CHECK(GlobMatch("a*b*c", "abc"));
	CHECK_FALSE(GlobMatch("a*b*c", "axbycx"));
}

TEST_CASE("GlobMatch: case-insensitive on identifiers", "[policy][glob]") {
	CHECK(GlobMatch("MAIN.AUDIT", "main.audit"));
	CHECK(GlobMatch("main.audit", "MAIN.AUDIT"));
}

TEST_CASE("EvaluatePolicy: empty document, default deny", "[policy]") {
	PolicyDocument d; // no rules, default_allow = false
	const auto p = MakePrincipal("alice", {"quack:read"});
	CHECK(EvaluatePolicy(d, p, ReqAction(Action::Scan)).decision == Decision::Deny);
}

TEST_CASE("EvaluatePolicy: empty document, default allow", "[policy]") {
	PolicyDocument d;
	d.default_allow = true;
	const auto p = MakePrincipal("alice", {});
	CHECK(EvaluatePolicy(d, p, ReqAction(Action::Scan)).decision == Decision::Allow);
	CHECK(EvaluatePolicy(d, p, ReqAction(Action::ServeAdmin)).decision == Decision::Allow);
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
	CHECK(EvaluatePolicy(d, reader, ReqAction(Action::Scan)).decision == Decision::Allow);
	CHECK(EvaluatePolicy(d, reader, ReqAction(Action::Attach)).decision == Decision::Allow);
	CHECK(EvaluatePolicy(d, reader, ReqAction(Action::CopyTo)).decision == Decision::Deny);
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
	CHECK(EvaluatePolicy(d, admin, ReqAction(Action::ServeAdmin)).decision == Decision::Allow);
	CHECK(EvaluatePolicy(d, regular, ReqAction(Action::Scan)).decision == Decision::Deny);
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
	CHECK(EvaluatePolicy(d, bob_reader, ReqAction(Action::Scan)).decision == Decision::Deny);
	CHECK(EvaluatePolicy(d, alice_reader, ReqAction(Action::Scan)).decision == Decision::Allow);
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
	CHECK(EvaluatePolicy(d, MakePrincipal("blocked-user", {}), ReqAction(Action::Scan)).decision == Decision::Deny);
	CHECK(EvaluatePolicy(d, MakePrincipal("anyone-else", {}), ReqAction(Action::Scan)).decision == Decision::Allow);
}

TEST_CASE("EvaluatePolicy: rule with no constraints matches everything", "[policy]") {
	PolicyDocument d;
	{
		PolicyRule r;
		r.allow = true;
		d.rules.push_back(r);
	}
	const auto p = MakePrincipal("alice", {});
	CHECK(EvaluatePolicy(d, p, ReqAction(Action::Scan)).decision == Decision::Allow);
	CHECK(EvaluatePolicy(d, p, ReqAction(Action::ServeAdmin)).decision == Decision::Allow);
}

TEST_CASE("EvaluatePolicy: object_pattern restricts to specific tables", "[policy][object]") {
	PolicyDocument d;
	{
		PolicyRule r;
		r.any_scope = {"analyst"};
		r.actions = {Action::Scan};
		r.object_pattern = "main.trips_*";
		r.allow = true;
		d.rules.push_back(r);
	}
	const auto p = MakePrincipal("alice", {"analyst"});
	// Allowed table:
	CHECK(EvaluatePolicy(d, p, ReqObj(Action::Scan, "main.trips_enriched")).decision == Decision::Allow);
	// Disallowed table -- rule doesn't match, default-deny kicks in:
	CHECK(EvaluatePolicy(d, p, ReqObj(Action::Scan, "main.audit")).decision == Decision::Deny);
}

TEST_CASE("EvaluatePolicy: object-targeted deny short-circuits the request", "[policy][object]") {
	// Deny-by-pattern rule with higher priority than a generic allow.
	PolicyDocument d;
	{
		PolicyRule deny;
		deny.any_scope = {"analyst"};
		deny.actions = {Action::Scan};
		deny.object_pattern = "main.audit";
		deny.allow = false;
		d.rules.push_back(deny);
	}
	{
		PolicyRule allow;
		allow.any_scope = {"analyst"};
		allow.actions = {Action::Scan};
		allow.allow = true;
		d.rules.push_back(allow);
	}
	const auto p = MakePrincipal("alice", {"analyst"});
	CHECK(EvaluatePolicy(d, p, ReqObj(Action::Scan, "main.trips_enriched")).decision == Decision::Allow);
	CHECK(EvaluatePolicy(d, p, ReqObj(Action::Scan, "main.audit")).decision == Decision::Deny);
}

TEST_CASE("EvaluatePolicy: column_pattern requires a specific scope for sensitive cols",
          "[policy][column]") {
	PolicyDocument d;
	// Baseline allow on the table (any column).
	{
		PolicyRule r;
		r.any_scope = {"analyst"};
		r.actions = {Action::Scan};
		r.object_pattern = "main.users";
		r.allow = true;
		d.rules.push_back(r);
	}
	// Carve-out: deny `ssn` for analysts.
	{
		PolicyRule r;
		r.any_scope = {"analyst"};
		r.actions = {Action::Scan};
		r.object_pattern = "main.users";
		r.column_pattern = "ssn";
		r.allow = false;
		// Higher priority -- must be added first in rules vector.
		d.rules.insert(d.rules.begin(), r);
	}
	// Override: pii:read grants ssn.
	{
		PolicyRule r;
		r.any_scope = {"pii:read"};
		r.actions = {Action::Scan};
		r.object_pattern = "main.users";
		r.column_pattern = "ssn";
		r.allow = true;
		d.rules.insert(d.rules.begin(), r);
	}

	const auto analyst = MakePrincipal("alice", {"analyst"});
	const auto pii_reader = MakePrincipal("bob", {"analyst", "pii:read"});

	// Non-sensitive columns: both OK.
	CHECK(EvaluatePolicy(d, analyst, ReqObj(Action::Scan, "main.users", {"id", "name"})).decision ==
	      Decision::Allow);
	// Analyst hitting ssn: denied.
	CHECK(EvaluatePolicy(d, analyst, ReqObj(Action::Scan, "main.users", {"id", "ssn"})).decision == Decision::Deny);
	// PII reader hitting ssn: allowed (override matches first).
	CHECK(EvaluatePolicy(d, pii_reader, ReqObj(Action::Scan, "main.users", {"id", "ssn"})).decision ==
	      Decision::Allow);
}

TEST_CASE("EvaluatePolicy: multi-object request fails on any denied object", "[policy][object]") {
	PolicyDocument d;
	{
		PolicyRule r;
		r.any_scope = {"analyst"};
		r.actions = {Action::Scan};
		r.object_pattern = "main.trips_*";
		r.allow = true;
		d.rules.push_back(r);
	}
	const auto p = MakePrincipal("alice", {"analyst"});
	AuthzRequest req;
	req.action = Action::Scan;
	req.objects.push_back("main.trips_enriched");
	req.objects.push_back("main.audit"); // not covered by any rule -> default-deny
	const auto outcome = EvaluatePolicy(d, p, req);
	CHECK(outcome.decision == Decision::Deny);
	// Reason should name the failing object for operator-facing audit:
	CHECK(outcome.reason.find("main.audit") != std::string::npos);
}

TEST_CASE("EvaluatePolicy: backward compat -- rules without object/column match any", "[policy]") {
	// A rule built without object_pattern / column_pattern (the v1
	// schema) must continue to match every object + column. This is
	// the upgrade-without-migration guarantee.
	PolicyDocument d;
	{
		PolicyRule r;
		r.any_scope = {"quack:read"};
		r.actions = {Action::Scan};
		r.allow = true; // no object/column constraint
		d.rules.push_back(r);
	}
	const auto p = MakePrincipal("alice", {"quack:read"});
	CHECK(EvaluatePolicy(d, p, ReqObj(Action::Scan, "main.audit", {"subject", "issuer"})).decision ==
	      Decision::Allow);
	CHECK(EvaluatePolicy(d, p, ReqObj(Action::Scan, "main.trips_enriched")).decision == Decision::Allow);
}
