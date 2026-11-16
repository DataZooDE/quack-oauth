// Native host integration tests. Authentication uses the production validator;
// only the IdP is synthetic. No SQL-callable trusted-session hook is registered.
#include "duckdb.hpp"
#include "duckdb_compat.hpp"
#include "quack_oauth_extension.hpp"
#include "check_token_function.hpp"
#include "quack_oauth_state.hpp"

#include <iostream>
#include <stdexcept>

using namespace duckdb;

static void Require(bool condition, const string &message) {
	if (!condition) {
		throw std::runtime_error(message);
	}
}

template <typename... Args>
static std::vector<std::vector<Value>> Query(Connection &conn, const string &sql, Args... args) {
	unique_ptr<QueryResult> result = conn.Query(sql, Value(args)...);
	if (result->HasError()) {
		throw std::runtime_error(result->GetError());
	}
	// Fetch drains deferred execution on 2.0 and materialized results on 1.5.
	auto rows = duckdb_compat::FetchRows(*result);
	if (result->HasError()) {
		throw std::runtime_error(result->GetError());
	}
	return rows;
}

template <typename... Args>
static bool Boolean(Connection &conn, const string &sql, Args... args) {
	auto result = Query(conn, sql, args...);
	Require(result.size() == 1, "boolean query must return exactly one row");
	const Value value = result.at(0).at(0);
	return !value.IsNull() && value.GetValue<bool>();
}

static idx_t PrincipalCount(Connection &conn, const string &sid) {
	return Query(conn, "SELECT count(*) FROM quack_oauth_current_principal() WHERE session_id = ?", sid)
	    .at(0).at(0)
	    .GetValue<int64_t>();
}

static void RequirePrincipal(Connection &conn, const string &sid, const string &subject, const string &scope) {
	auto result = Query(conn, "SELECT subject, scopes FROM quack_oauth_current_principal() WHERE session_id = ?", sid);
	Require(result.size() == 1, "expected exactly one seeded principal");
	Require(result.at(0).at(0).GetValue<string>() == subject, "principal subject changed");
	auto scopes = ListValue::GetChildren(result.at(0).at(1));
	Require(scopes.size() == 1 && scopes[0].GetValue<string>() == scope, "principal scopes changed");
}

static idx_t AuditCount(Connection &conn, const string &subject) {
	return Query(conn, "SELECT count(*) FROM quack_oauth_audit_log() WHERE subject = ?", subject)
	    .at(0).at(0)
	    .GetValue<int64_t>();
}

static bool Authorize(Connection &conn, const string &sid, const string &sql = "SELECT 1") {
	return Boolean(conn, "SELECT quack_oauth_check_authorization(?, ?)", sid, sql);
}

static void Configure(Connection &conn, const string &endpoint) {
	Query(conn, "LOAD quack_oauth");
	// endpoint is produced by the localhost test harness, never user input.
	Require(endpoint.find('\'') == string::npos, "invalid fixture endpoint");
	Query(conn, "CREATE SECRET isolation_server (TYPE quack_oauth_server, "
	            "issuer 'https://isolation.test', audience 'isolation-test', introspection_endpoint '" +
	                endpoint + "')");
	Query(conn, "SET quack_oauth_server_secret_name = 'isolation_server'");
	Query(conn, "SET quack_oauth_validation_mode = 'introspect'");
}

static void Run(const string &test, const string &endpoint, const string &owner_token, const string &other_token,
                const string &subject, const string &other_subject) {
	auto db = make_uniq<DuckDB>(nullptr);
	DuckDB other_db(nullptr);
	db->LoadStaticExtension<QuackOauthExtension>();
	other_db.LoadStaticExtension<QuackOauthExtension>();
	auto owner = make_uniq<Connection>(*db);
	auto peer = make_uniq<Connection>(*db);
	Connection other(other_db);
	Configure(*owner, endpoint);
	Configure(other, endpoint);
	Query(*owner, "CREATE TABLE isolation_marker AS SELECT 42 AS value");
	Require(Query(*peer, "SELECT value FROM isolation_marker").at(0).at(0).GetValue<int>() == 42,
	        "peer must share the owner's database");
	const string sid = "owner-session";
	Require(AuthenticateQuackOauthSession(*owner->context, sid, owner_token), "owner token must validate");
	RequirePrincipal(*owner, sid, subject, "quack:read");
	Require(AuditCount(*owner, subject) > 0, "owner audit must be seeded");
	Require(Authorize(*owner, sid), "owner read must be authorized");
	Require(!Authorize(*owner, sid, "INSERT INTO isolation_marker VALUES (1)"), "owner write must be denied");

	auto seed_peer = [&]() {
		Require(AuthenticateQuackOauthSession(*peer->context, "peer-session", other_token), "peer token must validate");
		RequirePrincipal(*peer, "peer-session", other_subject, "quack:write");
		Require(Authorize(*peer, "peer-session", "INSERT INTO isolation_marker VALUES (1)"),
		        "peer write must be authorized");
	};
	auto sql_validate = [&](Connection &conn, const string &session, const string &token) {
		return Boolean(conn, "SELECT quack_oauth_check_token(?, ?, '')", session, token);
	};

	if (test == "unrelated_database_cannot_read_principal") {
		Require(PrincipalCount(other, sid) == 0, "unrelated database exposed principal");
	} else if (test == "unrelated_database_cannot_read_audit") {
		Require(AuditCount(other, subject) == 0, "unrelated database exposed audit");
	} else if (test == "unrelated_database_cannot_replace_principal") {
		Require(Boolean(other, "SELECT quack_oauth_check_token(?)", other_token), "other token must validate");
		sql_validate(other, sid, other_token);
		RequirePrincipal(*owner, sid, subject, "quack:read");
	} else if (test == "same_database_unbound_connection_cannot_read_principal") {
		Require(PrincipalCount(*peer, sid) == 0, "unbound peer exposed principal");
		Require(AuditCount(*peer, subject) == 0, "unbound peer exposed audit");
	} else if (test == "same_database_distinct_sessions_cannot_read_each_others_principal") {
		seed_peer();
		Require(PrincipalCount(*peer, sid) == 0, "peer exposed owner principal");
		Require(PrincipalCount(*owner, "peer-session") == 0, "owner exposed peer principal");
	} else if (test == "same_database_distinct_sessions_cannot_read_each_others_audit") {
		seed_peer();
		Require(AuditCount(*peer, other_subject) > 0, "peer audit must be seeded");
		Require(AuditCount(*peer, subject) == 0, "peer exposed owner audit");
		Require(AuditCount(*owner, other_subject) == 0, "owner exposed peer audit");
	} else if (test == "same_database_connection_cannot_replace_principal") {
		seed_peer();
		sql_validate(*peer, sid, other_token);
		RequirePrincipal(*owner, sid, subject, "quack:read");
		RequirePrincipal(*peer, "peer-session", other_subject, "quack:write");
	} else if (test == "sql_validation_cannot_create_session_principal") {
		Require(Boolean(*owner, "SELECT quack_oauth_check_token(?)", other_token), "other token must validate");
		Require(PrincipalCount(*owner, "ordinary-sql") == 0, "new identity must not exist");
		sql_validate(*owner, "ordinary-sql", other_token);
		Require(PrincipalCount(*owner, "ordinary-sql") == 0, "SQL created principal");
		RequirePrincipal(*owner, sid, subject, "quack:read");
	} else if (test == "closing_owner_connection_revokes_session" || test == "closing_owner_database_revokes_session") {
		weak_ptr<QuackOauthSessionState> lifetime =
		    owner->context->registered_state->Get<QuackOauthSessionState>("quack_oauth_session");
		Require(!lifetime.expired(), "session state must exist before close");
		owner.reset();
		Require(lifetime.expired(), "session state outlived its connection");
		if (test == "closing_owner_database_revokes_session") {
			peer.reset();
			db.reset();
			Require(!Authorize(other, sid), "closed database retained authority");
		} else {
			Require(!Authorize(*peer, sid), "closed connection retained authority");
		}
	} else if (test == "one_argument_validation_preserves_principal") {
		Require(Boolean(*peer, "SELECT quack_oauth_check_token(?)", other_token), "other token must validate");
		RequirePrincipal(*owner, sid, subject, "quack:read");
	} else if (test == "invalid_token_cannot_replace_principal") {
		Require(!sql_validate(*peer, sid, "synthetic-invalid-token"), "invalid SQL token accepted");
		RequirePrincipal(*owner, sid, subject, "quack:read");
	} else if (test == "validation_caches_are_database_local") {
		auto &owner_cache = GetQuackOauthState(*owner->context);
		auto &peer_cache = GetQuackOauthState(*peer->context);
		auto &other_cache = GetQuackOauthState(*other.context);
		Require(&owner_cache == &peer_cache, "same database must share validation caches");
		Require(&owner_cache != &other_cache, "different databases shared validation caches");
		Require(owner_cache.decision_cache.Size() > 0, "owner decision cache must be populated");
		Require(other_cache.decision_cache.Size() == 0, "other database inherited cached decisions");
		Query(*owner, "SET quack_oauth_jwks_min_refresh_s = 3600");
		Require(GetQuackOauthState(*peer->context).jwks_cache.GetMinRefreshSeconds() == 3600,
		        "database setting must apply on peer connection");
		Require(GetQuackOauthState(*other.context).jwks_cache.GetMinRefreshSeconds() != 3600,
		        "JWKS setting crossed databases");
	} else if (test == "native_configuration_error_revokes_principal") {
		Query(*owner, "SET quack_oauth_server_secret_name = 'missing'");
		bool rejected = false;
		try {
			AuthenticateQuackOauthSession(*owner->context, sid, owner_token);
		} catch (const InvalidInputException &) {
			rejected = true;
		}
		Require(rejected, "missing secret must reject authentication");
		Query(*owner, "SET quack_oauth_server_secret_name = 'isolation_server'");
		Require(PrincipalCount(*owner, sid) == 0, "configuration failure retained principal");
		Require(!Authorize(*owner, sid), "configuration failure retained authority");
	} else if (test == "failed_native_reauthentication_revokes_principal") {
		Require(!AuthenticateQuackOauthSession(*owner->context, sid, "synthetic-invalid-token"),
		        "invalid native token accepted");
		Require(PrincipalCount(*owner, sid) == 0, "failed reauthentication retained principal");
		Require(!Authorize(*owner, sid), "failed reauthentication retained authority");
	} else if (test == "connection_cannot_be_rebound_to_another_session") {
		bool rejected = false;
		try {
			AuthenticateQuackOauthSession(*owner->context, "another-session", other_token);
		} catch (const InvalidInputException &) {
			rejected = true;
		}
		Require(rejected, "native session rebinding must be rejected");
		RequirePrincipal(*owner, sid, subject, "quack:read");
	} else if (test == "authorization_cannot_select_another_sessions_principal") {
		seed_peer();
		Require(!Authorize(*owner, "peer-session"), "owner selected peer authority");
		Require(!Authorize(*peer, sid), "peer selected owner authority");
	} else {
		throw std::runtime_error("unknown test case: " + test);
	}
}

int main(int argc, char **argv) {
	try {
		Require(argc == 7, "usage: security_tests CASE ENDPOINT OWNER_TOKEN OTHER_TOKEN OWNER_SUB OTHER_SUB");
		Run(argv[1], argv[2], argv[3], argv[4], argv[5], argv[6]);
		std::cout << "PASS " << argv[1] << std::endl;
		return 0;
	} catch (const std::exception &error) {
		std::cerr << "FAIL: " << error.what() << std::endl;
		return 1;
	}
}
