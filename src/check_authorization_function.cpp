#include "check_authorization_function.hpp"

#include <mutex>
#include <string>

#include "duckdb/common/types/data_chunk.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/common/vector_operations/binary_executor.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"

#include <chrono>

#include "audit.hpp"
#include "audit_sink.hpp"
#include "authz.hpp"
#include "decision_cache.hpp"
#include "policy.hpp"
#include "policy_table.hpp"
#include "principal_expiry.hpp"
#include "quack_oauth_state.hpp"
#include "secret_accessor.hpp"
#include "sql_inspect.hpp"
#include "tracing.hpp"

#ifndef EMSCRIPTEN
#include "telemetry.hpp"
#endif

namespace duckdb {

// Resolve the policy_table from the active TYPE=quack_oauth_server SECRET.
static string LookupPolicyTable(ClientContext &context) {
	Value v;
	if (!context.TryGetCurrentSetting("quack_oauth_server_secret_name", v) || v.IsNull()) {
		return "";
	}
	auto accessor = TryOpenSecret(context, v.ToString(), "quack_oauth_server");
	return accessor.Get("policy_table");
}

static bool LookupDefaultAllow(ClientContext &context) {
	Value v;
	if (!context.TryGetCurrentSetting("quack_oauth_policy_default", v) || v.IsNull()) {
		return false; // default-deny
	}
	const auto s = v.ToString();
	return s == "allow";
}

static int64_t LookupClockSkew(ClientContext &context) {
	Value v;
	if (!context.TryGetCurrentSetting("quack_oauth_clock_skew_s", v) || v.IsNull()) {
		return 60; // matches R-S-3 default
	}
	return static_cast<int64_t>(v.GetValue<int32_t>());
}

static void CheckAuthorizationScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
#ifndef EMSCRIPTEN
	PostHogTelemetry::Instance().RecordFunctionCall("quack_oauth_check_authorization");
#endif
	auto &context = state.GetContext();
	auto &shared_state = GetQuackOauthState();

	// Resolve the policy once per chunk: same SECRET applies to every row.
	// If policy_table is set but the query fails (table missing, wrong
	// schema, malformed action name), we default-deny rather than silently
	// falling back to the default scope policy -- safer for accidental
	// typos than failing open.
	const auto policy_table = LookupPolicyTable(context);
	const auto default_allow = LookupDefaultAllow(context);
	std::optional<quack_oauth::PolicyDocument> policy;
	bool policy_load_failed = false;
	if (!policy_table.empty()) {
		policy = LoadPolicyFromTable(context, policy_table);
		if (!policy.has_value()) {
			policy_load_failed = true;
		} else {
			policy->default_allow = default_allow;
		}
	}

	const int64_t now_s =
	    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	const int64_t clock_skew_s = LookupClockSkew(context);

	BinaryExecutor::Execute<string_t, string_t, bool>(
	    args.data[0], args.data[1], result, args.size(),
	    [&](string_t session_id_str, string_t query_string_str) -> bool {
		    const auto sid = session_id_str.GetString();
		    const auto query = query_string_str.GetString();
		    const auto request = quack_oauth::InspectSql(query);

		    quack_oauth::AuditEvent e;
		    e.timestamp_unix_s = now_s;
		    e.action = string(quack_oauth::ActionName(request.action));
		    // `query` is not redacted here -- it is intentionally NOT logged.
		    // We log the action + reason instead so operators can audit policy
		    // outcomes without seeing user SQL in clear text.

		    quack_oauth::Principal principal;
		    bool found_session = false;
		    {
			    std::lock_guard<std::mutex> guard(shared_state.mu);
			    const auto it = shared_state.session_principals.find(sid);
			    if (it != shared_state.session_principals.end()) {
				    principal = it->second.principal;
				    found_session = true;
			    }
		    }
		    if (!found_session) {
			    e.event_type = quack_oauth::AuditEventType::AuthzDeny;
			    e.reason = "unknown session";
			    EmitAuditEvent(context, e);
			    return false;
		    }
		    e.subject = principal.subject;
		    e.issuer = principal.issuer;
		    // R-S-9: every check_authorization re-evaluates token validity.
		    // The principal cache from check_token gives us `exp`; if the
		    // wall clock is past it (plus skew), drop the entry and deny.
		    if (quack_oauth::IsPrincipalExpired(principal, now_s, clock_skew_s)) {
			    {
				    std::lock_guard<std::mutex> guard(shared_state.mu);
				    shared_state.session_principals.erase(sid);
			    }
			    e.event_type = quack_oauth::AuditEventType::AuthzDeny;
			    e.reason = "principal expired";
			    EmitAuditEvent(context, e);
			    return false;
		    }
		    if (policy_load_failed) {
			    e.event_type = quack_oauth::AuditEventType::AuthzDeny;
			    e.reason = "policy_table load failed";
			    EmitAuditEvent(context, e);
			    return false;
		    }
		    if (request.unsafe) {
			    // Parser failure / unsupported shape: fail closed and
			    // surface a short error rather than echoing parser
			    // internals (which could leak SQL fragments back to
			    // wire clients).
			    e.event_type = quack_oauth::AuditEventType::AuthzDeny;
			    e.reason = "parse_error";
			    EmitAuditEvent(context, e);
			    return false;
		    }
		    const auto outcome = policy.has_value()
		                             ? quack_oauth::EvaluatePolicy(*policy, principal, request)
		                             : quack_oauth::EvaluateDefaultPolicy(principal, request.action);
		    const bool allow = outcome.decision == quack_oauth::Decision::Allow;
		    e.event_type = allow ? quack_oauth::AuditEventType::AuthzAllow : quack_oauth::AuditEventType::AuthzDeny;
		    e.reason = outcome.reason;
		    EmitAuditEvent(context, e);
		    return allow;
	    });
}

void RegisterQuackOauthCheckAuthorization(ExtensionLoader &loader) {
	ScalarFunction fn("quack_oauth_check_authorization", {LogicalType::VARCHAR, LogicalType::VARCHAR},
	                  LogicalType::BOOLEAN, CheckAuthorizationScalarFun);
	// Emits an audit event per call AND reads from session-keyed in-memory
	// state that may change between rows. MUST NOT be constant-folded.
	fn.stability = FunctionStability::VOLATILE;
	CreateScalarFunctionInfo info(std::move(fn));
	FunctionDescription desc;
	desc.description =
	    "Authorize a query for a session whose Principal was previously cached by "
	    "quack_oauth_check_token(). Parses the SQL with DuckDB's parser, classifies the "
	    "action (Attach / Scan / Insert / Update / Delete / Ddl / Pragma / CopyTo / CopyFrom / "
	    "ServeAdmin) and enumerates the referenced objects + columns, then evaluates the "
	    "policy: either the SQL-native rules in the table named by `policy_table` on the "
	    "active quack_oauth_server SECRET (rules can target subject / scope / action / "
	    "object_pattern / column_pattern), or the default scope-based policy (quack:read → "
	    "Attach + Scan; quack:write → also Insert/Update/Delete/CopyTo/CopyFrom; admin "
	    "actions always denied). Returns false for unknown session_id, policy_table load "
	    "failure, parser failure, or any policy deny. Wired into quack via "
	    "`SET quack_authorization_function = 'quack_oauth_check_authorization'`.";
	desc.parameter_names = {"session_id", "query_string"};
	desc.parameter_types = {LogicalType::VARCHAR, LogicalType::VARCHAR};
	desc.examples = {"SELECT quack_oauth_check_authorization('sess-1', 'SELECT * FROM t')",
	                 "SELECT quack_oauth_check_authorization('sess-1', 'COPY t TO ''out.csv''')"};
	desc.categories = {"quack_oauth"};
	info.descriptions.push_back(std::move(desc));
	loader.RegisterFunction(std::move(info));
}

} // namespace duckdb
