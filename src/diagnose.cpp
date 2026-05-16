#include "diagnose.hpp"

#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "duckdb/common/types/data_chunk.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"

#include "audit.hpp"
#include "http_client_duckdb.hpp"
#include "idp_probe.hpp"
#include "quack_oauth_state.hpp"
#include "retry_http_client.hpp"
#include "secret_accessor.hpp"

namespace duckdb {

struct DiagnoseRow {
	string component;
	string status;
	string detail;
};

struct DiagnoseBindData : public TableFunctionData {
	vector<DiagnoseRow> rows;
};

struct DiagnoseGlobalState : public GlobalTableFunctionState {
	idx_t cursor = 0;
};

// Format "k=v" -- escapes nothing, used for `detail` strings the operator
// reads, not for log parsing.
static void Append(std::ostringstream &os, const char *k, const string &v) {
	if (!os.str().empty())
		os << " ";
	os << k << "=" << v;
}

static string ReadSetting(ClientContext &context, const string &key) {
	Value v;
	if (!context.TryGetCurrentSetting(key, v) || v.IsNull())
		return "";
	return v.ToString();
}

static unique_ptr<FunctionData> DiagnoseBind(ClientContext &context, TableFunctionBindInput &,
                                             vector<LogicalType> &return_types, vector<string> &names) {
	return_types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR};
	names = {"component", "status", "detail"};

	auto data = make_uniq<DiagnoseBindData>();
	auto &state = GetQuackOauthState();
	std::lock_guard<std::mutex> guard(state.mu);

	// 1. extension master switch + active SECRET
	{
		const auto enabled = ReadSetting(context, "quack_oauth_enabled");
		const auto secret_name = ReadSetting(context, "quack_oauth_server_secret_name");
		std::ostringstream detail;
		Append(detail, "enabled", enabled.empty() ? "false" : enabled);
		Append(detail, "secret_name", secret_name.empty() ? "(unset)" : secret_name);
		Append(detail, "validation_mode", ReadSetting(context, "quack_oauth_validation_mode"));
		Append(detail, "provider", ReadSetting(context, "quack_oauth_provider"));
		const string status = secret_name.empty() ? "unconfigured" : "configured";
		data->rows.push_back({"extension", status, detail.str()});
	}

	// 2. JWKS cache
	{
		const auto entries = state.jwks_cache.Size();
		std::ostringstream detail;
		Append(detail, "entries", std::to_string(entries));
		data->rows.push_back({"jwks_cache", entries == 0 ? "empty" : "warm", detail.str()});
	}

	// 3. Decision cache
	{
		const auto entries = state.decision_cache.Size();
		std::ostringstream detail;
		Append(detail, "entries", std::to_string(entries));
		data->rows.push_back({"decision_cache", entries == 0 ? "empty" : "warm", detail.str()});
	}

	// 4. Session principals
	{
		const auto entries = state.session_principals.size();
		std::ostringstream detail;
		Append(detail, "sessions", std::to_string(entries));
		data->rows.push_back({"session_principals", entries == 0 ? "empty" : "active", detail.str()});
	}

	// R-N-13 IdP reachability: live GET on jwks_uri (or introspection_endpoint
	// when there's no JWKS, e.g. GitHub). No-op when there's no configured
	// SECRET -- emits an `unconfigured` row.
	//
	// On WASM the network-touching `DuckdbHttpClient` is excluded from the
	// build (it's in DUCKDB_NATIVE_ONLY_SOURCES), so the probe itself can't
	// run. We still emit a row so `diagnose()`'s output shape is stable
	// across builds; the status just reports the path is unavailable.
	{
		const auto secret_name = ReadSetting(context, "quack_oauth_server_secret_name");
		auto accessor = TryOpenSecret(context, secret_name, "quack_oauth_server");
		string probe_uri = accessor.Get("jwks_uri");
		if (probe_uri.empty()) {
			probe_uri = accessor.Get("introspection_endpoint");
		}

		std::ostringstream detail;
#ifndef EMSCRIPTEN
		DuckdbHttpClient base_http;
		quack_oauth::RetryingHttpClient http(base_http, /*max_retries=*/0);
		const auto probe = quack_oauth::ProbeIdpReachability(http, probe_uri);

		if (probe.probed_uri.empty()) {
			Append(detail, "uri", "(none)");
		} else {
			Append(detail, "uri", probe.probed_uri);
		}
		if (probe.status != quack_oauth::IdpProbeResult::Status::Unconfigured) {
			Append(detail, "http_status", std::to_string(probe.http_status));
		}
		data->rows.push_back({"idp_reachability", quack_oauth::StatusName(probe.status), detail.str()});
#else
		// Wasm clients let the host page own the network. Surface the
		// configured probe URI for visibility but report status as
		// `skipped_wasm` so operators can tell at a glance why no
		// http_status is attached.
		if (probe_uri.empty()) {
			Append(detail, "uri", "(none)");
		} else {
			Append(detail, "uri", probe_uri);
		}
		Append(detail, "reason", "network probe excluded from wasm build");
		data->rows.push_back({"idp_reachability", "skipped_wasm", detail.str()});
#endif
	}

	// 5. Audit ring: count + decision split
	{
		const auto snap = state.audit_ring.Snapshot();
		std::size_t accepts = 0, rejects = 0, allows = 0, denies = 0;
		for (const auto &e : snap) {
			switch (e.event_type) {
			case quack_oauth::AuditEventType::TokenAccepted:
				++accepts;
				break;
			case quack_oauth::AuditEventType::TokenRejected:
				++rejects;
				break;
			case quack_oauth::AuditEventType::AuthzAllow:
				++allows;
				break;
			case quack_oauth::AuditEventType::AuthzDeny:
				++denies;
				break;
			case quack_oauth::AuditEventType::JwksRefresh:
				break;
			}
		}
		std::ostringstream detail;
		Append(detail, "count", std::to_string(snap.size()) + "/" + std::to_string(state.audit_ring.capacity()));
		Append(detail, "accepted", std::to_string(accepts));
		Append(detail, "rejected", std::to_string(rejects));
		Append(detail, "allowed", std::to_string(allows));
		Append(detail, "denied", std::to_string(denies));
		data->rows.push_back({"recent_decisions", snap.empty() ? "empty" : "active", detail.str()});
	}

	return std::move(data);
}

static unique_ptr<GlobalTableFunctionState> DiagnoseInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<DiagnoseGlobalState>();
}

static void DiagnoseScan(ClientContext &, TableFunctionInput &input, DataChunk &output) {
	auto &bind_data = input.bind_data->Cast<DiagnoseBindData>();
	auto &state = input.global_state->Cast<DiagnoseGlobalState>();
	idx_t out_row = 0;
	while (state.cursor < bind_data.rows.size() && out_row < STANDARD_VECTOR_SIZE) {
		const auto &row = bind_data.rows[state.cursor];
		output.SetValue(0, out_row, Value(row.component));
		output.SetValue(1, out_row, Value(row.status));
		output.SetValue(2, out_row, Value(row.detail));
		state.cursor++;
		out_row++;
	}
	output.SetCardinality(out_row);
}

// ---------------------------------------------------------------------------
// quack_oauth_audit_log() -- the in-memory audit ring as a table.
// ---------------------------------------------------------------------------

struct AuditLogBindData : public TableFunctionData {
	vector<quack_oauth::AuditEvent> events;
};

struct AuditLogGlobalState : public GlobalTableFunctionState {
	idx_t cursor = 0;
};

static unique_ptr<FunctionData> AuditLogBind(ClientContext &, TableFunctionBindInput &,
                                             vector<LogicalType> &return_types, vector<string> &names) {
	return_types = {LogicalType::BIGINT,  LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR,
	                LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR};
	names = {"timestamp_unix_s", "event_type", "subject", "issuer", "kid", "token_hash", "action", "reason"};

	auto data = make_uniq<AuditLogBindData>();
	auto &state = GetQuackOauthState();
	std::lock_guard<std::mutex> guard(state.mu);
	data->events = state.audit_ring.Snapshot();
	return std::move(data);
}

static unique_ptr<GlobalTableFunctionState> AuditLogInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<AuditLogGlobalState>();
}

static void AuditLogScan(ClientContext &, TableFunctionInput &input, DataChunk &output) {
	auto &bind_data = input.bind_data->Cast<AuditLogBindData>();
	auto &state = input.global_state->Cast<AuditLogGlobalState>();
	idx_t out_row = 0;
	auto str_or_null = [&](idx_t col, const string &v) {
		if (v.empty())
			output.SetValue(col, out_row, Value(LogicalType::VARCHAR));
		else
			output.SetValue(col, out_row, Value(v));
	};
	while (state.cursor < bind_data.events.size() && out_row < STANDARD_VECTOR_SIZE) {
		const auto &e = bind_data.events[state.cursor];
		output.SetValue(0, out_row, Value::BIGINT(e.timestamp_unix_s));
		output.SetValue(1, out_row, Value(quack_oauth::AuditEventTypeName(e.event_type)));
		str_or_null(2, e.subject);
		str_or_null(3, e.issuer);
		str_or_null(4, e.kid);
		str_or_null(5, e.token_hash);
		str_or_null(6, e.action);
		str_or_null(7, e.reason);
		state.cursor++;
		out_row++;
	}
	output.SetCardinality(out_row);
}

// ---------------------------------------------------------------------------
// quack_oauth_current_principal() -- per-session Principal cache as a table.
// Mirrors R-S-6: "subject, issuer, scopes, and a JSON blob of claims, derived
// from the most recently authenticated token on the current connection." We
// don't have a way to identify "current connection" from a regular scalar
// invocation (quack's session_id is server-side state), so the function
// surfaces ALL cached principals as rows -- operators filter as they like.
// ---------------------------------------------------------------------------

struct PrincipalRow {
	string session_id;
	string subject;
	string issuer;
	vector<string> scopes;
	int64_t exp = 0;
};

struct CurrentPrincipalBindData : public TableFunctionData {
	vector<PrincipalRow> rows;
};

struct CurrentPrincipalGlobalState : public GlobalTableFunctionState {
	idx_t cursor = 0;
};

static unique_ptr<FunctionData> CurrentPrincipalBind(ClientContext &, TableFunctionBindInput &,
                                                     vector<LogicalType> &return_types, vector<string> &names) {
	return_types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR,
	                LogicalType::LIST(LogicalType::VARCHAR), LogicalType::BIGINT};
	names = {"session_id", "subject", "issuer", "scopes", "exp"};

	auto data = make_uniq<CurrentPrincipalBindData>();
	auto &state = GetQuackOauthState();
	std::lock_guard<std::mutex> guard(state.mu);
	data->rows.reserve(state.session_principals.size());
	for (const auto &kv : state.session_principals) {
		PrincipalRow row;
		row.session_id = kv.first;
		row.subject = kv.second.subject;
		row.issuer = kv.second.issuer;
		row.scopes.assign(kv.second.scopes.begin(), kv.second.scopes.end());
		row.exp = kv.second.exp;
		data->rows.push_back(std::move(row));
	}
	return std::move(data);
}

static unique_ptr<GlobalTableFunctionState> CurrentPrincipalInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<CurrentPrincipalGlobalState>();
}

static void CurrentPrincipalScan(ClientContext &, TableFunctionInput &input, DataChunk &output) {
	auto &bind_data = input.bind_data->Cast<CurrentPrincipalBindData>();
	auto &state = input.global_state->Cast<CurrentPrincipalGlobalState>();
	idx_t out_row = 0;
	while (state.cursor < bind_data.rows.size() && out_row < STANDARD_VECTOR_SIZE) {
		const auto &row = bind_data.rows[state.cursor];
		output.SetValue(0, out_row, Value(row.session_id));
		output.SetValue(1, out_row, row.subject.empty() ? Value(LogicalType::VARCHAR) : Value(row.subject));
		output.SetValue(2, out_row, row.issuer.empty() ? Value(LogicalType::VARCHAR) : Value(row.issuer));
		vector<Value> scope_vs;
		scope_vs.reserve(row.scopes.size());
		for (const auto &s : row.scopes)
			scope_vs.emplace_back(s);
		output.SetValue(3, out_row, Value::LIST(LogicalType::VARCHAR, scope_vs));
		output.SetValue(4, out_row, Value::BIGINT(row.exp));
		state.cursor++;
		out_row++;
	}
	output.SetCardinality(out_row);
}

void RegisterQuackOauthDiagnose(ExtensionLoader &loader) {
	{
		TableFunction fn("quack_oauth_diagnose", {}, DiagnoseScan, DiagnoseBind, DiagnoseInit);
		CreateTableFunctionInfo info(fn);
		FunctionDescription desc;
		desc.description = "Health and configuration snapshot for the quack_oauth extension. Returns one row "
		                   "per component (extension, jwks_cache, decision_cache, session_principals, "
		                   "recent_decisions) with a status and a free-form `detail` string of key=value "
		                   "pairs. Use to verify that a freshly-loaded extension is configured and that the "
		                   "caches behave (R-N-13).";
		desc.parameter_names = {};
		desc.parameter_types = {};
		desc.examples = {"SELECT * FROM quack_oauth_diagnose()"};
		desc.categories = {"quack_oauth"};
		info.descriptions.push_back(std::move(desc));
		loader.RegisterFunction(std::move(info));
	}

	{
		TableFunction fn("quack_oauth_current_principal", {}, CurrentPrincipalScan, CurrentPrincipalBind,
		                 CurrentPrincipalInit);
		CreateTableFunctionInfo info(fn);
		FunctionDescription desc;
		desc.description = "Returns the per-session Principal cache as a typed table (R-S-6): "
		                   "one row per active session_id with subject, issuer, scopes "
		                   "(VARCHAR[]), and exp (BIGINT unix seconds). Populated by the "
		                   "3-arg form of quack_oauth_check_token. Useful for ops "
		                   "introspection -- e.g. `SELECT * FROM quack_oauth_current_principal() "
		                   "WHERE exp < epoch(now())` shows stale entries that should be "
		                   "expired.";
		desc.parameter_names = {};
		desc.parameter_types = {};
		desc.examples = {"SELECT * FROM quack_oauth_current_principal()"};
		desc.categories = {"quack_oauth"};
		info.descriptions.push_back(std::move(desc));
		loader.RegisterFunction(std::move(info));
	}

	{
		TableFunction fn("quack_oauth_audit_log", {}, AuditLogScan, AuditLogBind, AuditLogInit);
		CreateTableFunctionInfo info(fn);
		FunctionDescription desc;
		desc.description = "Returns the in-memory audit ring (last N auth decisions) as a typed table. "
		                   "Columns: timestamp_unix_s BIGINT, event_type VARCHAR, subject VARCHAR, "
		                   "issuer VARCHAR, kid VARCHAR, token_hash VARCHAR, action VARCHAR, reason VARCHAR. "
		                   "`token_hash` is the 8-hex-char SHA-256 prefix of the raw token; the raw token "
		                   "is never exposed. For persistent audit, set `audit_table` on the server SECRET.";
		desc.parameter_names = {};
		desc.parameter_types = {};
		desc.examples = {"SELECT * FROM quack_oauth_audit_log() ORDER BY timestamp_unix_s DESC LIMIT 20"};
		desc.categories = {"quack_oauth"};
		info.descriptions.push_back(std::move(desc));
		loader.RegisterFunction(std::move(info));
	}
}

} // namespace duckdb
