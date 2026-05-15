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
#include "quack_oauth_state.hpp"

namespace duckdb {

namespace {

struct DiagnoseRow {
	std::string component;
	std::string status;
	std::string detail;
};

struct DiagnoseBindData : public TableFunctionData {
	std::vector<DiagnoseRow> rows;
};

struct DiagnoseGlobalState : public GlobalTableFunctionState {
	idx_t cursor = 0;
};

// Format "k=v" -- escapes nothing, used for `detail` strings the operator
// reads, not for log parsing.
void Append(std::ostringstream &os, const char *k, const std::string &v) {
	if (!os.str().empty()) os << " ";
	os << k << "=" << v;
}

std::string ReadSetting(ClientContext &context, const std::string &key) {
	Value v;
	if (!context.TryGetCurrentSetting(key, v) || v.IsNull()) return "";
	return v.ToString();
}

unique_ptr<FunctionData> DiagnoseBind(ClientContext &context,
                                     TableFunctionBindInput &,
                                     vector<LogicalType> &return_types,
                                     vector<string> &names) {
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
		Append(detail, "validation_mode",
		       ReadSetting(context, "quack_oauth_validation_mode"));
		Append(detail, "provider",
		       ReadSetting(context, "quack_oauth_provider"));
		const std::string status = secret_name.empty() ? "unconfigured" : "configured";
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
		data->rows.push_back({"session_principals",
		                      entries == 0 ? "empty" : "active", detail.str()});
	}

	// 5. Audit ring: count + decision split
	{
		const auto snap = state.audit_ring.Snapshot();
		std::size_t accepts = 0, rejects = 0, allows = 0, denies = 0;
		for (const auto &e : snap) {
			switch (e.event_type) {
			case quack_oauth::AuditEventType::TokenAccepted: ++accepts; break;
			case quack_oauth::AuditEventType::TokenRejected: ++rejects; break;
			case quack_oauth::AuditEventType::AuthzAllow:    ++allows;  break;
			case quack_oauth::AuditEventType::AuthzDeny:     ++denies;  break;
			case quack_oauth::AuditEventType::JwksRefresh:   break;
			}
		}
		std::ostringstream detail;
		Append(detail, "count",
		       std::to_string(snap.size()) + "/" + std::to_string(state.audit_ring.capacity()));
		Append(detail, "accepted", std::to_string(accepts));
		Append(detail, "rejected", std::to_string(rejects));
		Append(detail, "allowed", std::to_string(allows));
		Append(detail, "denied", std::to_string(denies));
		data->rows.push_back({"recent_decisions",
		                      snap.empty() ? "empty" : "active", detail.str()});
	}

	return std::move(data);
}

unique_ptr<GlobalTableFunctionState> DiagnoseInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<DiagnoseGlobalState>();
}

void DiagnoseScan(ClientContext &, TableFunctionInput &input, DataChunk &output) {
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
	std::vector<quack_oauth::AuditEvent> events;
};

struct AuditLogGlobalState : public GlobalTableFunctionState {
	idx_t cursor = 0;
};

unique_ptr<FunctionData> AuditLogBind(ClientContext &, TableFunctionBindInput &,
                                      vector<LogicalType> &return_types,
                                      vector<string> &names) {
	return_types = {LogicalType::BIGINT, LogicalType::VARCHAR, LogicalType::VARCHAR,
	                LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR,
	                LogicalType::VARCHAR, LogicalType::VARCHAR};
	names = {"timestamp_unix_s", "event_type", "subject", "issuer", "kid",
	         "token_hash", "action", "reason"};

	auto data = make_uniq<AuditLogBindData>();
	auto &state = GetQuackOauthState();
	std::lock_guard<std::mutex> guard(state.mu);
	data->events = state.audit_ring.Snapshot();
	return std::move(data);
}

unique_ptr<GlobalTableFunctionState> AuditLogInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<AuditLogGlobalState>();
}

void AuditLogScan(ClientContext &, TableFunctionInput &input, DataChunk &output) {
	auto &bind_data = input.bind_data->Cast<AuditLogBindData>();
	auto &state = input.global_state->Cast<AuditLogGlobalState>();
	idx_t out_row = 0;
	auto str_or_null = [&](idx_t col, const std::string &v) {
		if (v.empty()) output.SetValue(col, out_row, Value(LogicalType::VARCHAR));
		else output.SetValue(col, out_row, Value(v));
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

} // namespace

void RegisterQuackOauthDiagnose(ExtensionLoader &loader) {
	{
		TableFunction fn("quack_oauth_diagnose", {}, DiagnoseScan, DiagnoseBind, DiagnoseInit);
		CreateTableFunctionInfo info(fn);
		FunctionDescription desc;
		desc.description =
		    "Health and configuration snapshot for the quack_oauth extension. Returns one row "
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
		TableFunction fn("quack_oauth_audit_log", {}, AuditLogScan, AuditLogBind, AuditLogInit);
		CreateTableFunctionInfo info(fn);
		FunctionDescription desc;
		desc.description =
		    "Returns the in-memory audit ring (last N auth decisions) as a typed table. "
		    "Columns: timestamp_unix_s BIGINT, event_type VARCHAR, subject VARCHAR, "
		    "issuer VARCHAR, kid VARCHAR, token_hash VARCHAR, action VARCHAR, reason VARCHAR. "
		    "`token_hash` is the 8-hex-char SHA-256 prefix of the raw token; the raw token "
		    "is never exposed. For persistent audit, set `audit_table` on the server SECRET.";
		desc.parameter_names = {};
		desc.parameter_types = {};
		desc.examples = {
		    "SELECT * FROM quack_oauth_audit_log() ORDER BY timestamp_unix_s DESC LIMIT 20"};
		desc.categories = {"quack_oauth"};
		info.descriptions.push_back(std::move(desc));
		loader.RegisterFunction(std::move(info));
	}
}

} // namespace duckdb
