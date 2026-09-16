#include "inspect_sql_function.hpp"

#include <string>
#include <vector>

#include "duckdb/common/types/data_chunk.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"

#include "authz.hpp"
#include "quack_oauth_banner.hpp"
#include "sql_inspect.hpp"

#ifndef __EMSCRIPTEN__
#include "telemetry.hpp"
#endif

namespace duckdb {

struct InspectSqlBindData : public TableFunctionData {
	quack_oauth::AuthzRequest request;
};

struct InspectSqlGlobalState : public GlobalTableFunctionState {
	bool done = false;
};

static unique_ptr<FunctionData> InspectSqlBind(ClientContext &, TableFunctionBindInput &input,
                                               vector<LogicalType> &return_types, vector<string> &names) {
#ifndef __EMSCRIPTEN__
	PostHogTelemetry::Instance().RecordFunctionCall("quack_oauth_inspect_sql");
#endif
	return_types = {LogicalType::VARCHAR, LogicalType::LIST(LogicalType::VARCHAR),
	                LogicalType::LIST(LogicalType::VARCHAR), LogicalType::BOOLEAN, LogicalType::VARCHAR};
	names = {"action", "objects", "columns", "unsafe", "error"};

	auto data = make_uniq<InspectSqlBindData>();
	if (input.inputs.empty() || input.inputs[0].IsNull()) {
		throw BinderException("quack_oauth_inspect_sql: SQL argument must not be NULL");
	}
	data->request = quack_oauth::InspectSql(input.inputs[0].GetValue<string>());
	return std::move(data);
}

static unique_ptr<GlobalTableFunctionState> InspectSqlInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<InspectSqlGlobalState>();
}

// Build a VARCHAR[] Value from a vector<std::string>. An empty vector stays
// an empty list rather than NULL -- "touched nothing" is a real answer here.
static Value StringList(const std::vector<std::string> &items) {
	vector<Value> values;
	values.reserve(items.size());
	for (const auto &s : items) {
		values.push_back(Value(s));
	}
	return Value::LIST(LogicalType::VARCHAR, std::move(values));
}

static void InspectSqlScan(ClientContext &, TableFunctionInput &input, DataChunk &output) {
	auto &bind_data = input.bind_data->Cast<InspectSqlBindData>();
	auto &state = input.global_state->Cast<InspectSqlGlobalState>();
	if (state.done) {
		output.SetCardinality(0);
		return;
	}
	const auto &req = bind_data.request;
	output.SetValue(0, 0, Value(quack_oauth::ActionName(req.action)));
	output.SetValue(1, 0, StringList(req.objects));
	output.SetValue(2, 0, StringList(req.columns));
	output.SetValue(3, 0, Value::BOOLEAN(req.unsafe));
	if (req.error.empty()) {
		output.SetValue(4, 0, Value(LogicalType::VARCHAR));
	} else {
		output.SetValue(4, 0, Value(req.error));
	}
	output.SetCardinality(1);
	state.done = true;
}

void RegisterQuackOauthInspectSql(ExtensionLoader &loader) {
	TableFunction fn("quack_oauth_inspect_sql", {LogicalTypeId::VARCHAR},
	                 DATAZOO_GUARD(QUACK_OAUTH_BANNER, InspectSqlScan),
	                 DATAZOO_GUARD(QUACK_OAUTH_BANNER, InspectSqlBind), InspectSqlInit);
	CreateTableFunctionInfo info(fn);
	FunctionDescription desc;
	desc.description = "Parses a SQL string and returns what the authorization layer would gate on: "
	                   "action VARCHAR, objects VARCHAR[], columns VARCHAR[], unsafe BOOLEAN, error VARCHAR. "
	                   "Objects are `schema.table` for base tables and views, or `fn:<name>` for table "
	                   "functions (`fn:read_csv`). Catalog metadata -- information_schema.*, pg_catalog.*, "
	                   "and the duckdb_* family -- is not gated, except duckdb_secrets / duckdb_settings, "
	                   "which carry credentials. `unsafe` marks SQL that fails closed. The statement is "
	                   "only parsed, never executed, and no policy is consulted -- use it to see why a "
	                   "query was denied, or which object_pattern a rule needs.";
	desc.parameter_names = {"sql"};
	desc.parameter_types = {LogicalTypeId::VARCHAR};
	desc.examples = {"SELECT * FROM quack_oauth_inspect_sql('SELECT a FROM t')"};
	desc.categories = {"quack_oauth"};
	info.descriptions.push_back(std::move(desc));
	loader.RegisterFunction(std::move(info));
}

} // namespace duckdb
