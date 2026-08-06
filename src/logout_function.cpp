#include "logout_function.hpp"

#include <string>

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/enums/on_create_conflict.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/types/data_chunk.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/common/vector_operations/unary_executor.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"

#include "secret_accessor.hpp"
#include "telemetry.hpp"
#include "quack_oauth_banner.hpp"

namespace duckdb {

static bool DoLogout(ClientContext &context, const string &secret_name) {
	auto accessor = OpenSecret(context, secret_name, "quack_oauth", "quack_oauth_logout");

	// Clear the three token fields. We erase rather than set-to-empty
	// so the SECRET's secret_string serialisation drops them entirely
	// -- otherwise empty redacted fields linger as `access_token=`.
	KeyValueSecret updated(*accessor.kv);
	updated.secret_map.erase("access_token");
	updated.secret_map.erase("refresh_token");
	updated.secret_map.erase("expires_at");

	auto &secret_manager = SecretManager::Get(context);
	auto txn = CatalogTransaction::GetSystemCatalogTransaction(context);
	secret_manager.RegisterSecret(txn, make_uniq<KeyValueSecret>(updated), OnCreateConflict::REPLACE_ON_CONFLICT,
	                              accessor.entry->persist_type, accessor.entry->storage_mode);
	return true;
}

static void LogoutScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	PostHogTelemetry::Instance().RecordFunctionCall("quack_oauth_logout");
	auto &context = state.GetContext();
	UnaryExecutor::Execute<string_t, bool>(args.data[0], result, args.size(), [&](string_t secret_name_str) {
		return DoLogout(context, secret_name_str.GetString());
	});
}

void RegisterQuackOauthLogout(ExtensionLoader &loader) {
	ScalarFunction fn("quack_oauth_logout", {LogicalType::VARCHAR}, LogicalType::BOOLEAN,
	                  DATAZOO_GUARD(QUACK_OAUTH_BANNER, LogoutScalarFun));
	// Side-effecting (mutates the SECRET): never fold or memoise.
	fn.stability = FunctionStability::VOLATILE;
	CreateScalarFunctionInfo info(std::move(fn));
	FunctionDescription desc;
	desc.description = "Clears access_token, refresh_token, and expires_at on the named "
	                   "TYPE=quack_oauth SECRET (R-C-8). Returns true. The RFC 7009 "
	                   "revocation-endpoint call is a SHOULD in the spec and is deferred -- "
	                   "this version only does the local field clear. Use after a user "
	                   "explicitly logs out so a stolen refresh_token cannot be reused.";
	desc.parameter_names = {"secret_name"};
	desc.parameter_types = {LogicalType::VARCHAR};
	desc.examples = {"SELECT quack_oauth_logout('my_client_secret')"};
	desc.categories = {"quack_oauth"};
	info.descriptions.push_back(std::move(desc));
	loader.RegisterFunction(std::move(info));
}

} // namespace duckdb
