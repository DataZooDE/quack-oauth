#include "logout_function.hpp"

#include <string>

#include "duckdb.hpp"
#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"

namespace duckdb {

namespace {

bool DoLogout(ClientContext &context, const std::string &secret_name) {
	if (secret_name.empty()) {
		throw InvalidInputException(
		    "quack_oauth_logout: secret name must be non-empty");
	}

	auto &secret_manager = SecretManager::Get(context);
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	auto secret_entry = secret_manager.GetSecretByName(transaction, secret_name);
	if (!secret_entry) {
		throw InvalidInputException(
		    "quack_oauth_logout: SECRET '%s' not found", secret_name);
	}
	const auto *kv = dynamic_cast<const KeyValueSecret *>(secret_entry->secret.get());
	if (!kv) {
		throw InvalidInputException(
		    "quack_oauth_logout: SECRET '%s' is not a key-value secret",
		    secret_name);
	}
	if (kv->GetType() != "quack_oauth") {
		throw InvalidInputException(
		    "quack_oauth_logout: SECRET '%s' is not of TYPE quack_oauth "
		    "(got '%s')",
		    secret_name, kv->GetType());
	}

	// Clear the three token fields. We erase rather than set-to-empty
	// so the SECRET's secret_string serialisation drops them entirely
	// -- otherwise empty redacted fields linger as `access_token=`.
	KeyValueSecret updated(*kv);
	updated.secret_map.erase("access_token");
	updated.secret_map.erase("refresh_token");
	updated.secret_map.erase("expires_at");
	secret_manager.RegisterSecret(transaction, make_uniq<KeyValueSecret>(updated),
	                              OnCreateConflict::REPLACE_ON_CONFLICT,
	                              secret_entry->persist_type,
	                              secret_entry->storage_mode);
	return true;
}

void LogoutScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	UnaryExecutor::Execute<string_t, bool>(
	    args.data[0], result, args.size(), [&](string_t secret_name_str) {
		    return DoLogout(context, secret_name_str.GetString());
	    });
}

} // namespace

void RegisterQuackOauthLogout(ExtensionLoader &loader) {
	ScalarFunction fn("quack_oauth_logout", {LogicalType::VARCHAR},
	                  LogicalType::BOOLEAN, LogoutScalarFun);
	// Side-effecting (mutates the SECRET): never fold or memoise.
	fn.SetVolatile();
	CreateScalarFunctionInfo info(std::move(fn));
	FunctionDescription desc;
	desc.description =
	    "Clears access_token, refresh_token, and expires_at on the named "
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
