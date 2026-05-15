#include "login_function.hpp"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>

#include "duckdb.hpp"
#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"

#include "http_client_duckdb.hpp"
#include "token_endpoint.hpp"

namespace duckdb {

namespace {

std::string FormatUtcIso8601(std::int64_t unix_seconds) {
	std::time_t t = static_cast<std::time_t>(unix_seconds);
	std::tm tm_buf{};
	gmtime_r(&t, &tm_buf);
	std::ostringstream out;
	out << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
	return out.str();
}

std::string GetField(const KeyValueSecret &kv, const std::string &key) {
	const auto it = kv.secret_map.find(key);
	return it != kv.secret_map.end() ? it->second.ToString() : std::string();
}

std::string DoLogin(ClientContext &context, const std::string &secret_name) {
	if (secret_name.empty()) {
		throw InvalidInputException(
		    "quack_oauth_login: secret name must be non-empty");
	}

	// Keep `secret_entry` alive for the whole function -- the KeyValueSecret
	// pointer below borrows from it. Earlier versions of this function
	// returned the raw pointer past the lifetime of the owning unique_ptr;
	// that's a use-after-free.
	auto &secret_manager = SecretManager::Get(context);
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	auto secret_entry = secret_manager.GetSecretByName(transaction, secret_name);
	if (!secret_entry) {
		throw InvalidInputException(
		    "quack_oauth_login: SECRET '%s' not found", secret_name);
	}
	const auto *kv = dynamic_cast<const KeyValueSecret *>(secret_entry->secret.get());
	if (!kv) {
		throw InvalidInputException(
		    "quack_oauth_login: SECRET '%s' is not a key-value secret",
		    secret_name);
	}

	const auto token_endpoint = GetField(*kv, "token_endpoint");
	const auto client_id = GetField(*kv, "client_id");
	const auto client_secret = GetField(*kv, "client_secret");
	const auto scope = GetField(*kv, "scope");

	if (token_endpoint.empty()) {
		throw InvalidInputException(
		    "quack_oauth_login: SECRET '%s' is missing `token_endpoint`",
		    secret_name);
	}
	if (client_id.empty() || client_secret.empty()) {
		// S-12 supports only client_credentials; that grant requires both
		// client_id and client_secret. device_code / refresh_token defer.
		throw InvalidInputException(
		    "quack_oauth_login: SECRET '%s' is missing client_id or "
		    "client_secret (S-12 supports client_credentials only)",
		    secret_name);
	}

	DuckdbHttpClient http;
	const auto tok = quack_oauth::AcquireTokenClientCredentials(
	    http, token_endpoint, client_id, client_secret, scope);
	if (!tok.has_value()) {
		throw IOException(
		    "quack_oauth_login: token endpoint '%s' did not return a "
		    "valid response",
		    token_endpoint);
	}

	const auto now = std::chrono::duration_cast<std::chrono::seconds>(
	                     std::chrono::system_clock::now().time_since_epoch())
	                     .count();
	const auto expires_at = now + tok->expires_in;

	// Persist on the SECRET so subsequent queries see the fresh token.
	KeyValueSecret updated(*kv);
	updated.secret_map["access_token"] = Value(tok->access_token);
	updated.secret_map["expires_at"] = Value(FormatUtcIso8601(expires_at));
	secret_manager.RegisterSecret(transaction, make_uniq<KeyValueSecret>(updated),
	                              OnCreateConflict::REPLACE_ON_CONFLICT,
	                              secret_entry->persist_type,
	                              secret_entry->storage_mode);

	return FormatUtcIso8601(expires_at);
}

void LoginScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	UnaryExecutor::Execute<string_t, string_t>(
	    args.data[0], result, args.size(), [&](string_t secret_name_str) {
		    const auto iso = DoLogin(context, secret_name_str.GetString());
		    return StringVector::AddString(result, iso);
	    });
}

} // namespace

void RegisterQuackOauthLogin(ExtensionLoader &loader) {
	ScalarFunction fn("quack_oauth_login", {LogicalType::VARCHAR},
	                  LogicalType::VARCHAR, LoginScalarFun);
	// Side-effecting (writes access_token + expires_at back onto the SECRET)
	// and HTTP-bound: never fold or memoise across calls.
	fn.SetVolatile();
	CreateScalarFunctionInfo info(std::move(fn));
	FunctionDescription desc;
	desc.description =
	    "Run an RFC 6749 §4.4 client_credentials flow against the token endpoint of the "
	    "named quack_oauth SECRET. POSTs the SECRET's token_endpoint with "
	    "grant_type=client_credentials, persists the resulting access_token, "
	    "refresh_token (if any), and expires_at back onto the SECRET, and returns the "
	    "access token. Use for machine-to-machine (service account) flows.";
	desc.parameter_names = {"secret_name"};
	desc.parameter_types = {LogicalType::VARCHAR};
	desc.examples = {"SELECT quack_oauth_login('my_client_secret')"};
	desc.categories = {"quack_oauth"};
	info.descriptions.push_back(std::move(desc));
	loader.RegisterFunction(std::move(info));
}

} // namespace duckdb
