#include "refresh_function.hpp"

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

std::string DoRefresh(ClientContext &context, const std::string &secret_name) {
	if (secret_name.empty()) {
		throw InvalidInputException(
		    "quack_oauth_refresh: secret name must be non-empty");
	}

	// Keep `secret_entry` alive for the whole function -- the KeyValueSecret
	// pointer below borrows from it (use-after-free trap, see CLAUDE.md).
	auto &secret_manager = SecretManager::Get(context);
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	auto secret_entry = secret_manager.GetSecretByName(transaction, secret_name);
	if (!secret_entry) {
		throw InvalidInputException(
		    "quack_oauth_refresh: SECRET '%s' not found", secret_name);
	}
	const auto *kv = dynamic_cast<const KeyValueSecret *>(secret_entry->secret.get());
	if (!kv) {
		throw InvalidInputException(
		    "quack_oauth_refresh: SECRET '%s' is not a key-value secret",
		    secret_name);
	}

	const auto token_endpoint = GetField(*kv, "token_endpoint");
	const auto client_id = GetField(*kv, "client_id");
	const auto client_secret = GetField(*kv, "client_secret");
	const auto refresh_token = GetField(*kv, "refresh_token");
	const auto scope = GetField(*kv, "scope");

	if (token_endpoint.empty()) {
		throw InvalidInputException(
		    "quack_oauth_refresh: SECRET '%s' is missing `token_endpoint`",
		    secret_name);
	}
	if (refresh_token.empty()) {
		throw InvalidInputException(
		    "quack_oauth_refresh: SECRET '%s' has no `refresh_token` -- run "
		    "quack_oauth_login first or set one explicitly",
		    secret_name);
	}

	DuckdbHttpClient http;
	const auto tok = quack_oauth::AcquireTokenRefreshToken(
	    http, token_endpoint, client_id, client_secret, refresh_token, scope);
	if (!tok.has_value()) {
		throw IOException(
		    "quack_oauth_refresh: token endpoint '%s' did not return a valid "
		    "response (refresh_token may be expired or revoked)",
		    token_endpoint);
	}

	const auto now = std::chrono::duration_cast<std::chrono::seconds>(
	                     std::chrono::system_clock::now().time_since_epoch())
	                     .count();
	const auto expires_at = now + tok->expires_in;

	// Persist on the SECRET. R-C-5: refresh_tokens are persisted via the
	// SecretManager, never to a separate file.
	KeyValueSecret updated(*kv);
	updated.secret_map["access_token"] = Value(tok->access_token);
	updated.secret_map["expires_at"] = Value(FormatUtcIso8601(expires_at));
	if (!tok->refresh_token.empty()) {
		// IdP rotated the refresh token -- replace ours.
		updated.secret_map["refresh_token"] = Value(tok->refresh_token);
	}
	// else: IdP didn't rotate; keep the original refresh_token in place.

	secret_manager.RegisterSecret(transaction, make_uniq<KeyValueSecret>(updated),
	                              OnCreateConflict::REPLACE_ON_CONFLICT,
	                              secret_entry->persist_type,
	                              secret_entry->storage_mode);

	return FormatUtcIso8601(expires_at);
}

void RefreshScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	UnaryExecutor::Execute<string_t, string_t>(
	    args.data[0], result, args.size(), [&](string_t secret_name_str) {
		    const auto iso = DoRefresh(context, secret_name_str.GetString());
		    return StringVector::AddString(result, iso);
	    });
}

} // namespace

void RegisterQuackOauthRefresh(ExtensionLoader &loader) {
	ScalarFunction fn("quack_oauth_refresh", {LogicalType::VARCHAR},
	                  LogicalType::VARCHAR, RefreshScalarFun);
	// Side-effecting (rotates tokens on the SECRET) and HTTP-bound.
	fn.SetVolatile();
	CreateScalarFunctionInfo info(std::move(fn));
	FunctionDescription desc;
	desc.description =
	    "Run an RFC 6749 §6 refresh_token grant against the token endpoint of the named "
	    "quack_oauth SECRET. Reads token_endpoint + client_id [+ client_secret] + "
	    "refresh_token from the SECRET, POSTs grant_type=refresh_token, and persists the "
	    "rotated access_token + refresh_token (if returned) + expires_at back onto the "
	    "SECRET. Supports both public and confidential clients.";
	desc.parameter_names = {"secret_name"};
	desc.parameter_types = {LogicalType::VARCHAR};
	desc.examples = {"SELECT quack_oauth_refresh('my_client_secret')"};
	desc.categories = {"quack_oauth"};
	info.descriptions.push_back(std::move(desc));
	loader.RegisterFunction(std::move(info));
}

} // namespace duckdb
