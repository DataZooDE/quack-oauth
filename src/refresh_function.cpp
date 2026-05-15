#include "refresh_function.hpp"

#include <chrono>
#include <cstdint>
#include <string>

#include "duckdb/common/exception.hpp"
#include "duckdb/common/types/data_chunk.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/common/vector_operations/unary_executor.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"

#include "http_client_duckdb.hpp"
#include "platform_time.hpp"
#include "retry_http_client.hpp"
#include "secret_accessor.hpp"
#include "token_endpoint.hpp"

namespace duckdb {

using quack_oauth::FormatUtcIso8601;

static string DoRefresh(ClientContext &context, const string &secret_name) {
	auto accessor = OpenSecret(context, secret_name, "quack_oauth", "quack_oauth_refresh");

	const auto token_endpoint = accessor.Get("token_endpoint");
	const auto client_id = accessor.Get("client_id");
	const auto client_secret = accessor.Get("client_secret");
	const auto refresh_token = accessor.Get("refresh_token");
	const auto scope = accessor.Get("scope");

	if (token_endpoint.empty()) {
		throw InvalidInputException("quack_oauth_refresh: SECRET '%s' is missing `token_endpoint`", secret_name);
	}
	if (refresh_token.empty()) {
		throw InvalidInputException("quack_oauth_refresh: SECRET '%s' has no `refresh_token` -- run "
		                            "quack_oauth_login first or set one explicitly",
		                            secret_name);
	}

	DuckdbHttpClient base_http;
	quack_oauth::RetryingHttpClient http(base_http);
	const auto tok =
	    quack_oauth::AcquireTokenRefreshToken(http, token_endpoint, client_id, client_secret, refresh_token, scope);
	if (!tok.has_value()) {
		throw IOException("quack_oauth_refresh: token endpoint '%s' did not return a valid "
		                  "response (refresh_token may be expired or revoked)",
		                  token_endpoint);
	}

	const auto now =
	    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	const auto expires_at = now + tok->expires_in;

	// Persist on the SECRET. R-C-5: refresh_tokens are persisted via the
	// SecretManager, never to a separate file. Empty refresh_token means
	// the IdP didn't rotate -- PersistTokenFields keeps the existing one.
	const auto expires_at_iso = FormatUtcIso8601(expires_at);
	PersistTokenFields(context, accessor, tok->access_token, expires_at_iso, tok->refresh_token);
	return expires_at_iso;
}

static void RefreshScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t secret_name_str) {
		const auto iso = DoRefresh(context, secret_name_str.GetString());
		return StringVector::AddString(result, iso);
	});
}

void RegisterQuackOauthRefresh(ExtensionLoader &loader) {
	ScalarFunction fn("quack_oauth_refresh", {LogicalType::VARCHAR}, LogicalType::VARCHAR, RefreshScalarFun);
	// Side-effecting (rotates tokens on the SECRET) and HTTP-bound.
	fn.SetVolatile();
	CreateScalarFunctionInfo info(std::move(fn));
	FunctionDescription desc;
	desc.description = "Run an RFC 6749 §6 refresh_token grant against the token endpoint of the named "
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
