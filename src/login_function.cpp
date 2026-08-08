#include "login_function.hpp"

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
#include "telemetry.hpp"
#include "token_endpoint.hpp"
#include "quack_oauth_banner.hpp"

namespace duckdb {

using quack_oauth::FormatUtcIso8601;

string DoLogin(ClientContext &context, const string &secret_name) {
	auto accessor = OpenSecret(context, secret_name, "quack_oauth", "quack_oauth_login");

	const auto token_endpoint = accessor.Get("token_endpoint");
	const auto client_id = accessor.Get("client_id");
	const auto client_secret = accessor.Get("client_secret");
	const auto scope = accessor.Get("scope");

	if (token_endpoint.empty()) {
		throw InvalidInputException("quack_oauth_login: SECRET '%s' is missing `token_endpoint`", secret_name);
	}
	if (client_id.empty() || client_secret.empty()) {
		throw InvalidInputException("quack_oauth_login: SECRET '%s' is missing client_id or "
		                            "client_secret (S-12 supports client_credentials only)",
		                            secret_name);
	}

	DuckdbHttpClient base_http;
	quack_oauth::RetryingHttpClient http(base_http);
	const auto tok = quack_oauth::AcquireTokenClientCredentials(http, token_endpoint, client_id, client_secret, scope);
	if (!tok.has_value()) {
		throw IOException("quack_oauth_login: token endpoint '%s' did not return a "
		                  "valid response",
		                  token_endpoint);
	}

	const auto now =
	    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	const auto expires_at = now + tok->expires_in;

	// Persist on the SECRET so subsequent queries see the fresh token.
	// client_credentials doesn't return a refresh_token; pass "" to skip.
	const auto expires_at_iso = FormatUtcIso8601(expires_at);
	PersistTokenFields(context, accessor, tok->access_token, expires_at_iso,
	                   /*refresh_token=*/"");
	return expires_at_iso;
}

static void LoginScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	PostHogTelemetry::Instance().RecordFunctionCall("quack_oauth_login");
	auto &context = state.GetContext();
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t secret_name_str) {
		const auto iso = DoLogin(context, secret_name_str.GetString());
		return StringVector::AddString(result, iso);
	});
}

void RegisterQuackOauthLogin(ExtensionLoader &loader) {
	ScalarFunction fn("quack_oauth_login", {LogicalType::VARCHAR}, LogicalType::VARCHAR,
	                  DATAZOO_GUARD(QUACK_OAUTH_BANNER, LoginScalarFun));
	// Side-effecting (writes access_token + expires_at back onto the SECRET)
	// and HTTP-bound: never fold or memoise across calls.
	fn.stability = FunctionStability::VOLATILE;
	CreateScalarFunctionInfo info(std::move(fn));
	FunctionDescription desc;
	desc.description = "Run an RFC 6749 §4.4 client_credentials flow against the token endpoint of the "
	                   "named quack_oauth SECRET. POSTs the SECRET's token_endpoint with "
	                   "grant_type=client_credentials, persists the resulting access_token, "
	                   "refresh_token (if any), and expires_at back onto the SECRET, and returns the "
	                   "ISO-8601 expires_at timestamp. Use for machine-to-machine (service account) flows.";
	desc.parameter_names = {"secret_name"};
	desc.parameter_types = {LogicalType::VARCHAR};
	desc.examples = {"SELECT quack_oauth_login('my_client_secret')"};
	desc.categories = {"quack_oauth"};
	info.descriptions.push_back(std::move(desc));
	loader.RegisterFunction(std::move(info));
}

} // namespace duckdb
