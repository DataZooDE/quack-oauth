#include "device_login_function.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <thread>

#include "duckdb.hpp"
#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"

#include "device_code.hpp"
#include "http_client_duckdb.hpp"
#include "platform_time.hpp"
#include "retry_http_client.hpp"

namespace duckdb {

namespace {

using quack_oauth::FormatUtcIso8601;

std::string GetField(const KeyValueSecret &kv, const std::string &key) {
	const auto it = kv.secret_map.find(key);
	return it != kv.secret_map.end() ? it->second.ToString() : std::string();
}

void EmitUserNotice(const quack_oauth::DeviceAuthorizationResponse &auth) {
	// Surface to stderr so any DuckDB client surfaces the message. The
	// proper DuckDB notice mechanism would route via ClientContext logging,
	// but that requires more wiring -- stderr is the universally-visible
	// fallback. Operators can pipe `duckdb 2>&1 | tee log` if needed.
	std::cerr << "[quack_oauth_device_login] visit "
	          << (auth.verification_uri_complete.empty()
	                  ? auth.verification_uri
	                  : auth.verification_uri_complete)
	          << " and enter code: " << auth.user_code << std::endl;
}

std::string DoDeviceLogin(ClientContext & /*context*/,
                          const std::string &secret_name) {
	if (secret_name.empty()) {
		throw InvalidInputException(
		    "quack_oauth_device_login: secret name must be non-empty");
	}

	auto &secret_manager = SecretManager::Get(*reinterpret_cast<ClientContext *>(0));
	(void)secret_manager;
	throw NotImplementedException(
	    "Should not reach -- DoDeviceLogin must be called via the wrapper that "
	    "supplies a real ClientContext.");
}

std::string DoDeviceLoginImpl(ClientContext &context,
                              const std::string &secret_name) {
	if (secret_name.empty()) {
		throw InvalidInputException(
		    "quack_oauth_device_login: secret name must be non-empty");
	}

	auto &secret_manager = SecretManager::Get(context);
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	auto secret_entry = secret_manager.GetSecretByName(transaction, secret_name);
	if (!secret_entry) {
		throw InvalidInputException(
		    "quack_oauth_device_login: SECRET '%s' not found", secret_name);
	}
	const auto *kv = dynamic_cast<const KeyValueSecret *>(secret_entry->secret.get());
	if (!kv) {
		throw InvalidInputException(
		    "quack_oauth_device_login: SECRET '%s' is not a key-value secret",
		    secret_name);
	}

	const auto device_endpoint = GetField(*kv, "device_authorization_endpoint");
	const auto token_endpoint = GetField(*kv, "token_endpoint");
	const auto client_id = GetField(*kv, "client_id");
	const auto client_secret = GetField(*kv, "client_secret");
	const auto scope = GetField(*kv, "scope");

	if (device_endpoint.empty()) {
		throw InvalidInputException(
		    "quack_oauth_device_login: SECRET '%s' is missing "
		    "`device_authorization_endpoint`",
		    secret_name);
	}
	if (token_endpoint.empty() || client_id.empty()) {
		throw InvalidInputException(
		    "quack_oauth_device_login: SECRET '%s' is missing `token_endpoint` "
		    "or `client_id`",
		    secret_name);
	}

	DuckdbHttpClient base_http;
	quack_oauth::RetryingHttpClient http(base_http);
	const auto auth = quack_oauth::RequestDeviceAuthorization(
	    http, device_endpoint, client_id, client_secret, scope);
	if (!auth.has_value()) {
		throw IOException(
		    "quack_oauth_device_login: device_authorization_endpoint '%s' did "
		    "not return a valid response",
		    device_endpoint);
	}

	EmitUserNotice(*auth);

	// Poll the token endpoint until success / expired / denied. RFC 8628
	// requires we respect the `interval` field and bump it on `slow_down`.
	std::int64_t interval = auth->interval > 0 ? auth->interval : 5;
	const auto start =
	    std::chrono::steady_clock::now();
	const auto deadline =
	    start + std::chrono::seconds(auth->expires_in > 0 ? auth->expires_in : 600);
	while (std::chrono::steady_clock::now() < deadline) {
		std::this_thread::sleep_for(std::chrono::seconds(interval));
		const auto poll = quack_oauth::PollDeviceTokenEndpoint(
		    http, token_endpoint, client_id, client_secret, auth->device_code);
		switch (poll.outcome) {
		case quack_oauth::DevicePollOutcome::Pending:
			continue;
		case quack_oauth::DevicePollOutcome::SlowDown:
			interval += 5; // RFC 8628 §3.5
			continue;
		case quack_oauth::DevicePollOutcome::Success: {
			if (!poll.tokens.has_value()) {
				throw IOException(
				    "quack_oauth_device_login: token endpoint returned success "
				    "but no access_token");
			}
			const auto now = std::chrono::duration_cast<std::chrono::seconds>(
			                     std::chrono::system_clock::now().time_since_epoch())
			                     .count();
			const auto expires_at = now + poll.tokens->expires_in;

			KeyValueSecret updated(*kv);
			updated.secret_map["access_token"] = Value(poll.tokens->access_token);
			updated.secret_map["expires_at"] = Value(FormatUtcIso8601(expires_at));
			if (!poll.tokens->refresh_token.empty()) {
				updated.secret_map["refresh_token"] = Value(poll.tokens->refresh_token);
			}
			secret_manager.RegisterSecret(
			    transaction, make_uniq<KeyValueSecret>(updated),
			    OnCreateConflict::REPLACE_ON_CONFLICT,
			    secret_entry->persist_type, secret_entry->storage_mode);
			return FormatUtcIso8601(expires_at);
		}
		case quack_oauth::DevicePollOutcome::Denied:
			throw IOException(
			    "quack_oauth_device_login: user denied the authorization request");
		case quack_oauth::DevicePollOutcome::Expired:
			throw IOException(
			    "quack_oauth_device_login: device_code expired before the user "
			    "completed the authorization flow");
		case quack_oauth::DevicePollOutcome::Error:
		default:
			throw IOException(
			    "quack_oauth_device_login: token endpoint returned an "
			    "unexpected error while polling");
		}
	}
	throw IOException(
	    "quack_oauth_device_login: polling timed out before user authorized");
}

void DeviceLoginScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	UnaryExecutor::Execute<string_t, string_t>(
	    args.data[0], result, args.size(), [&](string_t secret_name_str) {
		    const auto iso = DoDeviceLoginImpl(context, secret_name_str.GetString());
		    return StringVector::AddString(result, iso);
	    });
}

} // namespace

void RegisterQuackOauthDeviceLogin(ExtensionLoader &loader) {
	ScalarFunction fn("quack_oauth_device_login", {LogicalType::VARCHAR},
	                  LogicalType::VARCHAR, DeviceLoginScalarFun);
	// Side-effecting (mutates SECRET state, emits audit events) AND
	// non-idempotent (each call mints a NEW device_code with the IdP).
	// MUST NOT be constant-folded or memoised across rows.
	fn.SetVolatile();
	CreateScalarFunctionInfo info(std::move(fn));
	FunctionDescription desc;
	desc.description =
	    "Run an RFC 8628 device authorization flow against the named quack_oauth SECRET. "
	    "Requests a device + user code, prints the verification URL + user_code to stderr "
	    "for the operator to visit on a second device, then polls the token endpoint with "
	    "RFC 8628 §3.5 error handling (pending / slow_down back-off / access_denied / "
	    "expired_token). On success persists access_token + refresh_token + expires_at "
	    "back onto the SECRET and returns the access token. Use for interactive auth on "
	    "input-constrained devices.";
	desc.parameter_names = {"secret_name"};
	desc.parameter_types = {LogicalType::VARCHAR};
	desc.examples = {"SELECT quack_oauth_device_login('my_client_secret')"};
	desc.categories = {"quack_oauth"};
	info.descriptions.push_back(std::move(desc));
	loader.RegisterFunction(std::move(info));
}

} // namespace duckdb
