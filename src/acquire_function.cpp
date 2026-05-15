#include "acquire_function.hpp"

#include <chrono>
#include <cstdint>
#include <string>

#include "duckdb.hpp"
#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"

#include "acquire_flow.hpp"
#include "platform_time.hpp"

namespace duckdb {

namespace {

std::int64_t ParseIso8601ToUnixSeconds(const std::string &iso) {
	// Accept "YYYY-MM-DDTHH:MM:SSZ" (the FormatUtcIso8601 shape we
	// persist). Anything else returns 0 = unknown.
	if (iso.size() < 20 || iso[10] != 'T' || iso[19] != 'Z') return 0;
	std::tm tm_buf{};
	tm_buf.tm_year = std::stoi(iso.substr(0, 4)) - 1900;
	tm_buf.tm_mon  = std::stoi(iso.substr(5, 2)) - 1;
	tm_buf.tm_mday = std::stoi(iso.substr(8, 2));
	tm_buf.tm_hour = std::stoi(iso.substr(11, 2));
	tm_buf.tm_min  = std::stoi(iso.substr(14, 2));
	tm_buf.tm_sec  = std::stoi(iso.substr(17, 2));
	// timegm is POSIX-only; do the conversion manually using days since
	// epoch. The Y-2038 problem is irrelevant for our 64-bit return.
	static constexpr int kDaysBeforeMonth[] = {
	    0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};
	const int year = tm_buf.tm_year + 1900;
	const bool leap =
	    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
	int yday = kDaysBeforeMonth[tm_buf.tm_mon] + (tm_buf.tm_mday - 1);
	if (tm_buf.tm_mon > 1 && leap) yday += 1;
	const std::int64_t days_before_year =
	    365LL * (year - 1970) + (year - 1969) / 4 -
	    (year - 1901) / 100 + (year - 1601) / 400;
	const std::int64_t days = days_before_year + yday;
	return days * 86400 + tm_buf.tm_hour * 3600 + tm_buf.tm_min * 60 + tm_buf.tm_sec;
}

quack_oauth::ClientSecretView LoadClientSecretView(
    ClientContext &context, const std::string &secret_name) {
	auto &secret_manager = SecretManager::Get(context);
	auto txn = CatalogTransaction::GetSystemCatalogTransaction(context);
	auto entry = secret_manager.GetSecretByName(txn, secret_name);
	if (!entry) {
		throw InvalidInputException(
		    "quack_oauth_acquire: SECRET '%s' not found", secret_name);
	}
	const auto *kv = dynamic_cast<const KeyValueSecret *>(entry->secret.get());
	if (!kv) {
		throw InvalidInputException(
		    "quack_oauth_acquire: SECRET '%s' is not a key-value secret",
		    secret_name);
	}
	if (kv->GetType() != "quack_oauth") {
		throw InvalidInputException(
		    "quack_oauth_acquire: SECRET '%s' is not of TYPE quack_oauth "
		    "(got '%s')",
		    secret_name, kv->GetType());
	}
	auto get = [&](const char *k) -> std::string {
		const auto it = kv->secret_map.find(k);
		return it != kv->secret_map.end() ? it->second.ToString() : std::string();
	};
	quack_oauth::ClientSecretView v;
	v.access_token = get("access_token");
	v.expires_at_unix_s = ParseIso8601ToUnixSeconds(get("expires_at"));
	v.refresh_token = get("refresh_token");
	v.client_id = get("client_id");
	v.client_secret = get("client_secret");
	v.token_endpoint = get("token_endpoint");
	v.device_authorization_endpoint = get("device_authorization_endpoint");
	v.scope = get("scope");
	return v;
}

std::int64_t NowUnixSeconds() {
	return std::chrono::duration_cast<std::chrono::seconds>(
	           std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

std::int64_t ReadRenewSkew(ClientContext &context) {
	Value v;
	if (!context.TryGetCurrentSetting("quack_oauth_renew_skew_s", v) || v.IsNull()) {
		return 60; // R-C-2 default
	}
	return static_cast<std::int64_t>(v.GetValue<std::int32_t>());
}

// Quote a SQL string literal: single-quote-delimited, with embedded
// single-quotes doubled. Robust against secret names that contain `'`
// or `\`.
std::string SqlQuote(const std::string &s) {
	std::string out = "'";
	for (char c : s) {
		if (c == '\'') out += "''";
		else out += c;
	}
	out += "'";
	return out;
}

// Invoke one of the existing flow scalars via a short-lived Connection,
// then re-read the SECRET to fetch the persisted access_token.
std::string RunFlowAndReadToken(ClientContext &context,
                                const std::string &flow_scalar,
                                const std::string &secret_name) {
	Connection conn(*context.db);
	const auto sql = "SELECT " + flow_scalar + "(" + SqlQuote(secret_name) + ")";
	auto result = conn.Query(sql);
	if (result->HasError()) {
		throw IOException("quack_oauth_acquire: %s failed: %s",
		                  flow_scalar, result->GetError());
	}
	// The flow scalars updated the SECRET. Re-read to get the access_token.
	auto v = LoadClientSecretView(context, secret_name);
	if (v.access_token.empty()) {
		throw IOException(
		    "quack_oauth_acquire: %s completed but no access_token was "
		    "persisted on SECRET '%s'",
		    flow_scalar, secret_name);
	}
	return v.access_token;
}

std::string DoAcquire(ClientContext &context, const std::string &secret_name) {
	if (secret_name.empty()) {
		throw InvalidInputException(
		    "quack_oauth_acquire: secret name must be non-empty");
	}
	auto view = LoadClientSecretView(context, secret_name);
	const auto decision = quack_oauth::DecideAcquireFlow(
	    view, NowUnixSeconds(), ReadRenewSkew(context));

	switch (decision.flow) {
	case quack_oauth::AcquireFlow::UseCached:
		return view.access_token;
	case quack_oauth::AcquireFlow::RefreshToken:
		return RunFlowAndReadToken(context, "quack_oauth_refresh", secret_name);
	case quack_oauth::AcquireFlow::ClientCredentials:
		return RunFlowAndReadToken(context, "quack_oauth_login", secret_name);
	case quack_oauth::AcquireFlow::DeviceCode:
		return RunFlowAndReadToken(context, "quack_oauth_device_login", secret_name);
	case quack_oauth::AcquireFlow::Unconfigured:
	default:
		throw InvalidInputException(
		    "quack_oauth_acquire: SECRET '%s' is %s. %s",
		    secret_name,
		    quack_oauth::AcquireFlowName(decision.flow),
		    decision.reason);
	}
}

void AcquireScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	UnaryExecutor::Execute<string_t, string_t>(
	    args.data[0], result, args.size(), [&](string_t secret_name_str) {
		    const auto tok = DoAcquire(context, secret_name_str.GetString());
		    return StringVector::AddString(result, tok);
	    });
}

} // namespace

void RegisterQuackOauthAcquire(ExtensionLoader &loader) {
	ScalarFunction fn("quack_oauth_acquire", {LogicalType::VARCHAR},
	                  LogicalType::VARCHAR, AcquireScalarFun);
	// Side-effecting + HTTP-bound + idempotent only in the UseCached
	// branch. Never fold or memoise.
	fn.SetVolatile();
	CreateScalarFunctionInfo info(std::move(fn));
	FunctionDescription desc;
	desc.description =
	    "One-stop client-side OAuth orchestrator (R-C-2 + R-C-4). Reads the "
	    "named TYPE=quack_oauth SECRET, decides the right flow from what's "
	    "available -- a fresh cached `access_token` short-circuits; "
	    "otherwise tries `refresh_token` grant, then `client_credentials`, "
	    "then RFC 8628 device_code -- runs it, persists rotated tokens "
	    "back onto the SECRET, and returns the access_token. Designed to "
	    "be threaded into ATTACH: "
	    "`ATTACH 'quack:host:port' AS rs (TYPE quack, token quack_oauth_acquire('cli'))`. "
	    "Honours `quack_oauth_renew_skew_s` (default 60 s) -- ATs within "
	    "the skew window of expiry are treated as stale and re-minted.";
	desc.parameter_names = {"secret_name"};
	desc.parameter_types = {LogicalType::VARCHAR};
	desc.examples = {
	    "SELECT quack_oauth_acquire('my_client')",
	    "ATTACH 'quack:rs.example.com:9494' AS rs "
	    "(TYPE quack, token quack_oauth_acquire('cli'))"};
	desc.categories = {"quack_oauth"};
	info.descriptions.push_back(std::move(desc));
	loader.RegisterFunction(std::move(info));
}

} // namespace duckdb
