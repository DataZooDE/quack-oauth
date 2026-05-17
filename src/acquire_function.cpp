#include "acquire_function.hpp"

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

#include "acquire_flow.hpp"
#include "device_login_function.hpp"
#include "login_function.hpp"
#include "platform_time.hpp"
#include "refresh_function.hpp"
#include "secret_accessor.hpp"

namespace duckdb {

static int64_t ParseIso8601ToUnixSeconds(const string &iso) {
	// Accept "YYYY-MM-DDTHH:MM:SSZ" (the FormatUtcIso8601 shape we
	// persist). Anything else returns 0 = unknown.
	if (iso.size() < 20 || iso[10] != 'T' || iso[19] != 'Z')
		return 0;
	std::tm tm_buf {};
	try {
		tm_buf.tm_year = std::stoi(iso.substr(0, 4)) - 1900;
		tm_buf.tm_mon = std::stoi(iso.substr(5, 2)) - 1;
		tm_buf.tm_mday = std::stoi(iso.substr(8, 2));
		tm_buf.tm_hour = std::stoi(iso.substr(11, 2));
		tm_buf.tm_min = std::stoi(iso.substr(14, 2));
		tm_buf.tm_sec = std::stoi(iso.substr(17, 2));
	} catch (...) {
		return 0;
	}
	if (tm_buf.tm_mon < 0 || tm_buf.tm_mon > 11 || tm_buf.tm_mday < 1 || tm_buf.tm_mday > 31 || tm_buf.tm_hour < 0 ||
	    tm_buf.tm_hour > 23 || tm_buf.tm_min < 0 || tm_buf.tm_min > 59 || tm_buf.tm_sec < 0 || tm_buf.tm_sec > 60) {
		return 0;
	}
	// timegm is POSIX-only; do the conversion manually using days since
	// epoch. The Y-2038 problem is irrelevant for our 64-bit return.
	static constexpr int kDaysBeforeMonth[] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};
	const int year = tm_buf.tm_year + 1900;
	const bool leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
	int yday = kDaysBeforeMonth[tm_buf.tm_mon] + (tm_buf.tm_mday - 1);
	if (tm_buf.tm_mon > 1 && leap)
		yday += 1;
	const int64_t days_before_year =
	    365LL * (year - 1970) + (year - 1969) / 4 - (year - 1901) / 100 + (year - 1601) / 400;
	const int64_t days = days_before_year + yday;
	return days * 86400 + tm_buf.tm_hour * 3600 + tm_buf.tm_min * 60 + tm_buf.tm_sec;
}

static quack_oauth::ClientSecretView LoadClientSecretView(ClientContext &context, const string &secret_name) {
	auto accessor = OpenSecret(context, secret_name, "quack_oauth", "quack_oauth_acquire");
	quack_oauth::ClientSecretView v;
	v.access_token = accessor.Get("access_token");
	v.expires_at_unix_s = ParseIso8601ToUnixSeconds(accessor.Get("expires_at"));
	v.refresh_token = accessor.Get("refresh_token");
	v.client_id = accessor.Get("client_id");
	v.client_secret = accessor.Get("client_secret");
	v.token_endpoint = accessor.Get("token_endpoint");
	v.device_authorization_endpoint = accessor.Get("device_authorization_endpoint");
	v.scope = accessor.Get("scope");
	return v;
}

static int64_t NowUnixSeconds() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

static int64_t ReadRenewSkew(ClientContext &context) {
	Value v;
	if (!context.TryGetCurrentSetting("quack_oauth_renew_skew_s", v) || v.IsNull()) {
		return 60; // R-C-2 default
	}
	return static_cast<int64_t>(v.GetValue<int32_t>());
}

// Invoke a flow implementation in-process (same ClientContext, same
// SecretManager state), then re-read the SECRET to fetch the persisted
// access_token. Earlier versions ran the flow scalar via a sub-Connection,
// but the persisted SECRET writes from that Connection's transaction were
// not visible to the outer context's GetSecretByName re-read -- the
// re-read saw an empty access_token even though the on-disk SECRET was
// already updated. Calling the impl directly keeps everything in one
// transaction scope.
using FlowFn = string (*)(ClientContext &, const string &);
static string RunFlowAndReadToken(ClientContext &context, FlowFn flow, const char *flow_name,
                                  const string &secret_name) {
	flow(context, secret_name);
	auto v = LoadClientSecretView(context, secret_name);
	if (v.access_token.empty()) {
		throw IOException("quack_oauth_acquire: %s completed but no access_token was "
		                  "persisted on SECRET '%s'",
		                  flow_name, secret_name);
	}
	return v.access_token;
}

static string DoAcquire(ClientContext &context, const string &secret_name) {
	if (secret_name.empty()) {
		throw InvalidInputException("quack_oauth_acquire: secret name must be non-empty");
	}
	auto view = LoadClientSecretView(context, secret_name);
	const auto decision = quack_oauth::DecideAcquireFlow(view, NowUnixSeconds(), ReadRenewSkew(context));

	switch (decision.flow) {
	case quack_oauth::AcquireFlow::UseCached:
		return view.access_token;
	case quack_oauth::AcquireFlow::RefreshToken:
		return RunFlowAndReadToken(context, &DoRefresh, "quack_oauth_refresh", secret_name);
	case quack_oauth::AcquireFlow::ClientCredentials:
		return RunFlowAndReadToken(context, &DoLogin, "quack_oauth_login", secret_name);
	case quack_oauth::AcquireFlow::DeviceCode:
		return RunFlowAndReadToken(context, &DoDeviceLoginImpl, "quack_oauth_device_login", secret_name);
	case quack_oauth::AcquireFlow::Unconfigured:
	default:
		throw InvalidInputException("quack_oauth_acquire: SECRET '%s' is %s. %s", secret_name,
		                            quack_oauth::AcquireFlowName(decision.flow), decision.reason);
	}
}

static void AcquireScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t secret_name_str) {
		const auto tok = DoAcquire(context, secret_name_str.GetString());
		return StringVector::AddString(result, tok);
	});
}

void RegisterQuackOauthAcquire(ExtensionLoader &loader) {
	ScalarFunction fn("quack_oauth_acquire", {LogicalType::VARCHAR}, LogicalType::VARCHAR, AcquireScalarFun);
	// Side-effecting + HTTP-bound + idempotent only in the UseCached
	// branch. Never fold or memoise.
	fn.SetVolatile();
	CreateScalarFunctionInfo info(std::move(fn));
	FunctionDescription desc;
	desc.description = "One-stop client-side OAuth orchestrator (R-C-2 + R-C-4). Reads the "
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
	desc.examples = {"SELECT quack_oauth_acquire('my_client')", "ATTACH 'quack:rs.example.com:9494' AS rs "
	                                                            "(TYPE quack, token quack_oauth_acquire('cli'))"};
	desc.categories = {"quack_oauth"};
	info.descriptions.push_back(std::move(desc));
	loader.RegisterFunction(std::move(info));
}

} // namespace duckdb
