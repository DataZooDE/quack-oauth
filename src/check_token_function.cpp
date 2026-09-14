#include "check_token_function.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "duckdb/common/exception.hpp"
#include "duckdb/logging/logger.hpp"

// DuckDB 1.4 spells this `DUCKDB_LOG_WARN`; 1.5+ renamed it to
// `DUCKDB_LOG_WARNING`. Map the new spelling to the old one when only
// the 1.4 macro is defined.
#if !defined(DUCKDB_LOG_WARNING) && defined(DUCKDB_LOG_WARN)
#define DUCKDB_LOG_WARNING DUCKDB_LOG_WARN
#endif

#include "duckdb/common/types/data_chunk.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/common/vector_operations/unary_executor.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"

#include "audit.hpp"
#include "audit_sink.hpp"
#include "github_check.hpp"
#include "http_client_duckdb.hpp"
#include "jwt_parse.hpp"
#include "jwt_verify.hpp"
#include "plaintext_guard.hpp"
#include "providers.hpp"
#include "quack_oauth_state.hpp"
#include "retry_http_client.hpp"
#include "secret_accessor.hpp"
#include "secrets.hpp"
#include "secure_scrub.hpp"

#include "telemetry.hpp"
#include "tracing.hpp"
#include "validator.hpp"

#include "duckdb/main/connection.hpp"
#include "quack_oauth_banner.hpp"

namespace duckdb {

struct ServerConfig {
	// Common
	string mode; // "jwks" (default) or "introspect"
	string issuer;
	string audience;
	int64_t clock_skew_s = 60;
	// jwks mode
	string jwks_uri;
	// introspect mode
	string introspection_endpoint;
	string introspect_client_id;
	string introspect_client_secret;
};

static string ReadStringSetting(ClientContext &context, const string &key) {
	Value v;
	if (!context.TryGetCurrentSetting(key, v) || v.IsNull()) {
		return "";
	}
	return v.ToString();
}

static int64_t ReadIntSetting(ClientContext &context, const string &key, int64_t fallback) {
	Value v;
	if (!context.TryGetCurrentSetting(key, v) || v.IsNull()) {
		return fallback;
	}
	return v.GetValue<int32_t>();
}

// Reads the SECRET + settings into a partially-populated ServerConfig.
// No validation; the caller layers provider presets and per-mode checks
// on top.
static ServerConfig ReadServerConfigCore(ClientContext &context, const SecretAccessor &accessor) {
	ServerConfig cfg;
	cfg.mode = ReadStringSetting(context, "quack_oauth_validation_mode");
	if (cfg.mode.empty()) {
		cfg.mode = "jwks";
	}
	cfg.issuer = accessor.Get("issuer");
	cfg.audience = accessor.Get("audience");
	cfg.clock_skew_s = std::clamp<int64_t>(ReadIntSetting(context, "quack_oauth_clock_skew_s", 60), 0, 3600);

	cfg.jwks_uri = accessor.Get("jwks_uri");
	cfg.introspection_endpoint = accessor.Get("introspection_endpoint");
	cfg.introspect_client_id = accessor.Get("introspect_client_id");
	cfg.introspect_client_secret = accessor.Get("introspect_client_secret");
	return cfg;
}

// R-S-12: provider presets fill empty issuer/jwks_uri/introspection_endpoint
// from per-provider templates. Explicit SECRET fields always win.
// R-S-13: 'github' provider auto-promotes mode 'jwks' → 'github_check'
// because GitHub tokens are opaque and have no JWKS.
//
// `tenant_or_realm` is required for tenant-templated providers
// (Entra, Keycloak, GitHub) and unused for Google. Earlier this branch
// short-circuited on empty tenant_or_realm, which silently skipped the
// Google preset and forced operators to set `introspection_endpoint`
// explicitly -- contradicting the README and producing a confusing
// `Authentication failed` at the first token request.
static void ApplyProviderPreset(ClientContext &context, const SecretAccessor &accessor, ServerConfig &cfg) {
	const auto provider_name = ReadStringSetting(context, "quack_oauth_provider");
	if (provider_name.empty() || provider_name == "generic") {
		return;
	}
	const auto provider_id = quack_oauth::ProviderFromString(provider_name);
	if (provider_id == quack_oauth::ProviderId::Okta) {
		if (cfg.issuer.empty() || cfg.jwks_uri.empty()) {
			throw InvalidInputException(
			    "quack_oauth: provider preset 'okta' is reserved for future auto-fill; "
			    "please configure `issuer` and `jwks_uri` explicitly on the SECRET (or use provider='generic').");
		}
	}
	const auto tenant_or_realm = accessor.Get("tenant_or_realm");
	if (provider_id != quack_oauth::ProviderId::Google && tenant_or_realm.empty()) {
		// Tenant-templated providers need a tenant/realm to materialise
		// URLs. Fail fast with a clear message rather than emitting
		// `https://login.microsoftonline.com//v2.0` and failing at fetch.
		throw InvalidInputException(
		    "quack_oauth provider preset '%s' requires `tenant_or_realm` on the active SECRET "
		    "(set it to the tenant id / realm URL / GitHub App client_id depending on the provider).",
		    provider_name);
	}
	const auto resolved = quack_oauth::ResolveProvider(provider_id, tenant_or_realm);
	if (cfg.issuer.empty())
		cfg.issuer = resolved.issuer;
	if (cfg.jwks_uri.empty())
		cfg.jwks_uri = resolved.jwks_uri;
	if (cfg.introspection_endpoint.empty())
		cfg.introspection_endpoint = resolved.introspection_endpoint;
	if (provider_id == quack_oauth::ProviderId::Github) {
		// For the github preset, `tenant_or_realm` IS the App's client_id
		// (same value goes into HTTP Basic auth user against
		// /applications/{client_id}/token). Default introspect_client_id
		// to it so users don't have to repeat the value -- removing the
		// redundancy in the documented SECRET shape.
		if (cfg.introspect_client_id.empty())
			cfg.introspect_client_id = tenant_or_realm;
		if (cfg.mode == "jwks")
			cfg.mode = "github_check";
	}
}

// Per-mode field-presence checks. Throws InvalidInputException on
// missing fields or unknown mode.
static void ValidateServerConfig(const ServerConfig &cfg, const string &secret_name) {
	if (cfg.mode == "jwks") {
		if (cfg.jwks_uri.empty()) {
			throw InvalidInputException("quack_oauth_check_token: SECRET '%s' is missing `jwks_uri` "
			                            "(required for validation_mode='jwks')",
			                            secret_name);
		}
		ValidateHttpUrl("jwks_uri", cfg.jwks_uri);
		return;
	}
	if (cfg.mode == "introspect") {
		if (cfg.introspection_endpoint.empty()) {
			throw InvalidInputException("quack_oauth_check_token: SECRET '%s' is missing "
			                            "`introspection_endpoint` (required for validation_mode='introspect')",
			                            secret_name);
		}
		ValidateHttpUrl("introspection_endpoint", cfg.introspection_endpoint);
		return;
	}
	if (cfg.mode == "tokeninfo") {
		if (cfg.introspection_endpoint.empty()) {
			throw InvalidInputException("quack_oauth_check_token: SECRET '%s' is missing "
			                            "`introspection_endpoint` (required for validation_mode='tokeninfo' -- "
			                            "use the IdP's tokeninfo URL, e.g. https://oauth2.googleapis.com/tokeninfo)",
			                            secret_name);
		}
		ValidateHttpUrl("introspection_endpoint", cfg.introspection_endpoint);
		return;
	}
	if (cfg.mode == "github_check") {
		if (cfg.introspection_endpoint.empty()) {
			throw InvalidInputException("quack_oauth_check_token: SECRET '%s' is missing "
			                            "`introspection_endpoint` (set to GitHub's "
			                            "`applications/{client_id}/token` URL, or rely on the "
			                            "`provider='github'` preset which fills it from tenant_or_realm).",
			                            secret_name);
		}
		if (cfg.introspect_client_id.empty() || cfg.introspect_client_secret.empty()) {
			throw InvalidInputException("quack_oauth_check_token: SECRET '%s' is missing "
			                            "`introspect_client_id` / `introspect_client_secret` "
			                            "(GitHub App credentials, required for HTTP Basic on the "
			                            "/applications/{client_id}/token endpoint).",
			                            secret_name);
		}
		ValidateHttpUrl("introspection_endpoint", cfg.introspection_endpoint);
		return;
	}

	throw InvalidInputException("quack_oauth_check_token: unknown validation_mode '%s' (expected 'jwks', "
	                            "'introspect', 'tokeninfo', or 'github_check')",
	                            cfg.mode);
}

static ServerConfig LoadServerConfig(ClientContext &context) {
	const auto secret_name = ReadStringSetting(context, "quack_oauth_server_secret_name");
	if (secret_name.empty()) {
		throw InvalidInputException("quack_oauth_check_token requires SET quack_oauth_server_secret_name "
		                            "to name the TYPE=quack_oauth_server SECRET to validate against.");
	}
	// `expected_type=nullptr`: server SECRETs may be either TYPE=quack_oauth_server
	// or older TYPE=quack_oauth (back-compat). We rely on validation_mode +
	// field presence to drive the actual mode-specific checks below.
	auto accessor = OpenSecret(context, secret_name, /*expected_type=*/nullptr, "quack_oauth_check_token");
	auto cfg = ReadServerConfigCore(context, accessor);
	ApplyProviderPreset(context, accessor, cfg);
	ValidateServerConfig(cfg, secret_name);
	return cfg;
}

// (cont'd) Build a Principal from a parsed JWT for the authz path.
// `scope` (space-delimited), `scp[]` (Microsoft delegated) and `roles[]`
// (Entra app roles / Auth0 RBAC) are merged into a single vector. The
// policy table's `any_scope` predicate then matches either OAuth scopes
// or app roles uniformly.
static quack_oauth::Principal PrincipalFromJwt(const quack_oauth::JwtParsed &jwt) {
	quack_oauth::Principal p;
	p.subject = jwt.subject;
	p.issuer = jwt.issuer;
	p.exp = jwt.exp;
	if (!jwt.scope.empty()) {
		std::size_t start = 0;
		while (start < jwt.scope.size()) {
			auto end = jwt.scope.find(' ', start);
			if (end == std::string::npos)
				end = jwt.scope.size();
			if (end > start) {
				p.scopes.emplace_back(jwt.scope.substr(start, end - start));
			}
			start = end + 1;
		}
	}
	for (const auto &s : jwt.scp) {
		p.scopes.push_back(s);
	}
	for (const auto &r : jwt.roles) {
		p.scopes.push_back(r);
	}
	return p;
}

static const char *VerifyResultReason(quack_oauth::VerifyResult r) {
	switch (r) {
	case quack_oauth::VerifyResult::Ok:
		return "ok";
	case quack_oauth::VerifyResult::Malformed:
		return "malformed";
	case quack_oauth::VerifyResult::DisallowedAlgorithm:
		return "disallowed_algorithm";
	case quack_oauth::VerifyResult::InvalidSignature:
		return "invalid_signature";
	case quack_oauth::VerifyResult::Expired:
		return "expired";
	case quack_oauth::VerifyResult::NotYetValid:
		return "not_yet_valid";
	case quack_oauth::VerifyResult::WrongIssuer:
		return "wrong_issuer";
	case quack_oauth::VerifyResult::WrongAudience:
		return "wrong_audience";
	case quack_oauth::VerifyResult::UnsupportedKeyType:
		return "unsupported_key_type";
	case quack_oauth::VerifyResult::UnusableKey:
		return "unusable_key";
	case quack_oauth::VerifyResult::UnknownKid:
		return "unknown_kid";
	case quack_oauth::VerifyResult::JwksFetchFailed:
		return "jwks_fetch_failed";
	case quack_oauth::VerifyResult::JwksThrottled:
		return "jwks_throttled";
	case quack_oauth::VerifyResult::NoMatchingKey:
		return "no_matching_key";
	}
	return "unknown";
}

static void EmitTokenAudit(ClientContext &context, const string &token, quack_oauth::VerifyResult outcome,
                           const string &reason, int64_t now_s, const quack_oauth::Principal *principal_on_success) {
	quack_oauth::AuditEvent e;
	e.timestamp_unix_s = now_s;
	const bool ok = outcome == quack_oauth::VerifyResult::Ok;
	e.event_type = ok ? quack_oauth::AuditEventType::TokenAccepted : quack_oauth::AuditEventType::TokenRejected;
	e.token_hash = quack_oauth::RedactSensitive(token);
	if (ok && principal_on_success != nullptr) {
		e.subject = principal_on_success->subject;
		e.issuer = principal_on_success->issuer;
	}
	e.reason = reason;
	EmitAuditEvent(context, e);
}

// Per-row validation result the row-validator lambdas return. `principal`
// is meaningful only when `outcome == Ok && have_principal`.
struct RowValidation {
	quack_oauth::VerifyResult outcome;
	bool have_principal = false;
	quack_oauth::Principal principal;
	std::string refresh_kid;
	std::string refresh_reason;
	quack_oauth::RefreshReason refresh_reason_enum = quack_oauth::RefreshReason::None;
};

struct ThrottledLogEvent {
	std::string kid;
	std::string reason;
	std::string jwks_uri;

	bool operator<(const ThrottledLogEvent &o) const {
		return std::tie(kid, reason, jwks_uri) < std::tie(o.kid, o.reason, o.jwks_uri);
	}
	bool operator==(const ThrottledLogEvent &o) const {
		return std::tie(kid, reason, jwks_uri) == std::tie(o.kid, o.reason, o.jwks_uri);
	}
};

class UnlockingHttpClient : public quack_oauth::IHttpClient {
public:
	UnlockingHttpClient(quack_oauth::IHttpClient &inner, std::unique_lock<std::mutex> &guard)
	    : inner_(inner), guard_(guard) {
	}

	std::optional<Response> Get(std::string_view url) override {
		guard_.unlock();
		try {
			auto result = inner_.Get(url);
			guard_.lock();
			return result;
		} catch (...) {
			guard_.lock();
			throw;
		}
	}

	std::optional<Response> Post(const PostRequest &req) override {
		guard_.unlock();
		try {
			auto result = inner_.Post(req);
			guard_.lock();
			return result;
		} catch (...) {
			guard_.lock();
			throw;
		}
	}

private:
	quack_oauth::IHttpClient &inner_;
	std::unique_lock<std::mutex> &guard_;
};

static void StoreSessionPrincipal(QuackOauthState &shared_state, const string &sid,
                                  const quack_oauth::Principal &principal, int64_t now_s) {
	static constexpr std::size_t kMaxSessionPrincipals = 1000;
	shared_state.session_principals[sid] = SessionPrincipal {principal, now_s};
	while (shared_state.session_principals.size() > kMaxSessionPrincipals) {
		auto victim = shared_state.session_principals.begin();
		for (auto it = shared_state.session_principals.begin(); it != shared_state.session_principals.end(); ++it) {
			const auto victim_exp = victim->second.principal.exp;
			const auto it_exp = it->second.principal.exp;
			if ((it_exp > 0 && victim_exp <= 0) || (it_exp > 0 && victim_exp > 0 && it_exp < victim_exp) ||
			    (it_exp == victim_exp && it->second.updated_at_s < victim->second.updated_at_s)) {
				victim = it;
			}
		}
		shared_state.session_principals.erase(victim);
	}
}

static void EmitAuditsAndScrub(ClientContext &context, string &token_str, const RowValidation &row, int64_t now_s,
                               std::unique_lock<std::mutex> &guard, const std::string &jwks_uri,
                               std::vector<ThrottledLogEvent> &throttled_events) {
	const bool ok = row.outcome == quack_oauth::VerifyResult::Ok;
	guard.unlock();
	std::string audit_reason = VerifyResultReason(row.outcome);
	if (!ok && (row.refresh_reason_enum == quack_oauth::RefreshReason::Throttled ||
	            row.refresh_reason_enum == quack_oauth::RefreshReason::BudgetThrottled)) {
		audit_reason = "jwks_throttled";
	}
	EmitTokenAudit(context, token_str, row.outcome, audit_reason, now_s,
	               (ok && row.have_principal) ? &row.principal : nullptr);
	if (!row.refresh_kid.empty()) {
		if (row.refresh_reason_enum == quack_oauth::RefreshReason::Throttled ||
		    row.refresh_reason_enum == quack_oauth::RefreshReason::BudgetThrottled) {
			throttled_events.push_back({row.refresh_kid, row.refresh_reason, jwks_uri});
		}

		if (quack_oauth::ShouldAudit(row.refresh_reason_enum)) {
			quack_oauth::AuditEvent e;
			e.timestamp_unix_s = now_s;
			e.event_type = quack_oauth::AuditEventType::JwksRefresh;
			e.kid = row.refresh_kid;
			e.reason = row.refresh_reason;
			e.token_hash = quack_oauth::RedactSensitive(token_str);
			EmitAuditEvent(context, e);
		}
	}
	guard.lock();
	quack_oauth::SecureScrub(token_str); // R-N-3
}

static string SanitizeLogField(const string &str, size_t max_len = 256) {
	string safe;
	for (char c : str) {
		if (static_cast<unsigned char>(c) >= 32 && static_cast<unsigned char>(c) < 127 && c != '"' && c != '\'' &&
		    c != '\\') {
			safe.push_back(c);
		}
	}
	if (safe.size() > max_len) {
		safe.resize(max_len);
	}
	return safe;
}

static void LogThrottledEvents(ClientContext &context, QuackOauthState &shared_state,
                               std::vector<ThrottledLogEvent> &throttled_events, int64_t now_s) {
	if (throttled_events.empty()) {
		return;
	}
	std::sort(throttled_events.begin(), throttled_events.end());
	throttled_events.erase(std::unique(throttled_events.begin(), throttled_events.end()), throttled_events.end());
	for (const auto &item : throttled_events) {
		const string safe_kid = SanitizeLogField(item.kid, 256);
		const string safe_uri = SanitizeLogField(item.jwks_uri, 512);
		const string dedup_key = safe_kid + ":" + item.reason + ":" + safe_uri;

		auto it = shared_state.last_throttle_logged_s.find(dedup_key);
		if (it != shared_state.last_throttle_logged_s.end() && now_s >= it->second && (now_s - it->second < 30)) {
			continue;
		}
		shared_state.last_throttle_logged_s[dedup_key] = now_s;

		const std::string uri_suffix = safe_uri.empty() ? "" : (" jwks_uri='" + safe_uri + "'");
		if (item.reason == quack_oauth::kReasonRefreshThrottled) {
			DUCKDB_LOG_WARNING(context, "quack_oauth: JWKS refresh rate-limited by min_refresh_s for kid='" + safe_kid +
			                                "'" + uri_suffix);
		} else {
			DUCKDB_LOG_WARNING(context,
			                   "quack_oauth: JWKS refresh throttled by global fetch budget (2s window) for kid='" +
			                       safe_kid + "'" + uri_suffix);
		}
	}
	if (shared_state.last_throttle_logged_s.size() > 1000) {
		for (auto it = shared_state.last_throttle_logged_s.begin(); it != shared_state.last_throttle_logged_s.end();) {
			if (now_s < it->second || (now_s - it->second > 30)) {
				it = shared_state.last_throttle_logged_s.erase(it);
			} else {
				++it;
			}
		}
		if (shared_state.last_throttle_logged_s.size() > 1000) {
			std::vector<std::pair<std::string, int64_t>> entries(shared_state.last_throttle_logged_s.begin(),
			                                                     shared_state.last_throttle_logged_s.end());
			std::sort(entries.begin(), entries.end(), [](const auto &a, const auto &b) { return a.second < b.second; });
			const size_t to_remove = entries.size() - 800;
			for (size_t i = 0; i < to_remove; ++i) {
				shared_state.last_throttle_logged_s.erase(entries[i].first);
			}
		}
	}
}

// Drive a chunk through a per-row validator. Centralises the boilerplate
// (UnifiedVectorFormat parallel iteration, principal caching, audit
// emission, R-N-3 secure scrub) that was previously copy-pasted across
// 4 modes × 2 (with/without session_ids).
template <class Fn>
static void RunValidationLoop(Vector &tokens, idx_t count, Vector &result, ClientContext &context, Vector *session_ids,
                              int64_t now_s, QuackOauthState &shared_state, std::unique_lock<std::mutex> &guard,
                              const std::string &jwks_uri, Fn &&validate_row) {
	std::vector<ThrottledLogEvent> throttled_events;
	if (session_ids != nullptr) {
		UnifiedVectorFormat tok_format;
		UnifiedVectorFormat sid_format;
		tokens.ToUnifiedFormat(count, tok_format);
		session_ids->ToUnifiedFormat(count, sid_format);

		const auto *tok_data = UnifiedVectorFormat::GetData<string_t>(tok_format);
		const auto *sid_data = UnifiedVectorFormat::GetData<string_t>(sid_format);
		auto *out_data = FlatVector::GetData<bool>(result);

		for (idx_t i = 0; i < count; ++i) {
			const auto tok_idx = tok_format.sel->get_index(i);
			const auto sid_idx = sid_format.sel->get_index(i);

			if (!tok_format.validity.RowIsValid(tok_idx)) {
				out_data[i] = false;
				continue;
			}

			const auto raw_token = tok_data[tok_idx].GetString();
			auto token_str = std::string(quack_oauth::StripBearerPrefix(raw_token));
			const auto row = validate_row(token_str);
			const bool ok = row.outcome == quack_oauth::VerifyResult::Ok;
			out_data[i] = ok;

			if (ok && row.have_principal && sid_format.validity.RowIsValid(sid_idx)) {
				const auto sid = sid_data[sid_idx].GetString();
				if (!sid.empty()) {
					StoreSessionPrincipal(shared_state, sid, row.principal, now_s);
				}
			}

			EmitAuditsAndScrub(context, token_str, row, now_s, guard, jwks_uri, throttled_events);
		}
	} else {
		UnaryExecutor::Execute<string_t, bool>(tokens, result, count, [&](string_t token) {
			const auto raw_token = token.GetString();
			auto token_str = std::string(quack_oauth::StripBearerPrefix(raw_token));
			const auto row = validate_row(token_str);
			const bool ok = row.outcome == quack_oauth::VerifyResult::Ok;
			EmitAuditsAndScrub(context, token_str, row, now_s, guard, jwks_uri, throttled_events);
			return ok;
		});
	}

	LogThrottledEvents(context, shared_state, throttled_events, now_s);
}

// Shared validation entry point. Both the 1-arg form (direct CLI use) and
// the 3-arg overload (the shape quack itself calls -- session_id, auth_string,
// token -- per `quack/src/quack_extension.cpp` line 125) route here.
//
// When a session_id is known (3-arg overload) and validation succeeds, we
// cache the extracted Principal in QuackOauthState::session_principals so
// the companion authz scalar can look it up.
static void ValidateChunk(Vector &tokens, idx_t count, Vector &result, ClientContext &context, Vector *session_ids) {
	PostHogTelemetry::Instance().RecordFunctionCall("quack_oauth_check_token");
	const auto cfg = LoadServerConfig(context);

	quack_oauth::VerifyOptions opts;
	opts.expected_issuer = cfg.issuer;
	opts.expected_audience = cfg.audience;
	opts.clock_skew_s = cfg.clock_skew_s;
	opts.now_s =
	    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

	auto &shared_state = GetQuackOauthState();
	// R-N-7: wrap with one retry on transient failure (5xx / transport).
	DuckdbHttpClient base_http;

	std::unique_lock<std::mutex> guard(shared_state.mu);
	UnlockingHttpClient unlocking_http(base_http, guard);
	quack_oauth::RetryingHttpClient http(unlocking_http, /*max_retries=*/1, std::chrono::milliseconds(1000),
	                                     [&](std::chrono::milliseconds delay) {
		                                     guard.unlock();
		                                     std::this_thread::sleep_for(delay);
		                                     guard.lock();
	                                     });

	if (cfg.mode == "introspect") {
		quack_oauth::IntrospectContext ictx {
		    http,
		    shared_state.decision_cache,
		    cfg.introspection_endpoint,
		    cfg.introspect_client_id,
		    cfg.introspect_client_secret,
		    cfg.issuer,
		    cfg.audience,
		};
		RunValidationLoop(tokens, count, result, context, session_ids, opts.now_s, shared_state, guard, "",
		                  [&](string &token_str) -> RowValidation {
			                  RowValidation r;
			                  r.outcome =
			                      quack_oauth::ValidateTokenViaIntrospection(token_str, opts, ictx, &r.principal);
			                  r.have_principal = r.outcome == quack_oauth::VerifyResult::Ok;
			                  return r;
		                  });
	} else if (cfg.mode == "tokeninfo") {
		quack_oauth::TokeninfoContext tctx {
		    http,
		    shared_state.decision_cache,
		    cfg.introspection_endpoint,
		    cfg.audience,
		};
		RunValidationLoop(tokens, count, result, context, session_ids, opts.now_s, shared_state, guard, "",
		                  [&](string &token_str) -> RowValidation {
			                  RowValidation r;
			                  r.outcome = quack_oauth::ValidateTokenViaTokeninfo(token_str, opts, tctx, &r.principal);
			                  r.have_principal = r.outcome == quack_oauth::VerifyResult::Ok;
			                  return r;
		                  });
	} else if (cfg.mode == "github_check") {
		quack_oauth::GithubContext gctx {
		    http,
		    shared_state.decision_cache,
		    cfg.introspection_endpoint,
		    cfg.introspect_client_id,
		    cfg.introspect_client_secret,
		};
		RunValidationLoop(tokens, count, result, context, session_ids, opts.now_s, shared_state, guard, "",
		                  [&](string &token_str) -> RowValidation {
			                  RowValidation r;
			                  r.outcome = quack_oauth::ValidateTokenViaGithubCheck(token_str, opts, gctx, &r.principal);
			                  r.have_principal = r.outcome == quack_oauth::VerifyResult::Ok;
			                  return r;
		                  });
	} else { // jwks
		quack_oauth::ValidateContext vctx {http, shared_state.jwks_cache, cfg.jwks_uri};
		RunValidationLoop(tokens, count, result, context, session_ids, opts.now_s, shared_state, guard, cfg.jwks_uri,
		                  [&](string &token_str) -> RowValidation {
			                  RowValidation r;
			                  quack_oauth::RefreshEvent refresh_event;
			                  r.outcome = quack_oauth::ValidateToken(token_str, opts, vctx, &refresh_event);
			                  if (!refresh_event.reason.empty()) {
				                  r.refresh_kid = std::move(refresh_event.kid);
				                  r.refresh_reason = std::move(refresh_event.reason);
				                  r.refresh_reason_enum = refresh_event.reason_enum;
			                  }
			                  if (r.outcome == quack_oauth::VerifyResult::Ok) {
				                  const auto parsed = quack_oauth::ParseJwt(token_str);
				                  if (parsed.has_value()) {
					                  r.principal = PrincipalFromJwt(*parsed);
					                  r.have_principal = true;
				                  }
			                  }
			                  return r;
		                  });
	}
}

// R-N-4: refuse to validate a token over the wire when the active quack
// listener is bound to a non-loopback host AND the operator has not
// explicitly opted in via `quack_oauth_trust_plaintext = true`. The check
// is best-effort: if quack isn't loaded, or the listener list query fails,
// we assume no public surface exists and let the call through. (In the
// real wire path, our check_token is only invoked by quack's auth thread,
// which by construction means a listener is up.)
static void EnforcePlaintextGuard(ClientContext &context) {
	Value v;
	if (context.TryGetCurrentSetting("quack_oauth_trust_plaintext", v) && !v.IsNull() && v.GetValue<bool>()) {
		return; // operator has opted into plaintext.
	}

	Connection conn(*context.db);
	auto result = conn.Query("SELECT listen_uri FROM quack_server_list()");
	if (result->HasError()) {
		return; // quack isn't loaded, or no server is running. Nothing to guard.
	}
	for (auto &row : result->Collection().GetRows()) {
		const auto uri_v = row.GetValue(0);
		if (uri_v.IsNull())
			continue;
		const auto uri = StringValue::Get(uri_v);
		const auto host = quack_oauth::HostFromQuackUri(uri);
		if (!quack_oauth::IsLoopbackHost(host)) {
			throw InvalidInputException("quack_oauth: refusing to validate a bearer token because the "
			                            "active quack listener '%s' is bound to a non-loopback host "
			                            "and `quack_oauth_trust_plaintext` is not true. Either "
			                            "terminate TLS in front of this listener and `SET "
			                            "quack_oauth_trust_plaintext = true`, or bind the listener "
			                            "to 127.0.0.1 / ::1 / localhost. (R-N-4)",
			                            uri);
		}
	}
}

static void CheckTokenScalarFun1(DataChunk &args, ExpressionState &state, Vector &result) {
	EnforcePlaintextGuard(state.GetContext());
	ValidateChunk(args.data[0], args.size(), result, state.GetContext(), nullptr);
}

static void CheckTokenScalarFun3(DataChunk &args, ExpressionState &state, Vector &result) {
	EnforcePlaintextGuard(state.GetContext());
	// quack's calling convention (verified against duckdb-quack
	// src/quack_server.cpp): SELECT <fn>(session_id, auth_string, token)
	// where:
	//   args[0] = session_id        -- server-generated, used as the
	//                                  Principal-cache key for the authz
	//                                  handoff.
	//   args[1] = auth_string       -- the HTTP Authorization header (e.g.
	//                                  'Bearer eyJ...') or token attach option
	//                                  the client supplied. Optional 'Bearer '
	//                                  prefix is stripped automatically.
	//   args[2] = token             -- quack's internal PSK (from quack_serve's
	//                                  token option). Ignored here because we
	//                                  authenticate the client's bearer token,
	//                                  not the server PSK.
	ValidateChunk(args.data[1], args.size(), result, state.GetContext(), &args.data[0]);
}

void RegisterQuackOauthCheckToken(ExtensionLoader &loader) {
	ScalarFunctionSet set("quack_oauth_check_token");

	ScalarFunction fn1({LogicalType::VARCHAR}, LogicalType::BOOLEAN,
	                   DATAZOO_GUARD(QUACK_OAUTH_BANNER, CheckTokenScalarFun1));
	fn1.stability = FunctionStability::VOLATILE;
	set.AddFunction(fn1);

	ScalarFunction fn3({LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR}, LogicalType::BOOLEAN,
	                   DATAZOO_GUARD(QUACK_OAUTH_BANNER, CheckTokenScalarFun3));
	fn3.stability = FunctionStability::VOLATILE;
	set.AddFunction(fn3);

	CreateScalarFunctionInfo info(std::move(set));
	FunctionDescription desc1;
	desc1.description = "Validate an OAuth 2.1 / OIDC access token against the active quack_oauth_server "
	                    "SECRET. Returns true if the token verifies (JWKS-mode signature check, RFC 7662 "
	                    "introspection, or Google-style tokeninfo per global setting quack_oauth_validation_mode "
	                    "or provider preset).";
	desc1.parameter_names = {"token"};

	desc1.parameter_types = {LogicalType::VARCHAR};
	desc1.examples = {"SELECT quack_oauth_check_token('eyJhbGciOi...')"};
	desc1.categories = {"quack_oauth"};
	info.descriptions.push_back(std::move(desc1));

	FunctionDescription desc3;
	desc3.description =
	    "3-argument form matching quack's quack_check_token callback signature. "
	    "Validates client token in auth_string (arg 2) after stripping optional Bearer prefix (ignoring quack's "
	    "internal PSK in arg 3) AND caches the extracted Principal keyed by session_id (arg 1) so a subsequent "
	    "quack_oauth_check_authorization() call can apply policies. Wired into quack via `SET "
	    "quack_authentication_function = 'quack_oauth_check_token'`.";
	desc3.parameter_names = {"session_id", "auth_string", "token"};
	desc3.parameter_types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR};

	desc3.examples = {"SELECT quack_oauth_check_token('sess-1', 'Bearer eyJhbGciOi...', '')"};
	desc3.categories = {"quack_oauth"};
	info.descriptions.push_back(std::move(desc3));

	loader.RegisterFunction(std::move(info));
}

} // namespace duckdb
