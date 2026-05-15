#include "check_token_function.hpp"

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
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
#include "secure_scrub.hpp"
#include "tracing.hpp"
#include "validator.hpp"

#include "duckdb/main/connection.hpp"

namespace duckdb {

namespace {

struct ServerConfig {
	// Common
	std::string mode; // "jwks" (default) or "introspect"
	std::string issuer;
	std::string audience;
	std::int64_t clock_skew_s = 60;
	// jwks mode
	std::string jwks_uri;
	// introspect mode
	std::string introspection_endpoint;
	std::string introspect_client_id;
	std::string introspect_client_secret;
};

std::string ReadStringSetting(ClientContext &context, const std::string &key) {
	Value v;
	if (!context.TryGetCurrentSetting(key, v) || v.IsNull()) {
		return "";
	}
	return v.ToString();
}

std::int64_t ReadIntSetting(ClientContext &context, const std::string &key,
                            std::int64_t fallback) {
	Value v;
	if (!context.TryGetCurrentSetting(key, v) || v.IsNull()) {
		return fallback;
	}
	return v.GetValue<std::int32_t>();
}

ServerConfig LoadServerConfig(ClientContext &context) {
	const auto secret_name = ReadStringSetting(context, "quack_oauth_server_secret_name");
	if (secret_name.empty()) {
		throw InvalidInputException(
		    "quack_oauth_check_token requires SET quack_oauth_server_secret_name "
		    "to name the TYPE=quack_oauth_server SECRET to validate against.");
	}

	auto &secret_manager = SecretManager::Get(context);
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
	auto secret_entry = secret_manager.GetSecretByName(transaction, secret_name);
	if (!secret_entry) {
		throw InvalidInputException(
		    "quack_oauth_check_token: SECRET '%s' not found", secret_name);
	}
	const auto *kv = dynamic_cast<const KeyValueSecret *>(secret_entry->secret.get());
	if (!kv) {
		throw InvalidInputException(
		    "quack_oauth_check_token: SECRET '%s' is not a key-value secret",
		    secret_name);
	}

	auto get = [kv](const std::string &k) -> std::string {
		const auto it = kv->secret_map.find(k);
		return (it != kv->secret_map.end()) ? it->second.ToString() : std::string();
	};

	ServerConfig cfg;
	cfg.mode = ReadStringSetting(context, "quack_oauth_validation_mode");
	if (cfg.mode.empty()) {
		cfg.mode = "jwks";
	}
	cfg.issuer = get("issuer");
	cfg.audience = get("audience");
	cfg.clock_skew_s = ReadIntSetting(context, "quack_oauth_clock_skew_s", 60);
	cfg.jwks_uri = get("jwks_uri");
	cfg.introspection_endpoint = get("introspection_endpoint");
	cfg.introspect_client_id = get("introspect_client_id");
	cfg.introspect_client_secret = get("introspect_client_secret");

	// R-S-12: provider presets fill in issuer/jwks_uri/introspection_endpoint
	// from per-provider templates when the operator didn't set them
	// explicitly. Explicit SECRET fields always win.
	const auto provider_name = ReadStringSetting(context, "quack_oauth_provider");
	if (!provider_name.empty() && provider_name != "generic") {
		const auto tenant_or_realm = get("tenant_or_realm");
		if (!tenant_or_realm.empty()) {
			const auto resolved = quack_oauth::ResolveProvider(
			    quack_oauth::ProviderFromString(provider_name), tenant_or_realm);
			if (cfg.issuer.empty()) cfg.issuer = resolved.issuer;
			if (cfg.jwks_uri.empty()) cfg.jwks_uri = resolved.jwks_uri;
			if (cfg.introspection_endpoint.empty())
				cfg.introspection_endpoint = resolved.introspection_endpoint;
		}
		// R-S-13: GitHub is not OIDC; auto-route to the bespoke
		// `applications/{client_id}/token` check unless the operator
		// explicitly picked a different mode. The default `jwks` would
		// fail (GitHub tokens are opaque).
		if (provider_name == "github" && cfg.mode == "jwks") {
			cfg.mode = "github_check";
		}
	}

	if (cfg.mode == "jwks") {
		if (cfg.jwks_uri.empty()) {
			throw InvalidInputException(
			    "quack_oauth_check_token: SECRET '%s' is missing `jwks_uri` "
			    "(required for validation_mode='jwks')",
			    secret_name);
		}
	} else if (cfg.mode == "introspect") {
		if (cfg.introspection_endpoint.empty()) {
			throw InvalidInputException(
			    "quack_oauth_check_token: SECRET '%s' is missing "
			    "`introspection_endpoint` (required for validation_mode='introspect')",
			    secret_name);
		}
	} else if (cfg.mode == "tokeninfo") {
		if (cfg.introspection_endpoint.empty()) {
			throw InvalidInputException(
			    "quack_oauth_check_token: SECRET '%s' is missing "
			    "`introspection_endpoint` (required for validation_mode='tokeninfo' -- "
			    "use the IdP's tokeninfo URL, e.g. https://oauth2.googleapis.com/tokeninfo)",
			    secret_name);
		}
	} else if (cfg.mode == "github_check") {
		if (cfg.introspection_endpoint.empty()) {
			throw InvalidInputException(
			    "quack_oauth_check_token: SECRET '%s' is missing "
			    "`introspection_endpoint` (set to GitHub's "
			    "`applications/{client_id}/token` URL, or rely on the "
			    "`provider='github'` preset which fills it from tenant_or_realm).",
			    secret_name);
		}
		if (cfg.introspect_client_id.empty() ||
		    cfg.introspect_client_secret.empty()) {
			throw InvalidInputException(
			    "quack_oauth_check_token: SECRET '%s' is missing "
			    "`introspect_client_id` / `introspect_client_secret` "
			    "(GitHub App credentials, required for HTTP Basic on the "
			    "/applications/{client_id}/token endpoint).",
			    secret_name);
		}
	} else {
		throw InvalidInputException(
		    "quack_oauth_check_token: unknown validation_mode '%s' (expected 'jwks', "
		    "'introspect', 'tokeninfo', or 'github_check')",
		    cfg.mode);
	}
	return cfg;
}

// (cont'd) Build a Principal from a parsed JWT for the authz path.
// `scope` (space-delimited) and `scp[]` are merged into a single vector.
quack_oauth::Principal PrincipalFromJwt(const quack_oauth::JwtParsed &jwt) {
	quack_oauth::Principal p;
	p.subject = jwt.subject;
	p.issuer = jwt.issuer;
	p.exp = jwt.exp;
	if (!jwt.scope.empty()) {
		std::size_t start = 0;
		while (start < jwt.scope.size()) {
			auto end = jwt.scope.find(' ', start);
			if (end == std::string::npos) end = jwt.scope.size();
			if (end > start) {
				p.scopes.emplace_back(jwt.scope.substr(start, end - start));
			}
			start = end + 1;
		}
	}
	for (const auto &s : jwt.scp) {
		p.scopes.push_back(s);
	}
	return p;
}

const char *VerifyResultReason(quack_oauth::VerifyResult r) {
	switch (r) {
	case quack_oauth::VerifyResult::Ok: return "ok";
	case quack_oauth::VerifyResult::Malformed: return "malformed";
	case quack_oauth::VerifyResult::DisallowedAlgorithm: return "disallowed_algorithm";
	case quack_oauth::VerifyResult::InvalidSignature: return "invalid_signature";
	case quack_oauth::VerifyResult::Expired: return "expired";
	case quack_oauth::VerifyResult::NotYetValid: return "not_yet_valid";
	case quack_oauth::VerifyResult::WrongIssuer: return "wrong_issuer";
	case quack_oauth::VerifyResult::WrongAudience: return "wrong_audience";
	case quack_oauth::VerifyResult::UnsupportedKeyType: return "unsupported_key_type";
	case quack_oauth::VerifyResult::UnknownKid: return "unknown_kid";
	case quack_oauth::VerifyResult::JwksFetchFailed: return "jwks_fetch_failed";
	}
	return "unknown";
}

void EmitTokenAudit(ClientContext &context, const std::string &token,
                    quack_oauth::VerifyResult outcome, std::int64_t now_s,
                    const quack_oauth::Principal *principal_on_success) {
	quack_oauth::AuditEvent e;
	e.timestamp_unix_s = now_s;
	const bool ok = outcome == quack_oauth::VerifyResult::Ok;
	e.event_type = ok ? quack_oauth::AuditEventType::TokenAccepted
	                  : quack_oauth::AuditEventType::TokenRejected;
	e.token_hash = quack_oauth::RedactSensitive(token);
	if (ok && principal_on_success != nullptr) {
		e.subject = principal_on_success->subject;
		e.issuer = principal_on_success->issuer;
	}
	e.reason = VerifyResultReason(outcome);
	EmitAuditEvent(context, e);
}

// Shared validation entry point. Both the 1-arg form (direct CLI use) and
// the 3-arg overload (the shape quack itself calls -- session_id, auth_string,
// token -- per `quack/src/quack_extension.cpp` line 125) route here.
//
// When a session_id is known (3-arg overload), and validation succeeds in
// jwks mode, we extract the Principal from the token's claims and store it
// in QuackOauthState::session_principals so the companion authz scalar can
// look it up. introspect / tokeninfo paths also could populate this -- they
// don't yet because their Principal extraction happens deeper inside the
// validator and isn't surfaced to the caller (deferred).
// `session_ids` is optional. When non-null (the 3-arg path), every
// successful jwks-mode validation also caches the resulting Principal
// against the session id so the authz scalar can look it up later.
void ValidateChunk(Vector &tokens, idx_t count, Vector &result,
                   ClientContext &context, Vector *session_ids) {
	const auto cfg = LoadServerConfig(context);

	quack_oauth::VerifyOptions opts;
	opts.expected_issuer = cfg.issuer;
	opts.expected_audience = cfg.audience;
	opts.clock_skew_s = cfg.clock_skew_s;
	opts.now_s = std::chrono::duration_cast<std::chrono::seconds>(
	                 std::chrono::system_clock::now().time_since_epoch())
	                 .count();

	auto &shared_state = GetQuackOauthState();
	// R-N-7: wrap with one retry on transient failure (5xx / transport).
	DuckdbHttpClient base_http;
	quack_oauth::RetryingHttpClient http(base_http);

	std::lock_guard<std::mutex> guard(shared_state.mu);

	if (cfg.mode == "introspect") {
		quack_oauth::IntrospectContext ictx{
		    http,
		    shared_state.decision_cache,
		    cfg.introspection_endpoint,
		    cfg.introspect_client_id,
		    cfg.introspect_client_secret,
		    cfg.issuer,
		    cfg.audience,
		};
		// 3-arg path: capture Principal via the out_principal parameter for
		// session_principals. 1-arg path: pass nullptr.
		if (session_ids != nullptr) {
			UnifiedVectorFormat tok_format;
			UnifiedVectorFormat sid_format;
			tokens.ToUnifiedFormat(count, tok_format);
			session_ids->ToUnifiedFormat(count, sid_format);
			const auto *tok_data = UnifiedVectorFormat::GetData<string_t>(tok_format);
			const auto *sid_data = UnifiedVectorFormat::GetData<string_t>(sid_format);
			result.SetVectorType(VectorType::FLAT_VECTOR);
			auto *out_data = FlatVector::GetData<bool>(result);
			for (idx_t i = 0; i < count; ++i) {
				const auto tok_idx = tok_format.sel->get_index(i);
				const auto sid_idx = sid_format.sel->get_index(i);
				auto token_str = tok_data[tok_idx].GetString();
				const auto sid_str = sid_data[sid_idx].GetString();
				quack_oauth::Principal principal_out;
				const auto outcome = quack_oauth::ValidateTokenViaIntrospection(
				    token_str, opts, ictx, &principal_out);
				const bool ok = outcome == quack_oauth::VerifyResult::Ok;
				out_data[i] = ok;
				if (ok && !sid_str.empty()) {
					shared_state.session_principals[sid_str] = principal_out;
				}
				EmitTokenAudit(context, token_str, outcome, opts.now_s,
				               ok ? &principal_out : nullptr);
				quack_oauth::SecureScrub(token_str); // R-N-3
			}
		} else {
			UnaryExecutor::Execute<string_t, bool>(
			    tokens, result, count, [&](string_t token) {
				    auto token_str = token.GetString();
				    const auto outcome = quack_oauth::ValidateTokenViaIntrospection(
				        token_str, opts, ictx);
				    EmitTokenAudit(context, token_str, outcome, opts.now_s, nullptr);
				    const bool ok = outcome == quack_oauth::VerifyResult::Ok;
				    quack_oauth::SecureScrub(token_str); // R-N-3
				    return ok;
			    });
		}
	} else if (cfg.mode == "tokeninfo") {
		quack_oauth::TokeninfoContext tctx{
		    http,
		    shared_state.decision_cache,
		    cfg.introspection_endpoint,
		    cfg.audience,
		};
		if (session_ids != nullptr) {
			UnifiedVectorFormat tok_format;
			UnifiedVectorFormat sid_format;
			tokens.ToUnifiedFormat(count, tok_format);
			session_ids->ToUnifiedFormat(count, sid_format);
			const auto *tok_data = UnifiedVectorFormat::GetData<string_t>(tok_format);
			const auto *sid_data = UnifiedVectorFormat::GetData<string_t>(sid_format);
			result.SetVectorType(VectorType::FLAT_VECTOR);
			auto *out_data = FlatVector::GetData<bool>(result);
			for (idx_t i = 0; i < count; ++i) {
				const auto tok_idx = tok_format.sel->get_index(i);
				const auto sid_idx = sid_format.sel->get_index(i);
				auto token_str = tok_data[tok_idx].GetString();
				const auto sid_str = sid_data[sid_idx].GetString();
				quack_oauth::Principal principal_out;
				const auto outcome = quack_oauth::ValidateTokenViaTokeninfo(
				    token_str, opts, tctx, &principal_out);
				const bool ok = outcome == quack_oauth::VerifyResult::Ok;
				out_data[i] = ok;
				if (ok && !sid_str.empty()) {
					shared_state.session_principals[sid_str] = principal_out;
				}
				EmitTokenAudit(context, token_str, outcome, opts.now_s,
				               ok ? &principal_out : nullptr);
				quack_oauth::SecureScrub(token_str); // R-N-3
			}
		} else {
			UnaryExecutor::Execute<string_t, bool>(
			    tokens, result, count, [&](string_t token) {
				    auto token_str = token.GetString();
				    const auto outcome = quack_oauth::ValidateTokenViaTokeninfo(
				        token_str, opts, tctx);
				    EmitTokenAudit(context, token_str, outcome, opts.now_s, nullptr);
				    const bool ok = outcome == quack_oauth::VerifyResult::Ok;
				    quack_oauth::SecureScrub(token_str); // R-N-3
				    return ok;
			    });
		}
	} else if (cfg.mode == "github_check") {
		quack_oauth::GithubContext gctx{
		    http,
		    cfg.introspection_endpoint,
		    cfg.introspect_client_id,
		    cfg.introspect_client_secret,
		};
		if (session_ids != nullptr) {
			UnifiedVectorFormat tok_format;
			UnifiedVectorFormat sid_format;
			tokens.ToUnifiedFormat(count, tok_format);
			session_ids->ToUnifiedFormat(count, sid_format);
			const auto *tok_data = UnifiedVectorFormat::GetData<string_t>(tok_format);
			const auto *sid_data = UnifiedVectorFormat::GetData<string_t>(sid_format);
			result.SetVectorType(VectorType::FLAT_VECTOR);
			auto *out_data = FlatVector::GetData<bool>(result);
			for (idx_t i = 0; i < count; ++i) {
				const auto tok_idx = tok_format.sel->get_index(i);
				const auto sid_idx = sid_format.sel->get_index(i);
				auto token_str = tok_data[tok_idx].GetString();
				const auto sid_str = sid_data[sid_idx].GetString();
				quack_oauth::Principal principal_out;
				const auto outcome = quack_oauth::ValidateTokenViaGithubCheck(
				    token_str, gctx, &principal_out);
				const bool ok = outcome == quack_oauth::VerifyResult::Ok;
				out_data[i] = ok;
				if (ok && !sid_str.empty()) {
					shared_state.session_principals[sid_str] = principal_out;
				}
				EmitTokenAudit(context, token_str, outcome, opts.now_s,
				               ok ? &principal_out : nullptr);
				quack_oauth::SecureScrub(token_str); // R-N-3
			}
		} else {
			UnaryExecutor::Execute<string_t, bool>(
			    tokens, result, count, [&](string_t token) {
				    auto token_str = token.GetString();
				    const auto outcome = quack_oauth::ValidateTokenViaGithubCheck(
				        token_str, gctx, nullptr);
				    EmitTokenAudit(context, token_str, outcome, opts.now_s, nullptr);
				    const bool ok = outcome == quack_oauth::VerifyResult::Ok;
				    quack_oauth::SecureScrub(token_str); // R-N-3
				    return ok;
			    });
		}
	} else {
		quack_oauth::ValidateContext vctx{http, shared_state.jwks_cache, cfg.jwks_uri};
		// For the jwks path with a session_id, populate session_principals on
		// success so the authz scalar can resolve the principal. We iterate
		// directly instead of using UnaryExecutor's lambda so we can read
		// the parallel session_id Vector by row.
		if (session_ids != nullptr) {
			UnifiedVectorFormat tok_format;
			UnifiedVectorFormat sid_format;
			tokens.ToUnifiedFormat(count, tok_format);
			session_ids->ToUnifiedFormat(count, sid_format);
			const auto *tok_data = UnifiedVectorFormat::GetData<string_t>(tok_format);
			const auto *sid_data = UnifiedVectorFormat::GetData<string_t>(sid_format);
			result.SetVectorType(VectorType::FLAT_VECTOR);
			auto *out_data = FlatVector::GetData<bool>(result);
			for (idx_t i = 0; i < count; ++i) {
				const auto tok_idx = tok_format.sel->get_index(i);
				const auto sid_idx = sid_format.sel->get_index(i);
				auto token_str = tok_data[tok_idx].GetString();
				const auto sid_str = sid_data[sid_idx].GetString();
				const auto outcome = quack_oauth::ValidateToken(token_str, opts, vctx);
				const bool ok = outcome == quack_oauth::VerifyResult::Ok;
				out_data[i] = ok;
				quack_oauth::Principal principal_for_audit;
				bool have_principal = false;
				if (ok) {
					const auto parsed = quack_oauth::ParseJwt(token_str);
					if (parsed.has_value()) {
						principal_for_audit = PrincipalFromJwt(*parsed);
						have_principal = true;
						if (!sid_str.empty()) {
							shared_state.session_principals[sid_str] = principal_for_audit;
						}
					}
				}
				EmitTokenAudit(context, token_str, outcome, opts.now_s,
				               have_principal ? &principal_for_audit : nullptr);
				quack_oauth::SecureScrub(token_str); // R-N-3
			}
		} else {
			UnaryExecutor::Execute<string_t, bool>(
			    tokens, result, count, [&](string_t token) {
				    auto token_str = token.GetString();
				    const auto outcome =
				        quack_oauth::ValidateToken(token_str, opts, vctx);
				    EmitTokenAudit(context, token_str, outcome, opts.now_s, nullptr);
				    const bool ok = outcome == quack_oauth::VerifyResult::Ok;
				    quack_oauth::SecureScrub(token_str); // R-N-3
				    return ok;
			    });
		}
	}
}

void CheckTokenScalarFun1(DataChunk &args, ExpressionState &state, Vector &result) {
	ValidateChunk(args.data[0], args.size(), result, state.GetContext(), nullptr);
}

// R-N-4: refuse to validate a token over the wire when the active quack
// listener is bound to a non-loopback host AND the operator has not
// explicitly opted in via `quack_oauth_trust_plaintext = true`. The check
// is best-effort: if quack isn't loaded, or the listener list query fails,
// we assume no public surface exists and let the call through. (In the
// real wire path, our check_token is only invoked by quack's auth thread,
// which by construction means a listener is up.)
void EnforcePlaintextGuard(ClientContext &context) {
	Value v;
	if (context.TryGetCurrentSetting("quack_oauth_trust_plaintext", v) &&
	    !v.IsNull() && v.GetValue<bool>()) {
		return; // operator has opted into plaintext.
	}

	Connection conn(*context.db);
	auto result = conn.Query("SELECT listen_uri FROM quack_server_list()");
	if (result->HasError()) {
		return; // quack isn't loaded, or no server is running. Nothing to guard.
	}
	for (auto &row : result->Collection().GetRows()) {
		const auto uri_v = row.GetValue(0);
		if (uri_v.IsNull()) continue;
		const auto uri = StringValue::Get(uri_v);
		const auto host = quack_oauth::HostFromQuackUri(uri);
		if (!quack_oauth::IsLoopbackHost(host)) {
			throw InvalidInputException(
			    "quack_oauth: refusing to validate a bearer token because the "
			    "active quack listener '%s' is bound to a non-loopback host "
			    "and `quack_oauth_trust_plaintext` is not true. Either "
			    "terminate TLS in front of this listener and `SET "
			    "quack_oauth_trust_plaintext = true`, or bind the listener "
			    "to 127.0.0.1 / ::1 / localhost. (R-N-4)",
			    uri);
		}
	}
}

void CheckTokenScalarFun3(DataChunk &args, ExpressionState &state, Vector &result) {
	EnforcePlaintextGuard(state.GetContext());
	// quack's calling convention (verified against duckdb-quack
	// src/quack_server.cpp): SELECT <fn>(session_id, auth_string, token)
	// where:
	//   args[0] = session_id        -- server-generated, used as the
	//                                  Principal-cache key for the authz
	//                                  handoff.
	//   args[1] = auth_string       -- the `token` attach option the
	//                                  client supplied on `ATTACH … (TYPE
	//                                  quack, token '<JWT>')`. This is
	//                                  where the OAuth bearer lives.
	//   args[2] = token             -- quack's own pre-shared random PSK
	//                                  (from `quack_serve`). The default
	//                                  `quack_check_token` uses it for a
	//                                  shared-secret check; we ignore it,
	//                                  the JWKS / introspect / tokeninfo
	//                                  paths don't need it.
	ValidateChunk(args.data[1], args.size(), result, state.GetContext(), &args.data[0]);
}

} // namespace

void RegisterQuackOauthCheckToken(ExtensionLoader &loader) {
	// Both signatures share the name so operators can pick the one that fits.
	// The 1-arg form is convenient for direct SQL invocation; the 3-arg form
	// matches `quack_check_token`'s signature exactly so it can be wired in
	// via `SET quack_authentication_function = 'quack_oauth_check_token'`
	// after `LOAD quack` (slice S-9).
	ScalarFunctionSet set("quack_oauth_check_token");
	ScalarFunction fn1({LogicalType::VARCHAR}, LogicalType::BOOLEAN, CheckTokenScalarFun1);
	// Each call may issue an HTTP fetch (JWKS / introspect / tokeninfo) and
	// always emits audit events. MUST NOT be constant-folded.
	fn1.SetVolatile();
	set.AddFunction(fn1);
	ScalarFunction fn3({LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
	                   LogicalType::BOOLEAN, CheckTokenScalarFun3);
	fn3.SetVolatile();
	set.AddFunction(fn3);

	CreateScalarFunctionInfo info(std::move(set));
	FunctionDescription desc1;
	desc1.description =
	    "Validate an OAuth 2.1 / OIDC access token against the active quack_oauth_server "
	    "SECRET. Returns true if the token verifies (JWKS-mode signature check, RFC 7662 "
	    "introspection, or Google-style tokeninfo per the SECRET's validation_mode).";
	desc1.parameter_names = {"token"};
	desc1.parameter_types = {LogicalType::VARCHAR};
	desc1.examples = {"SELECT quack_oauth_check_token('eyJhbGciOi...')"};
	desc1.categories = {"quack_oauth"};
	info.descriptions.push_back(std::move(desc1));

	FunctionDescription desc3;
	desc3.description =
	    "3-argument form that matches quack's quack_check_token callback signature exactly. "
	    "Validates the token AND caches the extracted Principal keyed by session_id so a "
	    "subsequent quack_oauth_check_authorization() call can apply the policy. Wired into "
	    "quack via `SET quack_authentication_function = 'quack_oauth_check_token'`.";
	desc3.parameter_names = {"session_id", "auth_string", "token"};
	desc3.parameter_types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR};
	desc3.examples = {
	    "SELECT quack_oauth_check_token('sess-1', 'bearer', 'eyJhbGciOi...')"};
	desc3.categories = {"quack_oauth"};
	info.descriptions.push_back(std::move(desc3));

	loader.RegisterFunction(std::move(info));
}

} // namespace duckdb
