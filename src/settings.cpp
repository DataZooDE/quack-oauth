#include "settings.hpp"

#include "duckdb/main/config.hpp"

#include "env_overrides.hpp"

namespace duckdb {

// R-S-11(c) helpers: resolve each setting's default from the matching
// `QUACK_OAUTH_<UPPER>` environment variable when present. SET in SQL
// still overrides at runtime. SECRET-field overrides happen at SECRET
// read time, not here. Convention: setting `quack_oauth_validation_mode`
// → env var `QUACK_OAUTH_VALIDATION_MODE`.
static Value EnvStringDefault(const char *env_name, const char *fallback) {
	const auto v = quack_oauth::EnvString(env_name);
	return v.empty() ? Value(fallback) : Value(v);
}

static Value EnvBoolDefault(const char *env_name, bool fallback) {
	return Value::BOOLEAN(quack_oauth::EnvBoolOrDefault(env_name, fallback));
}

static Value EnvIntDefault(const char *env_name, int32_t fallback) {
	return Value::INTEGER(quack_oauth::EnvIntOrDefault(env_name, fallback));
}

// All quack_oauth_* settings are SetScope::GLOBAL. Reason: quack's auth
// thread (`quack_server.cpp`) runs the configured authn/authz scalars on
// fresh `ClientContext` objects per incoming wire request -- a SESSION
// scope would mean those contexts see only the defaults, so e.g.
// `quack_oauth_server_secret_name` would resolve to "" and check_token
// would reject every connection. Quack's own settings
// (`quack_authentication_function`, `quack_authorization_function`)
// are GLOBAL for the same reason.
void RegisterQuackOauthSettings(DBConfig &config) {
	// R-S-1: master switch. Default false so LOAD is side-effect-free.
	config.AddExtensionOption("quack_oauth_enabled",
	                          "Swap quack's auth callbacks for the OAuth implementation (R-S-1).", LogicalType::BOOLEAN,
	                          EnvBoolDefault("QUACK_OAUTH_ENABLED", false), nullptr, SetScope::GLOBAL);

	// R-S-2: jwks (local JWT verification) vs introspect (RFC 7662).
	config.AddExtensionOption("quack_oauth_validation_mode",
	                          "Token validation strategy: 'jwks' or 'introspect' (R-S-2).", LogicalType::VARCHAR,
	                          EnvStringDefault("QUACK_OAUTH_VALIDATION_MODE", "jwks"), nullptr, SetScope::GLOBAL);

	// R-S-12: first-class provider selector (entra|google|keycloak|okta|github|generic).
	config.AddExtensionOption(
	    "quack_oauth_provider", "First-class IdP preset: entra|google|keycloak|okta|github|generic (R-S-12).",
	    LogicalType::VARCHAR, EnvStringDefault("QUACK_OAUTH_PROVIDER", "generic"), nullptr, SetScope::GLOBAL);

	// R-S-3: clock skew for JWT exp/nbf/iat checks.
	config.AddExtensionOption(
	    "quack_oauth_clock_skew_s", "Allowable clock skew (seconds) when verifying JWT exp/nbf/iat (R-S-3).",
	    LogicalType::INTEGER, EnvIntDefault("QUACK_OAUTH_CLOCK_SKEW_S", 60), nullptr, SetScope::GLOBAL);

	// R-S-4: rate-limit per-kid JWKS refresh to guard against poll DoS.
	config.AddExtensionOption("quack_oauth_jwks_min_refresh_s",
	                          "Minimum seconds between JWKS refreshes per kid (R-S-4).", LogicalType::INTEGER,
	                          EnvIntDefault("QUACK_OAUTH_JWKS_MIN_REFRESH_S", 30), nullptr, SetScope::GLOBAL);

	// R-S-5: cache RFC 7662 introspect results.
	config.AddExtensionOption("quack_oauth_introspect_cache_s",
	                          "Cache lifetime (seconds) for introspect-mode decisions, capped at token exp (R-S-5).",
	                          LogicalType::INTEGER, EnvIntDefault("QUACK_OAUTH_INTROSPECT_CACHE_S", 30), nullptr,
	                          SetScope::GLOBAL);

	// R-C-2: client-side proactive renewal window.
	config.AddExtensionOption(
	    "quack_oauth_renew_skew_s", "Client refreshes the access token this many seconds before expires_at (R-C-2).",
	    LogicalType::INTEGER, EnvIntDefault("QUACK_OAUTH_RENEW_SKEW_S", 60), nullptr, SetScope::GLOBAL);

	// R-S-7: default decision when no policy_table rule matches. The rules
	// themselves live in a SQL table named per-resource-server via the
	// `policy_table` field on the quack_oauth_server SECRET; this setting
	// only controls the fallback when none of those rules fire. Default is
	// 'deny' to preserve fail-closed behaviour.
	config.AddExtensionOption(
	    "quack_oauth_policy_default", "Default decision when no policy_table rule matches: 'allow' or 'deny' (R-S-7).",
	    LogicalType::VARCHAR, EnvStringDefault("QUACK_OAUTH_POLICY_DEFAULT", "deny"), nullptr, SetScope::GLOBAL);

	// R-N-4: explicit operator opt-in to serving bearer tokens over plaintext.
	config.AddExtensionOption(
	    "quack_oauth_trust_plaintext", "Allow LOAD with enabled=true even when no TLS terminator is detected (R-N-4).",
	    LogicalType::BOOLEAN, EnvBoolDefault("QUACK_OAUTH_TRUST_PLAINTEXT", false), nullptr, SetScope::GLOBAL);

	// Names the `quack_oauth_server` SECRET the validator reads issuer /
	// audience / jwks_uri from. Empty means `check_token` has no config and
	// will raise.
	config.AddExtensionOption("quack_oauth_server_secret_name",
	                          "Name of the quack_oauth_server SECRET that check_token reads.", LogicalType::VARCHAR,
	                          EnvStringDefault("QUACK_OAUTH_SERVER_SECRET_NAME", ""), nullptr, SetScope::GLOBAL);
}

} // namespace duckdb
