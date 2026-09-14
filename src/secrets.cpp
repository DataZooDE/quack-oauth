#include "secrets.hpp"
#include "plaintext_guard.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

#include <initializer_list>

namespace duckdb {

// Sensitive field allowlist. Kept in sync with `IsSensitiveField` in
// src/tracing_redact.cpp -- if you change one, change the other.
static constexpr const char *kClientSensitiveFields[] = {
    "client_secret",
    "access_token",
    "refresh_token",
};

static void CopyParams(CreateSecretInput &input, KeyValueSecret &result,
                       std::initializer_list<const char *> field_names) {
	for (const auto *field : field_names) {
		const auto it = input.options.find(field);
		if (it != input.options.end()) {
			result.secret_map[field] = it->second;
		}
	}
}

static void Redact(KeyValueSecret &secret, std::initializer_list<const char *> field_names) {
	for (const auto *field : field_names) {
		secret.redact_keys.insert(field);
	}
}

static bool IsLocalhostUrl(const string &url) {
	static const string kHttpPrefix = "http://";
	if (url.rfind(kHttpPrefix, 0) != 0) {
		return false;
	}

	const size_t auth_start = kHttpPrefix.size();
	const size_t auth_end = url.find_first_of("/?#", auth_start);
	const std::string_view authority = (auth_end == string::npos)
	                                       ? std::string_view(url).substr(auth_start)
	                                       : std::string_view(url).substr(auth_start, auth_end - auth_start);

	if (authority.empty()) {
		return false;
	}

	// Reject userinfo in authority (@)
	if (authority.find('@') != std::string_view::npos) {
		return false;
	}

	std::string_view host;
	std::string_view port_str;

	if (authority.front() == '[') {
		const size_t bracket_end = authority.find(']');
		if (bracket_end == std::string_view::npos) {
			return false;
		}
		host = authority.substr(1, bracket_end - 1);
		const std::string_view remainder = authority.substr(bracket_end + 1);
		if (!remainder.empty()) {
			if (remainder.front() != ':') {
				return false;
			}
			port_str = remainder.substr(1);
		}
	} else {
		const size_t colon = authority.find(':');
		if (colon != std::string_view::npos) {
			host = authority.substr(0, colon);
			port_str = authority.substr(colon + 1);
		} else {
			host = authority;
		}
	}

	if (!port_str.empty()) {
		if (port_str.size() > 5) {
			return false;
		}
		int port = 0;
		for (char c : port_str) {
			if (c < '0' || c > '9') {
				return false;
			}
			port = port * 10 + (c - '0');
		}
		if (port <= 0 || port > 65535) {
			return false;
		}
	}

	if (host.empty()) {
		return false;
	}

	return quack_oauth::IsLoopbackHost(host);
}

void ValidateHttpUrl(const string &field_name, const string &url) {
	if (url.empty()) {
		return;
	}
	if (url.size() > 2048) {
		throw InvalidInputException("quack_oauth: " + field_name +
		                            " exceeds maximum allowed length of 2048 characters");
	}
	for (char c : url) {
		if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) == 127 || c == '"' || c == '\'' ||
		    c == '\\' || c == ' ') {
			throw InvalidInputException("quack_oauth: " + field_name + " contains invalid or control characters");
		}
	}
	const bool is_https = url.rfind("https://", 0) == 0;
	const bool is_http = url.rfind("http://", 0) == 0;
	if (!is_https && !is_http) {
		throw InvalidInputException("quack_oauth: " + field_name +
		                            " must begin with 'https://' (or 'http://localhost' for local development)");
	}
	const size_t scheme_len = is_https ? 8 : 7;
	const size_t auth_end = url.find_first_of("/?#", scheme_len);
	const std::string_view authority = (auth_end == string::npos)
	                                       ? std::string_view(url).substr(scheme_len)
	                                       : std::string_view(url).substr(scheme_len, auth_end - scheme_len);
	if (authority.find('@') != std::string_view::npos) {
		throw InvalidInputException("quack_oauth: " + field_name + " must not contain userinfo ('@')");
	}
	if (is_http && !IsLocalhostUrl(url)) {
		throw InvalidInputException("quack_oauth: " + field_name +
		                            " must use 'https://' (plain 'http://' is only allowed for localhost development)");
	}
}

static void ValidateTenantOrRealm(const string &val) {
	if (val.empty()) {
		return;
	}
	if (val.size() > 2048) {
		throw InvalidInputException("quack_oauth: tenant_or_realm exceeds maximum allowed length of 2048 characters");
	}
	for (char c : val) {
		if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) == 127 || c == '"' || c == '\'' ||
		    c == '\\' || c == ' ') {
			throw InvalidInputException(
			    "quack_oauth: tenant_or_realm contains invalid or control characters (must not contain spaces, quotes, "
			    "backslashes, or control characters)");
		}
	}
	if (val.rfind("http://", 0) == 0 || val.rfind("https://", 0) == 0) {
		ValidateHttpUrl("tenant_or_realm", val);
	} else if (val.find('@') != string::npos) {
		throw InvalidInputException("quack_oauth: tenant_or_realm must not contain userinfo ('@')");
	}
}

static unique_ptr<BaseSecret> CreateClientSecret(ClientContext &, CreateSecretInput &input) {
	auto result = make_uniq<KeyValueSecret>(input.scope, input.type, input.provider, input.name);

	// R-C-1 field set.
	CopyParams(input, *result,
	           {"issuer", "client_id", "client_secret", "audience", "scope", "device_authorization_endpoint",
	            "token_endpoint", "redirect_listener_port", "access_token", "refresh_token", "expires_at"});

	// DuckDB's `CREATE SECRET (..., scope '...')` parser consumes `scope` as
	// the SECRET-API's URL-scope vector (input.scope) BEFORE CopyParams sees
	// it in input.options. We use `scope` as our OAuth scope field, so fall
	// back to input.scope (space-joined) when the options path didn't
	// populate secret_map["scope"]. Without this, the AcquireTokenClientCredentials
	// request lands at IdPs (e.g. Entra v2.0) without a `scope` parameter and
	// fails with AADSTS90014.
	if (result->secret_map.find("scope") == result->secret_map.end() && !input.scope.empty()) {
		string joined;
		for (const auto &s : input.scope) {
			if (!joined.empty()) {
				joined.push_back(' ');
			}
			joined += s;
		}
		result->secret_map["scope"] = Value(joined);
	}

	const auto dev_it = result->secret_map.find("device_authorization_endpoint");
	if (dev_it != result->secret_map.end()) {
		ValidateHttpUrl("device_authorization_endpoint", dev_it->second.ToString());
	}
	const auto tok_it = result->secret_map.find("token_endpoint");
	if (tok_it != result->secret_map.end()) {
		ValidateHttpUrl("token_endpoint", tok_it->second.ToString());
	}

	Redact(*result, {kClientSensitiveFields[0], kClientSensitiveFields[1], kClientSensitiveFields[2]});
	return std::move(result);
}

static unique_ptr<BaseSecret> CreateServerSecret(ClientContext &, CreateSecretInput &input) {
	auto result = make_uniq<KeyValueSecret>(input.scope, input.type, input.provider, input.name);

	// R-S-11 base fields + slice S-10b introspection extension.
	// R-S-11 lists `issuer / audience / jwks_uri / policy_table`; the three
	// `introspect_*` fields are the resolution of the open question raised
	// in docs/IMPLEMENTATION.md §9 -- RFC 7662 confidential clients need
	// credentials, and putting them on the server SECRET (rather than a
	// separate one) keeps the operator surface coherent. `policy_table`
	// names a SQL table in the active database (qualified, e.g.
	// `main.quack_oauth_policies`) holding the authorization rules;
	// see API_REFERENCE.md for the expected schema.
	CopyParams(input, *result,
	           {"issuer", "audience", "jwks_uri", "policy_table", "audit_table", "introspection_endpoint",
	            "introspect_client_id", "introspect_client_secret", "tenant_or_realm"});

	const auto jwks_it = result->secret_map.find("jwks_uri");
	if (jwks_it != result->secret_map.end()) {
		ValidateHttpUrl("jwks_uri", jwks_it->second.ToString());
	}
	const auto intro_it = result->secret_map.find("introspection_endpoint");
	if (intro_it != result->secret_map.end()) {
		ValidateHttpUrl("introspection_endpoint", intro_it->second.ToString());
	}
	const auto tenant_it = result->secret_map.find("tenant_or_realm");
	if (tenant_it != result->secret_map.end()) {
		ValidateTenantOrRealm(tenant_it->second.ToString());
	}

	Redact(*result, {"introspect_client_secret"});
	return std::move(result);
}

static void RegisterClientSecretType(ExtensionLoader &loader) {
	SecretType type;
	type.name = "quack_oauth";
	type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
	type.default_provider = "config";
	loader.RegisterSecretType(type);

	CreateSecretFunction fn = {type.name, "config", CreateClientSecret, {}};
	auto add = [&fn](const char *name, LogicalTypeId logical_type_id) {
		fn.named_parameters[name] = LogicalType(logical_type_id);
	};
	add("issuer", LogicalTypeId::VARCHAR);
	add("client_id", LogicalTypeId::VARCHAR);
	add("client_secret", LogicalTypeId::VARCHAR);
	add("audience", LogicalTypeId::VARCHAR);
	add("scope", LogicalTypeId::VARCHAR);
	add("device_authorization_endpoint", LogicalTypeId::VARCHAR);
	add("token_endpoint", LogicalTypeId::VARCHAR);
	add("redirect_listener_port", LogicalTypeId::INTEGER);
	add("access_token", LogicalTypeId::VARCHAR);
	add("refresh_token", LogicalTypeId::VARCHAR);
	add("expires_at", LogicalTypeId::VARCHAR);
	loader.RegisterFunction(fn);
}

static void RegisterServerSecretType(ExtensionLoader &loader) {
	SecretType type;
	type.name = "quack_oauth_server";
	type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
	type.default_provider = "config";
	loader.RegisterSecretType(type);

	CreateSecretFunction fn = {type.name, "config", CreateServerSecret, {}};
	auto add = [&fn](const char *name, LogicalTypeId logical_type_id) {
		fn.named_parameters[name] = LogicalType(logical_type_id);
	};
	add("issuer", LogicalTypeId::VARCHAR);
	add("audience", LogicalTypeId::VARCHAR);
	add("jwks_uri", LogicalTypeId::VARCHAR);
	add("policy_table", LogicalTypeId::VARCHAR);
	add("audit_table", LogicalTypeId::VARCHAR);
	add("introspection_endpoint", LogicalTypeId::VARCHAR);
	add("introspect_client_id", LogicalTypeId::VARCHAR);
	add("introspect_client_secret", LogicalTypeId::VARCHAR);
	add("tenant_or_realm", LogicalTypeId::VARCHAR);
	loader.RegisterFunction(fn);
}

void RegisterQuackOauthSecrets(ExtensionLoader &loader) {
	RegisterClientSecretType(loader);
	RegisterServerSecretType(loader);
}

} // namespace duckdb
