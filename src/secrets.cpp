#include "secrets.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

#include <initializer_list>

namespace duckdb {

namespace {

// Sensitive field allowlist. Kept in sync with `IsSensitiveField` in
// src/tracing_redact.cpp -- if you change one, change the other.
constexpr const char *kClientSensitiveFields[] = {
    "client_secret",
    "access_token",
    "refresh_token",
};

void CopyParams(CreateSecretInput &input, KeyValueSecret &result,
                std::initializer_list<const char *> field_names) {
	for (const auto *field : field_names) {
		const auto it = input.options.find(field);
		if (it != input.options.end()) {
			result.secret_map[field] = it->second;
		}
	}
}

void Redact(KeyValueSecret &secret, std::initializer_list<const char *> field_names) {
	for (const auto *field : field_names) {
		secret.redact_keys.insert(field);
	}
}

unique_ptr<BaseSecret> CreateClientSecret(ClientContext &, CreateSecretInput &input) {
	auto result = make_uniq<KeyValueSecret>(input.scope, input.type, input.provider, input.name);

	// R-C-1 field set.
	CopyParams(input, *result,
	           {"issuer", "client_id", "client_secret", "audience", "scope",
	            "device_authorization_endpoint", "token_endpoint",
	            "redirect_listener_port", "access_token", "refresh_token",
	            "expires_at"});

	Redact(*result, {kClientSensitiveFields[0], kClientSensitiveFields[1],
	                 kClientSensitiveFields[2]});
	return std::move(result);
}

unique_ptr<BaseSecret> CreateServerSecret(ClientContext &, CreateSecretInput &input) {
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
	           {"issuer", "audience", "jwks_uri", "policy_table", "audit_table",
	            "introspection_endpoint", "introspect_client_id",
	            "introspect_client_secret", "tenant_or_realm"});
	Redact(*result, {"introspect_client_secret"});
	return std::move(result);
}

void RegisterClientSecretType(ExtensionLoader &loader) {
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

void RegisterServerSecretType(ExtensionLoader &loader) {
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

} // namespace

void RegisterQuackOauthSecrets(ExtensionLoader &loader) {
	RegisterClientSecretType(loader);
	RegisterServerSecretType(loader);
}

} // namespace duckdb
