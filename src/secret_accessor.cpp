#include "secret_accessor.hpp"

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/exception.hpp"

namespace duckdb {

string SecretAccessor::Get(const char *field) const {
	if (kv == nullptr)
		return {};
	const auto it = kv->secret_map.find(field);
	return it != kv->secret_map.end() ? it->second.ToString() : string();
}

bool SecretAccessor::Has(const char *field) const {
	return kv != nullptr && kv->secret_map.find(field) != kv->secret_map.end();
}

SecretAccessor OpenSecret(ClientContext &context, const string &secret_name, const char *expected_type,
                          const char *fn_name_for_errors) {
	if (secret_name.empty()) {
		throw InvalidInputException("%s: secret name must be non-empty", fn_name_for_errors);
	}
	auto &secret_manager = SecretManager::Get(context);
	auto txn = CatalogTransaction::GetSystemCatalogTransaction(context);
	auto entry = secret_manager.GetSecretByName(txn, secret_name);
	if (!entry) {
		throw InvalidInputException("%s: SECRET '%s' not found", fn_name_for_errors, secret_name);
	}
	const auto *kv = dynamic_cast<const KeyValueSecret *>(entry->secret.get());
	if (!kv) {
		throw InvalidInputException("%s: SECRET '%s' is not a key-value secret", fn_name_for_errors, secret_name);
	}
	if (expected_type != nullptr && kv->GetType() != expected_type) {
		throw InvalidInputException("%s: SECRET '%s' is not of TYPE %s (got '%s')", fn_name_for_errors, secret_name,
		                            expected_type, kv->GetType());
	}
	return SecretAccessor {std::move(entry), kv};
}

SecretAccessor TryOpenSecret(ClientContext &context, const string &secret_name, const char *expected_type) {
	if (secret_name.empty())
		return {};
	auto &secret_manager = SecretManager::Get(context);
	auto txn = CatalogTransaction::GetSystemCatalogTransaction(context);
	auto entry = secret_manager.GetSecretByName(txn, secret_name);
	if (!entry)
		return {};
	const auto *kv = dynamic_cast<const KeyValueSecret *>(entry->secret.get());
	if (!kv)
		return {};
	if (expected_type != nullptr && kv->GetType() != expected_type)
		return {};
	return SecretAccessor {std::move(entry), kv};
}

void PersistTokenFields(ClientContext &context, const SecretAccessor &accessor, const string &access_token,
                        const string &expires_at_iso8601, const string &refresh_token) {
	KeyValueSecret updated(*accessor.kv);
	updated.secret_map["access_token"] = Value(access_token);
	updated.secret_map["expires_at"] = Value(expires_at_iso8601);
	if (!refresh_token.empty()) {
		updated.secret_map["refresh_token"] = Value(refresh_token);
	}
	auto &secret_manager = SecretManager::Get(context);
	auto txn = CatalogTransaction::GetSystemCatalogTransaction(context);
	secret_manager.RegisterSecret(txn, make_uniq<KeyValueSecret>(updated), OnCreateConflict::REPLACE_ON_CONFLICT,
	                              accessor.entry->persist_type, accessor.entry->storage_mode);
}

} // namespace duckdb
