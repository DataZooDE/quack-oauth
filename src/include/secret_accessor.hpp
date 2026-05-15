#pragma once

#include <string>

#include "duckdb/main/client_context.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

namespace duckdb {

// RAII handle for a typed quack_oauth SECRET. Centralises the 6-line
// `SecretManager::Get + GetSystemCatalogTransaction + GetSecretByName +
// dynamic_cast + null-check + type-check` boilerplate that was duplicated
// across 9 call sites.
//
// `OpenSecret` throws `InvalidInputException` (the user-facing fail loud
// path) when the SECRET is missing, of the wrong shape, or of the wrong
// TYPE. Callers don't have to re-check.
//
// Lifetime: `entry` owns the underlying SecretEntry. `kv` is borrowed
// from `entry->secret` and is valid for the lifetime of `entry`. Don't
// let `entry` go out of scope while you're still reading through `kv`.
struct SecretAccessor {
	unique_ptr<SecretEntry> entry;
	const KeyValueSecret *kv = nullptr;

	// Reads a field; returns empty string if absent.
	string Get(const char *field) const;
	string Get(const string &field) const {
		return Get(field.c_str());
	}

	// True if the field is present (even as empty string).
	bool Has(const char *field) const;
};

// Look up `secret_name`, verify it is a TYPE=`expected_type` SECRET, and
// return an accessor. Errors raise with `fn_name_for_errors` (e.g.
// "quack_oauth_login") in the message so operators see which scalar
// failed.
SecretAccessor OpenSecret(ClientContext &context, const string &secret_name, const char *expected_type,
                          const char *fn_name_for_errors);

// Soft variant: never throws. Returns an accessor with `kv == nullptr`
// (and `Get(...)` returning empty string) when the SECRET is missing,
// wrong-shape, or wrong-type. Use for fail-soft lookups (e.g. the
// policy_table / audit_table fields on the server SECRET, where the
// caller wants to default-deny / skip silently rather than error).
SecretAccessor TryOpenSecret(ClientContext &context, const string &secret_name, const char *expected_type);

// Persist `access_token` + `expires_at_iso8601` (and `refresh_token` if
// non-empty) back onto the SECRET that `accessor` opened. Uses
// REPLACE_ON_CONFLICT and preserves the SECRET's existing persist_type
// and storage_mode. The "write tokens back on the SECRET" path is the
// same for login / refresh / device_login -- centralised here.
void PersistTokenFields(ClientContext &context, const SecretAccessor &accessor, const string &access_token,
                        const string &expires_at_iso8601, const string &refresh_token);

} // namespace duckdb
