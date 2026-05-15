#define DUCKDB_EXTENSION_MAIN

#include "quack_oauth_extension.hpp"
#include "check_authorization_function.hpp"
#include "diagnose.hpp"
#include "secrets.hpp"
#include "settings.hpp"

// Network-touching scalars are skipped on wasm32 -- duckdb_httplib_openssl
// is not available there. See S-14 in docs/IMPLEMENTATION.md.
#ifndef EMSCRIPTEN
#include "check_token_function.hpp"
#include "device_login_function.hpp"
#include "login_function.hpp"
#include "logout_function.hpp"
#include "refresh_function.hpp"
#endif

#include "duckdb.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

static void LoadInternal(ExtensionLoader &loader) {
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	RegisterQuackOauthSettings(config);
	RegisterQuackOauthSecrets(loader);
	RegisterQuackOauthDiagnose(loader);
	RegisterQuackOauthCheckAuthorization(loader);
#ifndef EMSCRIPTEN
	RegisterQuackOauthCheckToken(loader);
	RegisterQuackOauthLogin(loader);
	RegisterQuackOauthLogout(loader);
	RegisterQuackOauthRefresh(loader);
	RegisterQuackOauthDeviceLogin(loader);
#endif
}

void QuackOauthExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}

std::string QuackOauthExtension::Name() {
	return "quack_oauth";
}

std::string QuackOauthExtension::Version() const {
#ifdef EXT_VERSION_QUACK_OAUTH
	return EXT_VERSION_QUACK_OAUTH;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(quack_oauth, loader) {
	duckdb::LoadInternal(loader);
}
}
