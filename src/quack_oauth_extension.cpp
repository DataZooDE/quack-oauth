#define DUCKDB_EXTENSION_MAIN

#include "quack_oauth_extension.hpp"
#include "check_authorization_function.hpp"
#include "diagnose.hpp"
#include "secrets.hpp"
#include "settings.hpp"

// Network-touching scalars are skipped on wasm32 -- duckdb_httplib_openssl
// is not available there. See S-14 in docs/IMPLEMENTATION.md.
#ifndef EMSCRIPTEN
#include "acquire_function.hpp"
#include "check_token_function.hpp"
#include "device_login_function.hpp"
#include "login_function.hpp"
#include "logout_function.hpp"
#include "refresh_function.hpp"
#include "telemetry.hpp"
#endif

#include "duckdb/main/config.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

static void LoadInternal(ExtensionLoader &loader) {
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
#ifndef EMSCRIPTEN
	// Anonymous usage telemetry. Same key, same library, same opt-out paths
	// as ../erpl and ../erpl-web. SetAPIKey must precede CaptureExtensionLoad;
	// settings registration follows so that user-supplied
	// `quack_oauth_telemetry_key` overrides the default via OnTelemetryKey.
	PostHogTelemetry::Instance().SetAPIKey("phc_t3wwRLtpyEmLHYaZCSszG0MqVr74J6wnCrj9D41zk2t");
	PostHogTelemetry::Instance().SetProduct("quack_oauth", "2026.05.28", "oss");
	PostHogTelemetry::Instance().AssociateGroup("deployment", PostHogTelemetry::GetDistinctId());
	PostHogTelemetry::Instance().CaptureExtensionLoad("quack_oauth", QuackOauthExtension().Version());
#endif
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
	RegisterQuackOauthAcquire(loader);
#endif
}

void QuackOauthExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}

string QuackOauthExtension::Name() {
	return "quack_oauth";
}

string QuackOauthExtension::Version() const {
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
