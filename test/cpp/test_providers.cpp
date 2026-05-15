#include <catch2/catch_test_macros.hpp>

#include "providers.hpp"

using quack_oauth::GetProviderConfig;
using quack_oauth::ProviderFromString;
using quack_oauth::ProviderId;
using quack_oauth::ProviderResolved;
using quack_oauth::ProviderValidation;
using quack_oauth::ResolveProvider;

TEST_CASE("ProviderFromString recognises canonical names", "[providers][parse]") {
	CHECK(ProviderFromString("entra") == ProviderId::Entra);
	CHECK(ProviderFromString("google") == ProviderId::Google);
	CHECK(ProviderFromString("keycloak") == ProviderId::Keycloak);
	CHECK(ProviderFromString("okta") == ProviderId::Okta);
	CHECK(ProviderFromString("github") == ProviderId::Github);
	CHECK(ProviderFromString("generic") == ProviderId::Generic);
}

TEST_CASE("ProviderFromString is case-insensitive", "[providers][parse]") {
	CHECK(ProviderFromString("ENTRA") == ProviderId::Entra);
	CHECK(ProviderFromString("Google") == ProviderId::Google);
	CHECK(ProviderFromString("KEYcloak") == ProviderId::Keycloak);
}

TEST_CASE("ProviderFromString defaults unknown names to Generic", "[providers][parse]") {
	CHECK(ProviderFromString("") == ProviderId::Generic);
	CHECK(ProviderFromString("auth0") == ProviderId::Generic);
	CHECK(ProviderFromString("something-weird") == ProviderId::Generic);
}

TEST_CASE("Entra: tenant substitutes into issuer and JWKS URI", "[providers][entra]") {
	const auto r = ResolveProvider(ProviderId::Entra, "11111111-2222-3333-4444-555555555555");
	CHECK(r.validation == ProviderValidation::Jwks);
	CHECK(r.issuer == "https://login.microsoftonline.com/"
	                  "11111111-2222-3333-4444-555555555555/v2.0");
	CHECK(r.jwks_uri == "https://login.microsoftonline.com/"
	                    "11111111-2222-3333-4444-555555555555/discovery/v2.0/keys");
	CHECK(r.introspection_endpoint.empty());
}

TEST_CASE("Entra: `common` and `organizations` are accepted as tenant placeholders", "[providers][entra]") {
	const auto r = ResolveProvider(ProviderId::Entra, "common");
	CHECK(r.issuer == "https://login.microsoftonline.com/common/v2.0");
	CHECK(r.jwks_uri == "https://login.microsoftonline.com/common/discovery/v2.0/keys");
}

TEST_CASE("Google: tenant is ignored; validation is Tokeninfo", "[providers][google]") {
	const auto r = ResolveProvider(ProviderId::Google, "anything");
	CHECK(r.validation == ProviderValidation::Tokeninfo);
	CHECK(r.issuer == "https://accounts.google.com");
	CHECK(r.jwks_uri == "https://www.googleapis.com/oauth2/v3/certs");
	CHECK(r.introspection_endpoint == "https://oauth2.googleapis.com/tokeninfo");
}

TEST_CASE("Keycloak: the realm-URL prefix substitutes into all three URIs", "[providers][keycloak]") {
	const auto r = ResolveProvider(ProviderId::Keycloak, "http://localhost:8080/realms/main");
	CHECK(r.validation == ProviderValidation::Jwks);
	CHECK(r.issuer == "http://localhost:8080/realms/main");
	CHECK(r.jwks_uri == "http://localhost:8080/realms/main/protocol/openid-connect/certs");
	CHECK(r.introspection_endpoint == "http://localhost:8080/realms/main/protocol/openid-connect/token/introspect");
}

TEST_CASE("Generic: all materialised URIs are empty -- operator must supply", "[providers][generic]") {
	const auto r = ResolveProvider(ProviderId::Generic, "ignored");
	CHECK(r.validation == ProviderValidation::Jwks);
	CHECK(r.issuer.empty());
	CHECK(r.jwks_uri.empty());
	CHECK(r.introspection_endpoint.empty());
}

TEST_CASE("Okta currently falls through to Generic behaviour", "[providers][reserved]") {
	const auto r = ResolveProvider(ProviderId::Okta, "whatever");
	CHECK(r.issuer.empty());
	CHECK(r.jwks_uri.empty());
	CHECK(r.introspection_endpoint.empty());
}

TEST_CASE("Github preset: introspection_endpoint substitutes client_id", "[providers][github]") {
	const auto r = ResolveProvider(ProviderId::Github, "Iv1.abcdef");
	CHECK(r.id == ProviderId::Github);
	CHECK(r.validation == quack_oauth::ProviderValidation::GithubCheck);
	CHECK(r.issuer == "https://api.github.com");
	CHECK(r.jwks_uri.empty()); // opaque tokens, no JWKS
	CHECK(r.introspection_endpoint == "https://api.github.com/applications/Iv1.abcdef/token");
}
