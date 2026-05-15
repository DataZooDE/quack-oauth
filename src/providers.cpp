#include "providers.hpp"

#include <algorithm>
#include <cctype>

namespace quack_oauth {

namespace {

std::string Substitute(const std::string &tmpl, const std::string &tenant) {
	const std::string placeholder = "{tenant}";
	std::string out = tmpl;
	std::size_t pos = 0;
	while ((pos = out.find(placeholder, pos)) != std::string::npos) {
		out.replace(pos, placeholder.size(), tenant);
		pos += tenant.size();
	}
	return out;
}

std::string LowerAscii(std::string_view s) {
	std::string out;
	out.reserve(s.size());
	for (unsigned char c : s) {
		out.push_back(static_cast<char>(std::tolower(c)));
	}
	return out;
}

} // namespace

ProviderId ProviderFromString(std::string_view s) {
	const auto lower = LowerAscii(s);
	if (lower == "entra") return ProviderId::Entra;
	if (lower == "google") return ProviderId::Google;
	if (lower == "keycloak") return ProviderId::Keycloak;
	if (lower == "okta") return ProviderId::Okta;
	if (lower == "github") return ProviderId::Github;
	return ProviderId::Generic;
}

ProviderConfig GetProviderConfig(ProviderId id) {
	switch (id) {
	case ProviderId::Entra:
		// Microsoft Entra ID v2.0 -- the tenant_id substitutes into both
		// the issuer and the JWKS URI. Per requirements R-S-3 audience is
		// the RS's API client ID; we don't template that.
		return {
		    ProviderId::Entra,
		    "entra",
		    ProviderValidation::Jwks,
		    "https://login.microsoftonline.com/{tenant}/v2.0",
		    "https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys",
		    "", // Entra has /introspect but we default to JWKS per R-S-2
		};
	case ProviderId::Google:
		// Google access tokens are opaque -- validation goes through the
		// tokeninfo endpoint, not JWKS. tenant_or_realm is unused.
		return {
		    ProviderId::Google,
		    "google",
		    ProviderValidation::Tokeninfo,
		    "https://accounts.google.com",
		    "https://www.googleapis.com/oauth2/v3/certs", // ID-token JWKS
		    "https://oauth2.googleapis.com/tokeninfo",
		};
	case ProviderId::Keycloak:
		// Keycloak ≥22. `{tenant}` is the realm. The base host is the
		// operator's deployment-specific URL prefix -- since that varies,
		// the template embeds the full base in the substitution: callers
		// pass `https://kc.example.com/realms/main` as tenant_or_realm
		// rather than just `main`. This keeps the template tenant-free
		// from the host's perspective.
		return {
		    ProviderId::Keycloak,
		    "keycloak",
		    ProviderValidation::Jwks,
		    "{tenant}",
		    "{tenant}/protocol/openid-connect/certs",
		    "{tenant}/protocol/openid-connect/token/introspect",
		};
	case ProviderId::Github:
		// R-S-13: GitHub is not OIDC. Validation goes through
		// /applications/{tenant}/token where `tenant` is the App's
		// client_id. Introspection / JWKS templates are unused. The
		// {tenant} substitution naturally drops into the URL.
		return {
		    ProviderId::Github,
		    "github",
		    ProviderValidation::GithubCheck,
		    "https://api.github.com",
		    "", // no JWKS for opaque GitHub tokens
		    "https://api.github.com/applications/{tenant}/token",
		};
	case ProviderId::Okta:
		// Reserved -- a dedicated entry lands in a follow-up slice.
		// Operators can still configure everything explicitly on the
		// SECRET; this just means no auto-fill yet.
	case ProviderId::Generic:
	default:
		return {
		    ProviderId::Generic,
		    "generic",
		    ProviderValidation::Jwks,
		    "", "", "",
		};
	}
}

ProviderResolved ResolveProvider(ProviderId id, const std::string &tenant_or_realm) {
	const auto cfg = GetProviderConfig(id);
	ProviderResolved out;
	out.id = cfg.id;
	out.validation = cfg.validation;
	out.issuer = Substitute(cfg.issuer_template, tenant_or_realm);
	out.jwks_uri = Substitute(cfg.jwks_uri_template, tenant_or_realm);
	out.introspection_endpoint =
	    Substitute(cfg.introspection_template, tenant_or_realm);
	return out;
}

} // namespace quack_oauth
