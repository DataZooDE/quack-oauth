#pragma once

#include <string>
#include <string_view>

namespace quack_oauth {

// First-class provider presets per R-S-12. `Okta` and `Github` are reserved
// names that currently fall through to `Generic` behaviour -- the dedicated
// strategy entries land when those slices come online (architecture §8.6).
enum class ProviderId {
	Generic,
	Entra,
	Google,
	Keycloak,
	Okta,
	Github,
};

// How does this provider expose token validity? Three of the five
// well-defined modes for now; `GithubCheck` is named so the strategy table
// can be extended without changing call sites.
enum class ProviderValidation {
	Jwks,        // RS-family JWT signature verification against JWKS
	Tokeninfo,   // Google-style: GET tokeninfo?access_token=...
	Introspect,  // RFC 7662 confidential-client POST
	GithubCheck, // POST applications/{client_id}/token with HTTP Basic
};

// Static description of a provider. Templates use `{tenant}` as the
// substitution token -- callers pass that in via `ResolveProvider`.
struct ProviderConfig {
	ProviderId id;
	std::string name; // canonical lowercase string ("entra", "keycloak"...)
	ProviderValidation validation;
	std::string issuer_template;
	std::string jwks_uri_template;
	std::string introspection_template; // empty if validation != Introspect
};

// Result of substituting a tenant / realm / org id into the templates.
struct ProviderResolved {
	ProviderId id = ProviderId::Generic;
	ProviderValidation validation = ProviderValidation::Jwks;
	std::string issuer;
	std::string jwks_uri;
	std::string introspection_endpoint;
};

// Parse a provider name. Unknown names map to `Generic`.
ProviderId ProviderFromString(std::string_view s);

// Static lookup -- never throws.
ProviderConfig GetProviderConfig(ProviderId id);

// Substitute `{tenant}` in the provider's templates with `tenant_or_realm`.
// For `Generic`, all materialised URIs are empty (operator MUST provide them
// explicitly on the SECRET). For `Google`, `tenant_or_realm` is ignored --
// Google's endpoints are tenant-free.
ProviderResolved ResolveProvider(ProviderId id, const std::string &tenant_or_realm);

} // namespace quack_oauth
