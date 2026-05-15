#include "plaintext_guard.hpp"

#include <algorithm>
#include <cctype>

namespace quack_oauth {

static std::string AsciiToLower(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return s;
}

static bool StartsWith(std::string_view s, std::string_view prefix) {
	return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

bool IsLoopbackHost(std::string_view host) {
	if (host.empty())
		return false;
	const auto lower = AsciiToLower(std::string(host));

	if (lower == "localhost")
		return true;
	if (lower == "::1" || lower == "[::1]")
		return true;
	// 127.0.0.0/8 — every IPv4 address starting with "127." is loopback.
	if (StartsWith(lower, "127.")) {
		// Confirm it's actually a dotted-quad and not a hostname starting
		// with "127.": all remaining chars must be digits or dots.
		bool ok = true;
		for (auto c : lower.substr(4)) {
			if (!(c == '.' || (c >= '0' && c <= '9'))) {
				ok = false;
				break;
			}
		}
		if (ok)
			return true;
	}
	return false;
}

std::string HostFromQuackUri(std::string_view uri) {
	if (uri.empty())
		return {};

	// Accept both "quack:" and "quack://" prefixes (the URI parser in
	// duckdb-quack normalises the latter to the former).
	std::string_view body;
	if (StartsWith(uri, "quack://"))
		body = uri.substr(8);
	else if (StartsWith(uri, "quack:"))
		body = uri.substr(6);
	else
		return {};

	if (body.empty())
		return {};

	// IPv6 bracket form: [::1]:port or [::1].
	if (body.front() == '[') {
		const auto close = body.find(']');
		if (close == std::string_view::npos)
			return {};
		return std::string(body.substr(0, close + 1));
	}

	// Dotted-quad or DNS name: host ends at the last ':' (the port separator)
	// or at end-of-string.
	const auto colon = body.rfind(':');
	if (colon == std::string_view::npos) {
		return std::string(body);
	}
	return std::string(body.substr(0, colon));
}

} // namespace quack_oauth
