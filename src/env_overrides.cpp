#include "env_overrides.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

namespace quack_oauth {

namespace {

std::string TrimAsciiWhitespace(std::string s) {
	auto issp = [](unsigned char c) { return std::isspace(c) != 0; };
	while (!s.empty() && issp(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
	while (!s.empty() && issp(static_cast<unsigned char>(s.back()))) s.pop_back();
	return s;
}

std::string AsciiToLower(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(),
	               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return s;
}

} // namespace

std::string EnvString(const char *name) {
	if (name == nullptr) return {};
	const char *raw = std::getenv(name);
	if (raw == nullptr) return {};
	return TrimAsciiWhitespace(std::string(raw));
}

bool EnvBoolOrDefault(const char *name, bool fallback) {
	const auto v = AsciiToLower(EnvString(name));
	if (v.empty()) return fallback;
	if (v == "1" || v == "true" || v == "yes" || v == "on") return true;
	if (v == "0" || v == "false" || v == "no" || v == "off") return false;
	return fallback;
}

std::int32_t EnvIntOrDefault(const char *name, std::int32_t fallback) {
	const auto v = EnvString(name);
	if (v.empty()) return fallback;
	try {
		std::size_t pos = 0;
		const long long parsed = std::stoll(v, &pos);
		if (pos != v.size()) return fallback; // trailing garbage
		if (parsed < INT32_MIN || parsed > INT32_MAX) return fallback;
		return static_cast<std::int32_t>(parsed);
	} catch (const std::exception &) {
		return fallback;
	}
}

} // namespace quack_oauth
